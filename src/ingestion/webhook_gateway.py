"""
VibeLock — Ingestion Layer: FastAPI Webhook Gateway
Handles GitHub webhooks, validates signatures, publishes to Redis queue.
Includes health monitoring, rate limiting, and webhook replay.
"""
import hashlib
import hmac
import json
import time
import asyncio
import uuid
from typing import Optional
from datetime import datetime, timezone
from collections import defaultdict

import structlog
from fastapi import FastAPI, Request, HTTPException, Header, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from pydantic_settings import BaseSettings, SettingsConfigDict

logger = structlog.get_logger(__name__)


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="VIBELOCK_", env_file=".env")
    
    github_webhook_secret: str = Field(default="", description="GitHub webhook shared secret")
    redis_url: str = Field(default="redis://localhost:6379/0")
    jwt_secret: str = Field(default="change-me-in-production")
    api_port: int = Field(default=8000)
    webhook_path: str = Field(default="/webhook/github")
    rate_limit_per_minute: int = Field(default=60)
    webhook_retry_max: int = Field(default=3)
    webhook_retry_backoff: float = Field(default=2.0)
    supabase_url: str = Field(default="")
    supabase_service_key: str = Field(default="")


settings = Settings()
app = FastAPI(
    title="VibeLock Ingestion Gateway",
    version="0.3.0",
    description="Autonomous security remediation — webhook ingestion, scanning, and PR automation API.",
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json",
)

# Mount GitHub App setup routes
from vibelock.src.api.github_setup_routes import router as github_setup_router
app.include_router(github_setup_router)

# Mount Dashboard API routes
from vibelock.src.api.dashboard import router as dashboard_router
app.include_router(dashboard_router)

# Mount API Keys routes
from vibelock.src.api.api_keys import router as api_keys_router
app.include_router(api_keys_router)

# Mount Prometheus metrics routes
from vibelock.src.shared.metrics import router as metrics_router
app.include_router(metrics_router)

# Mount Auth routes (login)
from vibelock.src.api.auth import auth_router
app.include_router(auth_router)

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)


# --- Redis-backed Rate Limiter ---
class RateLimiter:
    """Redis-backed sliding-window rate limiter using sorted sets."""

    REDIS_KEY_PREFIX = "vibelock:ratelimit:"

    def __init__(self, max_per_minute: int = 60):
        self.max_per_minute = max_per_minute

    async def is_allowed(self, key: str) -> bool:
        redis = get_redis()
        if redis is None:
            # Fallback: allow all if Redis is down
            return True

        now_ms = int(time.time() * 1000)
        window_ms = 60_000
        cutoff_ms = now_ms - window_ms
        redis_key = f"{self.REDIS_KEY_PREFIX}{key}"

        try:
            async with redis.pipeline(transaction=True) as pipe:
                # Remove expired entries
                await pipe.zremrangebyscore(redis_key, 0, cutoff_ms)
                # Count current window
                await pipe.zcard(redis_key)
                # Add current request
                await pipe.zadd(redis_key, {str(now_ms): now_ms})
                # Set TTL on the key
                await pipe.expire(redis_key, 120)
                _, count, _, _ = await pipe.execute()

            return count < self.max_per_minute
        except Exception as e:
            logger.error("rate_limiter_redis_error", error=str(e))
            return True  # Fail open

    async def remaining(self, key: str) -> int:
        redis = get_redis()
        if redis is None:
            return self.max_per_minute

        now_ms = int(time.time() * 1000)
        cutoff_ms = now_ms - 60_000
        redis_key = f"{self.REDIS_KEY_PREFIX}{key}"

        try:
            await redis.zremrangebyscore(redis_key, 0, cutoff_ms)
            count = await redis.zcard(redis_key)
            return max(0, self.max_per_minute - count)
        except Exception:
            return self.max_per_minute

    async def active_keys(self) -> int:
        """Count active rate-limit keys (for health monitoring)."""
        redis = get_redis()
        if redis is None:
            return 0
        try:
            keys = await redis.keys(f"{self.REDIS_KEY_PREFIX}*")
            return len(keys)
        except Exception:
            return 0


rate_limiter = RateLimiter(max_per_minute=settings.rate_limit_per_minute)


# --- Redis-backed Webhook Replay Store ---
class WebhookReplayStore:
    """Redis-backed store for failed webhook deliveries with retry support."""

    FAILED_KEY = "vibelock:failed_deliveries"
    DEAD_LETTER_KEY = "vibelock:dead_letter"
    STATUS_KEY_PREFIX = "vibelock:delivery_status:"

    async def record_failure(self, delivery_id: str, payload: dict, error: str):
        redis = get_redis()
        if redis is None:
            return
        entry = {
            "delivery_id": delivery_id,
            "payload": json.dumps(payload),
            "error": error,
            "failed_at": datetime.now(timezone.utc).isoformat(),
            "retry_count": "0",
        }
        try:
            await redis.hset(self.FAILED_KEY, delivery_id, json.dumps(entry))
            await redis.expire(self.FAILED_KEY, 86400 * 7)  # 7-day TTL
        except Exception as e:
            logger.error("replay_store_record_failure_error", error=str(e))

    async def record_success(self, delivery_id: str):
        redis = get_redis()
        if redis is None:
            return
        try:
            await redis.hdel(self.FAILED_KEY, delivery_id)
            await redis.setex(
                f"{self.STATUS_KEY_PREFIX}{delivery_id}",
                3600,
                json.dumps({"status": "delivered", "at": datetime.now(timezone.utc).isoformat()}),
            )
        except Exception as e:
            logger.error("replay_store_record_success_error", error=str(e))

    async def get_pending(self) -> list[dict]:
        redis = get_redis()
        if redis is None:
            return []
        try:
            raw = await redis.hgetall(self.FAILED_KEY)
            pending = []
            for delivery_id, data_json in raw.items():
                entry = json.loads(data_json)
                retry_count = int(entry.get("retry_count", 0))
                if retry_count < settings.webhook_retry_max:
                    pending.append({
                        "delivery_id": delivery_id,
                        "payload": json.loads(entry["payload"]),
                        "error": entry["error"],
                        "failed_at": entry["failed_at"],
                        "retry_count": retry_count,
                    })
            return pending
        except Exception as e:
            logger.error("replay_store_get_pending_error", error=str(e))
            return []

    async def increment_retry(self, delivery_id: str):
        redis = get_redis()
        if redis is None:
            return
        try:
            raw = await redis.hget(self.FAILED_KEY, delivery_id)
            if raw:
                entry = json.loads(raw)
                new_count = int(entry.get("retry_count", 0)) + 1
                entry["retry_count"] = str(new_count)
                await redis.hset(self.FAILED_KEY, delivery_id, json.dumps(entry))

                # Move to dead-letter if max retries exceeded
                if new_count >= settings.webhook_retry_max:
                    dead_entry = {
                        **entry,
                        "moved_to_dlq_at": datetime.now(timezone.utc).isoformat(),
                    }
                    await redis.lpush(self.DEAD_LETTER_KEY, json.dumps(dead_entry))
                    await redis.hdel(self.FAILED_KEY, delivery_id)
                    logger.warning("delivery_moved_to_dlq", delivery_id=delivery_id)
        except Exception as e:
            logger.error("replay_store_increment_retry_error", error=str(e))

    async def get_delivery_status(self, delivery_id: str) -> dict:
        """Check status of a specific delivery."""
        redis = get_redis()
        if redis is None:
            return {"delivery_id": delivery_id, "status": "unknown", "error": "redis_unavailable"}

        try:
            # Check success status
            status_raw = await redis.get(f"{self.STATUS_KEY_PREFIX}{delivery_id}")
            if status_raw:
                return {"delivery_id": delivery_id, **json.loads(status_raw)}

            # Check if in failed store
            failed_raw = await redis.hget(self.FAILED_KEY, delivery_id)
            if failed_raw:
                entry = json.loads(failed_raw)
                return {
                    "delivery_id": delivery_id,
                    "status": "pending_retry",
                    "retry_count": int(entry.get("retry_count", 0)),
                    "failed_at": entry.get("failed_at"),
                    "error": entry.get("error"),
                }

            # Check dead-letter
            dlq_items = await redis.lrange(self.DEAD_LETTER_KEY, 0, -1)
            for item_json in dlq_items:
                item = json.loads(item_json)
                if item.get("delivery_id") == delivery_id:
                    return {
                        "delivery_id": delivery_id,
                        "status": "dead_letter",
                        "retry_count": int(item.get("retry_count", 0)),
                        "moved_to_dlq_at": item.get("moved_to_dlq_at"),
                    }

            return {"delivery_id": delivery_id, "status": "not_found"}
        except Exception as e:
            return {"delivery_id": delivery_id, "status": "error", "error": str(e)}

    async def pending_count(self) -> int:
        redis = get_redis()
        if redis is None:
            return 0
        try:
            return await redis.hlen(self.FAILED_KEY)
        except Exception:
            return 0


replay_store = WebhookReplayStore()


# --- Models ---
class WebhookPayload(BaseModel):
    event_type: str = Field(alias="X-GitHub-Event", default="push")
    delivery_id: Optional[str] = Field(alias="X-GitHub-Delivery", default=None)
    signature: Optional[str] = Field(alias="X-Hub-Signature-256", default=None)
    body: dict


class HealthResponse(BaseModel):
    status: str
    service: str
    version: str
    uptime_seconds: float
    timestamp: str
    rate_limiter: dict
    pending_retries: int
    system: dict


# --- Startup time ---
START_TIME = time.time()


# --- Signature Verification ---
def verify_signature(payload_body: bytes, signature_header: str) -> bool:
    """Verify GitHub webhook HMAC-SHA256 signature."""
    if not settings.github_webhook_secret:
        logger.warning("webhook_secret_not_configured")
        return True
    
    if not signature_header:
        return False
    
    expected = "sha256=" + hmac.new(
        settings.github_webhook_secret.encode(),
        payload_body,
        hashlib.sha256,
    ).hexdigest()
    
    return hmac.compare_digest(expected, signature_header)


# --- Redis Publisher (lazy) ---
_redis = None

def get_redis():
    global _redis
    if _redis is None:
        try:
            import redis.asyncio as aioredis
            _redis = aioredis.from_url(settings.redis_url, decode_responses=True)
        except ImportError:
            logger.warning("redis_not_installed")
            _redis = None
        except Exception as e:
            logger.error("redis_connection_failed", error=str(e))
            _redis = None
    return _redis


async def publish_to_queue(payload: dict) -> bool:
    """Publish webhook payload to Redis queue for async scanning."""
    redis = get_redis()
    if redis is None:
        return False
    try:
        await redis.lpush("vibelock:scan_queue", json.dumps(payload))
        return True
    except Exception as e:
        logger.error("redis_publish_failed", error=str(e))
        return False


# --- Supabase Health Check ---
async def check_supabase_health() -> dict:
    """Check Supabase connectivity."""
    if not settings.supabase_url or not settings.supabase_service_key:
        return {"connected": False, "error": "SUPABASE_URL or SUPABASE_SERVICE_KEY not configured"}
    try:
        from supabase import create_client
        client = create_client(settings.supabase_url, settings.supabase_service_key)
        result = client.table("organizations").select("id").limit(1).execute()
        return {"connected": True}
    except ImportError:
        return {"connected": False, "error": "supabase-py not installed"}
    except Exception as e:
        return {"connected": False, "error": str(e)}


# --- Endpoints ---

@app.get("/health", response_model=HealthResponse)
async def health_check():
    """Detailed health check endpoint with system metrics."""
    try:
        import psutil
        
        cpu_percent = psutil.cpu_percent(interval=0.1)
        mem = psutil.virtual_memory()
        disk = psutil.disk_usage("/")
        
        system = {
            "cpu_percent": cpu_percent,
            "memory_total_gb": round(mem.total / (1024**3), 2),
            "memory_used_gb": round(mem.used / (1024**3), 2),
            "memory_available_gb": round(mem.available / (1024**3), 2),
            "memory_percent": mem.percent,
            "disk_total_gb": round(disk.total / (1024**3), 2),
            "disk_used_gb": round(disk.used / (1024**3), 2),
            "disk_free_gb": round(disk.free / (1024**3), 2),
            "disk_percent": disk.percent,
        }
    except ImportError:
        system = {"note": "psutil not installed — run: pip install psutil"}
    except Exception as e:
        system = {"error": str(e)}
    
    active_keys = await rate_limiter.active_keys()
    pending = await replay_store.pending_count()

    return {
        "status": "ok",
        "service": "vibelock-ingestion",
        "version": "0.3.0",
        "uptime_seconds": round(time.time() - START_TIME, 1),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "rate_limiter": {
            "max_per_minute": settings.rate_limit_per_minute,
            "active_keys": active_keys,
        },
        "pending_retries": pending,
        "system": system,
    }


@app.get("/health/live")
async def liveness():
    """Kubernetes-style liveness probe."""
    return {"status": "alive"}


@app.get("/health/ready")
async def readiness():
    """Kubernetes-style readiness probe — checks Redis and Supabase connectivity."""
    redis = get_redis()
    redis_ok = False
    if redis:
        try:
            await redis.ping()
            redis_ok = True
        except Exception:
            pass

    supabase_health = await check_supabase_health()
    
    checks = {
        "status": "ready",
        "redis": "connected" if redis_ok else ("not_configured" if not settings.redis_url else "disconnected"),
        "supabase": supabase_health,
    }

    if not redis_ok and settings.redis_url:
        return JSONResponse(status_code=503, content={**checks, "status": "not_ready"})
    return checks


@app.get("/webhook/replay/pending")
async def list_pending_retries():
    """List webhooks awaiting retry."""
    pending = await replay_store.get_pending()
    return {"pending": pending}


@app.post("/webhook/replay/retry")
async def trigger_retry():
    """Manually trigger retry of all pending webhooks."""
    pending = await replay_store.get_pending()
    results = []
    for item in pending:
        delivery_id = item["delivery_id"]
        payload = item["payload"]
        success = await publish_to_queue(payload)
        if success:
            await replay_store.record_success(delivery_id)
            results.append({"delivery_id": delivery_id, "status": "retried"})
        else:
            await replay_store.increment_retry(delivery_id)
            results.append({"delivery_id": delivery_id, "status": "failed_again"})
    return {"results": results}


@app.get("/webhook/status/{delivery_id}")
async def get_delivery_status(delivery_id: str):
    """Check the status of a specific webhook delivery."""
    status = await replay_store.get_delivery_status(delivery_id)
    return status


@app.post("/webhook/github")
async def github_webhook(
    request: Request,
    x_github_event: str = Header(default="push"),
    x_hub_signature_256: str = Header(default=""),
    x_github_delivery: str = Header(default=""),
):
    """Receive GitHub webhook, validate, and queue for scanning."""
    # Rate limit check
    client_ip = request.client.host if request.client else "unknown"
    allowed = await rate_limiter.is_allowed(client_ip)
    remaining = await rate_limiter.remaining(client_ip)

    if not allowed:
        logger.warning("rate_limited", ip=client_ip)
        return JSONResponse(
            status_code=429,
            content={"detail": "Too many requests"},
            headers={
                "X-RateLimit-Limit": str(settings.rate_limit_per_minute),
                "X-RateLimit-Remaining": "0",
                "Retry-After": "60",
            },
        )
    
    body = await request.body()
    
    if not verify_signature(body, x_hub_signature_256):
        logger.warning("invalid_signature", delivery=x_github_delivery)
        raise HTTPException(status_code=401, detail="Invalid signature")
    
    # Only process push/ping events
    if x_github_event not in ("push", "ping"):
        logger.info("ignored_event", event=x_github_event)
        return {"status": "ignored", "event": x_github_event}
    
    logger.info(
        "webhook_received",
        event=x_github_event,
        delivery=x_github_delivery,
        content_length=len(body),
    )
    
    # Parse payload
    try:
        payload = json.loads(body)
    except json.JSONDecodeError:
        raise HTTPException(status_code=400, detail="Invalid JSON body")
    
    # Build scan payload
    scan_payload = {
        "event": x_github_event,
        "delivery": x_github_delivery,
        "repository": payload.get("repository", {}).get("full_name", "unknown"),
        "repository_id": str(payload.get("repository", {}).get("id", "")),
        "commit_sha": payload.get("after", payload.get("head_commit", {}).get("id", "")),
        "branch": payload.get("ref", "refs/heads/main").replace("refs/heads/", ""),
        "installation_id": payload.get("installation", {}).get("id"),
        "changed_files": _extract_changed_files(payload),
        "pusher": payload.get("pusher", {}).get("name", "unknown"),
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    
    # Publish to Redis
    published = await publish_to_queue(scan_payload)
    
    if not published:
        # Queue failed — store for retry
        delivery_id = x_github_delivery or str(uuid.uuid4())
        await replay_store.record_failure(delivery_id, scan_payload, "redis_unavailable")
        logger.warning("queue_publish_failed_stored_for_retry", delivery=delivery_id)
        return JSONResponse(
            status_code=202,
            content={
                "status": "accepted_retry_pending",
                "delivery": delivery_id,
                "event": x_github_event,
            },
            headers={
                "X-RateLimit-Limit": str(settings.rate_limit_per_minute),
                "X-RateLimit-Remaining": str(remaining),
            },
        )
    
    delivery_id = x_github_delivery or str(uuid.uuid4())
    await replay_store.record_success(delivery_id)
    
    return JSONResponse(
        status_code=200,
        content={
            "status": "accepted",
            "delivery": delivery_id,
            "event": x_github_event,
        },
        headers={
            "X-RateLimit-Limit": str(settings.rate_limit_per_minute),
            "X-RateLimit-Remaining": str(remaining),
        },
    )


def _extract_changed_files(payload: dict) -> list[str]:
    """Extract list of changed files from webhook payload."""
    files = []
    
    # Push event: commits array
    for commit in payload.get("commits", []):
        for file in commit.get("added", []):
            files.append(file)
        for file in commit.get("modified", []):
            if file not in files:
                files.append(file)
        for file in commit.get("removed", []):
            if file not in files:
                files.append(file)
    
    # Head commit fallback
    if not files:
        head = payload.get("head_commit", {})
        for file in head.get("added", []):
            files.append(file)
        for file in head.get("modified", []):
            if file not in files:
                files.append(file)
    
    return files


# --- Startup / Shutdown ---
@app.on_event("startup")
async def startup():
    logger.info("vibelock_gateway_starting", port=settings.api_port)
    # Pre-warm Redis connection
    redis = get_redis()
    if redis:
        try:
            await redis.ping()
            logger.info("redis_connected")
        except Exception as e:
            logger.warning("redis_not_available_on_startup", error=str(e))


@app.on_event("shutdown")
async def shutdown():
    global _redis
    if _redis:
        await _redis.close()
        logger.info("redis_disconnected")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=settings.api_port)