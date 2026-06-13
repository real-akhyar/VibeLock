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


settings = Settings()
app = FastAPI(title="VibeLock Ingestion Gateway", version="0.2.0")

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)


# --- Rate Limiting ---
class RateLimiter:
    """Simple in-memory sliding-window rate limiter."""
    
    def __init__(self, max_per_minute: int = 60):
        self.max_per_minute = max_per_minute
        self._windows: dict[str, list[float]] = defaultdict(list)
    
    def is_allowed(self, key: str) -> bool:
        now = time.time()
        window = self._windows[key]
        # Remove expired entries
        self._windows[key] = [t for t in window if now - t < 60]
        if len(self._windows[key]) >= self.max_per_minute:
            return False
        self._windows[key].append(now)
        return True
    
    def remaining(self, key: str) -> int:
        now = time.time()
        window = [t for t in self._windows.get(key, []) if now - t < 60]
        return max(0, self.max_per_minute - len(window))


rate_limiter = RateLimiter(max_per_minute=settings.rate_limit_per_minute)


# --- Webhook Replay Store ---
class WebhookReplayStore:
    """In-memory store for failed webhook deliveries, with retry support."""
    
    def __init__(self):
        self._failed: dict[str, dict] = {}
        self._retry_counts: dict[str, int] = defaultdict(int)
    
    def record_failure(self, delivery_id: str, payload: dict, error: str):
        self._failed[delivery_id] = {
            "payload": payload,
            "error": error,
            "failed_at": datetime.now(timezone.utc).isoformat(),
            "retry_count": self._retry_counts[delivery_id],
        }
    
    def record_success(self, delivery_id: str):
        self._failed.pop(delivery_id, None)
        self._retry_counts.pop(delivery_id, None)
    
    def get_pending(self) -> list[dict]:
        return [
            {"delivery_id": did, **data}
            for did, data in self._failed.items()
            if self._retry_counts[did] < settings.webhook_retry_max
        ]
    
    def increment_retry(self, delivery_id: str):
        self._retry_counts[delivery_id] += 1


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
            _redis = aioredis.from_url(settings.redis_url)
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
    
    return {
        "status": "ok",
        "service": "vibelock-ingestion",
        "version": "0.2.0",
        "uptime_seconds": round(time.time() - START_TIME, 1),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "rate_limiter": {
            "max_per_minute": settings.rate_limit_per_minute,
        },
        "pending_retries": len(replay_store.get_pending()),
        "system": system,
    }


@app.get("/health/live")
async def liveness():
    """Kubernetes-style liveness probe."""
    return {"status": "alive"}


@app.get("/health/ready")
async def readiness():
    """Kubernetes-style readiness probe — checks Redis connectivity."""
    redis = get_redis()
    redis_ok = False
    if redis:
        try:
            await redis.ping()
            redis_ok = True
        except Exception:
            pass
    
    if not redis_ok and settings.redis_url:
        return JSONResponse(
            status_code=503,
            content={"status": "not_ready", "redis": "disconnected"},
        )
    return {"status": "ready", "redis": "connected" if redis_ok else "not_configured"}


@app.get("/webhook/replay/pending")
async def list_pending_retries():
    """List webhooks awaiting retry."""
    return {"pending": replay_store.get_pending()}


@app.post("/webhook/replay/retry")
async def trigger_retry():
    """Manually trigger retry of all pending webhooks."""
    pending = replay_store.get_pending()
    results = []
    for item in pending:
        delivery_id = item["delivery_id"]
        payload = item["payload"]
        success = await publish_to_queue(payload)
        if success:
            replay_store.record_success(delivery_id)
            results.append({"delivery_id": delivery_id, "status": "retried"})
        else:
            replay_store.increment_retry(delivery_id)
            results.append({"delivery_id": delivery_id, "status": "failed_again"})
    return {"results": results}


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
    if not rate_limiter.is_allowed(client_ip):
        logger.warning("rate_limited", ip=client_ip)
        raise HTTPException(status_code=429, detail="Too many requests")
    
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
        replay_store.record_failure(x_github_delivery, scan_payload, "redis_unavailable")
        logger.warning("queue_publish_failed_stored_for_retry", delivery=x_github_delivery)
        return {
            "status": "accepted_retry_pending",
            "delivery": x_github_delivery,
            "event": x_github_event,
        }
    
    replay_store.record_success(x_github_delivery)
    
    return {
        "status": "accepted",
        "delivery": x_github_delivery,
        "event": x_github_event,
    }


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