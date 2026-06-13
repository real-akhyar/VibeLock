"""
VibeLock — Redis Streams Job Queue
Replaces simple LPUSH/BRPOP with Redis Streams for:
- Consumer groups (horizontal scaling)
- Message acknowledgment (no lost jobs)
- Pending message tracking (stuck job detection)
- Message replay and dead-letter queue
"""

import os
import json
import time
import logging
import asyncio
from typing import Optional, List, Dict, Any
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


@dataclass
class StreamConfig:
    redis_url: str = field(
        default_factory=lambda: os.getenv("REDIS_URL", "redis://localhost:6379/0")
    )
    scan_stream: str = "vibelock:scan:stream"
    remediate_stream: str = "vibelock:remediate:stream"
    dead_letter_stream: str = "vibelock:dead:stream"
    scan_group: str = "scanner-workers"
    remediate_group: str = "remediation-workers"
    consumer_name: str = field(
        default_factory=lambda: f"worker-{os.getpid()}"
    )
    max_retries: int = 3
    claim_idle_ms: int = 60000  # Reclaim messages idle > 60s
    block_ms: int = 5000  # Block time for XREADGROUP


config = StreamConfig()


class RedisStreamQueue:
    """
    Redis Streams-based job queue with consumer groups.
    
    Features:
    - XADD to publish jobs
    - XREADGROUP for consumer-group based consumption
    - XACK for message acknowledgment
    - XPENDING for stuck message detection
    - XCLAIM for reclaiming abandoned messages
    - Dead-letter queue for messages exceeding max retries
    """

    def __init__(self, stream_config: Optional[StreamConfig] = None):
        self.cfg = stream_config or config
        self._redis = None

    async def _get_redis(self):
        """Lazy Redis connection."""
        if self._redis is None:
            try:
                import redis.asyncio as aioredis
                self._redis = aioredis.from_url(
                    self.cfg.redis_url,
                    decode_responses=True,
                )
                await self._redis.ping()
                logger.info("redis_streams_connected")
            except ImportError:
                logger.error("redis_not_installed — pip install redis")
                self._redis = None
            except Exception as e:
                logger.error(f"redis_connection_failed: {e}")
                self._redis = None
        return self._redis

    # --- Publish ---

    async def publish_scan_job(self, payload: dict) -> Optional[str]:
        """Publish a scan job to the scan stream."""
        return await self._publish(self.cfg.scan_stream, payload)

    async def publish_remediate_job(self, payload: dict) -> Optional[str]:
        """Publish a remediation job to the remediate stream."""
        return await self._publish(self.cfg.remediate_stream, payload)

    async def _publish(self, stream: str, payload: dict) -> Optional[str]:
        """Publish a message to a stream."""
        redis = await self._get_redis()
        if redis is None:
            return None

        data = {"payload": json.dumps(payload), "timestamp": str(time.time())}
        try:
            msg_id = await redis.xadd(stream, data, maxlen=10000)
            logger.debug(f"published_to_{stream}", msg_id=msg_id)
            return msg_id
        except Exception as e:
            logger.error(f"publish_failed: {e}")
            return None

    # --- Consumer Group Setup ---

    async def ensure_consumer_groups(self):
        """Create consumer groups if they don't exist."""
        redis = await self._get_redis()
        if redis is None:
            return

        streams = [
            (self.cfg.scan_stream, self.cfg.scan_group),
            (self.cfg.remediate_stream, self.cfg.remediate_group),
        ]

        for stream, group in streams:
            try:
                await redis.xgroup_create(stream, group, id="0", mkstream=True)
                logger.info(f"consumer_group_created", stream=stream, group=group)
            except Exception as e:
                if "BUSYGROUP" in str(e):
                    logger.debug(f"consumer_group_exists", stream=stream, group=group)
                else:
                    logger.error(f"consumer_group_create_failed: {e}")

    # --- Consume ---

    async def consume_scan_jobs(
        self,
        count: int = 1,
        block_ms: Optional[int] = None,
    ) -> List[Dict[str, Any]]:
        """Consume scan jobs using consumer group."""
        return await self._consume(
            self.cfg.scan_stream,
            self.cfg.scan_group,
            self.cfg.consumer_name,
            count,
            block_ms,
        )

    async def consume_remediate_jobs(
        self,
        count: int = 1,
        block_ms: Optional[int] = None,
    ) -> List[Dict[str, Any]]:
        """Consume remediation jobs using consumer group."""
        return await self._consume(
            self.cfg.remediate_stream,
            self.cfg.remediate_group,
            self.cfg.consumer_name,
            count,
            block_ms,
        )

    async def _consume(
        self,
        stream: str,
        group: str,
        consumer: str,
        count: int,
        block_ms: Optional[int],
    ) -> List[Dict[str, Any]]:
        """Read messages from a stream via consumer group."""
        redis = await self._get_redis()
        if redis is None:
            return []

        block = block_ms if block_ms is not None else self.cfg.block_ms

        try:
            results = await redis.xreadgroup(
                groupname=group,
                consumername=consumer,
                streams={stream: ">"},
                count=count,
                block=block,
            )

            messages = []
            for stream_name, entries in results:
                for msg_id, fields in entries:
                    try:
                        payload = json.loads(fields.get("payload", "{}"))
                    except json.JSONDecodeError:
                        payload = {}
                    messages.append({
                        "id": msg_id,
                        "stream": stream_name,
                        "payload": payload,
                        "timestamp": fields.get("timestamp"),
                    })

            return messages
        except Exception as e:
            logger.error(f"consume_failed: {e}")
            return []

    # --- Acknowledge ---

    async def ack_scan_job(self, msg_id: str):
        """Acknowledge a processed scan job."""
        await self._ack(self.cfg.scan_stream, self.cfg.scan_group, msg_id)

    async def ack_remediate_job(self, msg_id: str):
        """Acknowledge a processed remediation job."""
        await self._ack(self.cfg.remediate_stream, self.cfg.remediate_group, msg_id)

    async def _ack(self, stream: str, group: str, msg_id: str):
        """Acknowledge a message."""
        redis = await self._get_redis()
        if redis is None:
            return
        try:
            await redis.xack(stream, group, msg_id)
            logger.debug(f"acked", stream=stream, msg_id=msg_id)
        except Exception as e:
            logger.error(f"ack_failed: {e}")

    # --- Pending / Stuck Detection ---

    async def get_pending_scan_jobs(self) -> List[Dict]:
        """Get pending (unacknowledged) scan jobs."""
        return await self._get_pending(self.cfg.scan_stream, self.cfg.scan_group)

    async def get_pending_remediate_jobs(self) -> List[Dict]:
        """Get pending remediation jobs."""
        return await self._get_pending(self.cfg.remediate_stream, self.cfg.remediate_group)

    async def _get_pending(self, stream: str, group: str) -> List[Dict]:
        """Get pending messages for a consumer group."""
        redis = await self._get_redis()
        if redis is None:
            return []

        try:
            pending = await redis.xpending(stream, group)
            return [
                {
                    "id": p["message_id"],
                    "consumer": p["consumer"],
                    "idle_ms": p["time_since_delivered"],
                    "delivery_count": p["times_delivered"],
                }
                for p in pending.get("pending", [])
            ]
        except Exception as e:
            logger.error(f"xpending_failed: {e}")
            return []

    # --- Reclaim Stuck Messages ---

    async def reclaim_stuck_scan_jobs(self) -> int:
        """Reclaim scan messages idle for too long."""
        return await self._reclaim_stuck(
            self.cfg.scan_stream,
            self.cfg.scan_group,
            self.cfg.consumer_name,
        )

    async def reclaim_stuck_remediate_jobs(self) -> int:
        """Reclaim remediation messages idle for too long."""
        return await self._reclaim_stuck(
            self.cfg.remediate_stream,
            self.cfg.remediate_group,
            self.cfg.consumer_name,
        )

    async def _reclaim_stuck(self, stream: str, group: str, consumer: str) -> int:
        """Claim messages that have been idle beyond the threshold."""
        redis = await self._get_redis()
        if redis is None:
            return 0

        try:
            # Get pending messages
            pending = await redis.xpending_range(
                stream, group, min="-", max="+", count=100
            )

            reclaimed = 0
            for entry in pending:
                if entry["time_since_delivered"] > self.cfg.claim_idle_ms:
                    if entry["times_delivered"] > self.cfg.max_retries:
                        # Move to dead-letter queue
                        await self._move_to_dead_letter(stream, group, entry["message_id"])
                        logger.warning(
                            "moved_to_dead_letter",
                            msg_id=entry["message_id"],
                            deliveries=entry["times_delivered"],
                        )
                    else:
                        # Reclaim
                        claimed = await redis.xclaim(
                            stream, group, consumer,
                            min_idle_time=self.cfg.claim_idle_ms,
                            message_ids=[entry["message_id"]],
                        )
                        reclaimed += len(claimed)

            return reclaimed
        except Exception as e:
            logger.error(f"reclaim_failed: {e}")
            return 0

    # --- Dead Letter Queue ---

    async def _move_to_dead_letter(self, stream: str, group: str, msg_id: str):
        """Move a message to the dead-letter stream after max retries."""
        redis = await self._get_redis()
        if redis is None:
            return

        try:
            # Get the message
            result = await redis.xrange(stream, min=msg_id, max=msg_id, count=1)
            if result:
                _, fields = result[0]
                fields["original_stream"] = stream
                fields["original_group"] = group
                fields["dead_lettered_at"] = str(time.time())
                await redis.xadd(self.cfg.dead_letter_stream, fields)
                await redis.xack(stream, group, msg_id)
                logger.info("dead_lettered", msg_id=msg_id, original_stream=stream)
        except Exception as e:
            logger.error(f"dead_letter_move_failed: {e}")

    async def get_dead_letter_count(self) -> int:
        """Get count of messages in dead-letter queue."""
        redis = await self._get_redis()
        if redis is None:
            return 0
        try:
            return await redis.xlen(self.cfg.dead_letter_stream)
        except Exception:
            return 0

    async def replay_dead_letter(self, count: int = 10) -> int:
        """Replay messages from dead-letter queue back to original stream."""
        redis = await self._get_redis()
        if redis is None:
            return 0

        try:
            messages = await redis.xrange(
                self.cfg.dead_letter_stream, count=count
            )
            replayed = 0
            for msg_id, fields in messages:
                original_stream = fields.get("original_stream", self.cfg.scan_stream)
                # Remove metadata fields
                publish_fields = {
                    k: v for k, v in fields.items()
                    if k not in ("original_stream", "original_group", "dead_lettered_at")
                }
                await redis.xadd(original_stream, publish_fields)
                await redis.xdel(self.cfg.dead_letter_stream, msg_id)
                replayed += 1

            return replayed
        except Exception as e:
            logger.error(f"dead_letter_replay_failed: {e}")
            return 0

    # --- Stream Info ---

    async def get_stream_info(self, stream: str) -> Dict:
        """Get stream metadata."""
        redis = await self._get_redis()
        if redis is None:
            return {}
        try:
            return await redis.xinfo_stream(stream)
        except Exception:
            return {}

    async def get_queue_stats(self) -> Dict[str, Any]:
        """Get comprehensive queue statistics."""
        redis = await self._get_redis()
        if redis is None:
            return {"connected": False}

        try:
            scan_len = await redis.xlen(self.cfg.scan_stream)
            remediate_len = await redis.xlen(self.cfg.remediate_stream)
            dead_len = await redis.xlen(self.cfg.dead_letter_stream)

            scan_pending = await self.get_pending_scan_jobs()
            remediate_pending = await self.get_pending_remediate_jobs()

            return {
                "connected": True,
                "scan_queue_length": scan_len,
                "remediate_queue_length": remediate_len,
                "dead_letter_length": dead_len,
                "scan_pending": len(scan_pending),
                "remediate_pending": len(remediate_pending),
                "stuck_scan_jobs": [
                    p for p in scan_pending
                    if p["idle_ms"] > self.cfg.claim_idle_ms
                ],
                "stuck_remediate_jobs": [
                    p for p in remediate_pending
                    if p["idle_ms"] > self.cfg.claim_idle_ms
                ],
            }
        except Exception as e:
            return {"connected": False, "error": str(e)}


# Module-level singleton
queue = RedisStreamQueue()