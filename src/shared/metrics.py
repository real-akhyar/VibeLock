"""
VibeLock — Prometheus Metrics
Exposes metrics for scanner throughput, remediation success rate,
queue depths, and system health.
"""

import time
import logging
from typing import Optional
from dataclasses import dataclass, field
from collections import defaultdict

from fastapi import APIRouter, Response
from prometheus_client import (
    Counter, Gauge, Histogram, Summary,
    generate_latest, REGISTRY, CollectorRegistry,
    CONTENT_TYPE_LATEST,
)

logger = logging.getLogger(__name__)

# --- Custom Registry (isolated from other libs) ---
registry = CollectorRegistry(auto_describe=True)

router = APIRouter(prefix="/metrics", tags=["observability"])


# --- Metrics Definitions ---

# Scanner metrics
scans_total = Counter(
    "vibelock_scans_total",
    "Total number of scans initiated",
    ["status", "scanner_type"],
    registry=registry,
)

scan_duration_seconds = Histogram(
    "vibelock_scan_duration_seconds",
    "Scan duration in seconds",
    ["scanner_type"],
    buckets=[0.1, 0.5, 1.0, 2.0, 5.0, 10.0, 30.0, 60.0],
    registry=registry,
)

vulnerabilities_detected = Counter(
    "vibelock_vulnerabilities_detected_total",
    "Total vulnerabilities detected",
    ["severity", "type", "scanner_type"],
    registry=registry,
)

# Remediation metrics
remediation_attempts = Counter(
    "vibelock_remediation_attempts_total",
    "Total remediation attempts",
    ["status", "attempt_number"],
    registry=registry,
)

remediation_duration_seconds = Histogram(
    "vibelock_remediation_duration_seconds",
    "Remediation duration in seconds",
    buckets=[1.0, 5.0, 10.0, 30.0, 60.0, 120.0, 300.0],
    registry=registry,
)

prs_opened = Counter(
    "vibelock_prs_opened_total",
    "Total auto-fix PRs opened",
    ["severity"],
    registry=registry,
)

prs_merged = Counter(
    "vibelock_prs_merged_total",
    "Total auto-fix PRs merged",
    ["severity"],
    registry=registry,
)

# Queue metrics
queue_depth = Gauge(
    "vibelock_queue_depth",
    "Current queue depth",
    ["queue_name"],
    registry=registry,
)

queue_stuck_messages = Gauge(
    "vibelock_queue_stuck_messages",
    "Messages stuck (pending > idle threshold)",
    ["queue_name"],
    registry=registry,
)

dead_letter_count = Gauge(
    "vibelock_dead_letter_count",
    "Messages in dead-letter queue",
    registry=registry,
)

# Budget metrics
tokens_used_today = Gauge(
    "vibelock_tokens_used_today",
    "LLM tokens consumed today",
    registry=registry,
)

tokens_remaining_today = Gauge(
    "vibelock_tokens_remaining_today",
    "LLM tokens remaining for today",
    registry=registry,
)

budget_exhausted = Gauge(
    "vibelock_budget_exhausted",
    "1 if daily budget is exhausted, 0 otherwise",
    registry=registry,
)

# System metrics
webhooks_received = Counter(
    "vibelock_webhooks_received_total",
    "Total webhooks received",
    ["event_type", "status"],
    registry=registry,
)

webhook_processing_seconds = Histogram(
    "vibelock_webhook_processing_seconds",
    "Webhook processing duration",
    ["event_type"],
    buckets=[0.01, 0.05, 0.1, 0.5, 1.0, 2.0, 5.0],
    registry=registry,
)

api_requests = Counter(
    "vibelock_api_requests_total",
    "Total API requests",
    ["endpoint", "method", "status_code"],
    registry=registry,
)

api_request_duration = Histogram(
    "vibelock_api_request_duration_seconds",
    "API request duration",
    ["endpoint", "method"],
    buckets=[0.01, 0.05, 0.1, 0.5, 1.0, 2.0, 5.0, 10.0],
    registry=registry,
)

# Loop engineering metrics
loop_cycles_completed = Counter(
    "vibelock_loop_cycles_completed_total",
    "Total loop engineering cycles completed",
    registry=registry,
)

tasks_completed = Counter(
    "vibelock_tasks_completed_total",
    "Total tasks completed",
    ["priority"],
    registry=registry,
)

verification_failures = Counter(
    "vibelock_verification_failures_total",
    "Total verification failures (patches rejected by verifier)",
    ["reason"],
    registry=registry,
)


# --- Metrics Collector ---

class MetricsCollector:
    """Centralized metrics recording interface."""

    # Scan tracking
    def record_scan(self, status: str, scanner_type: str, duration: float, vulns_found: list):
        scans_total.labels(status=status, scanner_type=scanner_type).inc()
        scan_duration_seconds.labels(scanner_type=scanner_type).observe(duration)
        for vuln in vulns_found:
            vulnerabilities_detected.labels(
                severity=vuln.get("severity", "unknown"),
                type=vuln.get("type", "unknown"),
                scanner_type=scanner_type,
            ).inc()

    # Remediation tracking
    def record_remediation_attempt(self, status: str, attempt: int, duration: float):
        remediation_attempts.labels(status=status, attempt_number=str(attempt)).inc()
        remediation_duration_seconds.observe(duration)

    def record_pr(self, action: str, severity: str):
        if action == "opened":
            prs_opened.labels(severity=severity).inc()
        elif action == "merged":
            prs_merged.labels(severity=severity).inc()

    # Queue tracking
    def update_queue_metrics(self, stats: dict):
        if stats.get("connected"):
            queue_depth.labels(queue_name="scan").set(stats.get("scan_queue_length", 0))
            queue_depth.labels(queue_name="remediate").set(stats.get("remediate_queue_length", 0))
            queue_stuck_messages.labels(queue_name="scan").set(len(stats.get("stuck_scan_jobs", [])))
            queue_stuck_messages.labels(queue_name="remediate").set(len(stats.get("stuck_remediate_jobs", [])))
            dead_letter_count.set(stats.get("dead_letter_length", 0))

    # Budget tracking
    def update_budget_metrics(self, used: int, remaining: int, is_exhausted: bool):
        tokens_used_today.set(used)
        tokens_remaining_today.set(remaining)
        budget_exhausted.set(1 if is_exhausted else 0)

    # Webhook tracking
    def record_webhook(self, event_type: str, status: str, duration: float):
        webhooks_received.labels(event_type=event_type, status=status).inc()
        webhook_processing_seconds.labels(event_type=event_type).observe(duration)

    # API tracking
    def record_api_request(self, endpoint: str, method: str, status_code: int, duration: float):
        api_requests.labels(endpoint=endpoint, method=method, status_code=str(status_code)).inc()
        api_request_duration.labels(endpoint=endpoint, method=method).observe(duration)

    # Loop tracking
    def record_loop_cycle(self):
        loop_cycles_completed.inc()

    def record_task_completed(self, priority: str):
        tasks_completed.labels(priority=priority).inc()

    def record_verification_failure(self, reason: str):
        verification_failures.labels(reason=reason).inc()


# Module-level singleton
metrics = MetricsCollector()


# --- Metrics Endpoint ---

@router.get("")
async def get_metrics():
    """Prometheus metrics endpoint."""
    return Response(
        content=generate_latest(registry),
        media_type=CONTENT_TYPE_LATEST,
    )


@router.get("/json")
async def get_metrics_json():
    """JSON-formatted metrics for debugging/dashboards."""
    result = {}
    for metric in registry.collect():
        samples = []
        for sample in metric.samples:
            samples.append({
                "name": sample.name,
                "labels": dict(sample.labels),
                "value": sample.value,
            })
        if samples:
            result[metric.name] = {
                "type": metric.type,
                "documentation": metric.documentation,
                "samples": samples,
            }
    return result


# --- Middleware for API metrics ---

class MetricsMiddleware:
    """ASGI middleware to track API request metrics."""

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        start = time.time()
        path = scope.get("path", "/")
        method = scope.get("method", "GET")

        # Capture status code
        response_status = [200]

        async def send_wrapper(message):
            if message["type"] == "http.response.start":
                response_status[0] = message.get("status", 200)
            await send(message)

        try:
            await self.app(scope, receive, send_wrapper)
        finally:
            duration = time.time() - start
            # Simplify path for cardinality (strip IDs)
            endpoint = _simplify_path(path)
            metrics.record_api_request(endpoint, method, response_status[0], duration)


def _simplify_path(path: str) -> str:
    """Replace UUIDs and numbers in paths with placeholders."""
    import re
    # Replace UUIDs
    path = re.sub(
        r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',
        '{id}',
        path,
    )
    # Replace numeric IDs
    path = re.sub(r'/\d+', '/{id}', path)
    return path