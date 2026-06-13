"""
VibeLock — Notification Dispatcher
Celery task that routes notification events to enabled channels.
"""
import os
import logging
from datetime import datetime, timezone

from vibelock.src.notifications.models import NotificationEvent
from vibelock.src.notifications import slack, teams

logger = logging.getLogger(__name__)


def _get_min_severity() -> str:
    return os.getenv("VIBELOCK_NOTIFY_MIN_SEVERITY", "high")


def _is_severity_enabled(severity: str) -> bool:
    """Check if a severity level meets the minimum threshold."""
    levels = {"critical": 4, "high": 3, "medium": 2, "low": 1}
    min_level = levels.get(_get_min_severity(), 3)
    actual = levels.get(severity.lower(), 0)
    return actual >= min_level


def _is_event_enabled(event: NotificationEvent) -> bool:
    """Check if a specific event type is enabled for notifications."""
    event_env_map = {
        NotificationEvent.SCAN_COMPLETED: "VIBELOCK_NOTIFY_ON_SCAN_COMPLETE",
        NotificationEvent.CRITICAL_VULN_FOUND: "VIBELOCK_NOTIFY_ON_CRITICAL_VULN",
        NotificationEvent.PR_OPENED: "VIBELOCK_NOTIFY_ON_PR_OPENED",
        NotificationEvent.REMEDIATION_FAILED: "VIBELOCK_NOTIFY_ON_REMEDIATION_FAILED",
    }
    env_key = event_env_map.get(event)
    if env_key:
        return os.getenv(env_key, "true").lower() == "true"
    return True


def dispatch_notification(event: NotificationEvent, payload: dict) -> dict:
    """
    Synchronous dispatch (for use in Celery tasks or direct calls).
    Fan-out to all enabled channels.

    Returns dict with per-channel results.
    """
    if not _is_event_enabled(event):
        return {"status": "skipped", "reason": "event_disabled"}

    severity = payload.get("severity", "medium")
    if not _is_severity_enabled(severity):
        return {"status": "skipped", "reason": f"severity {severity} below threshold"}

    results = {}

    # Slack
    if slack.is_slack_enabled():
        try:
            if event == NotificationEvent.SCAN_COMPLETED:
                blocks = slack.build_scan_complete_blocks(payload)
            elif event == NotificationEvent.CRITICAL_VULN_FOUND:
                blocks = slack.build_critical_vuln_blocks(payload)
            elif event == NotificationEvent.PR_OPENED:
                blocks = slack.build_pr_opened_blocks(payload)
            elif event == NotificationEvent.REMEDIATION_FAILED:
                blocks = slack.build_remediation_failed_blocks(payload)
            else:
                blocks = None

            if blocks:
                # Run async in sync context
                import asyncio
                try:
                    loop = asyncio.get_event_loop()
                    if loop.is_running():
                        import concurrent.futures
                        future = asyncio.run_coroutine_threadsafe(
                            slack.send_slack_message(blocks), loop
                        )
                        results["slack"] = future.result(timeout=10)
                    else:
                        results["slack"] = asyncio.run(slack.send_slack_message(blocks))
                except RuntimeError:
                    results["slack"] = asyncio.run(slack.send_slack_message(blocks))
        except Exception as e:
            logger.error(f"Slack dispatch failed: {e}")
            results["slack"] = {"status": "error", "error": str(e)}

    # Teams
    if teams.is_teams_enabled():
        try:
            if event == NotificationEvent.SCAN_COMPLETED:
                card = teams.build_scan_complete_card(payload)
            elif event == NotificationEvent.CRITICAL_VULN_FOUND:
                card = teams.build_critical_vuln_card(payload)
            elif event == NotificationEvent.PR_OPENED:
                card = teams.build_pr_opened_card(payload)
            elif event == NotificationEvent.REMEDIATION_FAILED:
                card = teams.build_remediation_failed_card(payload)
            else:
                card = None

            if card:
                import asyncio
                try:
                    loop = asyncio.get_event_loop()
                    if loop.is_running():
                        import concurrent.futures
                        future = asyncio.run_coroutine_threadsafe(
                            teams.send_teams_message(card), loop
                        )
                        results["teams"] = future.result(timeout=10)
                    else:
                        results["teams"] = asyncio.run(teams.send_teams_message(card))
                except RuntimeError:
                    results["teams"] = asyncio.run(teams.send_teams_message(card))
        except Exception as e:
            logger.error(f"Teams dispatch failed: {e}")
            results["teams"] = {"status": "error", "error": str(e)}

    return results if results else {"status": "no_channels_enabled"}


# Celery task wrapper
def dispatch_notification_task(event: NotificationEvent, payload: dict):
    """
    Celery-compatible wrapper. Can be called with .delay() or .apply_async().
    Falls back to synchronous dispatch if Celery is not available.
    """
    try:
        from celery import Celery
        # Try to send via Celery if available
        app = Celery("vibelock_notifications")
        app.send_task(
            "vibelock.notify.send",
            args=[event.value, payload],
            queue="vibelock.notifications",
        )
    except Exception:
        # Fallback: dispatch synchronously
        return dispatch_notification(event, payload)