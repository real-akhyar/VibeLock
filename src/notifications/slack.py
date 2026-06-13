"""
VibeLock — Slack Notification Builder
Builds Slack Block Kit messages and sends via webhook.
"""
import os
import logging
from typing import Optional

logger = logging.getLogger(__name__)


def get_slack_webhook_url() -> Optional[str]:
    return os.getenv("VIBELOCK_SLACK_WEBHOOK_URL") or os.getenv("SLACK_WEBHOOK_URL")


def is_slack_enabled() -> bool:
    return os.getenv("VIBELOCK_SLACK_ENABLED", "false").lower() == "true"


def build_scan_complete_blocks(payload: dict) -> list[dict]:
    """Build Slack Block Kit message for scan completion."""
    emoji = "🔴" if payload.get("critical_count", 0) > 0 else "🟢"
    return [
        {
            "type": "header",
            "text": {"type": "plain_text", "text": f"{emoji} Scan Complete: {payload['repo']}"}
        },
        {
            "type": "section",
            "fields": [
                {"type": "mrkdwn", "text": f"*Commit:* `{payload['commit'][:7]}`"},
                {"type": "mrkdwn", "text": f"*Branch:* `{payload['branch']}`"},
                {"type": "mrkdwn", "text": f"*Vulnerabilities:* {payload['vulns_total']}"},
                {"type": "mrkdwn", "text": f"*Critical:* {payload['critical_count']} ⚠️"},
            ]
        },
        {
            "type": "context",
            "elements": [{"type": "mrkdwn", "text": f"VibeLock • {payload['timestamp']}"}]
        }
    ]


def build_critical_vuln_blocks(payload: dict) -> list[dict]:
    """Build Slack Block Kit message for critical vulnerability."""
    return [
        {
            "type": "header",
            "text": {"type": "plain_text", "text": f"🔴 CRITICAL: {payload['vuln_type']} in {payload['repo']}"}
        },
        {
            "type": "section",
            "fields": [
                {"type": "mrkdwn", "text": f"*File:* `{payload['file']}`"},
                {"type": "mrkdwn", "text": f"*Severity:* {payload['severity'].upper()}"},
            ]
        },
        {
            "type": "section",
            "text": {"type": "mrkdwn", "text": f"*Description:*\n{payload.get('description', 'No description')}"}
        },
        {
            "type": "context",
            "elements": [{"type": "mrkdwn", "text": f"VibeLock • {payload['timestamp']}"}]
        }
    ]


def build_pr_opened_blocks(payload: dict) -> list[dict]:
    """Build Slack Block Kit message for PR opened."""
    return [
        {
            "type": "header",
            "text": {"type": "plain_text", "text": f"✅ Auto-Fix PR Opened: {payload['repo']}"}
        },
        {
            "type": "section",
            "fields": [
                {"type": "mrkdwn", "text": f"*Type:* {payload['vuln_type']}"},
                {"type": "mrkdwn", "text": f"*File:* `{payload['file_path']}`"},
            ]
        },
        {
            "type": "section",
            "text": {"type": "mrkdwn", "text": f"🔗 <{payload['pr_url']}|View Pull Request>"}
        },
        {
            "type": "context",
            "elements": [{"type": "mrkdwn", "text": f"VibeLock • {payload['timestamp']}"}]
        }
    ]


def build_remediation_failed_blocks(payload: dict) -> list[dict]:
    """Build Slack Block Kit message for remediation failure."""
    return [
        {
            "type": "header",
            "text": {"type": "plain_text", "text": f"🚨 Remediation Failed: {payload['repo']}"}
        },
        {
            "type": "section",
            "fields": [
                {"type": "mrkdwn", "text": f"*Type:* {payload['vuln_type']}"},
                {"type": "mrkdwn", "text": f"*Vuln ID:* `{payload['vuln_id']}`"},
            ]
        },
        {
            "type": "section",
            "text": {"type": "mrkdwn", "text": f"*Reason:*\n{payload['reason']}\n\n⚠️ Manual review required."}
        },
        {
            "type": "context",
            "elements": [{"type": "mrkdwn", "text": f"VibeLock • {payload['timestamp']}"}]
        }
    ]


async def send_slack_message(blocks: list[dict], channel: Optional[str] = None) -> dict:
    """Send a Slack message via webhook."""
    webhook_url = get_slack_webhook_url()
    if not webhook_url:
        return {"status": "skipped", "reason": "no_webhook_url"}

    import aiohttp

    payload = {
        "blocks": blocks,
    }
    if channel:
        payload["channel"] = channel

    try:
        async with aiohttp.ClientSession() as session:
            async with session.post(
                webhook_url,
                json=payload,
                timeout=aiohttp.ClientTimeout(total=10),
            ) as resp:
                return {"status": "sent" if resp.status == 200 else f"failed_{resp.status}"}
    except Exception as e:
        logger.error(f"Slack notification failed: {e}")
        return {"status": "error", "error": str(e)}