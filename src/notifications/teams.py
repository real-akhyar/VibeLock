"""
VibeLock — Microsoft Teams Notification Builder
Builds Adaptive Card messages and sends via webhook.
"""
import os
import logging
from typing import Optional

logger = logging.getLogger(__name__)


def get_teams_webhook_url() -> Optional[str]:
    return os.getenv("VIBELOCK_TEAMS_WEBHOOK_URL") or os.getenv("TEAMS_WEBHOOK_URL")


def is_teams_enabled() -> bool:
    return os.getenv("VIBELOCK_TEAMS_ENABLED", "false").lower() == "true"


def _build_card(title: str, theme_color: str, facts: list[dict], text_sections: list[str]) -> dict:
    """Build a Microsoft Teams Adaptive Card (MessageCard format)."""
    sections = []
    if facts:
        sections.append({"facts": facts})
    for text in text_sections:
        sections.append({"text": text})

    return {
        "@type": "MessageCard",
        "@context": "https://schema.org/extensions",
        "themeColor": theme_color,
        "summary": title,
        "title": title,
        "sections": sections,
    }


def build_scan_complete_card(payload: dict) -> dict:
    """Build Teams card for scan completion."""
    color = "FF0000" if payload.get("critical_count", 0) > 0 else "36A64F"
    return _build_card(
        title=f"🔍 Scan Complete: {payload['repo']}",
        theme_color=color,
        facts=[
            {"name": "Commit", "value": payload["commit"][:7]},
            {"name": "Branch", "value": payload["branch"]},
            {"name": "Vulnerabilities", "value": str(payload["vulns_total"])},
            {"name": "Critical", "value": f"{payload['critical_count']} ⚠️"},
        ],
        text_sections=[f"VibeLock • {payload['timestamp']}"],
    )


def build_critical_vuln_card(payload: dict) -> dict:
    """Build Teams card for critical vulnerability."""
    return _build_card(
        title=f"🔴 CRITICAL: {payload['vuln_type']} in {payload['repo']}",
        theme_color="FF0000",
        facts=[
            {"name": "File", "value": payload["file"]},
            {"name": "Severity", "value": payload["severity"].upper()},
        ],
        text_sections=[
            f"**Description:** {payload.get('description', 'No description')}",
            f"VibeLock • {payload['timestamp']}",
        ],
    )


def build_pr_opened_card(payload: dict) -> dict:
    """Build Teams card for PR opened."""
    return _build_card(
        title=f"✅ Auto-Fix PR Opened: {payload['repo']}",
        theme_color="36A64F",
        facts=[
            {"name": "Type", "value": payload["vuln_type"]},
            {"name": "File", "value": payload["file_path"]},
        ],
        text_sections=[
            f"[🔗 View Pull Request]({payload['pr_url']})",
            f"VibeLock • {payload['timestamp']}",
        ],
    )


def build_remediation_failed_card(payload: dict) -> dict:
    """Build Teams card for remediation failure."""
    return _build_card(
        title=f"🚨 Remediation Failed: {payload['repo']}",
        theme_color="FF0000",
        facts=[
            {"name": "Type", "value": payload["vuln_type"]},
            {"name": "Vuln ID", "value": payload["vuln_id"]},
        ],
        text_sections=[
            f"**Reason:** {payload['reason']}",
            "⚠️ Manual review required.",
            f"VibeLock • {payload['timestamp']}",
        ],
    )


async def send_teams_message(card: dict) -> dict:
    """Send a Teams message via webhook."""
    webhook_url = get_teams_webhook_url()
    if not webhook_url:
        return {"status": "skipped", "reason": "no_webhook_url"}

    import aiohttp

    try:
        async with aiohttp.ClientSession() as session:
            async with session.post(
                webhook_url,
                json=card,
                timeout=aiohttp.ClientTimeout(total=10),
            ) as resp:
                return {"status": "sent" if resp.status == 200 else f"failed_{resp.status}"}
    except Exception as e:
        logger.error(f"Teams notification failed: {e}")
        return {"status": "error", "error": str(e)}