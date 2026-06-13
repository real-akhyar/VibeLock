"""
VibeLock — Notification Integration
Sends alerts to Slack and Microsoft Teams for critical findings.
"""

import os
import json
import logging
from typing import Optional
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


@dataclass
class NotificationConfig:
    slack_webhook_url: Optional[str] = field(
        default_factory=lambda: os.getenv("SLACK_WEBHOOK_URL")
    )
    teams_webhook_url: Optional[str] = field(
        default_factory=lambda: os.getenv("TEAMS_WEBHOOK_URL")
    )
    notify_on_severity: list[str] = field(
        default_factory=lambda: ["critical", "high"]
    )
    enabled: bool = field(
        default_factory=lambda: os.getenv("VIBELOCK_NOTIFICATIONS_ENABLED", "true").lower() == "true"
    )


config = NotificationConfig()


async def send_critical_alert(
    vulnerability: dict,
    repository: str = "unknown",
) -> dict:
    """
    Send notification for a critical/high vulnerability finding.
    Returns dict with per-channel results.
    """
    if not config.enabled:
        return {"status": "disabled"}

    severity = vulnerability.get("severity", "medium")
    if severity not in config.notify_on_severity:
        return {"status": "skipped", "reason": f"severity {severity} not in notify list"}

    results = {}

    if config.slack_webhook_url:
        results["slack"] = await _send_slack(vulnerability, repository)

    if config.teams_webhook_url:
        results["teams"] = await _send_teams(vulnerability, repository)

    return results


async def send_remediation_pr_alert(
    vulnerability: dict,
    pr_url: str,
    repository: str = "unknown",
) -> dict:
    """Send notification when an auto-fix PR is opened."""
    if not config.enabled:
        return {"status": "disabled"}

    results = {}

    if config.slack_webhook_url:
        results["slack"] = await _send_slack_pr(vulnerability, pr_url, repository)

    if config.teams_webhook_url:
        results["teams"] = await _send_teams_pr(vulnerability, pr_url, repository)

    return results


async def send_remediation_failed_alert(
    vulnerability: dict,
    reason: str,
    repository: str = "unknown",
) -> dict:
    """Send notification when remediation fails after max attempts."""
    if not config.enabled:
        return {"status": "disabled"}

    results = {}

    if config.slack_webhook_url:
        results["slack"] = await _send_slack_failed(vulnerability, reason, repository)

    if config.teams_webhook_url:
        results["teams"] = await _send_teams_failed(vulnerability, reason, repository)

    return results


# --- Slack ---

async def _send_slack(vulnerability: dict, repository: str) -> dict:
    """Send a critical vulnerability alert to Slack."""
    import aiohttp

    severity = vulnerability.get("severity", "unknown").upper()
    vuln_type = vulnerability.get("vulnerability_type", vulnerability.get("type", "unknown"))
    file_path = vulnerability.get("file_path", "unknown")
    description = vulnerability.get("description", "No description")
    line_number = vulnerability.get("line_number", "?")

    color = {
        "critical": "#FF0000",
        "high": "#FF6600",
        "medium": "#FFCC00",
        "low": "#00CC00",
    }.get(severity.lower(), "#CCCCCC")

    emoji = {
        "critical": "🔴",
        "high": "🟠",
        "medium": "🟡",
        "low": "🟢",
    }.get(severity.lower(), "⚪")

    payload = {
        "attachments": [
            {
                "color": color,
                "blocks": [
                    {
                        "type": "header",
                        "text": {
                            "type": "plain_text",
                            "text": f"{emoji} VibeLock: {severity} Vulnerability Detected",
                        }
                    },
                    {
                        "type": "section",
                        "fields": [
                            {"type": "mrkdwn", "text": f"*Repository:*\n{repository}"},
                            {"type": "mrkdwn", "text": f"*Type:*\n{vuln_type}"},
                            {"type": "mrkdwn", "text": f"*File:*\n`{file_path}:{line_number}`"},
                            {"type": "mrkdwn", "text": f"*Severity:*\n{severity}"},
                        ],
                    },
                    {
                        "type": "section",
                        "text": {
                            "type": "mrkdwn",
                            "text": f"*Description:*\n{description}",
                        },
                    },
                    {
                        "type": "context",
                        "elements": [
                            {
                                "type": "mrkdwn",
                                "text": "⚡ Auto-remediation will attempt to fix this. Max 3 attempts.",
                            }
                        ],
                    },
                ],
            }
        ]
    }

    try:
        async with aiohttp.ClientSession() as session:
            async with session.post(
                config.slack_webhook_url,
                json=payload,
                timeout=aiohttp.ClientTimeout(total=10),
            ) as resp:
                return {"status": "sent" if resp.status == 200 else f"failed_{resp.status}"}
    except Exception as e:
        logger.error(f"Slack notification failed: {e}")
        return {"status": "error", "error": str(e)}


async def _send_slack_pr(vulnerability: dict, pr_url: str, repository: str) -> dict:
    """Send PR opened notification to Slack."""
    import aiohttp

    vuln_type = vulnerability.get("vulnerability_type", vulnerability.get("type", "unknown"))
    file_path = vulnerability.get("file_path", "unknown")

    payload = {
        "attachments": [
            {
                "color": "#36A64F",
                "blocks": [
                    {
                        "type": "header",
                        "text": {
                            "type": "plain_text",
                            "text": "✅ VibeLock: Auto-Fix PR Opened",
                        }
                    },
                    {
                        "type": "section",
                        "fields": [
                            {"type": "mrkdwn", "text": f"*Repository:*\n{repository}"},
                            {"type": "mrkdwn", "text": f"*Type:*\n{vuln_type}"},
                            {"type": "mrkdwn", "text": f"*File:*\n`{file_path}`"},
                        ],
                    },
                    {
                        "type": "section",
                        "text": {
                            "type": "mrkdwn",
                            "text": f"🔗 <{pr_url}|View Pull Request>",
                        },
                    },
                ],
            }
        ]
    }

    try:
        async with aiohttp.ClientSession() as session:
            async with session.post(
                config.slack_webhook_url,
                json=payload,
                timeout=aiohttp.ClientTimeout(total=10),
            ) as resp:
                return {"status": "sent" if resp.status == 200 else f"failed_{resp.status}"}
    except Exception as e:
        logger.error(f"Slack PR notification failed: {e}")
        return {"status": "error", "error": str(e)}


async def _send_slack_failed(vulnerability: dict, reason: str, repository: str) -> dict:
    """Send remediation failure notification to Slack."""
    import aiohttp

    vuln_type = vulnerability.get("vulnerability_type", vulnerability.get("type", "unknown"))
    file_path = vulnerability.get("file_path", "unknown")

    payload = {
        "attachments": [
            {
                "color": "#FF0000",
                "blocks": [
                    {
                        "type": "header",
                        "text": {
                            "type": "plain_text",
                            "text": "🚨 VibeLock: Remediation Failed",
                        }
                    },
                    {
                        "type": "section",
                        "fields": [
                            {"type": "mrkdwn", "text": f"*Repository:*\n{repository}"},
                            {"type": "mrkdwn", "text": f"*Type:*\n{vuln_type}"},
                            {"type": "mrkdwn", "text": f"*File:*\n`{file_path}`"},
                        ],
                    },
                    {
                        "type": "section",
                        "text": {
                            "type": "mrkdwn",
                            "text": f"*Reason:*\n{reason}\n\n⚠️ Manual review required.",
                        },
                    },
                ],
            }
        ]
    }

    try:
        async with aiohttp.ClientSession() as session:
            async with session.post(
                config.slack_webhook_url,
                json=payload,
                timeout=aiohttp.ClientTimeout(total=10),
            ) as resp:
                return {"status": "sent" if resp.status == 200 else f"failed_{resp.status}"}
    except Exception as e:
        logger.error(f"Slack failure notification failed: {e}")
        return {"status": "error", "error": str(e)}


# --- Microsoft Teams ---

async def _send_teams(vulnerability: dict, repository: str) -> dict:
    """Send a critical vulnerability alert to Microsoft Teams."""
    import aiohttp

    severity = vulnerability.get("severity", "unknown").upper()
    vuln_type = vulnerability.get("vulnerability_type", vulnerability.get("type", "unknown"))
    file_path = vulnerability.get("file_path", "unknown")
    description = vulnerability.get("description", "No description")

    color = {
        "critical": "attention",
        "high": "warning",
        "medium": "default",
        "low": "good",
    }.get(severity.lower(), "default")

    payload = {
        "@type": "MessageCard",
        "@context": "https://schema.org/extensions",
        "themeColor": {
            "critical": "FF0000",
            "high": "FF6600",
            "medium": "FFCC00",
            "low": "00CC00",
        }.get(severity.lower(), "CCCCCC"),
        "summary": f"VibeLock: {severity} vulnerability in {repository}",
        "title": f"🔒 VibeLock: {severity} Vulnerability Detected",
        "sections": [
            {
                "facts": [
                    {"name": "Repository", "value": repository},
                    {"name": "Type", "value": vuln_type},
                    {"name": "File", "value": f"{file_path}"},
                    {"name": "Severity", "value": severity},
                ]
            },
            {
                "text": f"**Description:** {description}"
            },
        ],
    }

    try:
        async with aiohttp.ClientSession() as session:
            async with session.post(
                config.teams_webhook_url,
                json=payload,
                timeout=aiohttp.ClientTimeout(total=10),
            ) as resp:
                return {"status": "sent" if resp.status == 200 else f"failed_{resp.status}"}
    except Exception as e:
        logger.error(f"Teams notification failed: {e}")
        return {"status": "error", "error": str(e)}


async def _send_teams_pr(vulnerability: dict, pr_url: str, repository: str) -> dict:
    """Send PR opened notification to Teams."""
    import aiohttp

    vuln_type = vulnerability.get("vulnerability_type", vulnerability.get("type", "unknown"))
    file_path = vulnerability.get("file_path", "unknown")

    payload = {
        "@type": "MessageCard",
        "@context": "https://schema.org/extensions",
        "themeColor": "36A64F",
        "summary": f"VibeLock: Auto-fix PR opened for {repository}",
        "title": "✅ VibeLock: Auto-Fix PR Opened",
        "sections": [
            {
                "facts": [
                    {"name": "Repository", "value": repository},
                    {"name": "Type", "value": vuln_type},
                    {"name": "File", "value": file_path},
                ]
            },
            {
                "text": f"[🔗 View Pull Request]({pr_url})"
            },
        ],
    }

    try:
        async with aiohttp.ClientSession() as session:
            async with session.post(
                config.teams_webhook_url,
                json=payload,
                timeout=aiohttp.ClientTimeout(total=10),
            ) as resp:
                return {"status": "sent" if resp.status == 200 else f"failed_{resp.status}"}
    except Exception as e:
        logger.error(f"Teams PR notification failed: {e}")
        return {"status": "error", "error": str(e)}


async def _send_teams_failed(vulnerability: dict, reason: str, repository: str) -> dict:
    """Send remediation failure notification to Teams."""
    import aiohttp

    vuln_type = vulnerability.get("vulnerability_type", vulnerability.get("type", "unknown"))
    file_path = vulnerability.get("file_path", "unknown")

    payload = {
        "@type": "MessageCard",
        "@context": "https://schema.org/extensions",
        "themeColor": "FF0000",
        "summary": f"VibeLock: Remediation failed for {repository}",
        "title": "🚨 VibeLock: Remediation Failed",
        "sections": [
            {
                "facts": [
                    {"name": "Repository", "value": repository},
                    {"name": "Type", "value": vuln_type},
                    {"name": "File", "value": file_path},
                ]
            },
            {
                "text": f"**Reason:** {reason}\n\n⚠️ Manual review required."
            },
        ],
    }

    try:
        async with aiohttp.ClientSession() as session:
            async with session.post(
                config.teams_webhook_url,
                json=payload,
                timeout=aiohttp.ClientTimeout(total=10),
            ) as resp:
                return {"status": "sent" if resp.status == 200 else f"failed_{resp.status}"}
    except Exception as e:
        logger.error(f"Teams failure notification failed: {e}")
        return {"status": "error", "error": str(e)}