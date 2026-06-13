"""
VibeLock — Notification Models
Enums and payload schemas for notification events.
"""
from enum import Enum
from dataclasses import dataclass, field
from typing import Optional


class NotificationEvent(str, Enum):
    SCAN_COMPLETED = "scan.completed"
    CRITICAL_VULN_FOUND = "vulnerability.critical_found"
    PR_OPENED = "remediation.pr_opened"
    REMEDIATION_FAILED = "remediation.failed"


class ChannelType(str, Enum):
    SLACK = "slack"
    TEAMS = "teams"


@dataclass
class ScanCompletedPayload:
    org: str
    repo: str
    commit: str
    branch: str
    vulns_total: int
    critical_count: int
    high_count: int
    timestamp: str


@dataclass
class CriticalVulnPayload:
    org: str
    repo: str
    file: str
    vuln_type: str
    severity: str
    description: str
    timestamp: str


@dataclass
class PROpenedPayload:
    org: str
    repo: str
    pr_url: str
    vuln_type: str
    severity: str
    file_path: str
    timestamp: str


@dataclass
class RemediationFailedPayload:
    org: str
    repo: str
    vuln_id: str
    vuln_type: str
    reason: str
    timestamp: str