"""
VibeLock — Webhook Payload Schemas
Pydantic models for all GitHub webhook event types.
Provides strict validation of incoming payloads.
"""

from typing import Optional, List
from datetime import datetime
from pydantic import BaseModel, Field, field_validator


# --- GitHub User / Author ---

class GitHubUser(BaseModel):
    name: str
    email: Optional[str] = None
    username: Optional[str] = Field(default=None, alias="login")


class GitHubAuthor(BaseModel):
    name: str
    email: str
    username: Optional[str] = None


# --- Repository ---

class GitHubRepository(BaseModel):
    id: int
    name: str
    full_name: str
    private: bool = False
    html_url: Optional[str] = None
    description: Optional[str] = None
    default_branch: str = "main"
    owner: Optional[GitHubUser] = None


# --- Commit ---

class GitHubCommit(BaseModel):
    id: str
    message: str
    timestamp: Optional[str] = Field(default=None, alias="timestamp")
    url: Optional[str] = None
    author: GitHubAuthor
    committer: Optional[GitHubAuthor] = None
    added: List[str] = Field(default_factory=list)
    removed: List[str] = Field(default_factory=list)
    modified: List[str] = Field(default_factory=list)


# --- Push Event ---

class PushEvent(BaseModel):
    """GitHub push event payload."""
    ref: str  # e.g., "refs/heads/main"
    before: str  # SHA before push
    after: str  # SHA after push
    repository: GitHubRepository
    pusher: Optional[GitHubUser] = None
    sender: Optional[GitHubUser] = None
    commits: List[GitHubCommit] = Field(default_factory=list)
    head_commit: Optional[GitHubCommit] = None
    created: bool = False
    deleted: bool = False
    forced: bool = False
    compare: Optional[str] = None
    installation: Optional[dict] = None

    @property
    def branch(self) -> str:
        return self.ref.replace("refs/heads/", "")

    @property
    def all_changed_files(self) -> List[str]:
        """Get unique list of all changed files."""
        files = set()
        for commit in self.commits:
            files.update(commit.added)
            files.update(commit.modified)
            files.update(commit.removed)
        if self.head_commit:
            files.update(self.head_commit.added)
            files.update(self.head_commit.modified)
            files.update(self.head_commit.removed)
        return sorted(files)


# --- Pull Request Event ---

class PullRequestBase(BaseModel):
    number: int
    title: str
    body: Optional[str] = None
    state: str  # open, closed, merged
    html_url: str
    draft: bool = False
    merged: bool = False
    mergeable: Optional[bool] = None
    user: GitHubUser
    head: dict  # {ref, sha, repo}
    base: dict  # {ref, sha, repo}
    created_at: Optional[str] = None
    updated_at: Optional[str] = None
    merged_at: Optional[str] = None


class PullRequestEvent(BaseModel):
    """GitHub pull_request event payload."""
    action: str  # opened, closed, reopened, edited, synchronize
    number: int
    pull_request: PullRequestBase
    repository: GitHubRepository
    sender: GitHubUser
    installation: Optional[dict] = None


# --- Installation Event ---

class InstallationEvent(BaseModel):
    """GitHub App installation event."""
    action: str  # created, deleted, suspend, unsuspend
    installation: dict
    repositories: Optional[List[dict]] = None
    sender: GitHubUser


# --- Ping Event ---

class PingEvent(BaseModel):
    """GitHub webhook ping event."""
    zen: Optional[str] = None
    hook_id: Optional[int] = None
    hook: Optional[dict] = None
    repository: Optional[GitHubRepository] = None
    sender: Optional[GitHubUser] = None


# --- Unified Webhook Payload ---

class WebhookPayload(BaseModel):
    """Unified webhook payload after validation."""
    event_type: str
    delivery_id: str
    repository_full_name: str
    repository_id: int
    installation_id: Optional[int] = None
    branch: Optional[str] = None
    commit_sha: Optional[str] = None
    changed_files: List[str] = Field(default_factory=list)
    pusher: Optional[str] = None
    action: Optional[str] = None
    pr_number: Optional[int] = None
    raw_payload: dict = Field(default_factory=dict)

    @classmethod
    def from_push_event(cls, event: PushEvent, delivery_id: str) -> "WebhookPayload":
        return cls(
            event_type="push",
            delivery_id=delivery_id,
            repository_full_name=event.repository.full_name,
            repository_id=event.repository.id,
            installation_id=event.installation.get("id") if event.installation else None,
            branch=event.branch,
            commit_sha=event.after,
            changed_files=event.all_changed_files,
            pusher=event.pusher.name if event.pusher else None,
            raw_payload=event.model_dump(),
        )

    @classmethod
    def from_pr_event(cls, event: PullRequestEvent, delivery_id: str) -> "WebhookPayload":
        return cls(
            event_type="pull_request",
            delivery_id=delivery_id,
            repository_full_name=event.repository.full_name,
            repository_id=event.repository.id,
            installation_id=event.installation.get("id") if event.installation else None,
            branch=event.pull_request.head.get("ref"),
            commit_sha=event.pull_request.head.get("sha"),
            action=event.action,
            pr_number=event.number,
            raw_payload=event.model_dump(),
        )

    @classmethod
    def from_installation_event(cls, event: InstallationEvent, delivery_id: str) -> "WebhookPayload":
        return cls(
            event_type="installation",
            delivery_id=delivery_id,
            repository_full_name="",
            repository_id=0,
            installation_id=event.installation.get("id"),
            action=event.action,
            raw_payload=event.model_dump(),
        )


# --- Event Type Router ---

EVENT_PARSERS = {
    "push": PushEvent,
    "pull_request": PullRequestEvent,
    "installation": InstallationEvent,
    "ping": PingEvent,
}


def parse_webhook(event_type: str, body: dict) -> BaseModel:
    """Parse and validate a webhook payload based on event type."""
    parser = EVENT_PARSERS.get(event_type)
    if parser is None:
        raise ValueError(f"Unsupported event type: {event_type}")
    return parser(**body)


def to_scan_payload(event_type: str, body: dict, delivery_id: str) -> WebhookPayload:
    """Parse webhook and convert to unified scan payload."""
    parsed = parse_webhook(event_type, body)

    if isinstance(parsed, PushEvent):
        return WebhookPayload.from_push_event(parsed, delivery_id)
    elif isinstance(parsed, PullRequestEvent):
        return WebhookPayload.from_pr_event(parsed, delivery_id)
    elif isinstance(parsed, InstallationEvent):
        return WebhookPayload.from_installation_event(parsed, delivery_id)
    else:
        # Ping or unknown — minimal payload
        return WebhookPayload(
            event_type=event_type,
            delivery_id=delivery_id,
            repository_full_name=getattr(parsed, "repository", {}).get("full_name", ""),
            repository_id=getattr(parsed, "repository", {}).get("id", 0),
            raw_payload=parsed.model_dump() if hasattr(parsed, "model_dump") else {},
        )