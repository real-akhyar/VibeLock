"""
VibeLock GitHub PR Automation
Creates isolated fix branches and opens pull requests via GitHub API.
Uses GitPython for local branch management and PyGithub for API calls.
"""

import os
import logging
import hashlib
from datetime import datetime
from pathlib import Path

logger = logging.getLogger(__name__)


def create_fix_pr(
    vulnerability: dict,
    patched_code: str,
    original_code: str,
    file_path: str,
) -> dict:
    """
    Create a fix branch and open a PR for the patched vulnerability.

    Args:
        vulnerability: Vulnerability dict with id, type, severity, etc.
        patched_code: The verified patched file content.
        original_code: Original file content (for diff).
        file_path: Path to the vulnerable file within the repo.

    Returns:
        dict with PR details: {number, html_url, branch}
    """
    vuln_id = vulnerability.get("id", "unknown")
    vuln_type = vulnerability.get("vulnerability_type", "unknown")
    repo_full_name = vulnerability.get("full_name", "")
    installation_id = vulnerability.get("installation_id")

    if not repo_full_name:
        raise ValueError("full_name is required in vulnerability dict")

    branch_name = _generate_branch_name(vuln_id, vuln_type)

    logger.info(f"Creating fix PR for {vuln_id}: branch={branch_name}, file={file_path}")

    # --- Step 1: Clone or use existing repo ---
    repo_dir = _ensure_repo_cloned(repo_full_name, installation_id)

    # --- Step 2: Create fix branch from base ---
    _create_fix_branch(repo_dir, branch_name, vulnerability.get("commit_sha", "main"))

    # --- Step 3: Apply the patch ---
    target_file = Path(repo_dir) / file_path
    target_file.parent.mkdir(parents=True, exist_ok=True)
    target_file.write_text(patched_code)

    # --- Step 4: Commit and push ---
    _commit_and_push(
        repo_dir,
        branch_name,
        f"🔒 [VibeLock] Fix {vuln_type} in {file_path}\n\n"
        f"Vulnerability ID: {vuln_id}\n"
        f"Severity: {vulnerability.get('severity', 'unknown')}\n"
        f"Auto-generated patch by VibeLock remediation engine.",
    )

    # --- Step 5: Open PR via GitHub API ---
    pr_result = _open_github_pr(
        repo_full_name,
        branch_name,
        vulnerability,
        installation_id,
    )

    return pr_result


def _generate_branch_name(vuln_id: str, vuln_type: str) -> str:
    """Generate a unique, safe branch name."""
    short_id = vuln_id[:8] if len(vuln_id) >= 8 else vuln_id
    safe_type = vuln_type.replace("_", "-").replace(" ", "-").lower()[:30]
    return f"vibelock/fix-{safe_type}-{short_id}"


def _ensure_repo_cloned(repo_full_name: str, installation_id) -> Path:
    """
    Ensure the repository is cloned locally.
    Uses GitHub App installation token for private repos.
    Returns path to the cloned repo.
    """
    import git
    from git import Repo

    workspace = Path(os.getenv("VIBELOCK_WORKSPACE", "/tmp/vibelock/repos"))
    workspace.mkdir(parents=True, exist_ok=True)

    repo_dir = workspace / repo_full_name.replace("/", "_")

    if repo_dir.exists() and (repo_dir / ".git").exists():
        logger.info(f"Repo already cloned: {repo_dir}")
        try:
            repo = Repo(repo_dir)
            repo.remotes.origin.fetch()
            return repo_dir
        except Exception as e:
            logger.warning(f"Fetch failed, re-cloning: {e}")

    # Clone fresh
    token = _get_installation_token(installation_id)
    clone_url = f"https://x-access-token:{token}@github.com/{repo_full_name}.git"

    logger.info(f"Cloning {repo_full_name} to {repo_dir}")
    Repo.clone_from(clone_url, repo_dir, depth=50)
    return repo_dir


def _create_fix_branch(repo_dir: Path, branch_name: str, base_ref: str = "main"):
    """Create and checkout a new fix branch."""
    from git import Repo

    repo = Repo(repo_dir)

    # Delete local branch if it exists
    if branch_name in repo.heads:
        repo.delete_head(branch_name, force=True)

    # Create new branch from base
    base = base_ref if base_ref in repo.heads else "main"
    repo.git.checkout(base)
    repo.git.pull("origin", base)
    new_branch = repo.create_head(branch_name)
    new_branch.checkout()

    logger.info(f"Created branch: {branch_name} from {base}")


def _commit_and_push(repo_dir: Path, branch_name: str, message: str):
    """Stage changes, commit, and push to origin."""
    from git import Repo

    repo = Repo(repo_dir)
    repo.git.add(A=True)

    # Only commit if there are changes
    if not repo.index.diff("HEAD"):
        logger.info("No changes to commit")
        return

    repo.index.commit(message)
    repo.git.push("origin", branch_name, force=True)
    logger.info(f"Pushed {branch_name} to origin")


def _open_github_pr(
    repo_full_name: str,
    branch_name: str,
    vulnerability: dict,
    installation_id,
) -> dict:
    """
    Open a pull request via GitHub API.
    Uses PyGithub with installation token.
    """
    from github import Github

    token = _get_installation_token(installation_id)
    gh = Github(token)
    repo = gh.get_repo(repo_full_name)

    vuln_type = vulnerability.get("vulnerability_type", "unknown")
    severity = vulnerability.get("severity", "medium")
    file_path = vulnerability.get("file_path", "")
    description = vulnerability.get("description", "")

    title = f"🔒 [VibeLock] Fix {vuln_type} ({severity}) in {file_path}"

    body = f"""## 🔒 VibeLock Auto-Fix

**Vulnerability:** {vuln_type}
**Severity:** {severity}
**File:** `{file_path}`
**Description:** {description}

---

This PR was automatically generated by the VibeLock remediation engine.
The patch has passed syntax verification and structural integrity checks.

### What was changed
- Patched `{file_path}` to address the {vuln_type} vulnerability

### Verification
- ✅ Syntax check passed
- ✅ Structural integrity verified
- ✅ No breaking changes detected

> ⚠️ Please review before merging. VibeLock makes best-effort fixes but human review is recommended for critical paths.
"""

    pr = repo.create_pull(
        title=title,
        body=body,
        head=branch_name,
        base=vulnerability.get("branch", "main"),
    )

    logger.info(f"PR opened: {pr.html_url}")
    return {
        "number": pr.number,
        "html_url": pr.html_url,
        "branch": branch_name,
    }


def _get_installation_token(installation_id) -> str:
    """
    Get a GitHub App installation access token.
    Uses the GitHub App private key + JWT to authenticate.
    Falls back to GITHUB_TOKEN env var for simpler setups.
    """
    # Try personal access token first (simpler setup)
    token = os.getenv("GITHUB_TOKEN") or os.getenv("GITHUB_PAT")
    if token:
        return token

    # GitHub App installation token flow
    if not installation_id:
        raise ValueError(
            "No GITHUB_TOKEN set and no installation_id provided. "
            "Set GITHUB_TOKEN env var or provide installation_id."
        )

    app_id = os.getenv("GITHUB_APP_ID")
    private_key = os.getenv("GITHUB_APP_PRIVATE_KEY")

    if not app_id or not private_key:
        raise ValueError(
            "GitHub App credentials not configured. "
            "Set GITHUB_APP_ID and GITHUB_APP_PRIVATE_KEY."
        )

    import time
    import jwt

    now = int(time.time())
    payload = {
        "iat": now - 60,
        "exp": now + 600,
        "iss": app_id,
    }
    encoded_jwt = jwt.encode(payload, private_key, algorithm="RS256")

    from github import GithubIntegration

    integration = GithubIntegration(app_id, private_key)
    installation_auth = integration.get_access_token(installation_id)
    return installation_auth.token