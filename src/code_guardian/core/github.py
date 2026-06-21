import logging
import re
import subprocess
from pathlib import Path

import requests

from code_guardian.models import GitHubMetadata

logger = logging.getLogger(__name__)

GITHUB_REMOTE_RE = re.compile(r"github\.com[:/](?P<owner>[^/]+)/(?P<repo>[^/]+?)(?:\.git)?$")


def get_github_metadata(repo_path: Path) -> GitHubMetadata:
    remote_url = detect_remote_url(repo_path)
    if not remote_url:
        return GitHubMetadata()

    api_url = github_api_url(remote_url)
    if not api_url:
        return GitHubMetadata(remote_url=remote_url)

    try:
        response = requests.get(api_url, timeout=5)
        response.raise_for_status()
        payload = response.json()
        return GitHubMetadata(
            remote_url=remote_url,
            api_url=api_url,
            stars=payload.get("stargazers_count"),
            forks=payload.get("forks_count"),
        )
    except requests.RequestException as exc:
        logger.warning("Failed to fetch GitHub metadata for %s: %s", repo_path, exc)
        return GitHubMetadata(remote_url=remote_url, api_url=api_url)


def detect_remote_url(repo_path: Path) -> str | None:
    try:
        result = subprocess.run(
            ["git", "-C", str(repo_path), "remote", "get-url", "origin"],
            check=False,
            capture_output=True,
            text=True,
            timeout=5,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
        logger.warning("Could not inspect git remote for %s: %s", repo_path, exc)
        return None

    if result.returncode != 0:
        logger.info("No origin remote found for %s", repo_path)
        return None

    return result.stdout.strip() or None


def github_api_url(remote_url: str) -> str | None:
    match = GITHUB_REMOTE_RE.search(remote_url)
    if not match:
        return None
    owner = match.group("owner")
    repo = match.group("repo")
    return f"https://api.github.com/repos/{owner}/{repo}"
