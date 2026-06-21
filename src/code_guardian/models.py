from pathlib import Path

from pydantic import BaseModel, Field

SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN")


class Vulnerability(BaseModel):
    target: str | None = None
    package_name: str
    installed_version: str | None = None
    fixed_version: str | None = None
    severity: str = "UNKNOWN"
    vulnerability_id: str
    title: str | None = None


class GitHubMetadata(BaseModel):
    remote_url: str | None = None
    api_url: str | None = None
    stars: int | None = None
    forks: int | None = None


class RepoReport(BaseModel):
    repository_name: str
    repository_path: Path
    github: GitHubMetadata = Field(default_factory=GitHubMetadata)
    severity_counts: dict[str, int]
    vulnerabilities: list[Vulnerability]
