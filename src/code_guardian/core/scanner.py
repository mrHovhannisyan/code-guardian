import logging
import subprocess
from pathlib import Path

from code_guardian.core.github import get_github_metadata
from code_guardian.core.graph import render_dot
from code_guardian.core.parser import count_by_severity, parse_trivy_json
from code_guardian.models import RepoReport, ScanResult

logger = logging.getLogger(__name__)


def scan_repository(repo_path: Path, output_dir: Path) -> ScanResult:
    repo_path = repo_path.expanduser().resolve()
    repo_name = repo_path.name

    if not repo_path.exists() or not repo_path.is_dir():
        return ScanResult(repository_name=repo_name, repository_path=repo_path, error="Repository path does not exist or is not a directory")

    try:
        raw_trivy = run_trivy(repo_path)
        vulnerabilities = parse_trivy_json(raw_trivy)
        report = RepoReport(
            repository_name=repo_name,
            repository_path=repo_path,
            github=get_github_metadata(repo_path),
            severity_counts=count_by_severity(vulnerabilities),
            vulnerabilities=vulnerabilities,
        )
        output_dir.mkdir(parents=True, exist_ok=True)
        report_path = output_dir / f"{repo_name}.json"
        dot_path = output_dir / f"{repo_name}.dot"
        report_path.write_text(report.model_dump_json(indent=2), encoding="utf-8")
        dot_path.write_text(render_dot(report), encoding="utf-8")
        return ScanResult(
            repository_name=repo_name,
            repository_path=repo_path,
            report_path=report_path,
            dot_path=dot_path,
            report=report,
        )
    except Exception as exc:
        logger.exception("Failed to scan %s", repo_path)
        return ScanResult(repository_name=repo_name, repository_path=repo_path, error=str(exc))


def run_trivy(repo_path: Path) -> str:
    try:
        result = subprocess.run(
            ["trivy", "fs", "--format", "json", "--quiet", str(repo_path)],
            check=False,
            capture_output=True,
            text=True,
            timeout=300,
        )
    except FileNotFoundError as exc:
        raise RuntimeError("Trivy is not installed or not available on PATH") from exc
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError("Trivy scan timed out after 300 seconds") from exc

    if result.returncode != 0:
        message = result.stderr.strip() or result.stdout.strip() or "Trivy scan failed"
        raise RuntimeError(message)

    return result.stdout
