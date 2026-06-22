from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

import typer

from code_guardian.core.scanner import scan_repository
from code_guardian.logging_config import configure_logging
from code_guardian.models import SEVERITIES, ScanResult

app = typer.Typer(help="Scan local repositories with Trivy and generate JSON/DOT reports.")


@app.callback()
def main() -> None:
    """Code Guardian CLI."""


@app.command()
def scan(
        repo_paths: list[Path] = typer.Argument(..., metavar="REPO_PATH..."),
        output_dir: Path = typer.Option(Path("./reports"), "--output-dir", "-o",
                                        help="Directory for JSON and DOT reports."),
        workers: int = typer.Option(2, "--workers", "-w", min=1, help="Maximum concurrent repository scans."),
        log_level: str = typer.Option("INFO", "--log-level", help="Python logging level."),
) -> None:
    configure_logging(log_level)
    output_dir = output_dir.expanduser().resolve()

    results: list[ScanResult] = []
    max_workers = min(workers, max(1, len(repo_paths)))
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = [executor.submit(scan_repository, repo_path, output_dir) for repo_path in repo_paths]
        for future in as_completed(futures):
            result = future.result()
            results.append(result)
            _print_summary(result)

    if any(not result.succeeded for result in results):
        raise typer.Exit(code=1)


def _print_summary(result: ScanResult) -> None:
    if not result.succeeded or result.report is None:
        typer.echo(f"{result.repository_name}: FAILED {result.error}")
        return

    counts = result.report.severity_counts
    total = sum(counts.values())
    severity_part = " ".join(f"{severity}={counts.get(severity, 0)}" for severity in SEVERITIES)
    github = result.report.github
    metadata = ""
    if github.stars is not None or github.forks is not None:
        metadata = f" stars={github.stars if github.stars is not None else 'unknown'} forks={github.forks if github.forks is not None else 'unknown'}"
    typer.echo(f"{result.repository_name}: total={total} {severity_part}{metadata}")


if __name__ == "__main__":
    app()
