from pathlib import Path

from code_guardian.core.graph import render_dot
from code_guardian.models import RepoReport, Vulnerability
from code_guardian.core.parser import count_by_severity


def test_render_dot_highlights_packages_with_critical_findings():
    vulnerabilities = [
        Vulnerability(
            package_name="openssl",
            installed_version="1.0",
            fixed_version="1.1",
            severity="CRITICAL",
            vulnerability_id="CVE-2024-0001",
            title="Critical issue",
        )
    ]
    report = RepoReport(
        repository_name="repo",
        repository_path=Path("/tmp/repo"),
        severity_counts=count_by_severity(vulnerabilities),
        vulnerabilities=vulnerabilities,
    )

    dot = render_dot(report)

    assert "digraph code_guardian" in dot
    assert "openssl\\n1 finding(s)" in dot
    assert 'fillcolor="#ffcccc"' in dot
    assert "CVE-2024-0001\\nCRITICAL" in dot
