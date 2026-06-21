import json
from collections import Counter
from typing import Any

from code_guardian.models import SEVERITIES, Vulnerability


def parse_trivy_json(raw: str) -> list[Vulnerability]:
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError("Trivy returned malformed JSON") from exc

    vulnerabilities: list[Vulnerability] = []
    for result in payload.get("Results", []) or []:
        target = result.get("Target")
        for item in result.get("Vulnerabilities", []) or []:
            vuln_id = item.get("VulnerabilityID")
            package_name = item.get("PkgName")
            if not vuln_id or not package_name:
                continue

            vulnerabilities.append(
                Vulnerability(
                    target=target,
                    package_name=package_name,
                    installed_version=item.get("InstalledVersion"),
                    fixed_version=item.get("FixedVersion"),
                    severity=normalize_severity(item.get("Severity")),
                    vulnerability_id=vuln_id,
                    title=item.get("Title"),
                )
            )

    return vulnerabilities


def count_by_severity(vulnerabilities: list[Vulnerability]) -> dict[str, int]:
    counts = Counter(v.severity for v in vulnerabilities)
    return {severity: counts.get(severity, 0) for severity in SEVERITIES}


def normalize_severity(value: Any) -> str:
    if not isinstance(value, str):
        return "UNKNOWN"
    severity = value.upper()
    return severity if severity in SEVERITIES else "UNKNOWN"
