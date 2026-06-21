from code_guardian.models import Vulnerability
from code_guardian.core.parser import count_by_severity, normalize_severity


def test_count_by_severity_includes_zeroes_for_known_severities():
    vulnerabilities = [
        Vulnerability(package_name="a", severity="CRITICAL", vulnerability_id="CVE-1"),
        Vulnerability(package_name="b", severity="HIGH", vulnerability_id="CVE-2"),
        Vulnerability(package_name="c", severity="HIGH", vulnerability_id="CVE-3"),
    ]

    assert count_by_severity(vulnerabilities) == {
        "CRITICAL": 1,
        "HIGH": 2,
        "MEDIUM": 0,
        "LOW": 0,
        "UNKNOWN": 0,
    }


def test_normalize_severity_maps_unexpected_values_to_unknown():
    assert normalize_severity("critical") == "CRITICAL"
    assert normalize_severity("negligible") == "UNKNOWN"
    assert normalize_severity(None) == "UNKNOWN"
