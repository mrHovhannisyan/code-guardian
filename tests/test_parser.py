from code_guardian.parser import parse_trivy_json


def test_parse_trivy_json_extracts_required_fields():
    raw = """
    {
      "Results": [
        {
          "Target": "requirements.txt",
          "Vulnerabilities": [
            {
              "VulnerabilityID": "CVE-2024-0001",
              "PkgName": "demo",
              "InstalledVersion": "1.0.0",
              "FixedVersion": "1.0.1",
              "Severity": "HIGH",
              "Title": "Demo issue"
            }
          ]
        }
      ]
    }
    """

    vulnerabilities = parse_trivy_json(raw)

    assert len(vulnerabilities) == 1
    vulnerability = vulnerabilities[0]
    assert vulnerability.target == "requirements.txt"
    assert vulnerability.package_name == "demo"
    assert vulnerability.installed_version == "1.0.0"
    assert vulnerability.fixed_version == "1.0.1"
    assert vulnerability.severity == "HIGH"
    assert vulnerability.vulnerability_id == "CVE-2024-0001"
    assert vulnerability.title == "Demo issue"


def test_parse_trivy_json_skips_entries_without_package_or_id():
    raw = """
    {
      "Results": [
        {
          "Vulnerabilities": [
            {"PkgName": "missing-id", "Severity": "LOW"},
            {"VulnerabilityID": "CVE-2024-0002", "Severity": "LOW"}
          ]
        }
      ]
    }
    """

    assert parse_trivy_json(raw) == []
