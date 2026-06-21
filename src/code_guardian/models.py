from pydantic import BaseModel

SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN")


class Vulnerability(BaseModel):
    target: str | None = None
    package_name: str
    installed_version: str | None = None
    fixed_version: str | None = None
    severity: str = "UNKNOWN"
    vulnerability_id: str
    title: str | None = None

