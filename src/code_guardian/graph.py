from collections import defaultdict

from code_guardian.models import RepoReport, Vulnerability


def render_dot(report: RepoReport) -> str:
    lines = [
        "digraph code_guardian {",
        '  graph [rankdir="LR"];',
        '  node [shape="box", style="rounded,filled", fillcolor="white"];',
        f'  repo [label="{_escape(report.repository_name)}", shape="folder", fillcolor="#e8f0fe"];',
    ]

    by_package: dict[str, list[Vulnerability]] = defaultdict(list)
    for vulnerability in report.vulnerabilities:
        by_package[vulnerability.package_name].append(vulnerability)

    for index, (package_name, vulnerabilities) in enumerate(sorted(by_package.items())):
        package_id = f"pkg_{index}"
        has_critical = any(v.severity == "CRITICAL" for v in vulnerabilities)
        fill = "#ffcccc" if has_critical else "#f7f7f7"
        label = f"{package_name}\n{len(vulnerabilities)} finding(s)"
        lines.append(f'  {package_id} [label="{_escape(label)}", fillcolor="{fill}"];')
        lines.append(f"  repo -> {package_id};")

        for vuln_index, vulnerability in enumerate(vulnerabilities):
            vuln_id = f"{package_id}_vuln_{vuln_index}"
            vuln_label = f"{vulnerability.vulnerability_id}\n{vulnerability.severity}"
            vuln_fill = "#ff6666" if vulnerability.severity == "CRITICAL" else "#fff4cc"
            lines.append(f'  {vuln_id} [label="{_escape(vuln_label)}", fillcolor="{vuln_fill}"];')
            lines.append(f"  {package_id} -> {vuln_id};")

    lines.append("}")
    return "\n".join(lines) + "\n"


def _escape(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")
