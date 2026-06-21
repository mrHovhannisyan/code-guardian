    # code-guardian

`code-guardian` is a small Python CLI that scans local repositories with Trivy, summarizes vulnerabilities, and writes JSON plus Graphviz DOT reports.

The MVP is intentionally narrow: local paths in, Trivy JSON out, simple dependency nodes, and best-effort GitHub repository metadata.

## Run locally

Requirements:

- Python 3.12
- Trivy installed and available on `PATH`

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"

code-guardian scan /path/to/repo-a /path/to/repo-b --output-dir ./reports --workers 2 --log-level INFO
```
