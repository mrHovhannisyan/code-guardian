# code-guardian

`code-guardian` is a small Python CLI that scans local Git repositories with Trivy, summarizes vulnerabilities, and produces JSON and Graphviz DOT reports.

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

Run tests:

```bash
pytest
```

Tests focus on deterministic business logic:

- Trivy JSON parsing
- Severity aggregation
- Graph rendering

External systems such as Trivy and the GitHub API are intentionally not unit-tested in this MVP.

## Run with Docker

Build:

```bash
docker build -t code-guardian .
```

Scan a local repository by mounting it into the container:

```bash
docker run --rm \
  -v /path/to/repo:/scan/repo:ro \
  -v "$PWD/reports:/reports" \
  code-guardian scan /scan/repo --output-dir /reports
```

## Architecture

- `cli.py`: CLI entrypoint and orchestration
- `core/scanner.py`: Trivy execution and report generation
- `core/parser.py`: Trivy JSON parsing and severity aggregation
- `core/github.py`: GitHub repository metadata lookup
- `core/graph.py`: Graphviz DOT rendering
- `models.py`: Pydantic domain models

## Output

For each input repository, the CLI writes:

- `reports/<repo-name>.json`
- `reports/<repo-name>.dot`

It also prints a compact summary like:

```text
repo-a: total=3 CRITICAL=1 HIGH=1 MEDIUM=1 LOW=0 UNKNOWN=0 stars=42 forks=7
```

The scanner processes repositories independently, so failure in one repository does not stop scans of the remaining repositories. The command exits with a non-zero status if any repository fails.

## Assumptions

- Repositories already exist locally; this tool does not clone.
- Trivy is the source of truth for vulnerability discovery.
- GitHub metadata is optional and best effort.
- DOT output is a simple vulnerability-oriented view, not a reconstructed full dependency graph.
- Repository names are derived from the final path segment.

## Trade-offs

- The implementation uses `ThreadPoolExecutor` to keep multi-repository scans bounded and simple.
- Trivy is invoked via `subprocess.run` rather than a long-lived worker model.
- Parsing is defensive: malformed or partial Trivy entries are skipped where possible.
- The graph groups vulnerabilities by package and highlights packages with CRITICAL findings.
- GitHub API failures are logged but do not fail scans.

## Known limitations

- Requires Trivy to be installed locally unless using the Docker image.
- Does not authenticate to GitHub, so unauthenticated rate limits apply.
- Does not infer transitive dependency edges.
- Does not de-duplicate reports across ecosystems beyond package/version/vulnerability identity.
- DOT files need Graphviz tooling to render images, for example `dot -Tpng repo.dot -o repo.png`.

## What I would improve with more time

- Add optional GitHub token support.
- Add richer dependency graph extraction per package manager.
- Add SARIF output for security tooling interoperability.
- Add severity threshold configuration.
- Add snapshot fixtures from real Trivy output.
- Add structured JSON logging for CI usage.
