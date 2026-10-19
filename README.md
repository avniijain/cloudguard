# CloudGuard Sample Application

This repository contains a minimal Python Flask application used to validate the **CloudGuard** DevSecOps CI/CD pipeline.

**Current phase:** build, test, SonarQube code quality, Docker image build, Trivy scans, and the CloudGuard Risk Gate. The gate starts in report-only mode unless the `RISK_GATE_MODE` Actions variable is set to `enforce`.

## Endpoints

| Method | Path      | Description             |
|--------|-----------|-------------------------|
| GET    | `/`       | JSON welcome payload    |
| GET    | `/health` | `{"status": "healthy"}` |

## Run locally

From the repository root:

```bash
python -m venv .venv
```

**Windows (PowerShell):**

```powershell
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python -m app.app
```

**Linux / macOS:**

```bash
source .venv/bin/activate
pip install -r requirements.txt
python -m app.app
```

The app binds to `127.0.0.1` by default (loopback only). Then open `http://localhost:5000/` and `http://localhost:5000/health`.

The Docker image sets `FLASK_RUN_HOST=0.0.0.0` so the process is reachable through published container ports. Do not use that host on a raw host network unless you intend to expose the service.

## Run tests

```bash
pytest -v --cov=app --cov=risk_gate --cov=sonar_status --cov-report=term
```

## Docker

```bash
docker build -t cloudguard-app .
docker run --rm -p 5000:5000 cloudguard-app
```

## CI pipeline (Phase 2)

On every push and pull request, GitHub Actions (`.github/workflows/ci.yml`) runs:

1. Python 3.11 setup and dependency install
2. `pytest` with coverage (`coverage.xml` for SonarQube)
3. SonarQube / SonarCloud analysis (skipped until secrets are set)
4. Docker image build
5. Trivy filesystem scan (`vuln`, `secret`, `misconfig`)
6. Trivy container image scan
7. Evaluate Trivy results and the SonarQube Quality Gate, writing `risk-decision.json`
8. Upload scan reports and the risk decision as workflow artifacts
9. Upload SARIF to the GitHub Security tab when GitHub Advanced Security is available

Trivy `exit-code` is `0` on purpose: findings are evaluated by the CloudGuard Risk Gate rather than directly failing their scan steps. The gate initially reports its decision without failing CI. To enforce BLOCK decisions, set the repository or organization Actions variable `RISK_GATE_MODE` to `enforce`. See [docs/risk-gate.md](docs/risk-gate.md) for the policy, local usage, and limitations.

## Manual setup required

GitHub Actions cannot create a SonarQube/SonarCloud project or tokens for you. Complete these once per repository.

### 1. SonarQube or SonarCloud (required for the quality step)

Pick **one**:

**Option A — SonarCloud (typical with GitHub)**

1. Create an account at [sonarcloud.io](https://sonarcloud.io) and import this GitHub repository (or create a project manually).
2. Copy the **organization key** (for example `my-org`).
3. Generate a token: **My Account → Security → Generate Token**.
4. In GitHub: **Settings → Secrets and variables → Actions**:
   - Secret `SONAR_TOKEN` = the token
   - Secret `SONAR_HOST_URL` = `https://sonarcloud.io`
   - Variable `SONAR_ORGANIZATION` = your SonarCloud organization key
5. Either set `SONAR_ORGANIZATION` as above, or uncomment `sonar.organization` in `sonar-project.properties`.

**Option B — self-hosted SonarQube**

1. Run a SonarQube server that GitHub-hosted runners can reach (public URL or self-hosted runner on the same network).
2. Create a project with key `cloudguard` (must match `sonar.projectKey` in `sonar-project.properties`).
3. Generate a project or user token.
4. In GitHub:
   - Secret `SONAR_TOKEN` = the token
   - Secret `SONAR_HOST_URL` = your server URL, for example `https://sonarqube.example.com`
5. Do **not** set `SONAR_ORGANIZATION` unless your server requires it.

Until `SONAR_TOKEN` exists, CI still runs tests and Trivy, and skips SonarQube with a log message.

### 2. GitHub Security / SARIF (optional)

Uploading Trivy SARIF to **Security → Code scanning** needs GitHub Advanced Security (or code scanning on public repositories). On private repos without GHAS, the upload step is allowed to fail (`continue-on-error`); JSON reports are still available as **Actions artifacts**.

### 3. Trivy

No account or token is required. The first run downloads Trivy vulnerability databases (handled by the action).

### 4. Local Trivy (optional)

Install [Trivy](https://github.com/aquasecurity/trivy), then:

```bash
trivy fs --scanners vuln,secret,misconfig .
docker build -t cloudguard-app:local .
trivy image cloudguard-app:local
```

## Project layout

```
.
├── app/
│   ├── app.py                 # Flask application
│   └── test_app.py            # pytest tests
├── tests/
│   └── test_risk_gate.py      # Risk Gate and Sonar status tests
├── .github/workflows/
│   └── ci.yml                 # Build, test, SonarQube, Trivy
├── docs/
│   └── risk-gate.md           # Risk policy and operation
├── risk_gate.py               # Trivy aggregation, enrichment, and decision
├── sonar_status.py            # Analysis-specific Sonar Quality Gate lookup
├── Dockerfile
├── sonar-project.properties
├── pytest.ini
├── requirements.txt
└── README.md
```
