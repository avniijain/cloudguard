# Using CloudGuard from another repository

CloudGuard ships a reusable GitHub Actions workflow at
[`.github/workflows/cloudguard.yml`](../.github/workflows/cloudguard.yml). Your
repository keeps a small caller workflow; CloudGuard runs tests (optional),
Sonar (optional), Docker build, Trivy scans, and the Risk Gate in **your**
workspace.

Pin the workflow to a **release tag or commit SHA**, not `@main`.

## Minimal caller

Create `.github/workflows/security.yml` in the consumer repository:

```yaml
name: Security

on:
  push:
  pull_request:

# Caller must grant at least the permissions the reusable workflow needs.
permissions:
  contents: read
  security-events: write

jobs:
  cloudguard:
    uses: avniijain/cloudguard/.github/workflows/cloudguard.yml@v1  # pin a tag or SHA
    with:
      image-name: my-app
      # Optional: keep in sync with the @ref above if you override checkout.
      # cloudguard-ref: v1
    secrets:
      SONAR_TOKEN: ${{ secrets.SONAR_TOKEN }}
      SONAR_HOST_URL: ${{ secrets.SONAR_HOST_URL }}

  # Example: refuse deploy unless the gate ran in enforce mode and allowed.
  deploy:
    needs: cloudguard
    if: |
      needs.cloudguard.outputs.risk-gate-mode == 'enforce' &&
      needs.cloudguard.outputs.decision == 'ALLOW'
    runs-on: ubuntu-latest
    steps:
      - run: echo "Deploying ${{ needs.cloudguard.outputs.image-tag }}"
```

Replace `avniijain/cloudguard` and `@v1` with the CloudGuard repository and the
tag or SHA you intend to use.

### How CloudGuard scripts are checked out

The reusable workflow checks out **your** code first, then checks out the
CloudGuard repository into `.cloudguard/` for `risk_gate.py`, `sonar_status.py`,
and `safe_paths.py`.

On GitHub.com it defaults to the same revision as the workflow you pinned:

- `repository`: `job.workflow_repository`
- `ref`: `job.workflow_sha` (unless you set `cloudguard-ref`)

See [Contexts reference — `job.workflow_*`](https://docs.github.com/en/actions/writing-workflows/choosing-what-your-workflow-does/accessing-contextual-information-about-workflow-runs#job-context).
Those properties are **not available on GitHub Enterprise Server**; on GHES set
`cloudguard-ref` to the same tag/SHA you use in `uses:`.

`.cloudguard` is excluded from Trivy filesystem scans (`skip-dirs`) and from
Sonar analysis (`sonar.exclusions` / `sonar.coverage.exclusions`). Callers that
measure coverage should omit `.cloudguard` in their own coverage config if they
customize `test-command`.

## Required permissions

Set these on the **caller** workflow (or on the job that uses the reusable
workflow). The reusable workflow also declares the same minimum set:

| Permission         | Access | Why                                      |
|--------------------|--------|------------------------------------------|
| `contents`         | `read` | Check out caller and CloudGuard sources  |
| `security-events`  | `write`| Upload Trivy SARIF to code scanning      |

## Inputs

| Input                 | Type    | Default                   | Description |
|-----------------------|---------|---------------------------|-------------|
| `python-version`      | string  | `"3.13"`                  | Python for setup-python and tests |
| `dockerfile`          | string  | `"Dockerfile"`            | Dockerfile path relative to context |
| `docker-context`      | string  | `"."`                     | Docker build context |
| `image-name`          | string  | *(required)*              | Image name; tagged as `image-name:<caller-sha>` |
| `run-tests`           | boolean | `true`                    | Install deps and run `test-command` |
| `test-install-command`| string  | `pip install -r requirements.txt` | Install command when `run-tests` |
| `test-command`        | string  | `pytest -v --cov --cov-report=xml --cov-report=term` | Test command when `run-tests` |
| `risk-gate-mode`      | string  | `"enforce"`               | `enforce` or `report-only` |
| `policy-file`         | string  | `""`                      | Path to policy JSON in the caller repo; empty = built-in defaults |
| `artifact-name`       | string  | `"cloudguard-scan-reports"` | Artifact name (unique per call if you invoke CloudGuard more than once) |
| `cloudguard-ref`      | string  | `""`                      | Override checkout ref for gate scripts; empty = `job.workflow_sha` |
| `sonar-organization`  | string  | `""`                      | SonarCloud organization key; passed as `-Dsonar.organization` when set |

The reusable workflow always passes `--enforce-floor` to the Risk Gate so a
caller policy cannot weaken the floor (see below).

When `risk-gate-mode` is `report-only`, the job summary shows a clear warning
and the `risk-gate-mode` output is still `report-only` so deploy jobs can refuse
to run.

## Secrets

| Secret           | Required | Description |
|------------------|----------|-------------|
| `SONAR_TOKEN`    | no       | SonarQube/SonarCloud token |
| `SONAR_HOST_URL` | no       | Sonar server base URL |

If `SONAR_TOKEN` is absent (not passed or empty), Sonar analysis and status
collection are skipped with the same messaging as CloudGuard’s own CI. Pass both
secrets from the caller when you want Sonar enabled:

```yaml
    secrets:
      SONAR_TOKEN: ${{ secrets.SONAR_TOKEN }}
      SONAR_HOST_URL: ${{ secrets.SONAR_HOST_URL }}
```

Or use `secrets: inherit` when the caller and organization allow it.

### Adding Sonar secrets in the consumer repo

1. In the consumer repository: **Settings → Secrets and variables → Actions**.
2. Create repository secrets `SONAR_TOKEN` and `SONAR_HOST_URL`.
3. Add a `sonar-project.properties` (or equivalent scanner config) for your
   project. CloudGuard merges `.cloudguard/**` into `sonar.exclusions` and
   `sonar.coverage.exclusions` at scan time.
4. Pass the secrets into the reusable workflow as shown above.
5. For SonarCloud, pass `sonar-organization` (your org key) on the calling job.

## Outputs

| Output           | Description |
|------------------|-------------|
| `decision`       | `ALLOW`, `WARN`, or `BLOCK` (or `UNKNOWN` if no decision file) |
| `risk-score`     | Aggregate score 0–100 |
| `image-tag`      | Built image reference (`image-name:sha`) |
| `risk-gate-mode` | Mode used for this run (`enforce` or `report-only`) |

## Example policy and the enforce floor

Copy [`risk-policy.example.json`](../risk-policy.example.json) (generated from
`DEFAULT_POLICY` in `risk_gate.py`) into your repo and point `policy-file` at it.
You may **tighten** controls; the reusable workflow rejects policies that
**weaken** the floor (`--enforce-floor`, exit code 2).

| Field | Meaning | Floor? |
|-------|---------|--------|
| `version` | Policy document version string | — |
| `severity_scores` | Base points per vulnerability/misconfig severity | **Each severity must be ≥ its `DEFAULT_POLICY` value** |
| `secret_score` | Base points for a detected secret | — |
| `kev_points` | Extra points when a CVE is on the CISA KEV list | — |
| `epss` | EPSS thresholds and bonus points | — |
| `warn_score` | Score at or above which the verdict is at least WARN | — |
| `block_score` | Score at or above which the verdict is BLOCK | **Must be ≤ 70** |
| `block_on_critical` | Hard-block CRITICAL vulnerabilities | **Must stay `true`** |
| `block_on_kev` | Hard-block CISA KEV matches | **Must stay `true`** |
| `block_on_secrets` | Hard-block detected secrets | **Must stay `true`** |
| `block_on_missing_reports` | Hard-block missing/malformed Trivy reports | **Must stay `true`** |
| `block_on_enrichment_failure` | Hard-block when KEV/EPSS enrichment fails for CVEs | **Must stay `true`** |
| `block_on_sonar_security_failure` | Hard-block Sonar security Quality Gate failures | — (not floor-restricted) |
| `block_on_sonar_unavailable` | Hard-block when Sonar is configured but status is unavailable | **Must stay `true`** |

## What CloudGuard’s own `ci.yml` does

[`.github/workflows/ci.yml`](../.github/workflows/ci.yml) remains CloudGuard’s
in-repo CI. It is separate from the reusable workflow and is not removed or
replaced by this guide.
