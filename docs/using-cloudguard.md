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
      export-image: ${{ github.event_name != 'pull_request' }}  # only needed for publishing
      # Optional: keep in sync with the @ref above if you override checkout.
      # cloudguard-ref: v1
    secrets:
      SONAR_TOKEN: ${{ secrets.SONAR_TOKEN }}
      SONAR_HOST_URL: ${{ secrets.SONAR_HOST_URL }}

  # Optional: publish the scanned image and deploy it to Azure Container Apps.
  # Needs the one-time Azure setup described in "Publishing and deploying" below.
  publish-deploy:
    needs: cloudguard
    if: github.event_name == 'push' && github.ref == 'refs/heads/main'
    uses: avniijain/cloudguard/.github/workflows/cloudguard-publish.yml@v1  # same ref as above
    permissions:
      contents: read
      id-token: write
    with:
      publish: false   # set true to enable
      deploy: false    # set true to enable (requires publish)
      decision: ${{ needs.cloudguard.outputs.decision }}
      risk-gate-mode: ${{ needs.cloudguard.outputs.risk-gate-mode }}
      image-tag: ${{ needs.cloudguard.outputs.image-tag }}
      image-id: ${{ needs.cloudguard.outputs.image-id }}
      image-artifact: ${{ needs.cloudguard.outputs.image-artifact }}
      registry: ${{ vars.ACR_LOGIN_SERVER }}
      image-repository: my-app
      azure-client-id: ${{ vars.AZURE_CLIENT_ID }}
      azure-tenant-id: ${{ vars.AZURE_TENANT_ID }}
      azure-subscription-id: ${{ vars.AZURE_SUBSCRIPTION_ID }}
      resource-group: ${{ vars.AZURE_RESOURCE_GROUP }}
      container-app: ${{ vars.AZURE_CONTAINER_APP }}
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
| `export-image`        | boolean | `false`                   | Export the scanned image as an artifact so it can be published without rebuilding |

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
| `image-id`       | Image ID of the scanned image, verified again before publishing |
| `image-artifact` | Name of the artifact holding the exported image |

## Publishing and deploying to Azure (optional)

[`cloudguard-publish.yml`](../.github/workflows/cloudguard-publish.yml) is a separate
reusable workflow. Off by default (`publish: false`, `deploy: false`). When enabled
it takes the image CloudGuard already scanned (no rebuild), verifies the image ID,
pushes it to Azure Container Registry, then optionally creates a new Container Apps
revision at 0% traffic, health-checks it, shifts traffic, and rolls back automatically
if the public health check fails.

### Hard rules (callers cannot relax these)

Publishing only proceeds when **all** of the following hold:

- Event is `push` or `workflow_dispatch` (never a pull request)
- Ref is `refs/heads/<deploy-branch>` (`deploy-branch` defaults to `main`)
- `risk-gate-mode` is `enforce`
- `decision` is `ALLOW`

`WARN` and `BLOCK` never publish or deploy. Enabling `deploy` without `publish` fails
the gate.

### Caller requirements

- The calling job must grant `permissions: { contents: read, id-token: write }`
- Create a GitHub environment (default name `production`) restricted to the deploy
  branch
- Pass Azure IDs as repository **variables**, not secrets
- v1 supports **Azure Container Registry** and **Azure Container Apps** only

### `cloudguard-publish.yml` inputs

| Input                 | Type    | Default         | Description |
|-----------------------|---------|-----------------|-------------|
| `publish`             | boolean | `false`         | Push the scanned image to the registry. Off unless the caller enables it. |
| `deploy`              | boolean | `false`         | Deploy the published image to Azure Container Apps. Off by default; requires publish. |
| `decision`            | string  | `""`            | `decision` output of the CloudGuard scan workflow. |
| `risk-gate-mode`      | string  | `""`            | `risk-gate-mode` output of the CloudGuard scan workflow. |
| `image-tag`           | string  | `""`            | `image-tag` output of the scan workflow (local tag of the scanned image). |
| `image-id`            | string  | `""`            | `image-id` output of the scan workflow; verified after the image is loaded. |
| `image-artifact`      | string  | `""`            | `image-artifact` output of the scan workflow (artifact holding the exported image). |
| `registry`            | string  | `""`            | Azure Container Registry login server, for example `myregistry.azurecr.io`. |
| `image-repository`    | string  | `""`            | Repository name inside the registry, for example `bookmarks-api`. |
| `environment`         | string  | `"production"`  | GitHub environment used for publish and deploy jobs (must match the Azure trust). |
| `deploy-branch`       | string  | `"main"`        | Branch that is allowed to publish and deploy. |
| `azure-client-id`     | string  | `""`            | Client ID of the identity this repository uses to sign in to Azure (not a secret). |
| `azure-tenant-id`     | string  | `""`            | Azure tenant ID. |
| `azure-subscription-id` | string | `""`           | Azure subscription ID. |
| `resource-group`      | string  | `""`            | Resource group of the container app. |
| `container-app`       | string  | `""`            | Name of the existing container app. |
| `health-path`         | string  | `"/health"`     | HTTP path that returns 2xx when the app is healthy. |
| `env-vars`            | string  | `""`            | Space-separated `KEY=VALUE` settings for the app. Use `secretref:name` for secrets. |

Outputs: `image-ref` (digest-pinned published reference), `revision`, `previous-revision`.

### One-time Azure setup

Run [`docs/azure-bootstrap.ps1`](azure-bootstrap.ps1) once per consuming repository
(after the resource group, registry, and AcrPull identity already exist):

```powershell
.\docs\azure-bootstrap.ps1 -GitHubOwner OWNER -GitHubRepo REPO `
    -ResourceGroup rg-example -AcrName myregistry -Location centralindia `
    -ContainerApp my-app -TargetPort 8000
```

It prints repository variables to set (not secrets):

- `AZURE_CLIENT_ID`
- `AZURE_TENANT_ID`
- `AZURE_SUBSCRIPTION_ID`
- `ACR_LOGIN_SERVER`
- `AZURE_RESOURCE_GROUP`
- `AZURE_CONTAINER_APP`

Then create the matching GitHub environment and restrict it to the deploy branch.

### Security model

Azure trusts exactly one repository and one environment via a federated credential
subject of the form `repo:OWNER/REPO:environment:NAME`. No wildcards. One deployer
identity per consuming repo. CloudGuard stores no Azure credentials; the caller signs
in with OIDC (`id-token: write`).

### Required vs optional files in a consuming repo

| File / capability | Required? |
|-------------------|-----------|
| `Dockerfile` | **Required** |
| HTTP health endpoint (default `/health`) | **Required** for deploy |
| `sonar-project.properties` | Optional |
| Risk Gate policy file | Optional |

### Cost

The container app is created with min replicas `0` (scales to zero). Delete the
resource group when you are finished to avoid ongoing charges.

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
