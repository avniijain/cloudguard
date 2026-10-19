# CloudGuard Risk Gate

## Execution flow

CI runs filesystem and image Trivy scans as before, then `risk_gate.py` reads
`trivy-fs.json` and `trivy-image.json`, combines duplicate findings, optionally
enriches CVEs from the CISA KEV catalog and FIRST EPSS API, and writes
`risk-decision.json`. It also appends a concise summary to GitHub Actions'
`GITHUB_STEP_SUMMARY` when available. Scan reports, the decision, and a
retrieved Sonar status report are uploaded as artifacts.

When Sonar is configured, `sonar_status.py` reads the scanner's
`.scannerwork/report-task.txt`, waits for that specific analysis task, and
retrieves its Quality Gate by analysis ID from SonarQube's documented Web API
v1. It classifies failed conditions with `security` metric names separately
from other failed conditions. No status file is generated for an intentionally
unconfigured Sonar step. If a configured scan cannot supply a real status, the
Risk Gate marks the data degraded.

## Initial policy

The policy is centralized in `DEFAULT_POLICY` in `risk_gate.py` and can be
overridden with a JSON object passed using `--policy`. Default base scores are
critical 65, high 40, medium 25, low 8, unknown 25; a detected secret scores
80. Scores are summed across deduplicated findings and capped at 100. A KEV
match adds 25 points; EPSS at or above 0.7 adds 15, and EPSS at or above 0.3
adds 8. EPSS below 0.3 adds no points. An unknown feed result adds no
enrichment points, is never represented as an EPSS score of zero, and marks
the report degraded.

The default verdict thresholds are WARN at 25 and BLOCK at 70. Independent
hard-block rules default to enabled for critical vulnerabilities, detected
secrets, and CISA KEV matches. A missing, malformed, or incomplete required
Trivy report blocks when enforcement is active. Sonar security-related Quality
Gate failures block by default; non-security Quality Gate failures warn.
Configured-but-unavailable Sonar status blocks. A failure to retrieve KEV or
EPSS is degraded and blocks by default when CVEs need enrichment; set
`block_on_enrichment_failure` to `false` in a policy to make that a warning.
These defaults are adjustable in a policy file. Critical vulnerability handling is deliberately explicit:
`block_on_critical` defaults to `true` independently of its numeric score.

For example, a local policy can change that explicit hard-block rule and the
score threshold:

```json
{
  "version": "1.1",
  "block_on_critical": false,
  "block_score": 80
}
```

Deduplication keys are stable and documented: vulnerabilities use normalized
Vulnerability ID, package name, and installed version (and include target if
any identity field is absent); secrets use rule ID, target, and start line;
misconfigurations use rule ID, resource, and target. Findings retain their
source report(s), target(s), identifiers, and relevant package/version data.
Secret `Match` values and other secret evidence are never copied into the
decision report or console/Actions summary.

`ALLOW` means complete inputs had no warning/block rule and the score is below
the warning threshold. `WARN` indicates a warning score, non-security Sonar
failure, or degraded data. `BLOCK` indicates a hard-block rule or the block
score. Degraded means at least one required report, configured Sonar status, or
requested enrichment source was unavailable or invalid; it does not mean safe.

## Run locally

With local Trivy JSON files:

```powershell
python risk_gate.py --fs-report trivy-fs.json --image-report trivy-image.json --mode report-only
```

CLI report, Sonar status/task, enrichment fixture, and output paths are confined
to the current working directory after canonical resolution. Traversal,
absolute paths outside that workspace, Windows drive paths on non-Windows
systems, and symlinks resolving outside the workspace are rejected; file access
uses no-follow opens and validates regular files. Run local commands from the
project root, as CI does. A selected policy JSON is workspace-confined by
default. If an operator intentionally stores policy outside the workspace, use
the explicit `--allow-external-policy` option; the policy file remains read-only.
The GitHub-provided `GITHUB_STEP_SUMMARY` path is treated as a trusted runner
output path and is opened without following symlinks.

Use `--mode enforce` to return exit code 1 for BLOCK. ALLOW and WARN return 0;
report-only always returns 0 after writing the decision, including for BLOCK.
Missing required reports still produce a degraded BLOCK decision in either
mode. To test offline, pass local feed documents with `--kev-file` and
`--epss-file`; without files the gate uses the official public endpoints. For
Sonar, pass `--sonar-configured true` and `--sonar-status sonar-status.json`
only when an actual status document is available. The status collector itself
uses `SONAR_TOKEN` and `SONAR_HOST_URL`.

The default CI mode is report-only. Set the GitHub Actions variable
`RISK_GATE_MODE` to `enforce` to make BLOCK fail the CI step. No CISA or FIRST
API key is required; no Sonar credential is required when Sonar is intentionally
unconfigured. Sonar analysis/status retrieval uses the existing
`SONAR_TOKEN`, `SONAR_HOST_URL`, and optional `SONAR_ORGANIZATION` settings.

## Tests and limitations

Run tests with:

```powershell
pytest -v
```

Tests construct local Trivy reports and mock all external feed/API responses;
they do not require network access. Live KEV, EPSS, SonarQube Cloud, and GitHub
Actions behavior must be verified in a configured CI run. Sonar status uses
the analysis-specific Quality Gate endpoint from Web API v1 because the
scanner task response exposes its analysis ID; future migration to Web API v2
is possible as the corresponding analysis and Quality Gate APIs become
available. See the [SonarQube Cloud Web API documentation](https://docs.sonarsource.com/sonarqube-cloud/appendices/web-api/),
[CISA KEV catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog),
and [FIRST EPSS API guide](https://www.first.org/epss/data). EPSS and KEV are
optional public enrichments: transient feed errors degrade the decision, while
underlying severity and hard-block policies still apply.
