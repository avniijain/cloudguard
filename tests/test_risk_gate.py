import json
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import pytest

import risk_gate
from risk_gate import (
    DEFAULT_POLICY,
    EPSS_URL,
    KEV_URL,
    FeedEnricher,
    FeedError,
    PolicyError,
    decide,
    load_policy,
    main,
    validate_policy_floor,
)
from safe_paths import PathSecurityError, read_text, write_text
from sonar_status import collect_status


def write_report(path: Path, results=None):
    path.write_text(json.dumps({"SchemaVersion": 2, "Results": results or []}), encoding="utf-8")
    return path


def report_pair(tmp_path, fs_results=None, image_results=None):
    fs = write_report(tmp_path / "trivy-fs.json", fs_results)
    image = write_report(tmp_path / "trivy-image.json", image_results)
    return fs, image


def run_decision(fs_report, image_report, **kwargs):
    kwargs.setdefault("workspace_root", fs_report.parent)
    return decide(fs_report, image_report, **kwargs)


def vuln(identifier="CVE-2025-12345", severity="HIGH", package="demo", version="1.0"):
    return {
        "VulnerabilityID": identifier,
        "PkgName": package,
        "InstalledVersion": version,
        "FixedVersion": "2.0",
        "Severity": severity,
    }


class FixtureEnricher(FeedEnricher):
    def __init__(self, kev=None, epss=None, errors=None):
        super().__init__()
        self.kev_ids = kev
        self.epss_scores = epss or {}
        self.errors = errors or []

    def enrich(self, cves):
        if not cves:
            return None, {}
        return self.kev_ids, {cve: self.epss_scores.get(cve) for cve in cves}


def test_no_findings_allows_with_complete_reports(tmp_path):
    fs, image = report_pair(tmp_path)
    result = run_decision(fs, image, enricher=FixtureEnricher())
    assert result["decision"] == "ALLOW"
    assert result["risk_score"] == 0
    assert result["degraded_data"]["degraded"] is False


@pytest.mark.parametrize(
    ("severity", "score", "decision"),
    [
        ("LOW", 8, "ALLOW"),
        ("MEDIUM", 25, "WARN"),
        ("HIGH", 40, "WARN"),
        ("CRITICAL", 65, "BLOCK"),
    ],
)
def test_vulnerability_severity_policy(tmp_path, severity, score, decision):
    fs, image = report_pair(tmp_path, [{"Target": "requirements.txt", "Vulnerabilities": [vuln(severity=severity)]}])
    result = run_decision(fs, image, enricher=FixtureEnricher(kev=set(), epss={"CVE-2025-12345": 0.01}))
    assert result["risk_score"] == score
    assert result["decision"] == decision


def test_detected_secret_is_blocked_without_disclosing_value(tmp_path, capsys):
    secret_value = "test-only-secret-canary-7f039"
    fs, image = report_pair(
        tmp_path,
        [{"Target": "config.env", "Secrets": [{"RuleID": "generic-api-key", "Severity": "CRITICAL", "Match": secret_value, "StartLine": 4}]}],
    )
    result = run_decision(fs, image, enricher=FixtureEnricher())
    output = json.dumps(result)
    assert result["decision"] == "BLOCK"
    assert secret_value not in output
    assert result["findings"][0]["rule_id"] == "generic-api-key"
    assert secret_value not in capsys.readouterr().out


def test_misconfiguration_is_counted_and_scored(tmp_path):
    fs, image = report_pair(
        tmp_path,
        [{"Target": "Dockerfile", "Misconfigurations": [{"ID": "DS-0002", "Severity": "MEDIUM", "CauseMetadata": {"Resource": "app"}}]}],
    )
    result = run_decision(fs, image, enricher=FixtureEnricher())
    assert result["counts"]["by_type"]["misconfiguration"] == 1
    assert result["risk_score"] == 25
    assert result["decision"] == "WARN"


def test_kev_match_adds_risk_and_hard_blocks(tmp_path):
    fs, image = report_pair(tmp_path, [{"Target": "requirements.txt", "Vulnerabilities": [vuln(severity="LOW")]}])
    result = run_decision(
        fs, image, enricher=FixtureEnricher(kev={"CVE-2025-12345"}, epss={"CVE-2025-12345": 0.01})
    )
    finding = result["findings"][0]
    assert result["decision"] == "BLOCK"
    assert finding["kev"] is True
    assert finding["risk_score"] == 33


@pytest.mark.parametrize(("epss", "score"), [(0.9, 55), (0.05, 40)])
def test_epss_score_is_used_only_when_supplied(tmp_path, epss, score):
    fs, image = report_pair(tmp_path, [{"Target": "requirements.txt", "Vulnerabilities": [vuln()]}])
    result = run_decision(
        fs, image, enricher=FixtureEnricher(kev=set(), epss={"CVE-2025-12345": epss})
    )
    assert result["risk_score"] == score
    assert result["findings"][0]["epss"] == epss


def test_duplicate_vulnerability_merges_sources_and_targets(tmp_path):
    item = vuln()
    fs, image = report_pair(
        tmp_path,
        [{"Target": "requirements.txt", "Vulnerabilities": [item]}],
        [{"Target": "usr/local/lib/requirements.txt", "Vulnerabilities": [item]}],
    )
    result = run_decision(fs, image, enricher=FixtureEnricher(kev=set(), epss={"CVE-2025-12345": 0.01}))
    assert result["counts"]["total"] == 1
    assert result["findings"][0]["sources"] == ["filesystem", "image"]
    assert len(result["findings"][0]["targets"]) == 2


def test_missing_and_malformed_reports_are_degraded_and_blocking(tmp_path):
    missing = tmp_path / "missing.json"
    malformed = tmp_path / "broken.json"
    malformed.write_text("{", encoding="utf-8")
    valid = write_report(tmp_path / "valid.json")
    result = run_decision(missing, malformed, enricher=FixtureEnricher())
    assert result["decision"] == "BLOCK"
    assert result["degraded_data"]["degraded"] is True
    assert any("missing" in reason for reason in result["degraded_data"]["reasons"])
    assert any("malformed" in reason for reason in result["degraded_data"]["reasons"])
    assert valid.exists()


def test_report_paths_outside_workspace_fail_closed(tmp_path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    fs, _ = report_pair(workspace)
    outside = write_report(tmp_path / "outside.json")
    result = decide(
        fs,
        outside,
        enricher=FixtureEnricher(),
        workspace_root=workspace,
    )
    assert result["decision"] == "BLOCK"
    assert result["degraded_data"]["degraded"] is True
    assert result["counts"]["total"] == 0


def test_sonar_status_path_outside_workspace_fails_closed(tmp_path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    fs, image = report_pair(workspace)
    outside_status = tmp_path / "sonar-status.json"
    outside_status.write_text(
        '{"configured":true,"status":"OK","classification":"passed"}',
        encoding="utf-8",
    )
    result = decide(
        fs,
        image,
        enricher=FixtureEnricher(),
        sonar_configured=True,
        sonar_status=outside_status,
        workspace_root=workspace,
    )
    assert result["decision"] == "BLOCK"
    assert result["sonar"]["status"] == "UNKNOWN"
    assert result["degraded_data"]["degraded"] is True


def test_incomplete_vulnerability_identity_is_not_silently_accepted(tmp_path):
    fs, image = report_pair(
        tmp_path,
        [{"Target": "requirements.txt", "Vulnerabilities": [{"VulnerabilityID": "CVE-2025-12345", "Severity": "LOW"}]}],
    )
    result = run_decision(fs, image, enricher=FixtureEnricher())
    assert result["decision"] == "BLOCK"
    assert result["degraded_data"]["degraded"] is True
    assert result["findings"][0]["package"] is None


def test_unavailable_enrichment_is_unknown_and_degraded_not_safe(tmp_path):
    fs, image = report_pair(tmp_path, [{"Target": "requirements.txt", "Vulnerabilities": [vuln("CVE-2025-67890", "CRITICAL")]}])
    result = run_decision(
        fs,
        image,
        enricher=FixtureEnricher(kev=None, epss={}, errors=["CISA KEV catalog unavailable or invalid", "FIRST EPSS data unavailable or invalid"]),
    )
    finding = result["findings"][0]
    assert result["decision"] == "BLOCK"
    assert finding["kev"] is None
    assert finding["epss"] is None
    assert result["degraded_data"]["degraded"] is True
    assert not any(isinstance(finding["epss"], float) and finding["epss"] == 0 for finding in result["findings"])


def test_public_feed_failures_are_degraded_without_zero_substitution(tmp_path):
    fs, image = report_pair(
        tmp_path,
        [{"Target": "requirements.txt", "Vulnerabilities": [vuln("CVE-2025-67890", "HIGH")]}],
    )
    requested_urls = []

    def unavailable(url):
        requested_urls.append(url)
        raise FeedError("network unavailable")

    enricher = FeedEnricher(fetch_json=unavailable)
    result = run_decision(fs, image, enricher=enricher)
    assert KEV_URL in requested_urls
    assert any(url.startswith(EPSS_URL) for url in requested_urls)
    assert result["degraded_data"]["degraded"] is True
    assert result["findings"][0]["kev"] is None
    assert result["findings"][0]["epss"] is None


def test_epss_requests_are_batched_to_one_hundred_cves():
    cves = [f"CVE-2025-{number:04d}" for number in range(1000, 1201)]
    urls = []

    def fixture_fetch(url):
        if url == KEV_URL:
            return {"vulnerabilities": []}
        urls.append(url)
        batch = parse_qs(urlsplit(url).query)["cve"][0].split(",")
        return {
            "status": "OK",
            "data": [{"cve": cve, "epss": "0.1"} for cve in batch],
        }

    kev, scores = FeedEnricher(fetch_json=fixture_fetch).enrich(cves)
    assert kev == set()
    assert len(scores) == len(cves)
    assert len(urls) == 3
    assert [len(parse_qs(urlsplit(url).query)["cve"][0].split(",")) for url in urls] == [100, 100, 1]


def test_policy_can_disable_critical_hard_block(tmp_path):
    fs, image = report_pair(tmp_path, [{"Target": "requirements.txt", "Vulnerabilities": [vuln(severity="CRITICAL")]}])
    policy = load_policy(None)
    policy["block_on_critical"] = False
    result = run_decision(fs, image, policy=policy, enricher=FixtureEnricher(kev=set(), epss={"CVE-2025-12345": 0.01}))
    assert result["decision"] == "WARN"


def test_enforce_floor_rejects_weakened_policy(tmp_path):
    policy_path = tmp_path / "weak-policy.json"
    policy_path.write_text(
        json.dumps({"block_score": 90, "block_on_critical": False, "block_on_secrets": False}),
        encoding="utf-8",
    )
    with pytest.raises(PolicyError, match="enforce floor"):
        load_policy(policy_path, tmp_path, enforce_floor=True)
    # Without the flag, the same weakened policy remains loadable (existing behavior).
    loaded = load_policy(policy_path, tmp_path)
    assert loaded["block_score"] == 90
    assert loaded["block_on_critical"] is False


def test_enforce_floor_accepts_default_and_stricter_policy(tmp_path):
    validate_policy_floor(dict(DEFAULT_POLICY))
    stricter = load_policy(None)
    stricter["block_score"] = 50
    validate_policy_floor(stricter)
    policy_path = tmp_path / "strict-policy.json"
    policy_path.write_text(json.dumps({"block_score": 50}), encoding="utf-8")
    assert load_policy(policy_path, tmp_path, enforce_floor=True)["block_score"] == 50


@pytest.mark.parametrize(
    "override",
    [
        {"block_score": 71},
        {"block_on_critical": False},
        {"block_on_kev": False},
        {"block_on_secrets": False},
        {"block_on_missing_reports": False},
        {"block_on_enrichment_failure": False},
        {"block_on_sonar_security_failure": False},
        {"block_on_sonar_unavailable": False},
    ],
)
def test_enforce_floor_rejects_each_restricted_weakening(tmp_path, override):
    policy_path = tmp_path / "policy.json"
    policy_path.write_text(json.dumps(override), encoding="utf-8")
    with pytest.raises(PolicyError, match="enforce floor"):
        load_policy(policy_path, tmp_path, enforce_floor=True)


def test_enforce_floor_cli_exits_two_on_weak_policy(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    fs, image = report_pair(tmp_path)
    policy_path = tmp_path / "weak.json"
    policy_path.write_text(json.dumps({"block_on_kev": False}), encoding="utf-8")
    exit_code = main(
        [
            "--fs-report",
            str(fs),
            "--image-report",
            str(image),
            "--policy",
            str(policy_path),
            "--enforce-floor",
            "--mode",
            "enforce",
        ]
    )
    assert exit_code == 2
    assert "enforce floor" in capsys.readouterr().err


@pytest.mark.parametrize("severity", list(DEFAULT_POLICY["severity_scores"]))
def test_enforce_floor_rejects_severity_score_below_default(tmp_path, severity):
    lowered = DEFAULT_POLICY["severity_scores"][severity] - 1
    policy_path = tmp_path / "policy.json"
    policy_path.write_text(
        json.dumps({"severity_scores": {severity: lowered}}),
        encoding="utf-8",
    )
    with pytest.raises(PolicyError, match="enforce floor"):
        load_policy(policy_path, tmp_path, enforce_floor=True)
    loaded = load_policy(policy_path, tmp_path)
    assert loaded["severity_scores"][severity] == lowered


def test_enforce_floor_accepts_severity_scores_at_or_above_default(tmp_path):
    raised = {name: points + 1 for name, points in DEFAULT_POLICY["severity_scores"].items()}
    policy_path = tmp_path / "policy.json"
    policy_path.write_text(json.dumps({"severity_scores": raised}), encoding="utf-8")
    loaded = load_policy(policy_path, tmp_path, enforce_floor=True)
    assert loaded["severity_scores"] == raised
    validate_policy_floor(dict(DEFAULT_POLICY))


def test_enforce_floor_rejects_sonar_security_failure_disabled(tmp_path):
    policy_path = tmp_path / "policy.json"
    policy_path.write_text(
        json.dumps({"block_on_sonar_security_failure": False}),
        encoding="utf-8",
    )
    with pytest.raises(PolicyError, match="block_on_sonar_security_failure"):
        load_policy(policy_path, tmp_path, enforce_floor=True)


def test_sonar_status_pass_fail_and_unconfigured_states(tmp_path):
    fs, image = report_pair(tmp_path)
    sonar_file = tmp_path / "sonar-status.json"
    sonar_file.write_text(json.dumps({"configured": True, "status": "OK", "classification": "passed"}), encoding="utf-8")
    assert run_decision(fs, image, enricher=FixtureEnricher(), sonar_status=sonar_file, sonar_configured=True)["sonar"]["status"] == "OK"
    sonar_file.write_text(json.dumps({"configured": True, "status": "ERROR", "classification": "non_security_failure"}), encoding="utf-8")
    failed = run_decision(fs, image, enricher=FixtureEnricher(), sonar_status=sonar_file, sonar_configured=True)
    assert failed["decision"] == "WARN"
    assert "SONAR_NON_SECURITY_QUALITY_GATE_FAILURE" in failed["reasons"]
    security_file = tmp_path / "security-sonar.json"
    security_file.write_text(json.dumps({"configured": True, "status": "ERROR", "classification": "security_failure"}), encoding="utf-8")
    security = run_decision(fs, image, enricher=FixtureEnricher(), sonar_status=security_file, sonar_configured=True)
    assert security["decision"] == "BLOCK"
    unconfigured = run_decision(fs, image, enricher=FixtureEnricher())
    assert unconfigured["sonar"]["status"] == "NOT_CONFIGURED"
    assert unconfigured["degraded_data"]["degraded"] is False


def test_sonar_unavailable_when_configured_is_degraded_and_blocks(tmp_path):
    fs, image = report_pair(tmp_path)
    result = run_decision(fs, image, enricher=FixtureEnricher(), sonar_configured=True, sonar_status=tmp_path / "absent.json")
    assert result["decision"] == "BLOCK"
    assert result["degraded_data"]["degraded"] is True


@pytest.mark.parametrize(
    ("mode", "expected_exit"),
    [("report-only", 0), ("enforce", 1)],
)
def test_block_exit_code_respects_mode(tmp_path, mode, expected_exit, monkeypatch):
    monkeypatch.chdir(tmp_path)
    fs, image = report_pair(tmp_path, [{"Target": "requirements.txt", "Vulnerabilities": [vuln(severity="CRITICAL")]}])
    output = tmp_path / "decision.json"
    kev = tmp_path / "kev.json"
    epss = tmp_path / "epss.json"
    kev.write_text(json.dumps({"vulnerabilities": []}), encoding="utf-8")
    epss.write_text(
        json.dumps({"status": "OK", "data": [{"cve": "CVE-2025-12345", "epss": "0.01"}]}),
        encoding="utf-8",
    )
    exit_code = main(
        [
            "--fs-report", str(fs), "--image-report", str(image), "--output", str(output),
            "--mode", mode, "--kev-file", str(kev), "--epss-file", str(epss),
        ]
    )
    assert exit_code == expected_exit
    assert json.loads(output.read_text(encoding="utf-8"))["decision"] == "BLOCK"


def test_github_summary_is_concise_and_redacted(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    secret_value = "summary-secret-canary-99"
    fs, image = report_pair(
        tmp_path,
        [{"Target": "settings.env", "Secrets": [{"RuleID": "generic-api-key", "Match": secret_value}]}],
    )
    summary = tmp_path / "summary.md"
    output = tmp_path / "risk-decision.json"
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(summary))
    assert main([
        "--fs-report", str(fs), "--image-report", str(image), "--output", str(output),
    ]) == 0
    text = summary.read_text(encoding="utf-8")
    assert "BLOCK" in text
    assert "Findings:** 1" in text
    assert secret_value not in text


def run_cli_with_local_feeds(tmp_path, severity, mode, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("SONAR_CONFIGURED", "false")
    fs, image = report_pair(
        tmp_path,
        [{"Target": "requirements.txt", "Vulnerabilities": [vuln(severity=severity)]}],
    )
    output = tmp_path / "decision.json"
    kev = tmp_path / "kev.json"
    epss = tmp_path / "epss.json"
    kev.write_text(json.dumps({"vulnerabilities": []}), encoding="utf-8")
    epss.write_text(
        json.dumps({"status": "OK", "data": [{"cve": "CVE-2025-12345", "epss": "0.01"}]}),
        encoding="utf-8",
    )
    exit_code = main([
        "--fs-report", str(fs), "--image-report", str(image), "--output", str(output),
        "--kev-file", str(kev), "--epss-file", str(epss), "--mode", mode,
        "--sonar-configured", "false",
    ])
    report = json.loads(output.read_text(encoding="utf-8"))
    degraded = report["degraded_data"]
    assert degraded["degraded"] is False, (
        "CLI run was degraded; expected complete KEV/EPSS and unconfigured Sonar. "
        f"reasons={degraded.get('reasons')}"
    )
    return report, exit_code


@pytest.mark.parametrize(
    ("severity", "expected_decision"),
    [("LOW", "ALLOW"), ("HIGH", "WARN")],
)
def test_allow_and_warn_exit_zero_in_enforce_mode(
    tmp_path, severity, expected_decision, monkeypatch
):
    report, exit_code = run_cli_with_local_feeds(
        tmp_path, severity, "enforce", monkeypatch
    )
    assert report["decision"] == expected_decision
    assert exit_code == 0
    if expected_decision == "ALLOW":
        assert "NO_BLOCKING_OR_WARNING_FINDINGS" in report["reasons"]
    else:
        assert any(reason.startswith("RISK_SCORE_AT_OR_ABOVE_WARN_THRESHOLD") for reason in report["reasons"])


@pytest.mark.parametrize(
    ("severity", "expected_decision"),
    [("LOW", "ALLOW"), ("HIGH", "WARN")],
)
def test_allow_and_warn_exit_zero_in_report_only_mode(
    tmp_path, severity, expected_decision, monkeypatch
):
    report, exit_code = run_cli_with_local_feeds(
        tmp_path, severity, "report-only", monkeypatch
    )
    assert report["decision"] == expected_decision
    assert exit_code == 0


def test_unavailable_enrichment_blocks_high_vulnerability_in_enforcement(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)

    def unavailable(_url):
        raise FeedError("network unavailable")

    monkeypatch.setattr(risk_gate, "_fetch_json", unavailable)
    fs, image = report_pair(
        tmp_path,
        [{"Target": "requirements.txt", "Vulnerabilities": [vuln(severity="HIGH")]}],
    )
    output = tmp_path / "decision.json"
    exit_code = main([
        "--fs-report", str(fs), "--image-report", str(image), "--output", str(output),
        "--mode", "enforce",
    ])
    report = json.loads(output.read_text(encoding="utf-8"))
    assert report["decision"] == "BLOCK"
    assert "REQUIRED_ENRICHMENT_UNAVAILABLE" in report["reasons"]
    assert exit_code == 1


def test_sonar_collector_uses_analysis_id_and_classifies_security_failures(tmp_path):
    task_file = tmp_path / "report-task.txt"
    task_file.write_text(
        "ceTaskUrl=https://sonarcloud.io/api/ce/task?id=task-1\nceTaskId=task-1\n",
        encoding="utf-8",
    )
    calls = []

    def fake_request(url, token, timeout):
        calls.append((url, token))
        if "api/ce/task" in url:
            return {"task": {"status": "SUCCESS", "analysisId": "analysis-123"}}
        return {
            "projectStatus": {
                "status": "ERROR",
                "conditions": [
                    {"metricKey": "security_rating", "status": "ERROR"},
                    {"metricKey": "bugs", "status": "OK"},
                ],
            }
        }

    result = collect_status(task_file, "https://sonarcloud.io", "unit-token", request_json=fake_request, workspace_root=tmp_path)
    assert result["status"] == "ERROR"
    assert result["classification"] == "security_failure"
    assert "analysisId=analysis-123" in calls[1][0]
    assert all("unit-token" not in url for url, _ in calls)


def test_sonar_collector_rejects_untrusted_task_url(tmp_path):
    task_file = tmp_path / "report-task.txt"
    task_file.write_text("ceTaskUrl=https://attacker.invalid/task\n", encoding="utf-8")
    result = collect_status(task_file, "https://sonarcloud.io", "unit-token", workspace_root=tmp_path)
    assert result["status"] == "UNKNOWN"
    assert result["reason"] == "sonar_status_unavailable"


def test_sonar_task_file_cannot_escape_workspace_through_symlink(tmp_path):
    outside = tmp_path / "outside-task.txt"
    outside.write_text("ceTaskUrl=https://sonarcloud.io/api/ce/task?id=task-1\n", encoding="utf-8")
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    link = workspace / "report-task.txt"
    try:
        link.symlink_to(outside)
    except (OSError, NotImplementedError):
        pytest.skip("symlink creation is not available")
    result = collect_status(
        link,
        "https://sonarcloud.io",
        "unit-token",
        workspace_root=workspace,
        request_json=lambda *_: pytest.fail("escaped task file must not trigger an API request"),
    )
    assert result["status"] == "UNKNOWN"


def test_feed_enricher_validates_offline_fixture_files(tmp_path):
    kev = tmp_path / "kev.json"
    epss = tmp_path / "epss.json"
    kev.write_text(json.dumps({"vulnerabilities": [{"cveID": "CVE-2025-12345"}]}), encoding="utf-8")
    epss.write_text(json.dumps({"status": "OK", "data": [{"cve": "CVE-2025-12345", "epss": "0.81"}]}), encoding="utf-8")
    enricher = FeedEnricher(kev, epss, workspace_root=tmp_path)
    kev_ids, scores = enricher.enrich(["CVE-2025-12345"])
    assert kev_ids == {"CVE-2025-12345"}
    assert scores == {"CVE-2025-12345": 0.81}
    assert enricher.errors == []


def test_safe_paths_accept_workspace_and_explicit_external_policy_paths(tmp_path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    inside = workspace / "policy.json"
    inside.write_text('{"block_on_critical": false}', encoding="utf-8")
    assert load_policy(inside, workspace)["block_on_critical"] is False

    outside = tmp_path / "external-policy.json"
    outside.write_text('{"block_on_critical": false}', encoding="utf-8")
    with pytest.raises(PathSecurityError):
        load_policy(outside, workspace)
    assert load_policy(outside, workspace, allow_external=True)["block_on_critical"] is False

    nested = workspace / "nested"
    nested.mkdir()
    assert read_text(Path("nested") / ".." / "policy.json", workspace) == inside.read_text(encoding="utf-8")
    assert read_text(inside.resolve(), workspace) == inside.read_text(encoding="utf-8")
    write_text(Path("nested") / ".." / "generated.json", "{}", workspace)
    assert (workspace / "generated.json").read_text(encoding="utf-8") == "{}"
    linked = workspace / "linked-policy.json"
    try:
        linked.symlink_to(inside)
    except (OSError, NotImplementedError):
        pytest.skip("symlink creation is not available")
    assert read_text(linked, workspace) == inside.read_text(encoding="utf-8")


def test_safe_paths_reject_traversal_absolute_windows_drive_and_symlink_escape(tmp_path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    outside = tmp_path / "outside.txt"
    outside.write_text("outside", encoding="utf-8")
    with pytest.raises(PathSecurityError):
        read_text(Path("..") / outside.name, workspace)
    with pytest.raises(PathSecurityError):
        read_text(outside, workspace)
    with pytest.raises(PathSecurityError):
        read_text(r"Z:\private\secrets.json", workspace)
    with pytest.raises(PathSecurityError):
        write_text(outside, "overwrite", workspace)
    assert outside.read_text(encoding="utf-8") == "outside"

    link = workspace / "linked.txt"
    try:
        link.symlink_to(outside)
    except (OSError, NotImplementedError):
        pytest.skip("symlink creation is not available")
    with pytest.raises(PathSecurityError):
        read_text(link, workspace)


def test_external_enrichment_files_are_not_read(tmp_path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    kev = tmp_path / "kev.json"
    epss = tmp_path / "epss.json"
    kev.write_text('{"vulnerabilities": []}', encoding="utf-8")
    epss.write_text('{"status":"OK","data":[]}', encoding="utf-8")
    enricher = FeedEnricher(kev, epss, workspace_root=workspace)
    kev_ids, scores = enricher.enrich(["CVE-2025-12345"])
    assert kev_ids is None
    assert scores["CVE-2025-12345"] is None
    assert any("CISA KEV" in issue for issue in enricher.errors)
    assert any("FIRST EPSS" in issue for issue in enricher.errors)
