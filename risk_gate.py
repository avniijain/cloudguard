#!/usr/bin/env python3
"""Evaluate Trivy reports and optional security enrichment into a risk decision."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import urlopen

from safe_paths import PathSecurityError, read_text, write_text


POLICY_VERSION = "1.0"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://api.first.org/data/v1/epss"
EPSS_BATCH_SIZE = 100
CVE_PATTERN = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)
SEVERITY_ORDER = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN")

DEFAULT_POLICY: dict[str, Any] = {
    "version": POLICY_VERSION,
    "severity_scores": {
        "CRITICAL": 65,
        "HIGH": 40,
        "MEDIUM": 25,
        "LOW": 8,
        "UNKNOWN": 25,
    },
    "secret_score": 80,
    "kev_points": 25,
    "epss": {
        "high_threshold": 0.7,
        "high_points": 15,
        "medium_threshold": 0.3,
        "medium_points": 8,
    },
    "warn_score": 25,
    "block_score": 70,
    "block_on_critical": True,
    "block_on_kev": True,
    "block_on_secrets": True,
    "block_on_missing_reports": True,
    "block_on_enrichment_failure": True,
    "block_on_sonar_security_failure": True,
    "block_on_sonar_unavailable": True,
}


class PolicyError(ValueError):
    """Raised when a supplied policy is not usable."""


class FeedError(ValueError):
    """Raised when a public feed response is unavailable or invalid."""


def _valid_text(value: Any, limit: int = 300) -> str | None:
    if not isinstance(value, str):
        return None
    value = value.strip()
    return value[:limit] if value else None


def _severity(value: Any) -> str:
    normalized = value.upper().strip() if isinstance(value, str) else ""
    return normalized if normalized in SEVERITY_ORDER[:-1] else "UNKNOWN"


def _severity_rank(value: str) -> int:
    return SEVERITY_ORDER.index(value)


def _normalize_cve(value: Any) -> str | None:
    text = _valid_text(value, 40)
    if text and CVE_PATTERN.fullmatch(text):
        return text.upper()
    return None


def _read_json(path: Path, workspace_root: Path) -> Any:
    try:
        return json.loads(read_text(path, workspace_root))
    except PathSecurityError:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise FeedError("feed file could not be read or parsed") from exc


def _fetch_json(url: str, timeout: float = 10.0) -> Any:
    try:
        with urlopen(url, timeout=timeout) as response:
            if response.status != 200:
                raise FeedError("feed returned an unsuccessful HTTP status")
            return json.loads(response.read().decode("utf-8"))
    except (HTTPError, URLError, TimeoutError, OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise FeedError("feed request failed or returned invalid JSON") from exc


class FeedEnricher:
    """Fetch and validate the CISA KEV and FIRST EPSS data at most once per run."""

    def __init__(
        self,
        kev_file: Path | None = None,
        epss_file: Path | None = None,
        fetch_json: Callable[[str], Any] | None = None,
        workspace_root: Path | None = None,
    ) -> None:
        self.kev_file = kev_file
        self.epss_file = epss_file
        self.workspace_root = workspace_root or Path.cwd()
        self.fetch_json = fetch_json or _fetch_json
        self.kev_ids: set[str] | None = None
        self.epss_scores: dict[str, float] = {}
        self.errors: list[str] = []
        self._kev_loaded = False
        self._epss_requested: set[str] = set()

    def _load_kev(self) -> None:
        if self._kev_loaded:
            return
        self._kev_loaded = True
        try:
            payload = _read_json(self.kev_file, self.workspace_root) if self.kev_file else self.fetch_json(KEV_URL)
            records = payload.get("vulnerabilities") if isinstance(payload, dict) else None
            if not isinstance(records, list):
                raise FeedError("CISA KEV response has an invalid schema")
            ids: set[str] = set()
            for record in records:
                if not isinstance(record, dict) or not _normalize_cve(record.get("cveID")):
                    raise FeedError("CISA KEV response contains an invalid record")
                ids.add(_normalize_cve(record["cveID"]) or "")
            self.kev_ids = ids
        except (FeedError, OSError):
            self.errors.append("CISA KEV catalog unavailable or invalid")

    def _load_epss(self, cves: list[str]) -> None:
        missing = sorted(set(cves) - self._epss_requested)
        if not missing:
            return
        self._epss_requested.update(missing)
        try:
            if self.epss_file:
                payload = _read_json(self.epss_file, self.workspace_root)
                self._accept_epss_response(payload, set(missing))
                return
            for offset in range(0, len(missing), EPSS_BATCH_SIZE):
                batch = missing[offset : offset + EPSS_BATCH_SIZE]
                url = f"{EPSS_URL}?{urlencode({'cve': ','.join(batch)})}"
                self._accept_epss_response(self.fetch_json(url), set(batch))
        except (FeedError, OSError):
            self.errors.append("FIRST EPSS data unavailable or invalid")

    def _accept_epss_response(self, payload: Any, requested: set[str]) -> None:
        if not isinstance(payload, dict) or payload.get("status") != "OK":
            raise FeedError("FIRST EPSS response has an invalid status")
        records = payload.get("data")
        if not isinstance(records, list):
            raise FeedError("FIRST EPSS response has an invalid schema")
        received: set[str] = set()
        for record in records:
            if not isinstance(record, dict):
                raise FeedError("FIRST EPSS response contains an invalid record")
            cve = _normalize_cve(record.get("cve"))
            value = record.get("epss")
            if cve not in requested or not isinstance(value, (str, int, float)):
                raise FeedError("FIRST EPSS response contains an invalid record")
            try:
                score = float(value)
            except (TypeError, ValueError) as exc:
                raise FeedError("FIRST EPSS score is invalid") from exc
            if not math.isfinite(score) or not 0 <= score <= 1:
                raise FeedError("FIRST EPSS score is outside the valid range")
            received.add(cve)
            self.epss_scores[cve] = score
        if received != requested:
            raise FeedError("FIRST EPSS response omitted requested CVEs")

    def enrich(self, cves: list[str]) -> tuple[set[str] | None, dict[str, float | None]]:
        if not cves:
            return None, {}
        self._load_kev()
        self._load_epss(cves)
        return self.kev_ids, {cve: self.epss_scores.get(cve) for cve in cves}


def _policy_with_overrides(overrides: Any) -> dict[str, Any]:
    if not isinstance(overrides, dict):
        raise PolicyError("policy must be a JSON object")
    policy = dict(DEFAULT_POLICY)
    policy["severity_scores"] = dict(DEFAULT_POLICY["severity_scores"])
    policy["epss"] = dict(DEFAULT_POLICY["epss"])
    for key, value in overrides.items():
        if key in ("severity_scores", "epss") and isinstance(value, dict):
            policy[key].update(value)
        else:
            policy[key] = value
    try:
        if not isinstance(policy["version"], str) or not policy["version"].strip():
            raise ValueError
        for key in ("warn_score", "block_score", "secret_score", "kev_points"):
            if not isinstance(policy[key], int) or not 0 <= policy[key] <= 100:
                raise ValueError
        if policy["warn_score"] > policy["block_score"]:
            raise ValueError
        for severity in SEVERITY_ORDER:
            points = policy["severity_scores"][severity]
            if not isinstance(points, int) or not 0 <= points <= 100:
                raise ValueError
        for key in ("high_threshold", "medium_threshold"):
            value = policy["epss"][key]
            if not isinstance(value, (int, float)) or not 0 <= value <= 1:
                raise ValueError
        for key in ("high_points", "medium_points"):
            value = policy["epss"][key]
            if not isinstance(value, int) or not 0 <= value <= 100:
                raise ValueError
        for key in (
            "block_on_critical",
            "block_on_kev",
            "block_on_secrets",
            "block_on_missing_reports",
            "block_on_enrichment_failure",
            "block_on_sonar_security_failure",
            "block_on_sonar_unavailable",
        ):
            if not isinstance(policy[key], bool):
                raise ValueError
    except (KeyError, TypeError, ValueError):
        raise PolicyError("policy contains invalid or missing values") from None
    return policy


def load_policy(
    path: Path | None,
    workspace_root: Path | None = None,
    *,
    allow_external: bool = False,
) -> dict[str, Any]:
    if path is None:
        return _policy_with_overrides({})
    try:
        value = json.loads(
            read_text(path, workspace_root or Path.cwd(), allow_external=allow_external)
        )
    except PathSecurityError:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise PolicyError("policy file could not be read or parsed") from exc
    return _policy_with_overrides(value)


def _append_data_issue(issues: list[str], message: str) -> None:
    if message not in issues:
        issues.append(message)


def _parse_report(
    path: Path, source: str, issues: list[str], workspace_root: Path
) -> list[tuple[str, dict[str, Any], dict[str, Any]]]:
    try:
        report = json.loads(read_text(path, workspace_root))
    except FileNotFoundError:
        _append_data_issue(issues, f"{source} Trivy report is missing")
        return []
    except (OSError, UnicodeError, json.JSONDecodeError):
        _append_data_issue(issues, f"{source} Trivy report is unreadable or malformed")
        return []
    if not isinstance(report, dict) or not isinstance(report.get("Results"), list):
        _append_data_issue(issues, f"{source} Trivy report has an incomplete schema")
        return []

    records: list[tuple[str, dict[str, Any], dict[str, Any]]] = []
    for result in report["Results"]:
        if not isinstance(result, dict):
            _append_data_issue(issues, f"{source} Trivy report contains an invalid result")
            continue
        target = _valid_text(result.get("Target"), 500) or "unknown"
        for field, finding_type in (
            ("Vulnerabilities", "vulnerability"),
            ("Secrets", "secret"),
            ("Misconfigurations", "misconfiguration"),
        ):
            entries = result.get(field, [])
            if entries is None:
                continue
            if not isinstance(entries, list):
                _append_data_issue(issues, f"{source} Trivy report has an invalid {field} section")
                continue
            for entry in entries:
                if not isinstance(entry, dict):
                    _append_data_issue(issues, f"{source} Trivy report contains an invalid {field} finding")
                    continue
                records.append((finding_type, entry, {"source": source, "target": target}))
    return records


def _finding_key(kind: str, data: dict[str, Any], context: dict[str, str]) -> tuple[str, dict[str, Any]]:
    target = context["target"]
    severity = _severity(data.get("Severity"))
    if kind == "vulnerability":
        identifier = _valid_text(data.get("VulnerabilityID"), 100)
        package = _valid_text(data.get("PkgName"), 200)
        version = _valid_text(data.get("InstalledVersion"), 200)
        cve = _normalize_cve(identifier)
        missing_identity = not identifier or not package or not version
        key = "|".join(
            (
                "vulnerability",
                identifier.upper() if identifier else "",
                (package or "").lower(),
                version or "",
                target if missing_identity else "",
            )
        )
        display = {
            "type": kind,
            "severity": severity,
            "identifiers": [identifier] if identifier else [],
            "cve": cve,
            "package": package,
            "installed_version": version,
            "fixed_version": _valid_text(data.get("FixedVersion"), 200),
            "rule_id": None,
        }
    elif kind == "secret":
        rule = _valid_text(data.get("RuleID"), 100) or _valid_text(data.get("Category"), 100) or "SECRET"
        line = data.get("StartLine")
        line_text = str(line) if isinstance(line, (int, str)) else ""
        key = "|".join(("secret", rule, target, line_text))
        display = {
            "type": kind,
            "severity": severity if severity != "UNKNOWN" else "HIGH",
            "identifiers": [],
            "cve": None,
            "package": None,
            "installed_version": None,
            "fixed_version": None,
            "rule_id": rule,
            "line": line if isinstance(line, int) else None,
        }
    else:
        identifier = _valid_text(data.get("ID"), 100) or "MISCONFIG"
        cause = data.get("CauseMetadata")
        resource = _valid_text(cause.get("Resource"), 200) if isinstance(cause, dict) else None
        key = "|".join(("misconfiguration", identifier, resource or "", target))
        display = {
            "type": kind,
            "severity": severity,
            "identifiers": [identifier],
            "cve": None,
            "package": None,
            "installed_version": None,
            "fixed_version": None,
            "rule_id": identifier,
            "resource": resource,
        }
    return key, display


def _collect_findings(
    report_paths: list[tuple[Path, str]], issues: list[str], workspace_root: Path
) -> dict[str, dict[str, Any]]:
    findings: dict[str, dict[str, Any]] = {}
    for path, source in report_paths:
        for kind, data, context in _parse_report(path, source, issues, workspace_root):
            if kind == "vulnerability" and any(
                not _valid_text(data.get(field), 200)
                for field in ("VulnerabilityID", "PkgName", "InstalledVersion")
            ):
                _append_data_issue(issues, f"{source} Trivy report contains incomplete vulnerability identity")
            if kind == "secret" and not (
                _valid_text(data.get("RuleID"), 100) or _valid_text(data.get("Category"), 100)
            ):
                _append_data_issue(issues, f"{source} Trivy report contains a secret without a rule identifier")
            if kind == "misconfiguration" and not _valid_text(data.get("ID"), 100):
                _append_data_issue(issues, f"{source} Trivy report contains a misconfiguration without an identifier")
            key, display = _finding_key(kind, data, context)
            finding = findings.get(key)
            if finding is None:
                finding = {
                    **display,
                    "sources": [],
                    "targets": [],
                    "_key": key,
                }
                findings[key] = finding
            if context["source"] not in finding["sources"]:
                finding["sources"].append(context["source"])
            if context["target"] not in finding["targets"]:
                finding["targets"].append(context["target"])
            if _severity_rank(display["severity"]) < _severity_rank(finding["severity"]):
                finding["severity"] = display["severity"]
            for identifier in display["identifiers"]:
                if identifier not in finding["identifiers"]:
                    finding["identifiers"].append(identifier)
            if not finding.get("fixed_version") and display.get("fixed_version"):
                finding["fixed_version"] = display["fixed_version"]
    return findings


def _evaluate_sonar(
    configured: bool, path: Path, issues: list[str], workspace_root: Path
) -> tuple[dict[str, Any], list[str], list[str]]:
    if not configured:
        return {"configured": False, "status": "NOT_CONFIGURED"}, [], []
    try:
        value = json.loads(read_text(path, workspace_root))
    except FileNotFoundError:
        _append_data_issue(issues, "Configured SonarQube status report is missing")
        return {"configured": True, "status": "UNKNOWN"}, [], ["SONAR_STATUS_UNAVAILABLE"]
    except (OSError, UnicodeError, json.JSONDecodeError):
        _append_data_issue(issues, "Configured SonarQube status report is malformed")
        return {"configured": True, "status": "UNKNOWN"}, [], ["SONAR_STATUS_UNAVAILABLE"]
    if not isinstance(value, dict) or value.get("configured") is not True:
        _append_data_issue(issues, "Configured SonarQube status report has an invalid schema")
        return {"configured": True, "status": "UNKNOWN"}, [], ["SONAR_STATUS_UNAVAILABLE"]
    status = value.get("status")
    classification = value.get("classification")
    if status not in ("OK", "ERROR", "UNKNOWN"):
        _append_data_issue(issues, "Configured SonarQube status report has an invalid status")
        return {"configured": True, "status": "UNKNOWN"}, [], ["SONAR_STATUS_UNAVAILABLE"]
    if status == "UNKNOWN":
        _append_data_issue(issues, "Configured SonarQube Quality Gate status is unavailable")
        return {"configured": True, "status": status}, [], ["SONAR_STATUS_UNAVAILABLE"]
    if status == "OK":
        return {"configured": True, "status": status}, [], []
    if classification == "security_failure":
        return {"configured": True, "status": status, "classification": classification}, ["SONAR_SECURITY_QUALITY_GATE_FAILURE"], []
    if classification == "mixed_failure":
        return {"configured": True, "status": status, "classification": classification}, [
            "SONAR_SECURITY_QUALITY_GATE_FAILURE",
            "SONAR_NON_SECURITY_QUALITY_GATE_FAILURE",
        ], []
    if classification == "non_security_failure":
        return {"configured": True, "status": status, "classification": classification}, [
            "SONAR_NON_SECURITY_QUALITY_GATE_FAILURE"
        ], []
    _append_data_issue(issues, "SonarQube Quality Gate failed without classifiable conditions")
    return {"configured": True, "status": status, "classification": "unknown_failure"}, [], [
        "SONAR_STATUS_UNAVAILABLE"
    ]


def decide(
    fs_report: Path,
    image_report: Path,
    policy: dict[str, Any] | None = None,
    enricher: FeedEnricher | None = None,
    sonar_status: Path = Path("sonar-status.json"),
    sonar_configured: bool = False,
    workspace_root: Path | None = None,
) -> dict[str, Any]:
    root = (workspace_root or Path.cwd()).resolve(strict=True)
    active_policy = policy or _policy_with_overrides({})
    data_issues: list[str] = []
    findings = _collect_findings(
        [(fs_report, "filesystem"), (image_report, "image")], data_issues, root
    )
    cves = sorted(
        {
            finding["cve"]
            for finding in findings.values()
            if finding["type"] == "vulnerability" and finding.get("cve")
        }
    )
    active_enricher = enricher or FeedEnricher()
    kev_ids, epss_scores = active_enricher.enrich(cves)
    for error in active_enricher.errors:
        _append_data_issue(data_issues, error)

    rule_reasons: list[str] = []
    warning_reasons: list[str] = []
    total_score = 0
    severity_counts = {severity: 0 for severity in SEVERITY_ORDER}
    type_counts = {"vulnerability": 0, "secret": 0, "misconfiguration": 0}
    rendered_findings: list[dict[str, Any]] = []
    for finding in findings.values():
        kind = finding["type"]
        severity = finding["severity"]
        severity_counts[severity] += 1
        type_counts[kind] += 1
        base_score = (
            active_policy["secret_score"]
            if kind == "secret"
            else active_policy["severity_scores"][severity]
        )
        factors = [f"{kind} severity {severity}: {base_score} points"]
        score = base_score
        cve = finding.get("cve")
        if cve:
            kev_match: bool | None = None if kev_ids is None else cve in kev_ids
            epss = epss_scores.get(cve)
            finding["kev"] = kev_match
            finding["epss"] = epss
            if kev_match:
                score += active_policy["kev_points"]
                factors.append(f"CISA KEV match: +{active_policy['kev_points']} points")
            if epss is not None:
                if epss >= active_policy["epss"]["high_threshold"]:
                    score += active_policy["epss"]["high_points"]
                    factors.append(
                        f"EPSS {epss:.3f} at or above high threshold: "
                        f"+{active_policy['epss']['high_points']} points"
                    )
                elif epss >= active_policy["epss"]["medium_threshold"]:
                    score += active_policy["epss"]["medium_points"]
                    factors.append(
                        f"EPSS {epss:.3f} at or above medium threshold: "
                        f"+{active_policy['epss']['medium_points']} points"
                    )
                else:
                    factors.append(f"EPSS {epss:.3f} below medium threshold: +0 points")
            if kev_match is None or epss is None:
                factors.append("Enrichment unavailable; unknown is not treated as a negative match")
            if kev_match and active_policy["block_on_kev"]:
                rule_reasons.append(f"KEV_MATCH:{cve}")
        finding["risk_factors"] = factors
        finding["risk_score"] = min(score, 100)
        total_score += finding["risk_score"]
        if kind == "secret" and active_policy["block_on_secrets"]:
            rule_reasons.append("DETECTED_SECRET")
        if kind == "vulnerability" and severity == "CRITICAL" and active_policy["block_on_critical"]:
            rule_reasons.append(f"CRITICAL_VULNERABILITY:{cve or 'identifier-unavailable'}")
        rendered_findings.append(finding)

    sonar, sonar_rules, sonar_status_rules = _evaluate_sonar(
        sonar_configured, sonar_status, data_issues, root
    )
    security_failure = "SONAR_SECURITY_QUALITY_GATE_FAILURE" in sonar_rules
    non_security_failure = "SONAR_NON_SECURITY_QUALITY_GATE_FAILURE" in sonar_rules
    if security_failure:
        if active_policy["block_on_sonar_security_failure"]:
            rule_reasons.append("SONAR_SECURITY_QUALITY_GATE_FAILURE")
        else:
            warning_reasons.append("SONAR_SECURITY_QUALITY_GATE_FAILURE")
    if non_security_failure:
        warning_reasons.append("SONAR_NON_SECURITY_QUALITY_GATE_FAILURE")

    if active_policy["block_on_missing_reports"] and any(
        reason.endswith("Trivy report is missing")
        or reason.endswith("Trivy report is unreadable or malformed")
        or "Trivy report" in reason
        for reason in data_issues
    ):
        rule_reasons.append("REQUIRED_TRIVY_REPORT_UNAVAILABLE")
    if active_policy["block_on_enrichment_failure"] and cves and active_enricher.errors:
        rule_reasons.append("REQUIRED_ENRICHMENT_UNAVAILABLE")
    if active_policy["block_on_sonar_unavailable"] and "SONAR_STATUS_UNAVAILABLE" in sonar_status_rules:
        rule_reasons.append("CONFIGURED_SONAR_STATUS_UNAVAILABLE")

    score = min(total_score, 100)
    degraded_reasons = [f"DEGRADED_DATA:{reason}" for reason in data_issues]
    reasons = list(dict.fromkeys(rule_reasons + warning_reasons + degraded_reasons))
    if rule_reasons or score >= active_policy["block_score"]:
        verdict = "BLOCK"
        if score >= active_policy["block_score"]:
            reasons.append(f"RISK_SCORE_AT_OR_ABOVE_BLOCK_THRESHOLD:{active_policy['block_score']}")
    elif data_issues or score >= active_policy["warn_score"] or warning_reasons:
        verdict = "WARN"
        if score >= active_policy["warn_score"]:
            reasons.append(f"RISK_SCORE_AT_OR_ABOVE_WARN_THRESHOLD:{active_policy['warn_score']}")
    else:
        verdict = "ALLOW"
        reasons.append("NO_BLOCKING_OR_WARNING_FINDINGS")

    for finding in rendered_findings:
        finding["sources"].sort()
        finding["targets"].sort()
        finding["identifiers"].sort()
        finding["stable_id"] = hashlib.sha256(finding.pop("_key").encode("utf-8")).hexdigest()[:16]
    rendered_findings.sort(key=lambda item: item["stable_id"])
    return {
        "decision": verdict,
        "risk_score": score,
        "policy_version": active_policy["version"],
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "degraded_data": {"degraded": bool(data_issues), "reasons": data_issues},
        "counts": {
            "total": len(rendered_findings),
            "by_type": type_counts,
            "by_severity": severity_counts,
        },
        "reasons": reasons,
        "sonar": sonar,
        "enrichment": {
            "kev": "available" if kev_ids is not None else ("unavailable" if cves else "not_required"),
            "epss": "available" if cves and not any("FIRST EPSS" in error for error in active_enricher.errors) else (
                "unavailable" if cves else "not_required"
            ),
        },
        "findings": rendered_findings,
    }


def _write_summary(report: dict[str, Any]) -> None:
    summary_path = os.environ.get("GITHUB_STEP_SUMMARY")
    if not summary_path:
        return
    reasons = report["reasons"] or ["No additional reasons."]
    lines = [
        "## CloudGuard Risk Gate",
        "",
        f"**Decision:** {report['decision']}  ",
        f"**Risk score:** {report['risk_score']}/100  ",
        f"**Findings:** {report['counts']['total']} "
        f"(vulnerabilities: {report['counts']['by_type']['vulnerability']}, "
        f"secrets: {report['counts']['by_type']['secret']}, "
        f"misconfigurations: {report['counts']['by_type']['misconfiguration']})  ",
        f"**Degraded data:** {'yes' if report['degraded_data']['degraded'] else 'no'}",
        "",
        "Major reasons:",
    ]
    major_reasons = list(dict.fromkeys(reason.split(":", 1)[0] for reason in reasons))
    lines.extend(f"- `{reason}`" for reason in major_reasons)
    try:
        write_text(
            summary_path,
            "\n".join(lines) + "\n",
            Path.cwd(),
            append=True,
            allow_external=True,
        )
    except OSError:
        print("Risk Gate: unable to write the GitHub Actions summary.", file=sys.stderr)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fs-report", type=Path, default=Path("trivy-fs.json"))
    parser.add_argument("--image-report", type=Path, default=Path("trivy-image.json"))
    parser.add_argument("--output", type=Path, default=Path("risk-decision.json"))
    parser.add_argument("--policy", type=Path)
    parser.add_argument(
        "--allow-external-policy",
        action="store_true",
        help="Allow the explicitly selected policy JSON to reside outside the working directory.",
    )
    parser.add_argument("--kev-file", type=Path)
    parser.add_argument("--epss-file", type=Path)
    parser.add_argument("--sonar-status", type=Path, default=Path("sonar-status.json"))
    parser.add_argument(
        "--sonar-configured",
        choices=("true", "false"),
        default=os.environ.get("SONAR_CONFIGURED", "false").lower(),
    )
    parser.add_argument(
        "--mode",
        choices=("report-only", "enforce"),
        default=os.environ.get("RISK_GATE_MODE", "report-only"),
    )
    args = parser.parse_args(argv)
    workspace_root = Path.cwd().resolve(strict=True)
    try:
        policy = load_policy(
            args.policy,
            workspace_root,
            allow_external=args.allow_external_policy,
        )
        report = decide(
            args.fs_report,
            args.image_report,
            policy=policy,
            enricher=FeedEnricher(
                args.kev_file,
                args.epss_file,
                workspace_root=workspace_root,
            ),
            sonar_status=args.sonar_status,
            sonar_configured=args.sonar_configured == "true",
            workspace_root=workspace_root,
        )
        write_text(
            args.output,
            json.dumps(report, indent=2, sort_keys=True) + "\n",
            workspace_root,
        )
    except (PolicyError, OSError) as exc:
        print(f"Risk Gate: unable to produce decision report ({exc}).", file=sys.stderr)
        return 2
    _write_summary(report)
    print(
        f"Risk Gate: {report['decision']} (score {report['risk_score']}/100, "
        f"{report['counts']['total']} deduplicated findings, "
        f"degraded_data={str(report['degraded_data']['degraded']).lower()})."
    )
    return 1 if args.mode == "enforce" and report["decision"] == "BLOCK" else 0


if __name__ == "__main__":
    raise SystemExit(main())
