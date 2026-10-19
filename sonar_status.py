#!/usr/bin/env python3
"""Collect the Quality Gate result for the scanner's specific Sonar analysis."""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable
from urllib.parse import urlencode, urlsplit
from urllib.request import Request, urlopen

from safe_paths import read_text, write_text

def _fetch_json(url: str, token: str, timeout: float) -> Any:
    request = Request(url, headers={"Authorization": f"Bearer {token}"})
    with urlopen(request, timeout=timeout) as response:
        if response.status != 200:
            raise ValueError("SonarQube API returned an unsuccessful HTTP status")
        return json.loads(response.read().decode("utf-8"))


def _read_properties(path: Path, workspace_root: Path) -> dict[str, str]:
    properties: dict[str, str] = {}
    for raw_line in read_text(path, workspace_root).splitlines():
        line = raw_line.strip()
        if line and not line.startswith("#") and "=" in line:
            key, value = line.split("=", 1)
            properties[key.strip()] = value.strip()
    return properties


def _classify_conditions(conditions: Any) -> str:
    if not isinstance(conditions, list):
        return "unknown_failure"
    failed = [
        item for item in conditions
        if isinstance(item, dict) and item.get("status") == "ERROR"
    ]
    if not failed:
        return "unknown_failure"
    security_failed = [
        item for item in failed
        if isinstance(item.get("metricKey"), str)
        and "security" in item["metricKey"].lower()
    ]
    if security_failed and len(security_failed) == len(failed):
        return "security_failure"
    if security_failed:
        return "mixed_failure"
    if all(isinstance(item.get("metricKey"), str) for item in failed):
        return "non_security_failure"
    return "unknown_failure"


def collect_status(
    task_file: Path,
    host_url: str,
    token: str,
    timeout_seconds: float = 300.0,
    request_json: Callable[[str, str, float], Any] = _fetch_json,
    sleep: Callable[[float], None] = time.sleep,
    workspace_root: Path | None = None,
) -> dict[str, Any]:
    result: dict[str, Any] = {
        "configured": True,
        "status": "UNKNOWN",
        "classification": "unknown_failure",
        "reason": "sonar_status_unavailable",
        "retrieved_at": datetime.now(timezone.utc).isoformat(),
    }
    try:
        properties = _read_properties(task_file, workspace_root or Path.cwd())
        task_url = properties.get("ceTaskUrl")
        if not task_url:
            raise ValueError("scanner task URL is missing")
        configured_host = urlsplit(host_url)
        returned_host = urlsplit(task_url)
        if (
            configured_host.scheme not in ("http", "https")
            or not configured_host.hostname
            or returned_host.hostname != configured_host.hostname
            or returned_host.port != configured_host.port
            or returned_host.scheme != configured_host.scheme
        ):
            raise ValueError("scanner task URL does not match configured server")

        deadline = time.monotonic() + timeout_seconds
        while True:
            task = request_json(task_url, token, 10.0)
            task_info = task.get("task") if isinstance(task, dict) else None
            state = task_info.get("status") if isinstance(task_info, dict) else None
            if state == "SUCCESS":
                analysis_id = task_info.get("analysisId")
                if not isinstance(analysis_id, str) or not analysis_id:
                    raise ValueError("analysis identifier is missing")
                gate_url = host_url.rstrip("/") + "/api/qualitygates/project_status?"
                gate_url += urlencode({"analysisId": analysis_id})
                gate = request_json(gate_url, token, 10.0)
                project_status = gate.get("projectStatus") if isinstance(gate, dict) else None
                status = project_status.get("status") if isinstance(project_status, dict) else None
                if status not in ("OK", "ERROR"):
                    raise ValueError("Quality Gate response has an invalid status")
                result["status"] = status
                result["classification"] = (
                    _classify_conditions(project_status.get("conditions"))
                    if status == "ERROR"
                    else "passed"
                )
                result["reason"] = "quality_gate_retrieved"
                return result
            if state in ("FAILED", "CANCELED"):
                result["reason"] = "sonar_analysis_failed"
                return result
            if state not in ("PENDING", "IN_PROGRESS"):
                raise ValueError("scanner task response has an invalid status")
            if time.monotonic() >= deadline:
                result["reason"] = "sonar_analysis_poll_timeout"
                return result
            sleep(min(2.0, max(0.0, deadline - time.monotonic())))
    except (OSError, UnicodeError, ValueError, json.JSONDecodeError):
        return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--task-file", type=Path, default=Path(".scannerwork/report-task.txt"))
    parser.add_argument("--output", type=Path, default=Path("sonar-status.json"))
    parser.add_argument("--timeout-seconds", type=float, default=300.0)
    args = parser.parse_args(argv)
    workspace_root = Path.cwd().resolve(strict=True)
    token = os.environ.get("SONAR_TOKEN", "")
    host_url = os.environ.get("SONAR_HOST_URL", "")
    if not token or not host_url:
        print("Sonar status: configured scan credentials are unavailable.", file=sys.stderr)
        return 2
    status = collect_status(
        args.task_file,
        host_url,
        token,
        args.timeout_seconds,
        workspace_root=workspace_root,
    )
    try:
        write_text(
            args.output,
            json.dumps(status, indent=2, sort_keys=True) + "\n",
            workspace_root,
        )
    except OSError:
        print("Sonar status: unable to write status report.", file=sys.stderr)
        return 2
    print(f"Sonar Quality Gate: {status['status']} ({status['reason']}).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
