#!/usr/bin/env python3
from __future__ import annotations
import argparse
import json
import os
from pathlib import Path
import yaml

SAST = {"INFO": 1, "WARNING": 2, "ERROR": 3, "NONE": 999}
DAST = {"INFORMATIONAL": 0, "INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "NONE": 999}


def find_report(root: Path, name: str) -> Path | None:
    direct = root / name
    if direct.is_file():
        return direct
    matches = sorted(root.rglob(name))
    return matches[0] if matches else None


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("report_directory", type=Path)
    parser.add_argument("--job-results", type=Path)
    parser.add_argument("--output", type=Path, default=Path("reports/mandatory-gate.yaml"))
    args = parser.parse_args()
    failures = []
    sast_threshold = os.getenv("FAIL_ON_SAST", "ERROR").upper()
    dast_threshold = os.getenv("FAIL_ON_ZAP_RISK", "NONE").upper()
    if sast_threshold not in SAST or dast_threshold not in DAST:
        raise SystemExit("Invalid security threshold")
    semgrep_path = find_report(args.report_directory, "semgrep.json")
    zap_path = find_report(args.report_directory, "zap.json")
    if semgrep_path is None:
        failures.append("SAST report missing")
    if zap_path is None:
        failures.append("DAST report missing")
    if semgrep_path and sast_threshold != "NONE":
        report = json.loads(semgrep_path.read_text(encoding="utf-8"))
        blocking = 0
        for result in report.get("results", []):
            if not isinstance(result, dict):
                continue
            extra = result.get("extra", {})
            severity = str(extra.get("severity", "INFO")).upper() if isinstance(extra, dict) else "INFO"
            if SAST.get(severity, 1) >= SAST[sast_threshold]:
                blocking += 1
        if blocking:
            failures.append(f"{blocking} blocking SAST finding(s)")
    if zap_path and dast_threshold != "NONE":
        report = json.loads(zap_path.read_text(encoding="utf-8"))
        blocking = 0
        for site in report.get("site", []):
            if not isinstance(site, dict):
                continue
            for alert in site.get("alerts", []):
                if not isinstance(alert, dict):
                    continue
                raw = str(alert.get("riskdesc") or alert.get("risk") or alert.get("riskcode") or "").upper()
                risk = "HIGH" if "HIGH" in raw or raw == "3" else "MEDIUM" if "MEDIUM" in raw or raw == "2" else "LOW" if "LOW" in raw or raw == "1" else "INFORMATIONAL"
                if DAST[risk] >= DAST[dast_threshold]:
                    blocking += 1
        if blocking:
            failures.append(f"{blocking} blocking DAST finding(s)")
    if args.job_results and args.job_results.is_file():
        jobs = json.loads(args.job_results.read_text(encoding="utf-8"))
        for name, job in jobs.items():
            if isinstance(job, dict) and job.get("result") != "success":
                failures.append(f"Job {name}: {job.get('result', 'missing')}")
    document = {"mandatory_security_gate": {"status": "failed" if failures else "passed", "thresholds": {"sast": sast_threshold, "dast": dast_threshold}, "failures": failures}}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(yaml.safe_dump(document, sort_keys=False), encoding="utf-8")
    args.output.with_suffix(".json").write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")
    for failure in failures:
        print(f"- {failure}")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
