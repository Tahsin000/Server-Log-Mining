#!/usr/bin/env python3
"""
Local Laravel/Nginx log analyzer.

Corrected behavior:
- You do NOT need both ZIP files.
- `auto` analyzes whatever ZIP exists.
- If user requests nginx but only Laravel ZIP exists, it falls back to Laravel.
- If user requests laravel but only Nginx ZIP exists, it falls back to Nginx.
"""

from __future__ import annotations

import argparse
import gzip
import json
import os
import re
import shutil
import sys
import zipfile
from collections import Counter
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Iterable, Optional

import matplotlib.pyplot as plt
import pandas as pd

INPUT_ROOT = Path("/data/input")
OUTPUT_ROOT = Path("/data/output")
WORK_ROOT = Path("/data/work")

NGINX_DIR = INPUT_ROOT / "nginx"
LARAVEL_DIR = INPUT_ROOT / "laravel"

DEFAULT_REPORTS = {
    "nginx": OUTPUT_ROOT / "nginx-report",
    "laravel": OUTPUT_ROOT / "laravel-report",
}

NGINX_ACCESS_RE = re.compile(
    r'(?P<ip>\S+)\s+\S+\s+\S+\s+\[(?P<time>[^\]]+)\]\s+'
    r'"(?P<method>\S+)\s+(?P<path>\S+)(?:\s+(?P<protocol>[^\"]+))?"\s+'
    r'(?P<status>\d{3})\s+(?P<size>\S+)'
    r'(?:\s+"(?P<referer>[^"]*)"\s+"(?P<user_agent>[^"]*)")?'
)

LARAVEL_ENTRY_RE = re.compile(
    r"^\[(?P<time>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\]\s+"
    r"(?P<env>[\w.-]+)\.(?P<level>\w+):\s+(?P<message>.*)$"
)

EXCEPTION_RE = re.compile(r"(?P<class>[A-Za-z_\\][A-Za-z0-9_\\]*(?:Exception|Error))")
URL_HINT_RE = re.compile(r"(?:GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+(?P<url>/[^\s]+)", re.I)
USER_HINT_RE = re.compile(r"(?:user[_ -]?id|uid|user)[:=]\s*(?P<user>[A-Za-z0-9_.@-]+)", re.I)
SUSPICIOUS_PATH_RE = re.compile(
    r"(\.env|wp-admin|wp-login|phpmyadmin|/\.git|/vendor/|/storage/|/admin|/login|/shell|cmd=|select\+|union\+|eval\(|base64|passwd)",
    re.I,
)
BOT_RE = re.compile(r"bot|crawler|spider|scanner|curl|wget|python-requests|sqlmap|nikto|masscan|zgrab", re.I)


@dataclass
class Job:
    kind: str
    zip_path: Path
    out_path: Path


@dataclass
class Finding:
    area: str
    severity: str
    issue: str
    evidence: str
    likely_cause: str
    action: str


SEVERITY_ORDER = {"LOW": 1, "MODERATE": 2, "HIGH": 3, "CRITICAL": 4}
SEVERITY_SCORE = {"LOW": 10, "MODERATE": 20, "HIGH": 35, "CRITICAL": 50}


def ensure_dirs() -> None:
    for p in [NGINX_DIR, LARAVEL_DIR, OUTPUT_ROOT, WORK_ROOT]:
        p.mkdir(parents=True, exist_ok=True)


def first_zip(folder: Path) -> Optional[Path]:
    if not folder.exists():
        return None
    zips = sorted(folder.glob("*.zip"), key=lambda p: p.stat().st_mtime, reverse=True)
    return zips[0] if zips else None


def safe_extract_zip(zip_path: Path, dest: Path) -> None:
    if dest.exists():
        shutil.rmtree(dest)
    dest.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(zip_path, "r") as zf:
        for member in zf.infolist():
            target = dest / member.filename
            target_resolved = target.resolve()
            dest_resolved = dest.resolve()
            if not str(target_resolved).startswith(str(dest_resolved)):
                raise RuntimeError(f"Unsafe ZIP path blocked: {member.filename}")
        zf.extractall(dest)


def iter_text_files(root: Path) -> Iterable[Path]:
    for p in root.rglob("*"):
        if p.is_file() and not p.name.startswith("."):
            if p.suffix.lower() in {".log", ".gz", ".txt"} or "log" in p.name.lower():
                yield p


def read_lines(path: Path) -> Iterable[str]:
    try:
        if path.suffix.lower() == ".gz":
            with gzip.open(path, "rt", encoding="utf-8", errors="replace") as f:
                for line in f:
                    yield line.rstrip("\n")
        else:
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                for line in f:
                    yield line.rstrip("\n")
    except Exception as exc:
        print(f"[warn] Could not read {path}: {exc}")


def write_markdown(out_path: Path, filename: str, content: str) -> None:
    out_path.mkdir(parents=True, exist_ok=True)
    (out_path / filename).write_text(content, encoding="utf-8")


def write_json(out_path: Path, filename: str, payload: dict) -> None:
    out_path.mkdir(parents=True, exist_ok=True)
    (out_path / filename).write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")


def percent(part: int, whole: int) -> float:
    if whole <= 0:
        return 0.0
    return round((part / whole) * 100.0, 2)


def worst_severity(findings: list[Finding]) -> str:
    if not findings:
        return "LOW"
    return max(findings, key=lambda f: SEVERITY_ORDER.get(f.severity, 0)).severity


def risk_score(findings: list[Finding]) -> int:
    return min(100, sum(SEVERITY_SCORE.get(f.severity, 0) for f in findings))


def decision_label(overall_severity: str) -> str:
    if overall_severity in {"CRITICAL", "HIGH"}:
        return "Action Required"
    if overall_severity == "MODERATE":
        return "Monitor Closely"
    return "Healthy"


def confidence_label(sample_size: int) -> str:
    if sample_size >= 10000:
        return "High"
    if sample_size >= 1000:
        return "Medium"
    return "Low"


def finding_to_dict(finding: Finding) -> dict:
    return {
        "area": finding.area,
        "severity": finding.severity,
        "issue": finding.issue,
        "evidence": finding.evidence,
        "likely_cause": finding.likely_cause,
        "action": finding.action,
    }


def write_decision_outputs(
    out_path: Path,
    system_name: str,
    zip_path: Path,
    scanned_lines: int,
    parsed_entries: int,
    findings: list[Finding],
    key_metrics: dict[str, str],
) -> None:
    sorted_findings = sorted(findings, key=lambda f: SEVERITY_ORDER.get(f.severity, 0), reverse=True)
    overall = worst_severity(sorted_findings)
    score = risk_score(sorted_findings)
    decision = decision_label(overall)
    confidence = confidence_label(parsed_entries)

    if not sorted_findings:
        summary = "No major issue signatures were detected from the parsed logs."
    else:
        summary = "; ".join(f"{f.area}: {f.issue}" for f in sorted_findings[:3])

    payload = {
        "generated_at_utc": datetime.utcnow().isoformat(),
        "system": system_name,
        "input_zip": str(zip_path),
        "scanned_lines": scanned_lines,
        "parsed_entries": parsed_entries,
        "decision": decision,
        "overall_severity": overall,
        "risk_score": score,
        "confidence": confidence,
        "summary": summary,
        "key_metrics": key_metrics,
        "findings": [finding_to_dict(f) for f in sorted_findings],
    }
    write_json(out_path, "decision.json", payload)

    findings_md = ""
    if sorted_findings:
        for idx, f in enumerate(sorted_findings, start=1):
            findings_md += (
                f"### Finding {idx}: {f.issue}\n\n"
                f"- Area: `{f.area}`\n"
                f"- Severity: `{f.severity}`\n"
                f"- Evidence: {f.evidence}\n"
                f"- Likely cause: {f.likely_cause}\n"
                f"- Recommended action: {f.action}\n\n"
            )
    else:
        findings_md = "No high-signal risks were detected from available logs.\n\n"

    metrics_md = "\n".join(f"- {k}: `{v}`" for k, v in key_metrics.items())

    md = f"""# {system_name} Decision Report

## Executive Decision

- Decision: `{decision}`
- Overall severity: `{overall}`
- Risk score (0-100): `{score}`
- Confidence: `{confidence}`

## Decision Summary

{summary}

## Key Metrics

{metrics_md}

## Findings

{findings_md}## Notes for Senior Review

- Use `decision.json` for automation/alerting.
- Use this report with `report.md` and CSV files to validate remediation priority.
- Confidence reflects parsed sample size; low confidence means collect more logs before final sign-off.
"""
    write_markdown(out_path, "decision.md", md)


def save_bar_chart(series: pd.Series, title: str, xlabel: str, ylabel: str, out_file: Path) -> None:
    if series.empty:
        return
    plt.figure(figsize=(10, 5))
    series.head(20).plot(kind="bar")
    plt.title(title)
    plt.xlabel(xlabel)
    plt.ylabel(ylabel)
    plt.tight_layout()
    plt.savefig(out_file)
    plt.close()


def parse_nginx_time(raw: str) -> Optional[datetime]:
    # Example: 10/Oct/2000:13:55:36 -0700
    try:
        return datetime.strptime(raw, "%d/%b/%Y:%H:%M:%S %z").replace(tzinfo=None)
    except Exception:
        return None


def analyze_nginx(zip_path: Path, out_path: Path) -> None:
    print(f"[info] Analyzing Nginx ZIP: {zip_path}")
    work = WORK_ROOT / "nginx-extracted"
    safe_extract_zip(zip_path, work)
    out_path.mkdir(parents=True, exist_ok=True)

    rows = []
    error_lines = []
    total_lines = 0

    for file in iter_text_files(work):
        for line in read_lines(file):
            total_lines += 1
            m = NGINX_ACCESS_RE.search(line)
            if m:
                d = m.groupdict()
                status = int(d.get("status") or 0)
                dt = parse_nginx_time(d.get("time") or "")
                size_raw = d.get("size") or "0"
                rows.append(
                    {
                        "file": str(file.relative_to(work)),
                        "ip": d.get("ip"),
                        "time": dt,
                        "hour": dt.replace(minute=0, second=0, microsecond=0) if dt else None,
                        "method": d.get("method"),
                        "path": d.get("path"),
                        "status": status,
                        "size": int(size_raw) if size_raw.isdigit() else 0,
                        "referer": d.get("referer") or "",
                        "user_agent": d.get("user_agent") or "",
                        "is_error": status >= 400,
                        "is_server_error": status >= 500,
                        "is_bot": bool(BOT_RE.search(d.get("user_agent") or "")),
                        "is_suspicious": bool(SUSPICIOUS_PATH_RE.search(d.get("path") or "")),
                    }
                )
            elif "error" in file.name.lower() or any(level in line.lower() for level in ["error", "crit", "alert", "emerg"]):
                error_lines.append({"file": str(file.relative_to(work)), "line": line[:1000]})

    if not rows and not error_lines:
        write_decision_outputs(
            out_path=out_path,
            system_name="Nginx",
            zip_path=zip_path,
            scanned_lines=total_lines,
            parsed_entries=0,
            findings=[
                Finding(
                    area="Observability",
                    severity="MODERATE",
                    issue="No parseable Nginx access/error entries found",
                    evidence="0 parsed access rows and no sampled error lines",
                    likely_cause="Unexpected log format, wrong files in ZIP, or empty logs",
                    action="Validate ZIP contents and log format; rerun with complete access/error logs",
                )
            ],
            key_metrics={"Total scanned lines": str(total_lines), "Parsed access rows": "0"},
        )
        write_markdown(
            out_path,
            "report.md",
            "# Nginx Log Report\n\nNo readable Nginx access/error log lines were found in the ZIP.\n",
        )
        print(f"[done] No parseable Nginx data. Report: {out_path / 'report.md'}")
        return

    df = pd.DataFrame(rows)
    if not df.empty:
        df.to_csv(out_path / "parsed_nginx_access.csv", index=False)
        status_summary = df.groupby("status").size().sort_values(ascending=False).rename("count")
        status_summary.to_csv(out_path / "status_summary.csv")
        top_paths = df.groupby("path").size().sort_values(ascending=False).head(100).rename("hits")
        top_paths.to_csv(out_path / "top_paths.csv")
        top_ips = df.groupby("ip").size().sort_values(ascending=False).head(100).rename("hits")
        top_ips.to_csv(out_path / "top_ips.csv")
        friction = (
            df[df["status"] >= 400]
            .groupby(["path", "status"])
            .size()
            .sort_values(ascending=False)
            .head(200)
            .rename("count")
        )
        friction.to_csv(out_path / "friction_4xx_5xx_paths.csv")
        suspicious = df[df["is_suspicious"]].head(500)
        suspicious.to_csv(out_path / "suspicious_requests_sample.csv", index=False)
        hourly = df.groupby("hour").size().rename("requests") if "hour" in df else pd.Series(dtype=int)
        hourly.to_csv(out_path / "hourly_traffic.csv")
        save_bar_chart(status_summary, "Nginx status codes", "HTTP status", "Count", out_path / "status_codes.png")
        save_bar_chart(top_paths, "Top Nginx paths", "Path", "Hits", out_path / "top_paths.png")
    else:
        status_summary = pd.Series(dtype=int)
        top_paths = pd.Series(dtype=int)
        top_ips = pd.Series(dtype=int)
        friction = pd.Series(dtype=int)
        suspicious = pd.DataFrame()

    if error_lines:
        pd.DataFrame(error_lines).to_csv(out_path / "nginx_error_lines_sample.csv", index=False)

    total_requests = len(df)
    total_4xx_5xx = int((df["status"] >= 400).sum()) if not df.empty else 0
    total_5xx = int((df["status"] >= 500).sum()) if not df.empty else 0
    suspicious_count = int(df["is_suspicious"].sum()) if not df.empty else 0
    bot_count = int(df["is_bot"].sum()) if not df.empty else 0
    parse_coverage = percent(total_requests, total_lines)
    server_error_rate = percent(total_5xx, total_requests)
    total_error_rate = percent(total_4xx_5xx, total_requests)
    suspicious_rate = percent(suspicious_count, total_requests)
    bot_rate = percent(bot_count, total_requests)

    findings: list[Finding] = []

    if total_5xx >= 20 or server_error_rate >= 3.0:
        sev = "CRITICAL" if server_error_rate >= 5.0 else "HIGH"
        top_5xx_paths = (
            df[df["status"] >= 500]["path"].value_counts().head(5).to_dict() if not df.empty else {}
        )
        findings.append(
            Finding(
                area="Availability",
                severity=sev,
                issue="Elevated server-side failures (5xx)",
                evidence=f"{total_5xx}/{total_requests} requests are 5xx ({server_error_rate}%)",
                likely_cause=f"Application/runtime instability on paths: {top_5xx_paths or 'n/a'}",
                action="Treat as P0/P1 incident: inspect upstream app errors, DB connectivity, and dependency health",
            )
        )

    if total_4xx_5xx >= 50 or total_error_rate >= 10.0:
        sev = "HIGH" if total_error_rate >= 20.0 else "MODERATE"
        findings.append(
            Finding(
                area="Reliability",
                severity=sev,
                issue="High request friction from 4xx/5xx responses",
                evidence=f"{total_4xx_5xx}/{total_requests} requests are errors ({total_error_rate}%)",
                likely_cause="Broken routes, client misuse, auth/session issues, or upstream service faults",
                action="Review friction_4xx_5xx_paths.csv and prioritize top failing routes with product/backend owners",
            )
        )

    if suspicious_count >= 20 or suspicious_rate >= 1.0:
        sev = "HIGH" if suspicious_rate >= 5.0 else "MODERATE"
        suspicious_examples = (
            df[df["is_suspicious"]]["path"].value_counts().head(5).to_dict() if not df.empty else {}
        )
        findings.append(
            Finding(
                area="Security",
                severity=sev,
                issue="Suspicious probe traffic detected",
                evidence=f"{suspicious_count}/{total_requests} requests match attack signatures ({suspicious_rate}%)",
                likely_cause=f"Automated internet scanning/probing. Top patterns: {suspicious_examples or 'n/a'}",
                action="Apply/verify WAF and rate limiting, block abusive IPs, and confirm latest OS/web stack security patches",
            )
        )

    if bot_count >= 100 or bot_rate >= 20.0:
        sev = "MODERATE" if bot_rate < 40.0 else "HIGH"
        findings.append(
            Finding(
                area="Traffic Quality",
                severity=sev,
                issue="Bot-like traffic dominates a significant share of requests",
                evidence=f"{bot_count}/{total_requests} requests are bot-like ({bot_rate}%)",
                likely_cause="Crawler/scanner activity consuming capacity and obscuring real user behavior",
                action="Tune bot management rules and monitor infra capacity impact during peaks",
            )
        )

    if parse_coverage < 30.0 and total_lines > 0:
        findings.append(
            Finding(
                area="Observability",
                severity="MODERATE",
                issue="Low parse coverage against scanned lines",
                evidence=f"Parsed {total_requests} of {total_lines} scanned lines ({parse_coverage}%)",
                likely_cause="Mixed log formats, unexpected custom format, or non-log files in ZIP",
                action="Standardize logging format and include representative access/error logs for accurate scoring",
            )
        )

    if not findings:
        findings.append(
            Finding(
                area="Overall Health",
                severity="LOW",
                issue="No high-signal operational or security risk detected",
                evidence=f"{total_requests} access rows parsed with manageable error/security indicators",
                likely_cause="Normal traffic and error profile for the sampled window",
                action="Continue routine monitoring and periodic patch maintenance",
            )
        )

    key_metrics = {
        "Total scanned lines": str(total_lines),
        "Parsed access rows": str(total_requests),
        "4xx/5xx requests": f"{total_4xx_5xx} ({total_error_rate}%)",
        "5xx requests": f"{total_5xx} ({server_error_rate}%)",
        "Suspicious requests": f"{suspicious_count} ({suspicious_rate}%)",
        "Bot-like requests": f"{bot_count} ({bot_rate}%)",
        "Unique IPs": str(df["ip"].nunique() if not df.empty else 0),
        "Unique paths": str(df["path"].nunique() if not df.empty else 0),
        "Parse coverage": f"{parse_coverage}%",
    }
    write_decision_outputs(
        out_path=out_path,
        system_name="Nginx",
        zip_path=zip_path,
        scanned_lines=total_lines,
        parsed_entries=total_requests,
        findings=findings,
        key_metrics=key_metrics,
    )

    report = f"""# Nginx Log Report

## Input

- ZIP: `{zip_path}`
- Total scanned lines: `{total_lines}`
- Parsed access rows: `{len(df)}`
- Error-like lines sampled: `{len(error_lines)}`

## Summary

- Unique IPs: `{df['ip'].nunique() if not df.empty else 0}`
- Unique paths: `{df['path'].nunique() if not df.empty else 0}`
- 4xx/5xx requests: `{int((df['status'] >= 400).sum()) if not df.empty else 0}`
- 5xx requests: `{int((df['status'] >= 500).sum()) if not df.empty else 0}`
- Suspicious request samples: `{len(suspicious)}`
- Bot-like requests: `{int(df['is_bot'].sum()) if not df.empty else 0}`

## Key output files

- `parsed_nginx_access.csv`
- `decision.md`
- `decision.json`
- `status_summary.csv`
- `top_paths.csv`
- `top_ips.csv`
- `friction_4xx_5xx_paths.csv`
- `suspicious_requests_sample.csv`
- `hourly_traffic.csv`
- `nginx_error_lines_sample.csv`, if error lines exist

## How to read this report

Start with `friction_4xx_5xx_paths.csv` to see where users are blocked or server errors happen.
Then check `suspicious_requests_sample.csv` for unwanted probes such as `.env`, `wp-admin`, `.git`, or SQL-injection-like URLs.
Finally check `top_ips.csv` and `hourly_traffic.csv` for abnormal traffic bursts.
"""
    write_markdown(out_path, "report.md", report)
    print(f"[done] Nginx report generated: {out_path}")


def fingerprint_laravel_message(message: str) -> str:
    text = re.sub(r"\b\d+\b", "{num}", message)
    text = re.sub(r"/[A-Za-z0-9_./-]+", "/{path}", text)
    text = re.sub(r"[A-Za-z0-9_.+-]+@[A-Za-z0-9-]+\.[A-Za-z0-9-.]+", "{email}", text)
    return text[:250]


def analyze_laravel(zip_path: Path, out_path: Path) -> None:
    print(f"[info] Analyzing Laravel ZIP: {zip_path}")
    work = WORK_ROOT / "laravel-extracted"
    safe_extract_zip(zip_path, work)
    out_path.mkdir(parents=True, exist_ok=True)

    entries = []
    current = None
    total_lines = 0

    def flush_current():
        nonlocal current
        if current is not None:
            current["stack_or_context"] = "\n".join(current.get("extra_lines", []))[:5000]
            current.pop("extra_lines", None)
            entries.append(current)
            current = None

    for file in iter_text_files(work):
        for line in read_lines(file):
            total_lines += 1
            m = LARAVEL_ENTRY_RE.match(line)
            if m:
                flush_current()
                d = m.groupdict()
                dt = None
                try:
                    dt = datetime.strptime(d["time"], "%Y-%m-%d %H:%M:%S")
                except Exception:
                    pass
                msg = d["message"]
                exc = EXCEPTION_RE.search(msg)
                url = URL_HINT_RE.search(msg)
                user = USER_HINT_RE.search(msg)
                current = {
                    "file": str(file.relative_to(work)),
                    "time": dt,
                    "hour": dt.replace(minute=0, second=0, microsecond=0) if dt else None,
                    "env": d["env"],
                    "level": d["level"].upper(),
                    "message": msg[:2000],
                    "fingerprint": fingerprint_laravel_message(msg),
                    "exception_class": exc.group("class") if exc else "",
                    "url_hint": url.group("url") if url else "",
                    "user_hint": user.group("user") if user else "",
                    "extra_lines": [],
                }
            else:
                if current is not None:
                    current["extra_lines"].append(line)
                elif line.strip():
                    # Laravel multiline log without initial timestamp; keep as unknown entry.
                    entries.append(
                        {
                            "file": str(file.relative_to(work)),
                            "time": None,
                            "hour": None,
                            "env": "unknown",
                            "level": "UNKNOWN",
                            "message": line[:2000],
                            "fingerprint": fingerprint_laravel_message(line),
                            "exception_class": "",
                            "url_hint": "",
                            "user_hint": "",
                            "stack_or_context": "",
                        }
                    )
    flush_current()

    if not entries:
        write_decision_outputs(
            out_path=out_path,
            system_name="Laravel",
            zip_path=zip_path,
            scanned_lines=total_lines,
            parsed_entries=0,
            findings=[
                Finding(
                    area="Observability",
                    severity="MODERATE",
                    issue="No parseable Laravel log entries found",
                    evidence="0 parsed entries from scanned files",
                    likely_cause="Unexpected log format, missing log files, or empty ZIP",
                    action="Validate `storage/logs` exports and timestamped Laravel format before rerun",
                )
            ],
            key_metrics={"Total scanned lines": str(total_lines), "Parsed entries": "0"},
        )
        write_markdown(
            out_path,
            "report.md",
            "# Laravel Log Report\n\nNo readable Laravel log entries were found in the ZIP.\n",
        )
        print(f"[done] No parseable Laravel data. Report: {out_path / 'report.md'}")
        return

    df = pd.DataFrame(entries)
    df.to_csv(out_path / "parsed_laravel_logs.csv", index=False)

    level_summary = df.groupby("level").size().sort_values(ascending=False).rename("count")
    level_summary.to_csv(out_path / "level_summary.csv")

    top_error_fingerprints = (
        df[df["level"].isin(["ERROR", "CRITICAL", "ALERT", "EMERGENCY", "UNKNOWN"])]
        .groupby("fingerprint")
        .size()
        .sort_values(ascending=False)
        .head(100)
        .rename("count")
    )
    top_error_fingerprints.to_csv(out_path / "top_error_fingerprints.csv")

    top_exception_classes = df[df["exception_class"] != ""].groupby("exception_class").size().sort_values(ascending=False).head(100).rename("count")
    top_exception_classes.to_csv(out_path / "top_exception_classes.csv")

    possible_user_impact = df[df["user_hint"] != ""].groupby(["user_hint", "level"]).size().sort_values(ascending=False).head(200).rename("count")
    possible_user_impact.to_csv(out_path / "possible_user_impact.csv")

    possible_url_impact = df[df["url_hint"] != ""].groupby(["url_hint", "level"]).size().sort_values(ascending=False).head(200).rename("count")
    possible_url_impact.to_csv(out_path / "possible_url_impact.csv")

    if "hour" in df.columns:
        hourly = df.dropna(subset=["hour"]).groupby(["hour", "level"]).size().rename("count")
        hourly.to_csv(out_path / "hourly_laravel_errors.csv")

    save_bar_chart(level_summary, "Laravel log levels", "Level", "Count", out_path / "laravel_levels.png")
    save_bar_chart(top_exception_classes, "Top Laravel exception classes", "Exception", "Count", out_path / "laravel_exceptions.png")

    critical_count = int(df["level"].isin(["CRITICAL", "ALERT", "EMERGENCY"]).sum())
    error_count = int(df["level"].isin(["ERROR", "CRITICAL", "ALERT", "EMERGENCY"]).sum())
    unknown_count = int((df["level"] == "UNKNOWN").sum())
    critical_rate = percent(critical_count, len(df))
    error_rate = percent(error_count, len(df))
    unknown_rate = percent(unknown_count, len(df))

    findings: list[Finding] = []

    if critical_count >= 5 or critical_rate >= 1.0:
        sev = "CRITICAL" if critical_rate >= 3.0 else "HIGH"
        top_critical_fps = (
            df[df["level"].isin(["CRITICAL", "ALERT", "EMERGENCY"])]["fingerprint"]
            .value_counts()
            .head(5)
            .to_dict()
        )
        findings.append(
            Finding(
                area="Application Stability",
                severity=sev,
                issue="Critical-severity Laravel events are recurring",
                evidence=f"{critical_count}/{len(df)} entries are critical/alert/emergency ({critical_rate}%)",
                likely_cause=f"High-impact runtime faults. Dominant critical signatures: {top_critical_fps or 'n/a'}",
                action="Treat as incident: triage top critical fingerprints and map to failing services/deployments",
            )
        )

    if error_count >= 50 or error_rate >= 10.0:
        sev = "HIGH" if error_rate >= 20.0 else "MODERATE"
        dominant = top_error_fingerprints.head(1).to_dict() if not top_error_fingerprints.empty else {}
        findings.append(
            Finding(
                area="Reliability",
                severity=sev,
                issue="Error volume is high relative to total logged events",
                evidence=f"{error_count}/{len(df)} entries are error+ ({error_rate}%)",
                likely_cause=f"One or more repeated faults, likely concentrated in: {dominant or 'n/a'}",
                action="Prioritize top_error_fingerprints.csv and create owner-mapped remediation plan",
            )
        )

    if not top_exception_classes.empty:
        top_exc_name, top_exc_count = next(iter(top_exception_classes.items()))
        exception_rate = percent(int(top_exc_count), len(df))
        if int(top_exc_count) >= 10 or exception_rate >= 5.0:
            sev = "HIGH" if "PDO" in top_exc_name or "Query" in top_exc_name else "MODERATE"
            findings.append(
                Finding(
                    area="Root Cause",
                    severity=sev,
                    issue=f"Exception family '{top_exc_name}' is repeatedly raised",
                    evidence=f"{top_exc_count}/{len(df)} entries ({exception_rate}%)",
                    likely_cause="Shared underlying defect, dependency outage, or schema/query inconsistency",
                    action="Correlate exception stack traces with deployment/version changes and fix highest-frequency path first",
                )
            )

    security_hints = int(
        df["message"].str.contains(r"(cve-|vulnerab|security|deprecated|unsupported|exploit)", case=False, regex=True).sum()
    )
    security_hint_rate = percent(security_hints, len(df))
    if security_hints >= 5 or security_hint_rate >= 1.0:
        findings.append(
            Finding(
                area="Patch & Dependency Risk",
                severity="HIGH" if security_hint_rate >= 3.0 else "MODERATE",
                issue="Security or outdated dependency hints are present in logs",
                evidence=f"{security_hints}/{len(df)} entries contain security/deprecation indicators ({security_hint_rate}%)",
                likely_cause="Unpatched packages, unsupported runtime versions, or insecure configurations",
                action="Audit framework/runtime/package versions and apply latest security patches with changelog review",
            )
        )

    if unknown_count >= 20 or unknown_rate >= 5.0:
        findings.append(
            Finding(
                area="Observability",
                severity="MODERATE",
                issue="A meaningful share of logs could not be classified",
                evidence=f"{unknown_count}/{len(df)} entries are UNKNOWN ({unknown_rate}%)",
                likely_cause="Multiline fragments or format deviations reducing analytic fidelity",
                action="Normalize logging format and preserve structured metadata (request id, route, user id)",
            )
        )

    if not findings:
        findings.append(
            Finding(
                area="Overall Health",
                severity="LOW",
                issue="No high-signal application risk detected in sampled Laravel logs",
                evidence=f"{len(df)} entries parsed with limited critical/error concentration",
                likely_cause="Current log window appears operationally stable",
                action="Continue regular monitoring, deploy checks, and routine dependency patching",
            )
        )

    key_metrics = {
        "Total scanned lines": str(total_lines),
        "Parsed entries": str(len(df)),
        "Error/Critical entries": f"{error_count} ({error_rate}%)",
        "Critical/Alert/Emergency": f"{critical_count} ({critical_rate}%)",
        "Unknown-level entries": f"{unknown_count} ({unknown_rate}%)",
        "Unique fingerprints": str(df["fingerprint"].nunique()),
        "Unique exception classes": str(df[df["exception_class"] != ""]["exception_class"].nunique()),
        "URL hints found": str(int((df["url_hint"] != "").sum())),
        "User hints found": str(int((df["user_hint"] != "").sum())),
    }
    write_decision_outputs(
        out_path=out_path,
        system_name="Laravel",
        zip_path=zip_path,
        scanned_lines=total_lines,
        parsed_entries=len(df),
        findings=findings,
        key_metrics=key_metrics,
    )

    report = f"""# Laravel Log Report

## Input

- ZIP: `{zip_path}`
- Total scanned lines: `{total_lines}`
- Parsed entries: `{len(df)}`

## Summary

- Error/Critical entries: `{error_count}`
- Critical/Alert/Emergency entries: `{critical_count}`
- Unique fingerprints: `{df['fingerprint'].nunique()}`
- Unique exception classes: `{df[df['exception_class'] != '']['exception_class'].nunique()}`
- URL hints found: `{int((df['url_hint'] != '').sum())}`
- User hints found: `{int((df['user_hint'] != '').sum())}`

## Key output files

- `parsed_laravel_logs.csv`
- `decision.md`
- `decision.json`
- `level_summary.csv`
- `top_error_fingerprints.csv`
- `top_exception_classes.csv`
- `possible_user_impact.csv`
- `possible_url_impact.csv`
- `hourly_laravel_errors.csv`

## How to read this report

Start with `top_error_fingerprints.csv` to identify repeated problems.
Then check `top_exception_classes.csv` to know which exception types are recurring.
If your logs include user IDs, URLs, routes, or request hints, check `possible_user_impact.csv` and `possible_url_impact.csv`.
"""
    write_markdown(out_path, "report.md", report)
    print(f"[done] Laravel report generated: {out_path}")


def resolve_jobs(mode: str, zip_arg: Optional[str], out_arg: Optional[str]) -> list[Job]:
    ensure_dirs()

    nginx_zip = first_zip(NGINX_DIR)
    laravel_zip = first_zip(LARAVEL_DIR)

    if zip_arg:
        zp = Path(zip_arg)
        if not zp.exists():
            raise SystemExit(f"[error] ZIP not found: {zp}")
        if mode == "auto":
            lowered = str(zp).lower()
            inferred = "nginx" if "nginx" in lowered else "laravel" if "laravel" in lowered else "laravel"
            print(f"[info] --zip provided in auto mode. Inferred type: {inferred}")
            return [Job(inferred, zp, Path(out_arg) if out_arg else DEFAULT_REPORTS[inferred])]
        return [Job(mode, zp, Path(out_arg) if out_arg else DEFAULT_REPORTS[mode])]

    jobs: list[Job] = []

    if mode == "auto":
        if nginx_zip:
            jobs.append(Job("nginx", nginx_zip, Path(out_arg) if out_arg else DEFAULT_REPORTS["nginx"]))
        if laravel_zip:
            jobs.append(Job("laravel", laravel_zip, Path(out_arg) if out_arg else DEFAULT_REPORTS["laravel"]))
        if not jobs:
            raise SystemExit(
                "[error] No ZIP found. Put at least one ZIP here:\n"
                "  - /data/input/nginx/*.zip\n"
                "  - /data/input/laravel/*.zip\n"
                "Local folders:\n"
                "  - ./input/nginx/\n"
                "  - ./input/laravel/"
            )
        return jobs

    if mode == "nginx":
        if nginx_zip:
            return [Job("nginx", nginx_zip, Path(out_arg) if out_arg else DEFAULT_REPORTS["nginx"])]
        if laravel_zip:
            print("[warn] You requested nginx, but no Nginx ZIP was found.")
            print("[warn] Laravel ZIP exists, so running Laravel analysis instead.")
            return [Job("laravel", laravel_zip, Path(out_arg) if out_arg else DEFAULT_REPORTS["laravel"])]
        raise SystemExit("[error] No ZIP found in /data/input/nginx or /data/input/laravel.")

    if mode == "laravel":
        if laravel_zip:
            return [Job("laravel", laravel_zip, Path(out_arg) if out_arg else DEFAULT_REPORTS["laravel"])]
        if nginx_zip:
            print("[warn] You requested laravel, but no Laravel ZIP was found.")
            print("[warn] Nginx ZIP exists, so running Nginx analysis instead.")
            return [Job("nginx", nginx_zip, Path(out_arg) if out_arg else DEFAULT_REPORTS["nginx"])]
        raise SystemExit("[error] No ZIP found in /data/input/laravel or /data/input/nginx.")

    raise SystemExit(f"[error] Unknown mode: {mode}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Analyze local Nginx/Laravel log ZIP files.")
    parser.add_argument(
        "mode",
        nargs="?",
        default="auto",
        choices=["auto", "nginx", "laravel"],
        help="Which log type to analyze. Default: auto. Auto analyzes whichever ZIP exists.",
    )
    parser.add_argument("--zip", dest="zip_path", help="Optional explicit ZIP path inside container")
    parser.add_argument("--out", dest="out_path", help="Optional output folder inside container")
    args = parser.parse_args()

    jobs = resolve_jobs(args.mode, args.zip_path, args.out_path)
    print("[info] Jobs to run:")
    for j in jobs:
        print(f"  - {j.kind}: {j.zip_path} -> {j.out_path}")

    for job in jobs:
        if job.kind == "nginx":
            analyze_nginx(job.zip_path, job.out_path)
        elif job.kind == "laravel":
            analyze_laravel(job.zip_path, job.out_path)
        else:
            raise RuntimeError(f"Unknown job type: {job.kind}")

    print("[done] Finished.")


if __name__ == "__main__":
    main()
