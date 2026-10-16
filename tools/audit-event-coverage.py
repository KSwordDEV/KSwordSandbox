#!/usr/bin/env python3
"""Reconcile raw guest events with the sampled report view.

This deliberately audits the existing artifacts only.  It does not infer
that an event was collected when only a static finding exists: raw and report
counts are kept separate and are compared by EventType.  There is no stable
event id in the current JSON contract, so the result is a type-level audit.
"""
from __future__ import annotations

import argparse
import json
import os
from collections import Counter
from pathlib import Path

CONTROLLED = [
    "b4745a326d5f42b780929fa299dd3537",
    "c55484272e534e559b3d026b0a1fee82",
    "acb5d6d096b248e4b7e72ca15db4b9ec",
    "72440896b602484e9eddcd2f1f981648",
    "1feb22d0733b494fb2f46887d083e969",
    "d11d3637584a45f88b820783571d1456",
    "0f52c54084a74a15a17157f950d88828",
    "c1ce8d1c793148018a31ba6e4cf826b9",
    "663512a51d6f4286a738dce78eb5417d",
    "5d4cdb51a537471e9def13378a3fd184",
]
REAL = [
    "b54fd8e237c64b9c84223e912a5943a2",
    "7015c402d0f246ccbe1aeda92f81d512",
    "85f52b63104944ce84a5797ee0aa2110",
    "22df5e1201d84304a85d089907933374",
    "2c800d2d871f49f0b0a0b329268f7ea0",
    "6e15f600f44c44b3931805dd9fc1784d",
    "41d06d63920940edaece78e8e937d17a",
    "3fa55f9fec9648f9a0514d4f6b15adb1",
    "8809ae3f7c3b430ba2592d2171038653",
    "72310bdc773742f994801e9a686783c3",
]


def load_json(path: Path):
    with path.open(encoding="utf-8-sig") as stream:
        return json.load(stream)


def raw_events(job: Path, report: dict) -> list[dict]:
    post = job / "postprocess-result.json"
    if post.exists():
        value = load_json(post).get("eventsPath")
        if value and Path(value).exists():
            return load_json(Path(value))
    # Newer imported jobs may not retain postprocess-result.json.  Prefer a
    # directory whose name matches the job, avoiding policy files under guest.
    guest = job / "guest"
    candidates = list(guest.glob("*/events.json")) if guest.exists() else []
    candidates = [p for p in candidates if p.parent.name == job.name] or candidates
    if candidates:
        return load_json(candidates[0])
    # Some exported batch artifacts keep events.json beside report.json.
    beside = job / "events.json"
    return load_json(beside) if beside.exists() else []


def family(event_type: str) -> str:
    lower = event_type.lower()
    for prefix, name in (
        ("process", "process"),
        ("file", "file"),
        ("registry", "registry"),
        ("startup", "persistence"),
        ("scheduled_task", "persistence"),
        ("service", "persistence"),
        ("network", "network"),
        ("dns", "network"),
        ("socket", "network"),
        ("static", "static"),
    ):
        if lower.startswith(prefix):
            return name
    return "other"


def classify_report(events: list[dict]) -> Counter:
    out: Counter = Counter()
    for event in events:
        data = event.get("Data") or {}
        status = str(data.get("sampleCorrelationStatus") or data.get("sampleCorrelation") or "unclassified")
        counted = str(data.get("behaviorCounted", "")).lower() == "true"
        out[f"{status}|counted={str(counted).lower()}"] += 1
    return out


def audit_job(root: Path, job_id: str, source: str) -> dict:
    job = root / job_id
    report_path = job / "report.json"
    if not report_path.exists():
        return {"jobId": job_id, "source": source, "missing": True}
    report = load_json(report_path)
    raw = raw_events(job, report)
    report_events = report.get("Events") or []
    raw_types = Counter(str(e.get("EventType") or "<missing>") for e in raw)
    report_types = Counter(str(e.get("EventType") or "<missing>") for e in report_events)
    raw_families = Counter(family(k) for k in raw_types for _ in range(raw_types[k]))
    report_families = Counter(family(k) for k in report_types for _ in range(report_types[k]))
    dynamic_raw = sum(v for k, v in raw_types.items() if family(k) not in {"static", "other"})
    dynamic_report = sum(v for k, v in report_types.items() if family(k) not in {"static", "other"})
    marker = next((e for e in report_events if e.get("EventType") == "report.events.sampled"), None)
    marker_data = (marker or {}).get("Data") or {}
    return {
        "jobId": job_id,
        "source": source,
        "sample": (report.get("Sample") or {}).get("FileName"),
        "rawCount": len(raw),
        "reportCount": len(report_events),
        "rawMinusReport": len(raw) - len(report_events),
        "dynamicRawCount": dynamic_raw,
        "dynamicReportCount": dynamic_report,
        "dynamicOmittedByType": dynamic_raw - dynamic_report,
        "rawFamilies": dict(raw_families),
        "reportFamilies": dict(report_families),
        "rawEventTypes": dict(raw_types),
        "reportEventTypes": dict(report_types),
        "reportClassification": dict(classify_report(report_events)),
        "samplingMarker": {k: marker_data.get(k) for k in (
            "rawEventCount", "selectedRawEventCount", "reportEventCount", "omittedEventCount",
            "maxInlineEvents", "maxEventsPerType", "maxHighValueEventsPerType", "maxDiagnosticEvents",
        ) if k in marker_data},
    }


def markdown(rows: list[dict]) -> str:
    lines = [
        "# Event coverage audit",
        "",
        "This is a type-level reconciliation of raw `events.json` and the inline `report.json` view.",
        "The current schema has no stable event id, so equal EventType values are not treated as the same individual event.",
        "A report omission is therefore a report-view omission; it does not prove that the collector missed the event.",
        "",
        "| source | job | sample | raw | report | omitted | dynamic raw | dynamic report | dynamic omitted |",
        "|---|---|---|---:|---:|---:|---:|---:|---:|",
    ]
    for row in rows:
        if row.get("missing"):
            lines.append(f"| {row['source']} | `{row['jobId'][:8]}` | missing report | | | | | | |")
            continue
        lines.append(
            f"| {row['source']} | `{row['jobId'][:8]}` | {row.get('sample') or ''} | "
            f"{row['rawCount']} | {row['reportCount']} | {row['rawMinusReport']} | "
            f"{row['dynamicRawCount']} | {row['dynamicReportCount']} | {row['dynamicOmittedByType']} |"
        )
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--jobs-root", default=r"D:\Temp\KSwordSandbox\jobs")
    parser.add_argument("--output", default="docs/event-coverage-audit-2026-10-16.json")
    parser.add_argument("--markdown", default="docs/event-coverage-audit-2026-10-16.md")
    args = parser.parse_args()
    root = Path(args.jobs_root)
    rows = [audit_job(root, job_id, "controlled") for job_id in CONTROLLED]
    rows += [audit_job(root, job_id, "real") for job_id in REAL]
    payload = {"schema": "event-coverage-audit-v1", "rows": rows}
    Path(args.output).write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    Path(args.markdown).write_text(markdown(rows), encoding="utf-8")
    print(json.dumps({
        "jobs": len(rows),
        "missing": sum(1 for row in rows if row.get("missing")),
        "raw": sum(row.get("rawCount", 0) for row in rows),
        "report": sum(row.get("reportCount", 0) for row in rows),
        "dynamicRaw": sum(row.get("dynamicRawCount", 0) for row in rows),
        "dynamicReport": sum(row.get("dynamicReportCount", 0) for row in rows),
    }, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
