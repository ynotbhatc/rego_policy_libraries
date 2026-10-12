#!/usr/bin/env python3
"""compliance_report output → OCSF 1.9.0 Compliance Finding events (class_uid 2003), one per violation.

    python3 converters/exports/ocsf/build.py report.json [...] -o findings.ndjson [--time 2026-10-12T00:00:00Z]
                                                            [--severity 3] [--cloud-provider aws] [--json]

cloud and osint are OCSF profiles, not class attributes: cloud is emitted only with --cloud-provider (and declared
in metadata.profiles); osint is never emitted.

NDJSON by default (one event per line, what Security Lake / Splunk / Sentinel ingest); --json writes an array.
Control ids are the OSCAL control ids (<framework>-<control id>) in finding_info.uid and compliance.checks[].uid,
so the SIEM can join a finding to the OSCAL catalog and to the SARIF results.
"""
from __future__ import annotations
import argparse, json, sys, pathlib, datetime
HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
from _lib.findings import Index, findings, version, REPO  # noqa: E402

OCSF_VERSION = "1.9.0"
CLASS_UID, CATEGORY_UID, ACTIVITY_CREATE = 2003, 2, 1
SEVERITY = {1: "Informational", 2: "Low", 3: "Medium", 4: "High", 5: "Critical"}


def event(f, when_ms, severity, provider, v):
    r = f.rule
    ev = {
        "activity_id": ACTIVITY_CREATE, "activity_name": "Create",
        "category_uid": CATEGORY_UID, "category_name": "Findings",
        "class_uid": CLASS_UID, "class_name": "Compliance Finding",
        "type_uid": CLASS_UID * 100 + ACTIVITY_CREATE, "type_name": "Compliance Finding: Create",
        "time": when_ms,
        "severity_id": severity, "severity": SEVERITY[severity],
        "status_id": 1, "status": "New",
        "message": f.message,
        "metadata": {"version": OCSF_VERSION,
                     "product": {"name": "Rego Policy Libraries", "vendor_name": "ynotbhatc", "version": v, "uid": "rego_policy_libraries", "url_string": REPO},
                     "labels": ["compliance", r.framework]},
        "compliance": {"status": "Fail", "status_id": 3,
                       "control": r.label,
                       "standards": [r.framework],
                       "requirements": [r.text],
                       "desc": r.text,
                       "checks": [{"name": r.label, "uid": r.id, "status": "Fail", "status_id": 3, "version": v}]},
        "finding_info": {"title": f"{r.label}: {r.text}"[:255], "uid": r.id, "desc": r.text,
                         "types": ["compliance"], "src_url": f"{REPO}/blob/v{v}/{r.file}" if r.file else REPO},
        "resources": [{"name": f"data.{f.package}", "type": "opa-package", "uid": f.package}],
        "unmapped": {"rego_package": r.package, "rego_file": r.file, "report_path": f.report_path,
                     "control_mapped": r.mapped, "report_compliant": f.compliant},
    }
    if provider:  # the cloud profile: only when the caller says which cloud the facts came from
        ev["metadata"]["profiles"] = ["cloud"]
        ev["cloud"] = {"provider": provider}
    return ev


def build(paths, when_ms, severity, provider):
    v = version()
    ix = Index.build()
    return [event(f, when_ms, severity, provider, v) for f in findings(paths, ix)]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("reports", nargs="+"); ap.add_argument("-o", "--out", default="-")
    ap.add_argument("--time", default=None, help="finding time, RFC 3339 (default: now)")
    ap.add_argument("--severity", type=int, default=3, choices=sorted(SEVERITY))
    ap.add_argument("--cloud-provider", default=None, help="emit the cloud profile with this provider ('aws', 'azure', 'gcp'); omit for hosts and SaaS")
    ap.add_argument("--json", action="store_true", help="write a JSON array instead of NDJSON")
    a = ap.parse_args()
    when = datetime.datetime.fromisoformat(a.time.replace("Z", "+00:00")) if a.time else datetime.datetime.now(datetime.timezone.utc)
    evs = build(a.reports, int(when.timestamp() * 1000), a.severity, a.cloud_provider)
    text = json.dumps(evs, indent=1, ensure_ascii=False) + "\n" if a.json else "".join(json.dumps(e, ensure_ascii=False) + "\n" for e in evs)
    if a.out == "-":
        sys.stdout.write(text)
    else:
        pathlib.Path(a.out).write_text(text)
        print(f"ocsf: {len(evs)} compliance_finding events ({sum(1 for e in evs if e['unmapped']['control_mapped'])} mapped to controls) -> {a.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
