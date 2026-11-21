#!/usr/bin/env python3
"""compliance_report output → OSCAL 1.2.3 assessment-results.

    opa eval -f json -d . -i facts.json 'data.<key>.main.compliance_report' > report.json
    python3 converters/exports/oscal/build_assessment_results.py report.json --key <key> -o results.json --validate \
        [--time 2026-10-12T00:00:00Z] [--subject host01]

Input: `opa eval -f json` output, an OPA REST response ({"result": {...}}) or a bare compliance_report, for any
framework key (`--key` names the package when the input does not: REST and bare reports). Several inputs make one
result. `--validate` checks the document against the vendored OSCAL schema and exits 1 when it does not validate
(2 when jsonschema is missing), so nothing unvalidated is written as a success.

One result per run: reviewed-controls lists every control of the frameworks that reported.
  * Reports with control_results (NIST SP 800-53, CIS M365 v7, CIS RHEL 9, CIS Windows 2022, ...): one finding per
    row. "pass" -> satisfied (method EXAMINE when the row's basis is attestation, else TEST). "fail",
    "evidence_missing", "not_attested" and any other status -> not-satisfied, the status kept as the reason.
    "not_applicable" -> an observation and no finding: it is neither satisfied nor a failure. A violation for a
    control whose row says "pass" turns the row into a failure (fail closed). The row's findings and the
    violations that map to its control are the observations.
  * Violations with no row (reports without control_results): one observation and one not-satisfied finding each.
Absence of a finding is never taken as evidence: only a control_results "pass" row asserts satisfied. Targets
are the catalog control's statement part when the control is in the catalog; unmapped ids are kept, flagged
control-mapped=false. Uuids are uuid5 of (framework, control id, message) so re-running on the same facts
yields the same ids.
"""
from __future__ import annotations
import json, sys, pathlib, argparse, datetime
HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE)); sys.path.insert(0, str(HERE.parent))
from build import version_and_date, u5, NS, REPO, OSCAL_VERSION  # noqa: E402
from _lib.findings import Index, assess                           # noqa: E402

RAW = f"{REPO}/raw/v{{v}}/converters/exports/oscal/dist/catalogs/{{fw}}.json"


def _subject(subject):
    return [{"subject-uuid": u5("subject", subject or "unspecified"), "type": "component", "title": subject or "unspecified subject"}]


def build(reports, key=None, subject=None, when=None, catalogs=None, ix=None):
    version, _ = version_and_date()
    when = when or datetime.datetime.now(datetime.timezone.utc)
    stamp = when.strftime("%Y-%m-%dT%H:%M:%S+00:00")
    cat_dir = pathlib.Path(catalogs) if catalogs else HERE / "dist" / "catalogs"
    items = assess(reports, ix or Index.build(), key)
    fws = sorted({a.rule.framework for a in items})
    selections, known = [], set()
    for fw in fws:
        p = cat_dir / f"{fw}.json"
        if not p.exists():
            continue
        cat = json.loads(p.read_text())["catalog"]
        ids = [c["id"] for g in cat["groups"] for c in g["controls"]]
        known.update(ids)
        selections.append({"description": f"All {len(ids)} controls of {fw} (catalog {RAW.format(v=version, fw=fw)})",
                           "props": [{"name": "framework", "ns": NS, "value": fw}],
                           "include-controls": [{"control-id": i} for i in ids]})
    observations, results_findings, seen, obs_ids = [], [], set(), set()
    n = {"satisfied": 0, "not-satisfied": 0, "not-applicable": 0}

    def observe(a, key3, title, text, method):
        ouid = u5("observation", *key3)
        if ouid not in obs_ids:
            obs_ids.add(ouid)
            props = [{"name": "rego-package", "ns": NS, "value": a.package}, {"name": "report", "ns": NS, "value": a.report_path}]
            if a.row_id:
                props += [{"name": "status", "ns": NS, "value": a.status}]
                if a.basis:
                    props += [{"name": "basis", "ns": NS, "value": a.basis}]
            if a.severity:
                props += [{"name": "severity", "ns": NS, "value": a.severity}]
            observations.append({"uuid": ouid, "title": title, "description": text, "methods": [method],
                                 "types": ["control-objective"], "collected": stamp, "props": props, "subjects": _subject(subject)})
        return ouid

    for a in items:
        r = a.rule
        target = {"type": "objective-id" if r.id in known else "statement-id",
                  "target-id": f"{r.id}_stmt" if r.id in known else r.id}
        method = "EXAMINE" if a.basis == "attestation" or a.status == "not_attested" else "TEST"
        if a.row_id is None:   # a violation without a control_results row
            key3 = (r.framework, r.id, a.messages[0])
            if key3 in seen:
                continue
            seen.add(key3)
            ouid = observe(a, key3, f"{r.label}: violation", a.messages[0], method)
            status = {"state": "not-satisfied"} if a.status == "fail" else {"state": "not-satisfied", "reason": a.status}
            results_findings.append({"uuid": u5("finding", *key3), "title": f"{r.label} not satisfied", "description": a.messages[0],
                                     "props": [{"name": "framework", "ns": NS, "value": r.framework},
                                               {"name": "control-mapped", "ns": NS, "value": str(r.mapped).lower()}],
                                     "target": {**target, "status": status},
                                     "related-observations": [{"observation-uuid": ouid}]})
            n["not-satisfied"] += 1
            continue
        rkey = (r.framework, r.id, "row")
        if rkey in seen:
            continue
        seen.add(rkey)
        basis = a.basis or "evidence"
        msgs = a.messages or [f"{r.label}: {a.status} ({basis})."]
        ouids = [observe(a, (r.framework, r.id, m), f"{r.label}: {a.status}", m, method) for m in dict.fromkeys(msgs)]
        if a.status == "not_applicable":
            n["not-applicable"] += 1
            continue
        state = "satisfied" if a.satisfied else "not-satisfied"
        n[state] += 1
        status = {"state": state, "reason": a.status}
        results_findings.append({"uuid": u5("finding", *rkey, a.status),
                                 "title": f"{r.label} {'satisfied' if a.satisfied else 'not satisfied'}",
                                 "description": f"control_results row {a.row_id}: {a.status} ({basis})." + (f" {len(a.messages)} finding(s)." if a.messages else ""),
                                 "props": [{"name": "framework", "ns": NS, "value": r.framework},
                                           {"name": "control-mapped", "ns": NS, "value": str(r.mapped).lower()},
                                           {"name": "status", "ns": NS, "value": a.status}],
                                 "target": {**target, "status": status},
                                 "related-observations": [{"observation-uuid": o} for o in dict.fromkeys(ouids)]})
    ap_uuid = u5("assessment-plan", "implicit", version)
    meta_props = [{"name": "generator", "ns": NS, "value": "converters/exports/oscal/build_assessment_results.py"},
                  {"name": "authored-with", "ns": NS, "value": "Claude (Anthropic)"}]
    meta_props += [{"name": "subject", "ns": NS, "value": subject}] if subject else []
    meta_props += [{"name": "framework-key", "ns": NS, "value": key}] if key else []
    doc = {"assessment-results": {
        "uuid": u5("assessment-results", stamp, subject or "", key or "", *["|".join(k) for k in sorted(seen)[:50]]),
        "metadata": {"title": f"Rego Policy Libraries assessment results — {', '.join(fws) or 'no reports'}", "last-modified": stamp,
                     "version": version, "oscal-version": OSCAL_VERSION, "props": meta_props},
        "import-ap": {"href": f"#{ap_uuid}"},
        "results": [{"uuid": u5("result", stamp, *fws), "title": f"Automated evaluation, library v{version}",
                     "description": f"{n['not-satisfied']} not satisfied, {n['satisfied']} satisfied and {n['not-applicable']} not applicable across {len(fws)} framework(s); a control is asserted satisfied only from a control_results pass row (absence of a finding is not evidence).",
                     "start": stamp, "end": stamp,
                     "reviewed-controls": {"control-selections": selections or [{"description": "no catalog found for the reporting frameworks"}]},
                     **({"observations": observations} if observations else {}),
                     **({"findings": results_findings} if results_findings else {})}],
        "back-matter": {"resources": [{"uuid": ap_uuid, "title": "Implicit assessment plan",
                                       "description": "Evaluate the input facts against every control of the reporting frameworks with the Rego Policy Libraries; no separate assessment plan document exists.",
                                       "rlinks": [{"href": REPO}]}]}}}
    return doc, n


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("reports", nargs="+", help="compliance_report JSON: opa eval -f json output, an OPA REST response or a bare report")
    ap.add_argument("-o", "--out", default="-")
    ap.add_argument("--key", default=None, help="framework key (data.<key>.main.compliance_report); required for REST and bare reports")
    ap.add_argument("--time", default=None, help="assessment time, RFC 3339 (default: now)")
    ap.add_argument("--subject", default=None, help="what was assessed (host name, account id, cluster); recorded as a prop")
    ap.add_argument("--catalogs", default=None, help="catalog directory (default: dist/catalogs)")
    ap.add_argument("--validate", action="store_true", help="validate against the vendored OSCAL schema; exit 1 if invalid")
    a = ap.parse_args()
    when = datetime.datetime.fromisoformat(a.time.replace("Z", "+00:00")) if a.time else None
    doc, n = build(a.reports, a.key, a.subject, when, a.catalogs)
    res = doc["assessment-results"]["results"][0]
    if not res.get("findings") and not res.get("observations"):
        print("no compliance_report found in the input (a report has violations plus compliant/failed_controls)", file=sys.stderr)
        return 1
    if a.validate:
        from validate import validate_doc
        try:
            errs = validate_doc(doc)
        except ImportError:
            print("cannot validate: jsonschema not installed (pip install jsonschema)", file=sys.stderr); return 2
        if errs:
            print("\n".join(f"FAIL schema {e}" for e in errs), file=sys.stderr); return 1
    text = json.dumps(doc, indent=1, ensure_ascii=False) + "\n"
    if a.out == "-":
        sys.stdout.write(text)
    else:
        pathlib.Path(a.out).write_text(text)
        print(f"oscal assessment-results: {len(res.get('findings', []))} findings ({n['satisfied']} satisfied, {n['not-satisfied']} not satisfied), "
              f"{n['not-applicable']} not applicable, {len(res.get('observations', []))} observations, "
              f"{sum(len(s.get('include-controls', [])) for s in res['reviewed-controls']['control-selections'])} reviewed controls"
              f"{', schema-valid' if a.validate else ''} -> {a.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
