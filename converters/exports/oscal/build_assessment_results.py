#!/usr/bin/env python3
"""compliance_report output → OSCAL 1.2.3 assessment-results.

    opa eval -f json -d benchmarks/cis/rhel_9 -i facts.json 'data.cis_rhel9.main.compliance_report' > report.json
    python3 build_assessment_results.py report.json [...] -o results.json [--time 2026-10-12T00:00:00Z] [--subject host01]

One result per run: reviewed-controls lists every control of the frameworks that reported; one observation and
one finding (state not-satisfied, target = the control's statement part) per violation. Controls without a
violation are NOT asserted satisfied here: a report says which checks failed, and fail-closed sections appear
as violations, so absence of a finding is not evidence. Finding and observation uuids are uuid5 of
(framework, control id, message) so re-running on the same facts yields the same ids.
"""
from __future__ import annotations
import json, sys, pathlib, argparse, datetime
HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE)); sys.path.insert(0, str(HERE.parent))
from build import version_and_date, u5, NS, REPO, OSCAL_VERSION  # noqa: E402
from _lib.findings import Index, findings                        # noqa: E402

RAW = f"{REPO}/raw/v{{v}}/converters/exports/oscal/dist/catalogs/{{fw}}.json"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("reports", nargs="+"); ap.add_argument("-o", "--out", default="-")
    ap.add_argument("--time", default=None, help="assessment time, RFC 3339 (default: now)")
    ap.add_argument("--subject", default=None, help="what was assessed (host name, account id, cluster); recorded as a prop")
    ap.add_argument("--catalogs", default=None)
    a = ap.parse_args()
    version, _ = version_and_date()
    when = datetime.datetime.fromisoformat(a.time.replace("Z", "+00:00")) if a.time else datetime.datetime.now(datetime.timezone.utc)
    stamp = when.strftime("%Y-%m-%dT%H:%M:%S+00:00")
    cat_dir = pathlib.Path(a.catalogs) if a.catalogs else HERE / "dist" / "catalogs"
    ix = Index.build()
    fs = findings(a.reports, ix)
    fws = sorted({f.rule.framework for f in fs})
    # reviewed controls: every control of each framework that reported, from its catalog
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
    observations, results_findings = [], []
    seen = set()
    for f in fs:
        key = (f.rule.framework, f.rule.id, f.message)
        if key in seen:
            continue
        seen.add(key)
        ouid = u5("observation", *key); fuid = u5("finding", *key)
        observations.append({"uuid": ouid, "title": f"{f.rule.label}: violation", "description": f.message,
                             "methods": ["TEST"], "types": ["control-objective"], "collected": stamp,
                             "props": [{"name": "rego-package", "ns": NS, "value": f.package},
                                       {"name": "report", "ns": NS, "value": f.report_path}],
                             "subjects": [{"subject-uuid": u5("subject", a.subject or "unspecified"), "type": "component",
                                           "title": a.subject or "unspecified subject"}]})
        target_id = f"{f.rule.id}_stmt" if f.rule.id in known else f.rule.id
        results_findings.append({"uuid": fuid, "title": f"{f.rule.label} not satisfied", "description": f.message,
                                 "props": [{"name": "framework", "ns": NS, "value": f.rule.framework},
                                           {"name": "control-mapped", "ns": NS, "value": str(f.rule.mapped).lower()}],
                                 "target": {"type": "objective-id" if f.rule.id in known else "statement-id", "target-id": target_id,
                                            "status": {"state": "not-satisfied"}},
                                 "related-observations": [{"observation-uuid": ouid}]})
    ap_uuid = u5("assessment-plan", "implicit", version)
    doc = {"assessment-results": {
        "uuid": u5("assessment-results", stamp, a.subject or "", *["|".join(k) for k in sorted(seen)[:50]]),
        "metadata": {"title": f"Rego Policy Libraries assessment results — {', '.join(fws)}", "last-modified": stamp, "version": version,
                     "oscal-version": OSCAL_VERSION,
                     "props": [{"name": "generator", "ns": NS, "value": "converters/exports/oscal/build_assessment_results.py"},
                               {"name": "authored-with", "ns": NS, "value": "Claude (Anthropic)"}] +
                              ([{"name": "subject", "ns": NS, "value": a.subject}] if a.subject else [])},
        "import-ap": {"href": f"#{ap_uuid}"},
        "results": [{"uuid": u5("result", stamp, *fws), "title": f"Automated evaluation, library v{version}",
                     "description": f"{len(results_findings)} violations across {len(fws)} framework(s); controls without a finding are not asserted satisfied (absence of a finding is not evidence).",
                     "start": stamp, "end": stamp,
                     "reviewed-controls": {"control-selections": selections or [{"description": "no catalog found for the reporting frameworks"}]},
                     "observations": observations, "findings": results_findings}],
        "back-matter": {"resources": [{"uuid": ap_uuid, "title": "Implicit assessment plan",
                                       "description": "Evaluate the input facts against every control of the reporting frameworks with the Rego Policy Libraries; no separate assessment plan document exists.",
                                       "rlinks": [{"href": REPO}]}]}}}
    text = json.dumps(doc, indent=1, ensure_ascii=False) + "\n"
    if a.out == "-":
        sys.stdout.write(text)
    else:
        pathlib.Path(a.out).write_text(text)
        print(f"oscal assessment-results: {len(results_findings)} findings / {len(observations)} observations, {sum(len(s.get('include-controls', [])) for s in selections)} reviewed controls -> {a.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
