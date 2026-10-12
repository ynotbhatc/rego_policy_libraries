#!/usr/bin/env python3
"""compliance_report output → SARIF 2.1.0.

    opa eval -f json -d benchmarks/cis/rhel_9 -i facts.json 'data.cis_rhel9.main.compliance_report' > report.json
    python3 converters/exports/sarif/build.py report.json [more.json ...] -o results.sarif

One result per violation, level "error". Rule ids are the OSCAL control ids (<framework>-<control id>), so a
SARIF viewer, the OSCAL catalog and the OCSF findings all name a control the same way. Only rules that have
results are embedded unless --all-rules. Violations whose prefix is not a known control (section-level
fail-closed notices) still become results, under a rule flagged properties.mapped=false.
"""
from __future__ import annotations
import argparse, json, sys, pathlib
HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
from _lib.findings import Index, findings, version, REPO  # noqa: E402

RAW = f"{REPO}/blob/v{{v}}/"


def sarif_rule(r, v):
    rule = {"id": r.id, "name": r.label.replace(" ", "_"),
            "shortDescription": {"text": r.text[:1000]},
            "fullDescription": {"text": r.text},
            "helpUri": f"{REPO}/blob/v{v}/{r.file}" if r.file else REPO,
            "defaultConfiguration": {"level": "error"},
            "properties": {"framework": r.framework, "label": r.label, "regoPackage": r.package, "regoFile": r.file,
                           "mapped": r.mapped, "tags": ["compliance", r.framework]}}
    if r.file:
        rule["help"] = {"text": f"Implemented in {r.file} (package {r.package}). OSCAL catalog: converters/exports/oscal/dist/catalogs/{r.framework}.json"}
    return rule


def build(paths, all_rules=False):
    v = version()
    ix = Index.build()
    fs = findings(paths, ix)
    rules, idx = [], {}
    def ri(rule):
        if rule.id not in idx:
            idx[rule.id] = len(rules); rules.append(sarif_rule(rule, v))
        return idx[rule.id]
    if all_rules:
        for rule in sorted(ix.controls.values(), key=lambda r: r.id):
            ri(rule)
    results = []
    for f in fs:
        results.append({"ruleId": f.rule.id, "ruleIndex": ri(f.rule), "level": "error", "kind": "fail",
                        "message": {"text": f.message},
                        "locations": [{"logicalLocations": [{"name": f.package, "kind": "module", "fullyQualifiedName": f"data.{f.package}"}]}],
                        "partialFingerprints": {"control/v1": f.rule.id},
                        "properties": {"framework": f.rule.framework, "control": f.rule.label, "mapped": f.rule.mapped, "report": f.report_path}})
    reports = sorted({f.report_path for f in fs})
    return {"$schema": "https://json.schemastore.org/sarif-2.1.0.json", "version": "2.1.0",
            "runs": [{"tool": {"driver": {"name": "Rego Policy Libraries", "semanticVersion": v, "version": v, "informationUri": REPO,
                                          "organization": "ynotbhatc", "rules": rules}},
                      "originalUriBaseIds": {"REPO": {"uri": RAW.format(v=v)}},
                      "invocations": [{"executionSuccessful": True}],
                      "results": results,
                      "properties": {"reports": reports, "violations": len(results),
                                     "mapped": sum(1 for f in fs if f.rule.mapped), "unmapped": sum(1 for f in fs if not f.rule.mapped),
                                     "generator": "converters/exports/sarif/build.py", "authoredWith": "Claude (Anthropic)"}}]}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("reports", nargs="+"); ap.add_argument("-o", "--out", default="-"); ap.add_argument("--all-rules", action="store_true")
    a = ap.parse_args()
    doc = build(a.reports, a.all_rules)
    text = json.dumps(doc, indent=1, ensure_ascii=False) + "\n"
    if a.out == "-":
        sys.stdout.write(text)
    else:
        pathlib.Path(a.out).write_text(text)
        p = doc["runs"][0]["properties"]
        print(f"sarif: {p['violations']} results ({p['mapped']} mapped to controls, {p['unmapped']} unmapped), {len(doc['runs'][0]['tool']['driver']['rules'])} rules -> {a.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
