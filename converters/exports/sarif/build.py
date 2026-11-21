#!/usr/bin/env python3
"""compliance_report output → SARIF 2.1.0 (GitHub code scanning, any SARIF viewer).

    opa eval -f json -d . -i facts.json 'data.<key>.main.compliance_report' > report.json
    python3 converters/exports/sarif/build.py report.json --key <key> -o results.sarif --validate \
        [--subject host01] [--artifact-uri facts/host01.json] [--include-pass]
    gh api repos/{owner}/{repo}/code-scanning/sarifs ...   # or github/codeql-action/upload-sarif

Input: `opa eval -f json` output, an OPA REST response ({"result": {...}}) or a bare compliance_report, for any
framework key (`--key` names the package when the input does not). `--validate` checks the output against the
vendored SARIF 2.1.0 schema and exits 1 when it does not validate (2 when jsonschema is missing).

Results: one per violation message, kind "fail". A control_results row that is not satisfied and carries no
message still gets one result ("<id>: evidence_missing (evidence)"), so nothing the report states is lost; with
--include-pass, "pass" rows become kind "pass" and "not_applicable" rows kind "notApplicable" (level "none",
which code scanning does not raise as alerts). Level follows the module's own severity (STIG CAT I / high ->
error, CAT II / medium -> warning, CAT III / low -> note), else "error" (fail closed), "warning" for
not_attested. Rule ids are the OSCAL control ids (<framework>-<control id>), so SARIF, the OSCAL catalog and the
OCSF findings name a control the same way; rules carry `security-severity` when the module states a severity.
Every result has a physicalLocation (code scanning requires one): `--artifact-uri`, default the first input
path, is the file in the scanned repository the result is reported against, plus a logicalLocation naming the
Rego package. partialFingerprints hash rule, message and subject, so distinct findings of one control stay
distinct alerts. automationDetails.id is "rego_policy_libraries/<key>/<subject>/", the code-scanning category.
Violations whose prefix is not a known control (section-level fail-closed notices) still become results, under
a rule flagged properties.mapped=false.
"""
from __future__ import annotations
import argparse, hashlib, json, sys, pathlib
HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE)); sys.path.insert(0, str(HERE.parent))
from _lib.findings import Index, assess, load_reports, finding_text, version, REPO  # noqa: E402

RAW = f"{REPO}/blob/v{{v}}/"
LEVEL = {"cat i": "error", "critical": "error", "high": "error", "cat ii": "warning", "medium": "warning", "moderate": "warning",
         "cat iii": "note", "low": "note", "info": "note", "informational": "note"}
SEC_SEV = {"error": "8.0", "warning": "5.5", "note": "3.0"}
RANK = {"note": 0, "warning": 1, "error": 2}


def level_for(a):
    if a.severity and a.severity.strip().lower() in LEVEL:
        return LEVEL[a.severity.strip().lower()]
    return "warning" if a.status == "not_attested" else "error"


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


def build(paths, all_rules=False, key=None, subject=None, artifact_uri=None, include_pass=False, ix=None):
    v = version()
    ix = ix or Index.build()
    items = assess(paths, ix, key)
    if artifact_uri is None:
        first = next((p for p in paths if not isinstance(p, (dict, list))), None)
        artifact_uri = pathlib.Path(first).as_posix() if first else "compliance_report.json"
    rules, idx, worst = [], {}, {}

    def ri(rule):
        if rule.id not in idx:
            idx[rule.id] = len(rules); rules.append(sarif_rule(rule, v))
        return idx[rule.id]
    if all_rules:
        for rule in sorted(ix.controls.values(), key=lambda r: r.id):
            ri(rule)
    results = []

    def emit(a, text, kind, level):
        fp = hashlib.sha256(f"{a.rule.id}\n{text}\n{subject or ''}".encode()).hexdigest()[:32]
        props = {"framework": a.rule.framework, "control": a.rule.label, "mapped": a.rule.mapped, "report": a.report_path,
                 "severity": a.severity, "status": a.status if a.row_id else None, "basis": a.basis, "subject": subject}
        results.append({"ruleId": a.rule.id, "ruleIndex": ri(a.rule), "level": level, "kind": kind,
                        "message": {"text": text},
                        "locations": [{"physicalLocation": {"artifactLocation": {"uri": artifact_uri}, "region": {"startLine": 1}},
                                       "logicalLocations": [{"name": a.package, "kind": "module", "fullyQualifiedName": f"data.{a.package}"}]}],
                        "partialFingerprints": {"controlFinding/v1": fp},
                        "properties": {k: x for k, x in props.items() if x is not None}})
        if kind == "fail" and a.severity:
            worst[a.rule.id] = max(worst.get(a.rule.id, level), level, key=RANK.get)

    seen = set()
    for a in items:
        if a.satisfied or a.status == "not_applicable":
            if include_pass and (a.rule.id, a.status) not in seen:
                seen.add((a.rule.id, a.status))
                emit(a, f"{a.rule.label}: {a.status} ({a.basis or 'evidence'})", "pass" if a.satisfied else "notApplicable", "none")
            continue
        texts = a.messages or [f"{a.rule.label}: {a.status} ({a.basis or 'evidence'})"]
        for t in texts:
            emit(a, t, "fail", level_for(a))
    # report order: violations in the order the report lists them (the OCSF events follow the same order), then the
    # results that come only from control_results rows
    order = {}
    for rpath, rep in load_reports(paths, key):
        viol = rep["violations"]
        for m in (list(viol.values()) if isinstance(viol, dict) else list(viol)):
            order.setdefault((rpath, finding_text(m)), len(order))
    results.sort(key=lambda r: order.get((r["properties"]["report"], r["message"]["text"]), len(order)))
    for rid, lvl in worst.items():
        rules[idx[rid]]["properties"]["security-severity"] = SEC_SEV[lvl]
        rules[idx[rid]]["defaultConfiguration"]["level"] = lvl
    fails = [r for r in results if r["kind"] == "fail"]
    reports = sorted({a.report_path for a in items})
    run = {"tool": {"driver": {"name": "Rego Policy Libraries", "semanticVersion": v, "version": v, "informationUri": REPO,
                               "organization": "ynotbhatc", "rules": rules}},
           "automationDetails": {"id": f"rego_policy_libraries/{key or '+'.join(sorted({a.package for a in items})) or 'report'}/{subject or 'unspecified'}/"},
           "originalUriBaseIds": {"REPO": {"uri": RAW.format(v=v)}},
           "invocations": [{"executionSuccessful": True}],
           "results": results,
           "properties": {"reports": reports, "violations": len(fails),
                          "mapped": sum(1 for r in fails if r["properties"]["mapped"]), "unmapped": sum(1 for r in fails if not r["properties"]["mapped"]),
                          "passes": sum(1 for r in results if r["kind"] == "pass"),
                          "generator": "converters/exports/sarif/build.py", "authoredWith": "Claude (Anthropic)"}}
    if key:
        run["properties"]["frameworkKey"] = key
    return {"$schema": "https://json.schemastore.org/sarif-2.1.0.json", "version": "2.1.0", "runs": [run]}


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("reports", nargs="+", help="compliance_report JSON: opa eval -f json output, an OPA REST response or a bare report")
    ap.add_argument("-o", "--out", default="-")
    ap.add_argument("--key", default=None, help="framework key (data.<key>.main.compliance_report); required for REST and bare reports")
    ap.add_argument("--subject", default=None, help="what was assessed (host, account, cluster); part of fingerprints and the category")
    ap.add_argument("--artifact-uri", default=None, help="repository-relative file the results are reported against (default: the first input path)")
    ap.add_argument("--include-pass", action="store_true", help="also emit control_results pass / not_applicable rows (level none)")
    ap.add_argument("--all-rules", action="store_true", help="embed every catalog control as a rule, not only those with results")
    ap.add_argument("--validate", action="store_true", help="validate against the vendored SARIF 2.1.0 schema; exit 1 if invalid")
    a = ap.parse_args()
    doc = build(a.reports, a.all_rules, a.key, a.subject, a.artifact_uri, a.include_pass)
    p = doc["runs"][0]["properties"]
    if not p["reports"]:
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
        print(f"sarif: {p['violations']} results ({p['mapped']} mapped to controls, {p['unmapped']} unmapped), {p['passes']} pass, "
              f"{len(doc['runs'][0]['tool']['driver']['rules'])} rules{', schema-valid' if a.validate else ''} -> {a.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
