#!/usr/bin/env python3
"""Round-trip for the results exports (CONTRACT.md 5) across every framework key, in one process.

    python3 test_results_exports.py <tmp dir> <all-keys opa eval json> <key list json>

1. Every `<key>.main` entrypoint resolves to the framework of the Rego it bridges to (#312 follow-up: bridges such
   as nist_800_53.main -> nist.sp800_53.main), and that framework's files sit in the bridge's directory tree.
2. For every key, the bare compliance_report on empty input becomes SARIF and OSCAL assessment-results through the
   CLIs' build functions with --key: both validate against the vendored schemas, every violation message is a SARIF
   result and an OSCAL observation, nothing is asserted satisfied, and the share of results on catalog controls
   does not regress.
3. A fixture with every control_results status, as a bare report and as an OPA REST response: pass -> satisfied,
   pass contradicted by a violation -> not satisfied, not_applicable -> observation only, unknown status and
   unknown ids -> not satisfied and flagged unmapped.
Exit 0 with a SKIP line when jsonschema is missing; CI fails on SKIP.
"""
import json, sys, pathlib, datetime
HERE = pathlib.Path(__file__).resolve().parent
EXPORTS = HERE.parents[1]
ROOT = EXPORTS.parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import inventory_controls  # noqa: E402

_inv = inventory_controls.inventory(ROOT)          # parse the tree once for every builder below
inventory_controls.inventory = lambda root=None: _inv
for d in ("oscal", "sarif"):
    sys.path.insert(0, str(EXPORTS / d))
sys.path.insert(0, str(EXPORTS))
from _lib.findings import Index, load_reports, finding_text  # noqa: E402
import importlib.util  # noqa: E402


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec); spec.loader.exec_module(mod)
    return mod


oscal_build = load("oscal_build", EXPORTS / "oscal" / "build.py")
ar = load("oscal_ar", EXPORTS / "oscal" / "build_assessment_results.py")
sarif = load("sarif_build", EXPORTS / "sarif" / "build.py")
oscal_val = load("oscal_validate", EXPORTS / "oscal" / "validate.py")
sarif_val = load("sarif_validate", EXPORTS / "sarif" / "validate.py")

tmp, allkeys, keys = pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2]), json.loads(pathlib.Path(sys.argv[3]).read_text())
sys.argv = ["build.py", "--out", str(tmp)]
oscal_build.main()
catalogs = tmp / "catalogs"
ix = Index.build()
WHEN = datetime.datetime(2026, 10, 12, tzinfo=datetime.timezone.utc)
try:
    import jsonschema  # noqa: F401
    VALIDATE = True
except ImportError:
    VALIDATE = False

# 1. bridge resolution
bad = []
for k in keys:
    ents = ix.framework_for(f"{k}.main")
    if not ents:
        bad.append(f"{k}: unresolved"); continue
    d, _ = ix.imports.get(f"{k}.main", ("", []))
    if d and not ents[0]["file"].startswith(d + "/"):
        bad.append(f"{k}: resolved to {ents[0]['framework']} ({ents[0]['file']}), outside {d}/")
assert not bad, "key entrypoints that do not resolve to their own framework:\n  " + "\n  ".join(bad)
nist = ix.framework_for("nist_800_53.main")[0]["framework"]
assert nist == "nist_sp_800_53", nist
assert ix.rule_for("nist_800_53.main", "NIST AC-2: x").id == "nist_sp_800_53-NIST-AC-2", "a NIST key-main finding does not map to its catalog control"
assert ix.rule_for("stig_rhel9.main", "RHEL-09-611165: x").mapped, "a STIG key-main finding does not map to its catalog control"
assert ix.rule_for_row("nist_800_53.main", "AC-2").id == "nist_sp_800_53-NIST-AC-2", "a control_results row under the key path does not resolve"
print(f"PASS key entrypoints: all {len(keys)} <key>.main resolve to their framework (bridges followed through their imports)")

# 2. every key, bare report + --key
values = json.loads(allkeys.read_text())["result"][0]["expressions"][0]["value"]
missing = sorted(set(keys) - set(values))
assert not missing, f"keys without a compliance_report on empty input: {missing}"
tot = {"viol": 0, "mapped": 0, "keys": 0}
problems = []
for k in keys:
    rep = values[k]
    viols = [finding_text(m) for m in (rep["violations"].values() if isinstance(rep["violations"], dict) else rep["violations"])]
    assert [p for p, _ in load_reports([rep], k)][:1] == [f"{k}.main"], f"{k}: bare report not reported under {k}.main"
    s = sarif.build([rep], key=k, subject="roundtrip", ix=ix)
    o, n = ar.build([rep], key=k, subject="roundtrip", when=WHEN, catalogs=catalogs, ix=ix)
    run = s["runs"][0]
    texts = {r["message"]["text"] for r in run["results"]}
    lost = [m for m in viols if m not in texts]
    if lost:
        problems.append(f"{k}: {len(lost)} violations missing from SARIF, e.g. {lost[0][:80]}")
    for r in run["results"]:
        loc = r["locations"][0]
        if not (r["ruleId"] and r["level"] in ("error", "warning", "note") and loc["physicalLocation"]["artifactLocation"]["uri"]):
            problems.append(f"{k}: SARIF result without ruleId/level/physicalLocation"); break
    res = o["assessment-results"]["results"][0]
    obs = {x["description"] for x in res.get("observations", [])}
    lost = [m for m in viols if m not in obs]
    if lost:
        problems.append(f"{k}: {len(lost)} violations missing from OSCAL observations, e.g. {lost[0][:80]}")
    if n["satisfied"]:
        problems.append(f"{k}: empty input asserted {n['satisfied']} controls satisfied")
    if viols and not res.get("findings"):
        problems.append(f"{k}: violations but no OSCAL findings")
    if VALIDATE:
        for label, errs in (("SARIF", sarif_val.validate_doc(s)), ("OSCAL", oscal_val.validate_doc(o))):
            if errs:
                problems.append(f"{k}: {label} schema: {errs[0]}")
    fails = [r for r in run["results"] if r["kind"] == "fail"]
    tot["viol"] += len(fails); tot["mapped"] += sum(1 for r in fails if r["properties"]["mapped"]); tot["keys"] += 1
assert not problems, "\n  ".join([f"{len(problems)} problems:"] + problems[:25])
share = tot["mapped"] / tot["viol"]
assert share >= 0.7, f"only {tot['mapped']}/{tot['viol']} results across all keys map to catalog controls"
print(f"PASS every key: {tot['keys']} keys -> SARIF + OSCAL assessment-results{' (schema-valid)' if VALIDATE else ''}, "
      f"{tot['viol']} results, {tot['mapped']} ({share:.0%}) on catalog controls, no control satisfied on empty input")

# 3. every control_results status
fx = json.loads((HERE / "fixtures" / "nist_800_53_all_statuses.json").read_text())
for shape, doc in (("bare", fx), ("rest", {"result": fx})):
    o, n = ar.build([doc], key="nist_800_53", subject="fixture", when=WHEN, catalogs=catalogs, ix=ix)
    res = o["assessment-results"]["results"][0]
    st = {f["target"]["target-id"]: (f["target"]["status"]["state"], f["target"]["status"].get("reason")) for f in res["findings"]}
    want = {"nist_sp_800_53-NIST-AC-3_stmt": ("satisfied", "pass"),
            "nist_sp_800_53-NIST-AC-2_stmt": ("not-satisfied", "fail"),
            "nist_sp_800_53-NIST-AC-6_stmt": ("not-satisfied", "evidence_missing"),
            "nist_sp_800_53-NIST-AT-2_stmt": ("not-satisfied", "not_attested"),
            "nist_sp_800_53-NIST-AU-2_stmt": ("not-satisfied", "fail"),       # pass row contradicted by a violation
            "nist_sp_800_53-NIST-AC-5_stmt": ("not-satisfied", "waived")}     # unknown status: never satisfied
    for t, s_ in want.items():
        assert st.get(t) == s_, f"{shape}: {t} is {st.get(t)}, want {s_}"
    assert "nist_sp_800_53-NIST-AC-4_stmt" not in st, f"{shape}: not_applicable became a finding"
    assert any(x["title"].startswith("NIST AC-4: not_applicable") for x in res["observations"]), f"{shape}: not_applicable row lost"
    unm = {f["target"]["target-id"]: f for f in res["findings"] if f["target"]["type"] == "statement-id"}
    assert len(unm) == 2 and all(f["target"]["status"]["state"] == "not-satisfied" for f in unm.values()), f"{shape}: unmapped row/violation: {sorted(unm)}"
    assert all(next(p["value"] for p in f["props"] if p["name"] == "control-mapped") == "false" for f in unm.values())
    assert len(res["findings"]) == 8 and n == {"satisfied": 1, "not-satisfied": 7, "not-applicable": 1}, (len(res["findings"]), n)
    ac6 = next(f for f in res["findings"] if f["target"]["target-id"] == "nist_sp_800_53-NIST-AC-6_stmt")
    ac6_obs = {x["uuid"]: x for x in res["observations"]}[ac6["related-observations"][0]["observation-uuid"]]
    assert "least_privilege" in ac6_obs["description"], "a violation for a row's control was not attached to the row"
    at2 = next(x for x in res["observations"] if x["title"].startswith("NIST AT-2"))
    assert at2["methods"] == ["EXAMINE"], "an attestation row must be EXAMINE"
    s = sarif.build([doc], key="nist_800_53", subject="fixture", include_pass=True, ix=ix)
    run = s["runs"][0]
    kinds = {}
    for r in run["results"]:
        kinds.setdefault(r["ruleId"], set()).add((r["kind"], r["level"]))
    assert kinds["nist_sp_800_53-NIST-AC-3"] == {("pass", "none")}, kinds["nist_sp_800_53-NIST-AC-3"]
    assert kinds["nist_sp_800_53-NIST-AC-4"] == {("notApplicable", "none")}
    assert kinds["nist_sp_800_53-NIST-AU-2"] == {("fail", "error")}
    assert kinds["nist_sp_800_53-NIST-AT-2"] == {("fail", "warning")}
    assert kinds["nist_sp_800_53-NIST-AC-6"] == {("fail", "error")}
    assert run["automationDetails"]["id"] == "rego_policy_libraries/nist_800_53/fixture/"
    fps = [r["partialFingerprints"]["controlFinding/v1"] for r in run["results"]]
    assert len(fps) == len(set(fps)), "two results share a fingerprint"
    no_pass = sarif.build([doc], key="nist_800_53", subject="fixture", ix=ix)["runs"][0]["results"]
    assert all(r["kind"] == "fail" for r in no_pass) and len(no_pass) == len(run["results"]) - 2
    if VALIDATE:
        for label, errs in (("SARIF", sarif_val.validate_doc(s)), ("OSCAL", oscal_val.validate_doc(o))):
            assert not errs, f"{shape} fixture {label}: {errs}"
# a STIG severity sets level and security-severity
stig = values["stig_rhel9"]
run = sarif.build([stig], key="stig_rhel9", ix=ix)["runs"][0]
cat1 = [r for r in run["results"] if r["properties"].get("severity") == "CAT I"]
assert cat1 and all(r["level"] == "error" for r in cat1), "STIG CAT I is not level error"
rules = {r["id"]: r for r in run["tool"]["driver"]["rules"]}
assert rules[cat1[0]["ruleId"]]["properties"].get("security-severity") == "8.0", "CAT I rule lacks security-severity"
cat2 = [r for r in run["results"] if r["properties"].get("severity") == "CAT II"]
assert cat2 and all(r["level"] == "warning" for r in cat2), "STIG CAT II is not level warning"
if not VALIDATE:
    print("SKIP schema validation: jsonschema not installed")
print("PASS control_results: every status, bare and REST input, SARIF levels/kinds/fingerprints, STIG severities")
