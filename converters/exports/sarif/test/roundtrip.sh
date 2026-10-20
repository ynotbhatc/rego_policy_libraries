#!/usr/bin/env bash
# Round-trip for the SARIF export (CONTRACT.md): evaluate two real modules on empty input (fail-closed, so
# every section reports), convert, prove result count == violation count and every result names a rule that
# exists, then validate against the SARIF 2.1.0 schema. SKIP only when jsonschema is missing; CI fails on SKIP.
set -euo pipefail
HERE="$(cd "$(dirname "$0")/.." && pwd)"; ROOT="$(cd "$HERE/../../.." && pwd)"
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
echo '{}' > "$TMP/empty.json"
opa eval -f json -d "$ROOT/benchmarks/cis/rhel_9" -i "$TMP/empty.json" 'data.cis_rhel9.main.compliance_report' > "$TMP/cis.json"
opa eval -f json -d "$ROOT/frameworks/privacy/ccpa" -i "$TMP/empty.json" 'data.ccpa' > "$TMP/ccpa.json"
# a STIG module: its violations are objects ({vuln_id, stig_id, severity, rule_title, status}), not strings
opa eval -f json -d "$ROOT/benchmarks/stig/oracle_linux_9" -i "$TMP/empty.json" 'data.stig.oracle_linux_9.main.compliance_report' > "$TMP/stig.json"
python3 "$HERE/build.py" "$TMP/cis.json" "$TMP/ccpa.json" "$TMP/stig.json" -o "$TMP/out.sarif" >/dev/null
python3 - "$TMP" <<'PY'
import sys, json, pathlib
tmp = pathlib.Path(sys.argv[1])
def count(doc):
    n = 0
    def walk(x):
        nonlocal n
        if isinstance(x, dict):
            if "violations" in x and any(k in x for k in ("compliant", "violation_count", "failed_controls", "overall_compliant")):
                v = x["violations"]; n += len(v); return
            for y in x.values(): walk(y)
        elif isinstance(x, list):
            for y in x: walk(y)
    walk(doc["result"][0]["expressions"][0]["value"]); return n
want = sum(count(json.loads((tmp / f).read_text())) for f in ("cis.json", "ccpa.json", "stig.json"))
run = json.loads((tmp / "out.sarif").read_text())["runs"][0]
rules = {r["id"]: r for r in run["tool"]["driver"]["rules"]}
assert len(run["results"]) == want, f"{len(run['results'])} results for {want} violations"
assert want > 50, "fixture produced suspiciously few violations"
for r in run["results"]:
    assert r["ruleId"] in rules and run["tool"]["driver"]["rules"][r["ruleIndex"]]["id"] == r["ruleId"], r["ruleId"]
    assert r["message"]["text"], "empty message"
mapped = sum(1 for r in run["results"] if r["properties"]["mapped"])
assert mapped / want >= 0.6, f"only {mapped}/{want} results mapped to inventory controls"
cis = [r for r in run["results"] if r["ruleId"] == "cis_rhel_9-6.3.1"]
assert cis and "aide" in cis[0]["message"]["text"].lower(), "CIS RHEL 9 6.3.1 did not round-trip under its OSCAL id"
stig = [r for r in run["results"] if r["ruleId"] == "stig_oracle_linux_9-OL09-00-002413"]
assert stig and "Ctrl-Alt-Delete" in stig[0]["message"]["text"] and stig[0]["properties"]["mapped"], "STIG object finding did not map to its catalog control"
assert stig[0]["properties"]["severity"] == "CAT I", "STIG finding lost its severity"
assert "Ctrl-Alt-Delete" in rules[stig[0]["ruleId"]]["shortDescription"]["text"], "STIG rule text is not the DISA rule title"
unm = [r for r in run["results"] if r["properties"]["report"] == "stig.oracle_linux_9.main" and not r["properties"]["mapped"]]
assert len(unm) == 1 and "FAIL-CLOSED" in unm[0]["message"]["text"], "only the fail-closed notice may be unmapped for a STIG module"
print(f"PASS roundtrip: {want} violations -> {len(run['results'])} results, {mapped} mapped to controls, {len(rules)} rules, ids match the OSCAL catalog")
PY
out="$(python3 "$HERE/validate.py" "$TMP/out.sarif" 2>&1 || true)"
if [[ "$out" == *SKIP* ]]; then echo "SKIP schema validation: jsonschema not installed"; exit 0; fi
if [[ "$out" == *FAIL* ]]; then printf '%s\n' "$out" | sed -n '1,20p'; exit 1; fi
echo "PASS schema: SARIF 2.1.0"
