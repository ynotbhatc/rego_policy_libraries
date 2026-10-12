#!/usr/bin/env bash
# Round-trip for the OCSF export (CONTRACT.md): same evaluations as the SARIF test, one compliance_finding
# per violation, ids equal to the OSCAL/SARIF ids, validated against the vendored class schema. SKIP only
# when jsonschema is missing; CI fails on SKIP. The online check against schema.ocsf.io is opt-in (OCSF_ONLINE=1).
set -euo pipefail
HERE="$(cd "$(dirname "$0")/.." && pwd)"; ROOT="$(cd "$HERE/../../.." && pwd)"
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
echo '{}' > "$TMP/empty.json"
opa eval -f json -d "$ROOT/benchmarks/cis/rhel_9" -i "$TMP/empty.json" 'data.cis_rhel9.main.compliance_report' > "$TMP/cis.json"
opa eval -f json -d "$ROOT/frameworks/privacy/ccpa" -i "$TMP/empty.json" 'data.ccpa' > "$TMP/ccpa.json"
python3 "$HERE/build.py" "$TMP/cis.json" "$TMP/ccpa.json" -o "$TMP/out.ndjson" --time 2026-10-12T00:00:00Z >/dev/null
python3 "$HERE/../sarif/build.py" "$TMP/cis.json" "$TMP/ccpa.json" -o "$TMP/out.sarif" >/dev/null
python3 - "$TMP" <<'PY'
import sys, json, pathlib
tmp = pathlib.Path(sys.argv[1])
evs = [json.loads(l) for l in (tmp / "out.ndjson").read_text().splitlines() if l.strip()]
sarif = json.loads((tmp / "out.sarif").read_text())["runs"][0]["results"]
assert len(evs) == len(sarif) > 50, f"{len(evs)} events vs {len(sarif)} SARIF results"
assert [e["finding_info"]["uid"] for e in evs] == [r["ruleId"] for r in sarif], "OCSF uids differ from SARIF rule ids"
for e in evs:
    assert e["class_uid"] == 2003 and e["type_uid"] == 200301 and e["category_uid"] == 2
    assert e["compliance"]["status_id"] == 3 and e["compliance"]["control"] and e["message"]
    assert "cloud" not in e and "osint" not in e, "profile attributes must not appear without the profile"
    assert e["time"] == 1791763200000, e["time"]  # 2026-10-12T00:00:00Z in ms
print(f"PASS roundtrip: {len(evs)} compliance_finding events, uids identical to the SARIF/OSCAL ids")
PY
python3 "$HERE/build.py" "$TMP/cis.json" -o "$TMP/cloud.ndjson" --time 2026-10-12T00:00:00Z --cloud-provider aws >/dev/null
args=("$TMP/out.ndjson" "$TMP/cloud.ndjson"); [ "${OCSF_ONLINE:-}" = 1 ] && args+=(--online)
out="$(python3 "$HERE/validate.py" "${args[@]}" 2>&1 || true)"
if [[ "$out" == *SKIP* ]]; then echo "SKIP schema validation: jsonschema not installed"; exit 0; fi
if [[ "$out" == *FAIL* ]]; then printf '%s\n' "$out" | sed -n '1,20p'; exit 1; fi
echo "PASS schema: OCSF 1.9.0 compliance_finding${OCSF_ONLINE:+ (+ schema.ocsf.io)}"
