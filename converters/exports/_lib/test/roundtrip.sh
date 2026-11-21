#!/usr/bin/env bash
# Round-trip for the results exports (SARIF, OSCAL assessment-results) over every framework key: one opa eval of
# data.<key>.main.compliance_report for all keys on empty input, then test_results_exports.py (bridge resolution,
# per-key SARIF + OSCAL build and schema validation, every control_results status). SKIP when jsonschema is
# missing; CI fails on SKIP.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"; ROOT="$(cd "$HERE/../../../.." && pwd)"
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
python3 - "$ROOT" > "$TMP/keys.json" <<'PY'
import re, json, sys, pathlib
src = (pathlib.Path(sys.argv[1]) / "tests" / "framework_keys" / "test_keys.rego").read_text()
print(json.dumps(sorted(re.findall(r'"([a-z0-9_]+)"', src.split("keys := {", 1)[1].split("}", 1)[0]))))
PY
echo '{}' > "$TMP/empty.json"
( cd "$ROOT" && opa eval -f json --ignore .github --ignore converters --ignore tests -d . -i "$TMP/empty.json" \
    "{k: data[k].main.compliance_report | some k in $(cat "$TMP/keys.json")}" ) > "$TMP/allkeys.json"
python3 "$HERE/test_results_exports.py" "$TMP" "$TMP/allkeys.json" "$TMP/keys.json"
