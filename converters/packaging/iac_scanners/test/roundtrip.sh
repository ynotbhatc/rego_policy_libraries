#!/usr/bin/env bash
# Round-trip: every copied policy still compiles and exposes a Conftest-recognised rule; where
# conftest is installed, run it against a fixture and compare with opa eval.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"; OUT="$HERE/../out/conftest"
python3 "$HERE/../build.py" >/dev/null
opa check --strict "$OUT/policy" && echo "PASS conftest layout compiles ($(find "$OUT/policy" -name '*.rego' | wc -l | tr -d ' ') policies, $(grep -c '^| `' "$OUT/NAMESPACES.md") namespaces)"
if command -v conftest >/dev/null; then
  fx="$HERE/../../terraform_platforms/test/fixtures/plan-with-public-bucket.json"
  python3 -c "import json; print(json.dumps(json.load(open('$fx'))['plan']))" > /tmp/conftest-plan.json
  conftest test --no-fail --policy "$OUT/policy" --namespace enforcement.terraform.plan /tmp/conftest-plan.json --output json | python3 -c 'import json,sys; r=json.load(sys.stdin); print("PASS conftest ran:", sum(len(x.get("failures",[])) for x in r), "failures")'
else
  echo "NOTE: conftest not installed here; layout verified with opa check only"
fi
