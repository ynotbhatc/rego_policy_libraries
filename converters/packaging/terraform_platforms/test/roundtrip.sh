#!/usr/bin/env bash
# Round-trip: the TFC adapter on {"plan": P} must report the same violations as the gate on P.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"; ROOT="$(cd "$HERE/../../../.." && pwd)"; OUT="$HERE/../out/policy-set"
python3 "$HERE/../build.py" >/dev/null
fail=0
for fx in "$HERE"/fixtures/*.json; do
  name="$(basename "$fx" .json)"
  a="$(python3 -c "import json; print(json.dumps(json.load(open('$fx'))['plan']))" | opa eval -I -d "$ROOT/enforcement/terraform/terraform_plan_validation.rego" 'data.enforcement.terraform.plan.violation' -f json | python3 -c 'import json,sys; print(sorted(json.load(sys.stdin)["result"][0]["expressions"][0]["value"]))')"
  b="$(opa eval -d "$OUT" -i "$fx" 'data.terraform_cloud.main.violations' -f json | python3 -c 'import json,sys; print(sorted(json.load(sys.stdin)["result"][0]["expressions"][0]["value"]))')"
  if [ "$a" == "$b" ]; then echo "PASS $name ($(echo "$a" | tr -cd ',' | wc -c | tr -d ' ')+ violations)"; else echo "FAIL $name"; echo " gate   : $a"; echo " adapter: $b"; fail=1; fi
done
exit $fail
