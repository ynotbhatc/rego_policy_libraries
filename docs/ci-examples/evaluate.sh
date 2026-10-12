#!/usr/bin/env bash
# The exact commands from docs/INTEGRATIONS.md §1, runnable locally and in CI:
#   evaluate.sh <bundle.tar.gz|policy dir> <facts.json> <framework key>   (exit 1 on non-compliance)
set -euo pipefail
src="$1"; facts="$2"; fw="$3"
if [ -f "$src" ]; then load=(-b "$src"); else load=(-d "$src"); fi
opa eval "${load[@]}" -i "$facts" "data.${fw}.main.compliance_report" -f json > report.json
python3 - <<'PY'
import json, sys
r = json.load(open("report.json"))["result"][0]["expressions"][0]["value"]
viol = sorted(r.get("violations", []))
count = r.get("violation_count", r.get("failed_controls", len(viol)))
print(f"compliant={r['compliant']} violations={count}")
for v in viol[:50]:
    print(" -", v)
sys.exit(0 if r["compliant"] else 1)
PY
