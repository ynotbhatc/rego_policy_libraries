#!/usr/bin/env bash
# Proves the sample still evaluates the way examples/nist_800_53/README.md says it does.
#   bash examples/nist_800_53/check.sh   (run from anywhere; needs opa and python3; exits non-zero on any drift)
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root="$(cd "$here/../.." && pwd)"
nist="$root/frameworks/federal/nist/sp_800_53"

# 1. The Access Control family on its own.
opa eval -d "$nist/access_control" -i "$here/facts.json" -f json 'data.nist.sp800_53.access_control.compliance_report' |
python3 -c '
import json, sys
result = json.load(sys.stdin).get("result")
if not result:
    sys.exit("FAIL: nist.sp800_53.access_control.compliance_report is undefined")
r = result[0]["expressions"][0]["value"]
want = sorted(["AC-2(3)", "AC-6(7)", "AC-7", "AC-11", "AC-17(3)"])
got = sorted(v.split(":")[0].removeprefix("NIST ") for v in r.get("violations", []))
problems = [f"{k}: got {r.get(k)!r}, expected {w!r}" for k, w in
            (("compliant", False), ("controls_evaluated", 59), ("violation_count", 5)) if r.get(k) != w]
if got != want:
    problems.append(f"failing ids: got {got}, expected {want}")
if any("evidence missing" in v for v in r.get("violations", [])):
    problems.append("an AC finding says evidence missing; the sample supplies every AC fact")
if problems:
    sys.exit("FAIL (AC family): " + "; ".join(problems))
print("ok: AC family: 5 of 59 controls fail, no evidence missing")
'

# 2. The framework key on the same input: AC is assessed, the other 19 families have no facts.
opa eval -d "$nist" -i "$here/facts.json" -f json 'data.nist_800_53.main.compliance_report' |
python3 -c '
import json, sys
result = json.load(sys.stdin).get("result")
if not result:
    sys.exit("FAIL: nist_800_53.main.compliance_report is undefined")
r = result[0]["expressions"][0]["value"]
problems = []
def expect(label, got, want):
    if got != want:
        problems.append(f"{label}: got {got!r}, expected {want!r}")
expect("compliant", r.get("compliant"), False)
expect("assessed_at", r.get("assessed_at"), "2026-11-20")
expect("total_controls", r.get("total_controls"), 523)
expect("failed_controls", r.get("failed_controls"), 469)
expect("violation_count", r.get("violation_count"), 469)
expect("control_result_counts", r.get("control_result_counts"),
       {"pass": 54, "fail": 5, "evidence_missing": 416, "not_attested": 48})
expect("AC family summary", r.get("family_summary", {}).get("AC"), {"compliant": False, "violations": 5})
fails = sorted(c["id"] for c in r.get("control_results", []) if c.get("status") == "fail")
expect("ids with status fail", fails, sorted(["AC-2(3)", "AC-6(7)", "AC-7", "AC-11", "AC-17(3)"]))
passes = {c["id"].split("(")[0].split("-")[0] for c in r.get("control_results", []) if c.get("status") == "pass"}
expect("families with a passing control", passes, {"AC"})
if problems:
    sys.exit("FAIL (nist_800_53 key): examples/nist_800_53/facts.json no longer gives the documented result\n  " + "\n  ".join(problems))
print("ok: nist_800_53: 54 pass, 5 fail, 416 evidence missing, 48 not attested of 523")
'
