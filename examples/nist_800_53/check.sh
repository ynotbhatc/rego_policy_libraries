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
            (("compliant", False), ("controls_evaluated", 60), ("violation_count", 5)) if r.get(k) != w]
if got != want:
    problems.append(f"failing ids: got {got}, expected {want}")
if any("evidence missing" in v for v in r.get("violations", [])):
    problems.append("an AC finding says evidence missing; the sample supplies every AC fact")
if problems:
    sys.exit("FAIL (AC family): " + "; ".join(problems))
print("ok: AC family: 5 of 60 controls fail, no evidence missing")
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
expect("total_controls", r.get("total_controls"), 544)
expect("failed_controls", r.get("failed_controls"), 489)
expect("violation_count", r.get("violation_count"), 489)
expect("control_result_counts", r.get("control_result_counts"),
       {"pass": 55, "fail": 5, "evidence_missing": 418, "not_attested": 66})
expect("AC family summary", r.get("family_summary", {}).get("AC"), {"compliant": False, "violations": 5})
fails = sorted(c["id"] for c in r.get("control_results", []) if c.get("status") == "fail")
expect("ids with status fail", fails, sorted(["AC-2(3)", "AC-6(7)", "AC-7", "AC-11", "AC-17(3)"]))
passes = {c["id"].split("(")[0].split("-")[0] for c in r.get("control_results", []) if c.get("status") == "pass"}
expect("families with a passing control", passes, {"AC"})
if problems:
    sys.exit("FAIL (nist_800_53 key): examples/nist_800_53/facts.json no longer gives the documented result\n  " + "\n  ".join(problems))
print("ok: nist_800_53: 55 pass, 5 fail, 418 evidence missing, 66 not attested of 544")
'

# 3. The same facts plus benchmark results (benchmark_findings.json), with the crosswalk spine loaded: the
#    benchmark gap fails AC-8 over its declared evidence, and the satisfied verdict on AC-7 passes nothing.
python3 -c '
import json, sys
facts = json.load(open(sys.argv[1])); facts.update(json.load(open(sys.argv[2]))); json.dump(facts, sys.stdout)
' "$here/facts.json" "$here/benchmark_findings.json" |
opa eval -d "$nist" -d "$root/crosswalk/correlation.rego" \
  -d "crosswalk.stig_800_53:$root/crosswalk/stig_800_53/data.json" -I -f json 'data.nist_800_53.main.compliance_report' |
python3 -c '
import json, sys
result = json.load(sys.stdin).get("result")
if not result:
    sys.exit("FAIL: nist_800_53.main.compliance_report is undefined with benchmark results")
r = result[0]["expressions"][0]["value"]
b = r.get("benchmark_evidence", {})
rows = {c["id"]: c for c in r.get("control_results", [])}
problems = []
def expect(label, got, want):
    if got != want:
        problems.append(f"{label}: got {got!r}, expected {want!r}")
expect("spine_loaded", b.get("spine_loaded"), True)
expect("benchmark satisfied", b.get("satisfied"), ["AC-7"])
expect("benchmark gap", b.get("gap"), ["AC-8"])
expect("unmapped_rules", b.get("unmapped_rules"), ["EXAMPLE-00-000001"])
expect("control_result_counts", r.get("control_result_counts"),
       {"pass": 54, "fail": 6, "evidence_missing": 418, "not_attested": 66})
expect("AC-8 status", rows.get("AC-8", {}).get("status"), "fail")
expect("AC-8 open rules", rows.get("AC-8", {}).get("benchmark", {}).get("open_rules"), ["RHEL-09-211020"])
expect("AC-7 status", rows.get("AC-7", {}).get("status"), "fail")
expect("AC-7 benchmark", rows.get("AC-7", {}).get("benchmark", {}).get("status"), "satisfied")
expect("AC-2(1) benchmark", rows.get("AC-2(1)", {}).get("benchmark", {}).get("status"), "not_evaluated")
if problems:
    sys.exit("FAIL (nist_800_53 with benchmark results): examples/nist_800_53 no longer gives the documented result\n  " + "\n  ".join(problems))
print("ok: nist_800_53 with benchmark results: AC-8 fails on the benchmark gap, AC-7 satisfied by the benchmark and still failing on its own evidence")
'
