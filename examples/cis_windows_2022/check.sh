#!/usr/bin/env bash
# Proves the sample still evaluates the way examples/cis_windows_2022/README.md says it does.
#   bash examples/cis_windows_2022/check.sh   (run from anywhere; needs opa and python3; exits non-zero on any drift)
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root="$(cd "$here/../.." && pwd)"
opa eval -d "$root/benchmarks/cis/windows_server_2022_modular" --ignore tests -i "$here/facts.json" -f json \
  'data.cis_windows_2022.main.compliance_report' |
python3 -c '
import json, sys

EXPECTED_TOTAL = 378
EXPECTED_FAILING = "1.1.4 1.2.2 9.3.1 18.10.26.2.2 18.10.57.3.9.1".split()

result = json.load(sys.stdin).get("result")
if not result:
    sys.exit("FAIL: compliance_report is undefined")
r = result[0]["expressions"][0]["value"]
v = r.get("violations", [])
problems = []
def expect(label, got, want):
    if got != want:
        problems.append(f"{label}: got {got!r}, expected {want!r}")
expect("compliant", r.get("compliant"), False)
expect("role", r.get("profile", {}).get("role"), "member_server")
expect("level", r.get("profile", {}).get("level"), 2)
expect("total_controls", r.get("total_controls"), EXPECTED_TOTAL)
expect("failed_controls", r.get("failed_controls"), len(EXPECTED_FAILING))
expect("passed_controls", r.get("passed_controls"), EXPECTED_TOTAL - len(EXPECTED_FAILING))
expect("not_assessed_controls", r.get("not_assessed_controls"), 0)
expect("sections_not_assessed", r.get("sections_not_assessed"), [])
expect("evidence missing", r.get("control_result_counts", {}).get("evidence_missing"), 0)
expect("evidence-missing findings", [x for x in v if "evidence missing" in x], [])
expect("failing controls", sorted(x.split(":")[0].removeprefix("CIS ") for x in v), sorted(EXPECTED_FAILING))
if problems:
    sys.exit("FAIL: examples/cis_windows_2022/facts.json no longer gives the documented result\n  " + "\n  ".join(problems))
print("ok: compliant=false, %d of %d controls fail, no evidence missing" % (r["failed_controls"], r["total_controls"]))
'
