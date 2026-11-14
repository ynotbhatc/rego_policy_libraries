#!/usr/bin/env bash
# Proves the sample still evaluates the way examples/rhel9/README.md and the top-level README say it does.
#   bash examples/rhel9/check.sh        (run from anywhere; needs opa and python3; exits non-zero on any drift)
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root="$(cd "$here/../.." && pwd)"
opa eval -d "$root/benchmarks/cis/rhel_9" -i "$here/facts.json" -f json 'data.cis_rhel9.main.compliance_report' |
python3 -c '
import json, sys

EXPECTED_TOTAL = 352
EXPECTED_FAILING = """1.1.2.2.4 1.4.1 1.5.7 1.7.2 2.1.12 2.1.18 2.4.1.2 3.3.1.16 3.3.1.17 4.1.10 5.1.11 5.1.17 5.1.21
5.2.5 5.3.3.2.2 5.3.3.3.2 5.4.1.1 5.4.3.2 6.2.1.3 6.2.2.2 6.2.3.3 6.2.3.21 6.3.2 7.1.11 7.2.8""".split()

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
expect("profile", r.get("profile"), "level2_server")
expect("total_controls", r.get("total_controls"), EXPECTED_TOTAL)
expect("failed_controls", r.get("failed_controls"), len(EXPECTED_FAILING))
expect("passed_controls", r.get("passed_controls"), EXPECTED_TOTAL - len(EXPECTED_FAILING))
expect("sections_not_assessed", r.get("sections_not_assessed"), [])
expect("evidence-missing findings", [x for x in v if "evidence missing" in x], [])
expect("fail-closed or not-assessed notices", [x for x in v if x.startswith(("FAIL-CLOSED", "NOT ASSESSED"))], [])
expect("failing controls", sorted({x.split(":")[0] for x in v}), sorted(EXPECTED_FAILING))
if problems:
    sys.exit("FAIL: examples/rhel9/facts.json no longer gives the documented result\n  " + "\n  ".join(problems))
print("ok: compliant=false, %d of %d controls fail, no evidence missing" % (r["failed_controls"], r["total_controls"]))
'
