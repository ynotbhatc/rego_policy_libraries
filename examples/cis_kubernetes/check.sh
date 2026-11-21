#!/usr/bin/env bash
# Proves the sample still evaluates the way examples/cis_kubernetes/README.md says it does.
#   bash examples/cis_kubernetes/check.sh        (run from anywhere; needs opa and python3; exits non-zero on any drift)
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root="$(cd "$here/../.." && pwd)"
opa eval -d "$root/benchmarks/cis/kubernetes" -i "$here/facts.json" -f json 'data.cis_kubernetes.main.compliance_report' |
python3 -c '
import json, sys

EXPECTED_TOTAL = 134
EXPECTED_FAILING = "1.1.13 1.2.15 1.4.1 1.4.2 4.2.4 5.3.2 5.4.1".split()
EXPECTED_EVIDENCE_MISSING = ["1.4.1", "1.4.2"]

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
expect("facts_supplied", r.get("facts_supplied"), True)
expect("total_controls", r.get("total_controls"), EXPECTED_TOTAL)
expect("failed_controls", r.get("failed_controls"), len(EXPECTED_FAILING))
expect("passed_controls", r.get("passed_controls"), EXPECTED_TOTAL - len(EXPECTED_FAILING))
expect("evidence-missing controls", sorted(x.split(":")[0] for x in v if "evidence missing" in x), EXPECTED_EVIDENCE_MISSING)
expect("fail-closed notices", [x for x in v if x.startswith("FAIL-CLOSED")], [])
expect("failing controls", sorted({x.split(":")[0] for x in v}), sorted(EXPECTED_FAILING))
if problems:
    sys.exit("FAIL: examples/cis_kubernetes/facts.json no longer gives the documented result\n  " + "\n  ".join(problems))
print("ok: compliant=false, %d of %d controls fail, %d evidence missing" % (r["failed_controls"], r["total_controls"], len(EXPECTED_EVIDENCE_MISSING)))
'
