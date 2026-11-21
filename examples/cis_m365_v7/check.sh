#!/usr/bin/env bash
# Proves the sample still evaluates the way examples/cis_m365_v7/README.md says it does.
#   bash examples/cis_m365_v7/check.sh   (run from anywhere; needs opa and python3; exits non-zero on any drift)
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root="$(cd "$here/../.." && pwd)"
opa eval -d "$root/benchmarks/cis/saas/m365_v7" --ignore tests -i "$here/facts.json" -f json \
  'data.cis_m365_v7.main.compliance_report' |
python3 -c '
import json, sys

EXPECTED_TOTAL = 160
EXPECTED_EVALUATED = 144
EXPECTED_FAILING = "2.1.9 5.2.2.3 6.5.4 7.2.3 7.2.6 8.5.1".split()

result = json.load(sys.stdin).get("result")
if not result:
    sys.exit("FAIL: compliance_report is undefined")
r = result[0]["expressions"][0]["value"]
v = r.get("violations", [])
counts = r.get("control_result_counts", {})
problems = []
def expect(label, got, want):
    if got != want:
        problems.append(f"{label}: got {got!r}, expected {want!r}")
expect("assessed_controls_compliant", r.get("assessed_controls_compliant"), False)
expect("total_controls", r.get("total_controls"), EXPECTED_TOTAL)
expect("controls_evaluated", r.get("controls_evaluated"), EXPECTED_EVALUATED)
expect("failed_controls", r.get("failed_controls"), len(EXPECTED_FAILING))
expect("pass", counts.get("pass"), EXPECTED_TOTAL - len(EXPECTED_FAILING))
expect("evidence_missing", counts.get("evidence_missing"), 0)
expect("not_attested", counts.get("not_attested"), 0)
expect("passes by attestation", sum(1 for c in r.get("control_results", []) if c.get("status") == "pass" and c.get("basis") == "attestation"), 16)
expect("sections_not_evaluated", r.get("sections_not_evaluated"), [])
expect("evidence-missing findings", [x for x in v if "evidence missing" in x], [])
expect("failing controls", sorted(x.split(":")[0].removeprefix("CIS ") for x in v), sorted(EXPECTED_FAILING))
if problems:
    sys.exit("FAIL: examples/cis_m365_v7/facts.json no longer gives the documented result\n  " + "\n  ".join(problems))
print("ok: assessed_controls_compliant=false, %d of %d controls fail, no evidence missing" % (r["failed_controls"], r["total_controls"]))
'
