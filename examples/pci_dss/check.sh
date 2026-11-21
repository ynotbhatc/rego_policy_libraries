#!/usr/bin/env bash
# Proves the sample still evaluates the way examples/pci_dss/README.md says it does.
#   bash examples/pci_dss/check.sh   (run from anywhere; needs opa and python3; exits non-zero on any drift)
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root="$(cd "$here/../.." && pwd)"
opa eval -d "$root/frameworks/financial/pci_dss" -i "$here/facts.json" -f json 'data.pci_dss.main.compliance_report' |
python3 -c '
import json, sys

EXPECTED_FAILING = sorted(["req_8_authentication", "req_10_logging_monitoring", "req_11_security_testing"])
EXPECTED_FALSE_CHECKS = sorted([
    "requirement_8.requirement_8_3.password_requirements",
    "requirement_10.requirement_10_5.retention_12_months",
    "requirement_11.requirement_11_3.internal_scanning",
    "requirement_11.requirement_11_6.payment_page_integrity",
])

result = json.load(sys.stdin).get("result")
if not result:
    sys.exit("FAIL: pci_dss.main.compliance_report is undefined")
r = result[0]["expressions"][0]["value"]
problems = []
def expect(label, got, want):
    if got != want:
        problems.append(f"{label}: got {got!r}, expected {want!r}")
expect("standard", r.get("standard"), "PCI DSS v4.0.1")
expect("compliant", r.get("compliant"), False)
expect("total_controls", r.get("total_controls"), 12)
expect("failed_controls", r.get("failed_controls"), 3)
expect("requirements_passing", r.get("requirements_passing"), 9)
expect("validation_level", r.get("validation_level"), "Level 2")
expect("cde_scope_defined", r.get("compliance_status", {}).get("cde_scope_defined"), True)
expect("failing requirements", sorted(v.get("control") for v in r.get("violations", [])), EXPECTED_FAILING)
expect("fail-closed notices", [v for v in r.get("violations", []) if v.get("control") == "FAIL-CLOSED"], [])
false_checks = []
def walk(o, p):
    for k, v in o.items():
        if isinstance(v, dict):
            walk(v, p + [k])
        elif v is False and k != "overall_compliant":
            false_checks.append(".".join(p + [k]))
walk(r.get("requirement_details", {}), [])
expect("checks that are false", sorted(false_checks), EXPECTED_FALSE_CHECKS)
if problems:
    sys.exit("FAIL: examples/pci_dss/facts.json no longer gives the documented result\n  " + "\n  ".join(problems))
print("ok: compliant=false, 3 of 12 requirements fail (4 checks), CDE scope defined")
'
