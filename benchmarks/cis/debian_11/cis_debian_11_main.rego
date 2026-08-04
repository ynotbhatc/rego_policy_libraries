package cis_debian_11.main

# Bridge: expose cis_debian_11 under the /v1/data/<framework>/main/compliance_report
# convention consumed by the Generic Framework Assessment playbook
# (compliance repo, ansible/playbooks/generic_framework_assessment.yml).
#
# Two deliberate choices here:
#
# 1. Every field is sourced through a DEFAULTED local helper. An undefined
#    field inside an object literal makes the whole object undefined, which
#    OPA returns as {} — a silently empty compliance result rather than an
#    error. See library rule #5 in CLAUDE.md.
#
# 2. total_controls is the number of DISTINCT CIS control IDs this policy set
#    actually evaluates (counted from the violation messages), NOT the size of
#    the published CIS benchmark. Reporting the benchmark's headline number
#    would overstate coverage. See "controls_basis" in the report.

import rego.v1
import data.cis_debian_11 as bench

default _compliant := false

_compliant := bench.compliant

default _section_percentage := 0

_section_percentage := bench.compliance_percentage

default _violations := []

_violations := [v | some v in bench.violations]

default _sections := {}

_sections := bench.module_status

_total_controls := 163

_failed := count(_violations)

# Clamp: more violations than known controls must not yield a negative count.
_passed := max([0, _total_controls - _failed])

default _percentage := 0

_percentage := round((_passed * 100000) / _total_controls) / 1000 if _total_controls > 0

compliance_report := {
	"framework": "cis_debian_11",
	"benchmark": "CIS Debian Linux 11 Benchmark v2.0.0",
	"version": "v2.0.0",
	"total_controls": _total_controls,
	"controls_basis": "distinct CIS control IDs evaluated by this policy set",
	"passed_controls": _passed,
	"failed_controls": _failed,
	"compliance_percentage": _percentage,
	"section_compliance_percentage": _section_percentage,
	"compliant": _compliant,
	"violations": _violations,
	"section_results": _sections,
}
