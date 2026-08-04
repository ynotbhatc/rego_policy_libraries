package cis_ubuntu_2404.main

# Bridge: expose cis_ubuntu_24_04 under the /v1/data/<framework>/main/compliance_report
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

# PROVENANCE: this policy set is DERIVED — its controls are a copy of
# CIS Ubuntu Linux 22.04 LTS Benchmark v3.0.0, relabelled for Ubuntu 24.04 LTS. There is no
# Ubuntu 24.04 LTS-specific CIS benchmark implemented here. The report therefore
# publishes the version of the benchmark it ACTUALLY implements, plus
# derived/derived_from/applied_to so consumers can detect this.
# See README.md in this directory.

import rego.v1
import data.cis_ubuntu_24_04 as bench

default _compliant := false

_compliant := bench.compliant

default _section_percentage := 0

_section_percentage := bench.compliance_percentage

default _violations := []

_violations := [v | some v in bench.violations]

default _sections := {}

_sections := bench.module_status

_total_controls := 188

_failed := count(_violations)

# Clamp: more violations than known controls must not yield a negative count.
_passed := max([0, _total_controls - _failed])

default _percentage := 0

_percentage := round((_passed * 100000) / _total_controls) / 1000 if _total_controls > 0

compliance_report := {
	"framework": "cis_ubuntu_2404",
	"benchmark": "DERIVED from CIS Ubuntu Linux 22.04 LTS Benchmark v3.0.0 — applied to Ubuntu 24.04 LTS (provenance: see README)",
	"version": "v3.0.0",
	"derived": true,
	"derived_from": "CIS Ubuntu Linux 22.04 LTS Benchmark v3.0.0",
	"applied_to": "Ubuntu 24.04 LTS",
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
