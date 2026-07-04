package cis_rhel9_test

import rego.v1

import data.cis_rhel9

# Phase 1 contract smoke test.
# Proves the live orchestrator endpoint returns a well-formed report object on
# empty input, never the `undefined -> {}` collapse.
# Entrypoint: data.cis_rhel9.executive_summary
# (data.cis_rhel9.main.compliance_report is the fail-silent collapse endpoint —
#  it returns {} on empty input, so it is intentionally NOT tested here.)
test_report_wellformed_on_empty_input if {
	report := cis_rhel9.executive_summary with input as {}
	is_object(report)
	count(report) > 0
}
