package cis.rhel_10_test

import rego.v1

import data.cis.rhel_10

# Phase 1 contract smoke test.
# Proves the live orchestrator endpoint returns a well-formed report object on
# empty input, never the `undefined -> {}` collapse.
# Entrypoint: data.cis.rhel_10.compliance_summary
test_report_wellformed_on_empty_input if {
	report := rhel_10.compliance_summary with input as {}
	is_object(report)
	count(report) > 0
}
