package cis_rocky_linux_9_test

import rego.v1

import data.cis_rocky_linux_9

# Phase 1 contract smoke test.
# Proves the live orchestrator endpoint returns a well-formed report object on
# empty input, never the `undefined -> {}` collapse.
# Entrypoint: data.cis_rocky_linux_9.compliance_assessment
test_report_wellformed_on_empty_input if {
	report := cis_rocky_linux_9.compliance_assessment with input as {}
	is_object(report)
	count(report) > 0
}
