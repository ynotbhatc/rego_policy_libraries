package cis_rhel8_test

import rego.v1

import data.cis_rhel8

# Phase 1 contract smoke test.
# Proves the live orchestrator endpoint returns a well-formed report object on
# empty input, never the `undefined -> {}` collapse.
# Entrypoint: data.cis_rhel8.compliance_assessment
test_report_wellformed_on_empty_input if {
	report := cis_rhel8.compliance_assessment with input as {}
	is_object(report)
	count(report) > 0
}
