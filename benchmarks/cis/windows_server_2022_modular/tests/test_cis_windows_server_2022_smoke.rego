package cis_windows_server_2022_test

import rego.v1

import data.cis_windows_server_2022

# Phase 1 contract smoke test.
# Proves the live orchestrator endpoint returns a well-formed compliance
# report object on empty input, never the `undefined -> {}` collapse.
test_report_wellformed_on_empty_input if {
	report := cis_windows_server_2022.compliance_assessment with input as {}
	is_object(report)
	count(report) > 0
}
