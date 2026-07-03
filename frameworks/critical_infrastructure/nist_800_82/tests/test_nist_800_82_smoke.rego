package nist_800_82.main_test

import rego.v1

# Phase 1 contract smoke test.
# Proves data.nist_800_82.main.compliance_report returns a well-formed object
# on empty input — never the Rego v1 "undefined -> {}" collapse.
test_report_wellformed_on_empty_input if {
	report := data.nist_800_82.main.compliance_report with input as {}
	is_object(report)
	count(report) > 0
	is_boolean(report.compliant)
}
