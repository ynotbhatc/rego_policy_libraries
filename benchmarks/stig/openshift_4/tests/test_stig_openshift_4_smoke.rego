package stig_openshift_4.main_test

import rego.v1
import data.stig_openshift_4.main

# Phase 1 contract smoke test: the live orchestrator endpoint
# (data.stig_openshift_4.main.compliance_report) must return a well-formed
# object on empty input, never collapse to undefined.
test_report_wellformed_on_empty_input if {
	report := main.compliance_report with input as {}
	is_object(report)
	count(report) > 0
	is_boolean(report.compliant)
}
