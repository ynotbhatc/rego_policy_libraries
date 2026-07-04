package cis.postgresql_14_test

import rego.v1

import data.cis.postgresql_14 as pkg

# Phase 1 contract smoke test: the report must be a well-formed object with a
# boolean 'compliant' field even on empty input — never the undefined -> {} collapse.
test_report_wellformed_on_empty_input if {
	report := pkg.compliance_report with input as {}
	is_object(report)
	count(report) > 0
	is_boolean(report.compliant)
}
