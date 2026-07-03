package stig.ubuntu_20_04_test

import rego.v1
import data.stig.ubuntu_20_04

# Phase 1 contract smoke test: the primary aggregate report (stig_assessment)
# must return a well-formed object on empty input, never collapse to undefined.
todo_test_report_wellformed_on_empty_input if {
	report := ubuntu_20_04.stig_assessment with input as {}
	is_object(report)
	count(report) > 0
}
