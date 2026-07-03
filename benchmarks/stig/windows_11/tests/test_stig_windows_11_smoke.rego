package stig.windows_11_test

import rego.v1
import data.stig.windows_11

# Phase 1 contract smoke test: the primary aggregate report (stig_assessment)
# must return a well-formed object on empty input, never collapse to undefined.
test_report_wellformed_on_empty_input if {
	report := windows_11.stig_assessment with input as {}
	is_object(report)
	count(report) > 0
}
