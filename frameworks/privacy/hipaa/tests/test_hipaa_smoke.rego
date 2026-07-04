# Phase 1 contract smoke test — HIPAA full compliance report.
# Contract: the report entrypoint must return a well-formed, non-empty object
# on empty input (never the undefined -> {} collapse).
package hipaa.main_test

import rego.v1

import data.hipaa.main as pkg

test_report_wellformed_on_empty_input if {
	report := pkg.report with input as {}
	is_object(report)
	count(report) > 0
}
