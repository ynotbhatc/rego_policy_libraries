# Phase 1 contract smoke test — ISO 27001 compliance report.
# Contract: the report entrypoint must return a well-formed, non-empty object
# on empty input (never the undefined -> {} collapse).
package iso27001_test

import rego.v1

import data.iso27001 as pkg

test_report_wellformed_on_empty_input if {
	report := pkg.iso27001_compliance_report with input as {}
	is_object(report)
	count(report) > 0
}
