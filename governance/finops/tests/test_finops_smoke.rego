# Phase 1 contract smoke test — FinOps tagging aggregate compliance report.
# Contract: data.finops.tagging.compliance_report must return a well-formed,
# non-empty object on empty input (never undefined -> {}).
package finops.tagging_test

import rego.v1

import data.finops.tagging

todo_test_report_wellformed_on_empty_input if {
	result := tagging.compliance_report with input as {}
	is_object(result)
	count(result) > 0
	is_boolean(result.compliant)
}
