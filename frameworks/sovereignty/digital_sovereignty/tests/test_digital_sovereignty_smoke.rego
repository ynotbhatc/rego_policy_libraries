# Phase 1 contract smoke test — Digital Sovereignty aggregate report.
# Contract: data.digital_sovereignty.main.report must return a well-formed,
# non-empty object on empty input (never undefined -> {}).
package digital_sovereignty.main_test

import rego.v1

import data.digital_sovereignty.main

todo_test_report_wellformed_on_empty_input if {
	result := main.report with input as {}
	is_object(result)
	count(result) > 0
	is_boolean(result.overall_compliant)
}
