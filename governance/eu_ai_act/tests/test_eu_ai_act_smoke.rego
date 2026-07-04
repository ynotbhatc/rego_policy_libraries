# Phase 1 contract smoke test — EU AI Act compliance report.
# Contract: the report entrypoint must return a well-formed, non-empty object
# on empty input (never the undefined -> {} collapse).
package eu_ai_act.main_test

import rego.v1

import data.eu_ai_act.main as pkg

test_report_wellformed_on_empty_input if {
	report := pkg.compliance_report with input as {}
	is_object(report)
	count(report) > 0
}
