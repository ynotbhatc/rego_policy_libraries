# Phase 1 contract smoke test — NERC CIP aggregate compliance report.
# Contract: data.nerc_cip_main.report must return a well-formed, non-empty
# object on empty input (never the undefined -> {} collapse that consumers
# would receive as a silently-empty report).
package nerc_cip_main_test

import rego.v1

import data.nerc_cip_main

test_report_wellformed_on_empty_input if {
	result := nerc_cip_main.report with input as {}
	is_object(result)
	count(result) > 0
	is_boolean(result.overall_compliant)
}
