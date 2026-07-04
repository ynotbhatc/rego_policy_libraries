# Phase 1 contract smoke test — NERC CIP-015 INSM aggregate report.
# Contract: data.nerc_cip_cip015.cip_015_compliance_report must return a
# well-formed, non-empty object on empty input (never undefined -> {}).
package nerc_cip_cip015_test

import rego.v1

import data.nerc_cip_cip015

test_report_wellformed_on_empty_input if {
	result := nerc_cip_cip015.cip_015_compliance_report with input as {}
	is_object(result)
	count(result) > 0
	is_boolean(result.compliant)
}
