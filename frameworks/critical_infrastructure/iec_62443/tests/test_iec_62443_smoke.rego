# Phase 1 contract smoke test — IEC 62443 aggregate compliance report.
# Contract: data.iec_62443_main.iec_62443_compliance_report must return a
# well-formed, non-empty object on empty input (never undefined -> {}).
package iec_62443_main_test

import rego.v1

import data.iec_62443_main

test_report_wellformed_on_empty_input if {
	result := iec_62443_main.iec_62443_compliance_report with input as {}
	is_object(result)
	count(result) > 0
	is_boolean(result.compliant)
}
