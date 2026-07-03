# Phase 1 contract smoke test — proves the .main orchestrator's compliance_report
# returns a well-formed object on empty input (never the undefined -> {} collapse).
package csa_ccm.main_test

import rego.v1

import data.csa_ccm.main

test_report_wellformed_on_empty_input if {
	report := main.compliance_report with input as {}
	is_object(report)
	count(report) > 0
	is_boolean(report.compliant)
}
