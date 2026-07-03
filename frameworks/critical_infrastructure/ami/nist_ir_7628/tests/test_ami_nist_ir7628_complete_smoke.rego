# Phase 1 contract smoke test — AMI NIST IR 7628 complete assessment.
# Contract: data.ami.nist_ir7628.complete.compliance_assessment must return a
# well-formed, non-empty object on empty input (never undefined -> {}).
package ami.nist_ir7628.complete_test

import rego.v1

import data.ami.nist_ir7628.complete

test_report_wellformed_on_empty_input if {
	result := complete.compliance_assessment with input as {}
	is_object(result)
	count(result) > 0
}
