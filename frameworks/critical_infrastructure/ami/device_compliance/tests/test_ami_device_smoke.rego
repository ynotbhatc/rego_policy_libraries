# Phase 1 contract smoke test — AMI device compliance aggregate report.
# Contract: data.ami.device.compliance.compliance_report must return a
# well-formed, non-empty object on empty input (never undefined -> {}).
package ami.device.compliance_test

import rego.v1

import data.ami.device.compliance

test_report_wellformed_on_empty_input if {
	result := compliance.compliance_report with input as {}
	is_object(result)
	count(result) > 0
	is_boolean(result.compliant)
}
