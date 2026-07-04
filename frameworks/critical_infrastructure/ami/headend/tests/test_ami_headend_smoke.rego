# Phase 1 contract smoke test — AMI headend security aggregate report.
# Contract: data.ami.headend.security.compliance_report must return a
# well-formed, non-empty object on empty input (never undefined -> {}).
package ami.headend.security_test

import rego.v1

import data.ami.headend.security

test_report_wellformed_on_empty_input if {
	result := security.compliance_report with input as {}
	is_object(result)
	count(result) > 0
	is_boolean(result.compliant)
}
