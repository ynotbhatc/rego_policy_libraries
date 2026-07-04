# Contract smoke test for the CONSUMER endpoint /v1/data/cis_rhel9/compliance_assessment
package cis_rhel9_consumer_test

import rego.v1

import data.cis_rhel9

test_compliance_assessment_wellformed_on_empty_input if {
	a := cis_rhel9.compliance_assessment with input as {}
	is_object(a)
	is_boolean(a.compliant)
	is_number(a.score)
	is_number(a.violation_count)
}
