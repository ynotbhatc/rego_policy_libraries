# Contract smoke test for the CONSUMER endpoint /v1/data/soc2/soc2_assessment
package soc2_consumer_test

import rego.v1

import data.soc2

test_soc2_assessment_wellformed_on_empty_input if {
	a := soc2.soc2_assessment with input as {}
	is_object(a)
	is_boolean(a.compliant)
	is_number(a.score)
	is_object(a.tsc_results)
}
