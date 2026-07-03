# Contract smoke test for the CONSUMER endpoint /v1/data/iso27001/iso27001_assessment
package iso27001_consumer_test

import rego.v1

import data.iso27001

test_iso27001_assessment_wellformed_on_empty_input if {
	a := iso27001.iso27001_assessment with input as {}
	is_object(a)
	is_boolean(a.compliant)
	is_number(a.score)
	is_object(a.isms_results)
}
