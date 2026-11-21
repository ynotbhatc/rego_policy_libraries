package soc2.main_numeric_guards_test

import rego.v1

# "1" sorts above every number: a string testing period passed `>= 12`.
test_string_operating_effectiveness_demonstrated_is_false if {
	not data.soc2.main.operating_effectiveness_demonstrated with input as {"soc2": {"operating_effectiveness": {"testing_period_months": "1", "continuous_monitoring": true, "exception_reporting": true, "management_response": {"documented": true}}}}
}

test_null_operating_effectiveness_demonstrated_is_false if {
	not data.soc2.main.operating_effectiveness_demonstrated with input as {"soc2": {"operating_effectiveness": {"testing_period_months": null, "continuous_monitoring": true, "exception_reporting": true, "management_response": {"documented": true}}}}
}

test_text_operating_effectiveness_demonstrated_is_false if {
	not data.soc2.main.operating_effectiveness_demonstrated with input as {"soc2": {"operating_effectiveness": {"testing_period_months": "x", "continuous_monitoring": true, "exception_reporting": true, "management_response": {"documented": true}}}}
}

test_numeric_operating_effectiveness_demonstrated_unchanged if {
	data.soc2.main.operating_effectiveness_demonstrated with input as {"soc2": {"operating_effectiveness": {"testing_period_months": 12, "continuous_monitoring": true, "exception_reporting": true, "management_response": {"documented": true}}}}
}
