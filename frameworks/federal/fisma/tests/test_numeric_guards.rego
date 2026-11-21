package fisma.numeric_guards_test

import rego.v1

test_non_number_implementation_percentage_not_implemented if {
	every v in ["1", null, "x"] {
		not data.fisma.main.security_controls_implemented with input as {"fisma": {"implement": {"controls": {
			"implementation_percentage": v,
			"configuration_management_applied": true,
			"change_control_applied": true,
		}}}}
		not data.fisma.ato.control_implementation_verified with input as {"ato": {"controls": {"implementation": {
			"implementation_percentage": v,
			"evidence_artifacts_available": true,
			"configuration_verified": true,
			"procedures_documented": true,
		}}}}
	}
}

test_numeric_implementation_percentage_unchanged if {
	data.fisma.main.security_controls_implemented with input as {"fisma": {"implement": {"controls": {
		"implementation_percentage": 96,
		"configuration_management_applied": true,
		"change_control_applied": true,
	}}}}
	data.fisma.ato.control_implementation_verified with input as {"ato": {"controls": {"implementation": {
		"implementation_percentage": 95,
		"evidence_artifacts_available": true,
		"configuration_verified": true,
		"procedures_documented": true,
	}}}}
}
