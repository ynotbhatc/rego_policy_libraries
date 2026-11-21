package nist.sp800_171.identification_authentication_numeric_guards_test

import rego.v1

test_non_number_password_length_not_met if {
	every v in ["1", null, "x"] {
		not data.nist.sp800_171.identification_authentication.password_complexity with input as {"nist_800_171": {"identification_authentication": {"password_complexity": {
			"minimum_length": v,
			"complexity_enforced": true,
			"change_requirements_defined": true,
		}}}}
	}
}

test_numeric_password_length_unchanged if {
	data.nist.sp800_171.identification_authentication.password_complexity with input as {"nist_800_171": {"identification_authentication": {"password_complexity": {
		"minimum_length": 12,
		"complexity_enforced": true,
		"change_requirements_defined": true,
	}}}}
}
