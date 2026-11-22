package stig.ubuntu_20_04.numeric_guards_test

import rego.v1

# Type traps (#300): password history and length settings that are not numbers must not pass.

test_numbers_pass if {
	data.stig.ubuntu_20_04.password_history_status == "Not_a_Finding" with input as {"password_policy": {"password_history_size": 24}}
	data.stig.ubuntu_20_04.password_length_status == "Not_a_Finding" with input as {"password_policy": {"minimum_password_length": 15}}
}

test_type_traps_are_open if {
	every v in ["1", null, "x", "24"] {
		data.stig.ubuntu_20_04.password_history_status == "Open" with input as {"password_policy": {"password_history_size": v}}
		data.stig.ubuntu_20_04.password_length_status == "Open" with input as {"password_policy": {"minimum_password_length": v}}
	}
}
