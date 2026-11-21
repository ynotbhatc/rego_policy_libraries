package stig.rhel_8.numeric_guards_test

import rego.v1

# Type traps (#300): lockout, password length / age and inactivity settings that are not numbers must not pass.

test_numbers_pass if {
	data.stig.rhel_8.account_auth.status_rhel_08_020010 == "Not_a_Finding" with input as {"pam_config": {"lockout_attempts": 3}}
	data.stig.rhel_8.account_auth.status_rhel_08_020230 == "Not_a_Finding" with input as {"password_policy": {"minlen": 15}}
	data.stig.rhel_8.account_auth.status_rhel_08_020200 == "Not_a_Finding" with input as {"password_policy": {"maxdays": 60}}
	data.stig.rhel_8.account_auth.status_rhel_08_020012 == "Not_a_Finding" with input as {"pam_config": {"lockout_time": 900}}
	data.stig.rhel_8.account_auth.status_rhel_08_020260 == "Not_a_Finding" with input as {"password_policy": {"inactive_days": 35}}
}

test_type_traps_are_open if {
	every v in ["1", null, "x", "999"] {
		data.stig.rhel_8.account_auth.status_rhel_08_020010 == "Open" with input as {"pam_config": {"lockout_attempts": v}}
		data.stig.rhel_8.account_auth.status_rhel_08_020230 == "Open" with input as {"password_policy": {"minlen": v}}
		data.stig.rhel_8.account_auth.status_rhel_08_020200 == "Open" with input as {"password_policy": {"maxdays": v}}
		data.stig.rhel_8.account_auth.status_rhel_08_020012 == "Open" with input as {"pam_config": {"lockout_time": v}}
		data.stig.rhel_8.account_auth.status_rhel_08_020260 == "Open" with input as {"password_policy": {"inactive_days": v}}
	}
}
