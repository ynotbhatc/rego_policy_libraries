package nist.sp800_171.access_control_numeric_guards_test

import rego.v1

test_non_number_logon_limits_not_met if {
	every v in ["1", null, "x"] {
		not data.nist.sp800_171.access_control.logon_attempt_limits with input as {"cui_access": {"logon_limits": {
			"maximum_attempts": v,
			"lockout_implemented": true,
			"lockout_duration": 15,
		}}}
		not data.nist.sp800_171.access_control.logon_attempt_limits with input as {"cui_access": {"logon_limits": {
			"maximum_attempts": 3,
			"lockout_implemented": true,
			"lockout_duration": v,
		}}}
	}
}

test_numeric_logon_limits_unchanged if {
	data.nist.sp800_171.access_control.logon_attempt_limits with input as {"cui_access": {"logon_limits": {
		"maximum_attempts": 3,
		"lockout_implemented": true,
		"lockout_duration": 15,
	}}}
}
