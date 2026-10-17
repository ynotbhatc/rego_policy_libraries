package cis_oracle.user_account_management_test

import rego.v1

# Validation fix 2026-10-17: UNLIMITED values slipped through to_number() comparisons for
# non-DEFAULT profiles / FAILED_LOGIN_ATTEMPTS / GRACE_TIME; PASSWORD_VERIFY_FUNCTION=NULL never fired.

good_profile := {
	"profile_name": "APP",
	"PASSWORD_LIFE_TIME": "90",
	"PASSWORD_GRACE_TIME": "5",
	"FAILED_LOGIN_ATTEMPTS": "5",
	"PASSWORD_VERIFY_FUNCTION": "ORA12C_VERIFY_FUNCTION",
}

inp(p) := {"password_profiles": [p]}

viol(p) := v if v := data.cis_oracle.user_account_management.violations with input as inp(p)

test_good_profile_compliant if {
	data.cis_oracle.user_account_management.compliant with input as inp(good_profile)
}

test_failed_login_unlimited_violates if {
	count(viol(object.union(good_profile, {"FAILED_LOGIN_ATTEMPTS": "UNLIMITED"}))) == 1
}

test_non_default_life_time_unlimited_violates if {
	count(viol(object.union(good_profile, {"PASSWORD_LIFE_TIME": "UNLIMITED"}))) == 1
}

test_grace_time_unlimited_violates if {
	count(viol(object.union(good_profile, {"PASSWORD_GRACE_TIME": "UNLIMITED"}))) == 1
}

test_default_life_time_unlimited_single_message if {
	count(viol(object.union(good_profile, {"profile_name": "DEFAULT", "PASSWORD_LIFE_TIME": "UNLIMITED"}))) == 1
}

test_verify_function_null_violates if {
	count(viol(object.union(good_profile, {"PASSWORD_VERIFY_FUNCTION": "NULL"}))) == 1
}

test_verify_function_absent_violates if {
	count(viol(object.remove(good_profile, ["PASSWORD_VERIFY_FUNCTION"]))) == 1
}
