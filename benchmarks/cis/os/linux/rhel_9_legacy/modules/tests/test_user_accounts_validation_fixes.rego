package cis_rhel9.user_accounts_validation_test

import rego.v1

# Regression tests for the 2026-10-17 validation pass.

ids(v) := {x.control_id | some x in v; x.control_id}

user(mode) := {"user_accounts": {"interactive_users": [{
	"username": "alice", "home": "/home/alice", "home_mode": mode, "home_mode_octal": mode,
	"home_owner": "alice", "primary_group": "alice",
}]}}

test_user_accounts_home_705_flagged if {
	v := data.cis_rhel9.user_accounts_validation.violations with input as user(705)
	"6.2.12" in ids(v)
}

test_user_accounts_home_750_ok if {
	v := data.cis_rhel9.user_accounts_validation.violations with input as user(750)
	not "6.2.12" in ids(v)
}

test_user_accounts_home_700_ok if {
	v := data.cis_rhel9.user_accounts_validation.violations with input as user("0700")
	not "6.2.12" in ids(v)
}

test_user_accounts_home_751_flagged if {
	v := data.cis_rhel9.user_accounts_validation.violations with input as user(751)
	"6.2.12" in ids(v)
}

test_user_accounts_sudo_timeout_minus_one_flagged if {
	v := data.cis_rhel9.user_accounts_validation.violations with input as {"user_accounts": {"sudo_config": {"timestamp_timeout": -1}}}
	"5.3.6" in ids(v)
}

test_user_accounts_sudo_timeout_15_ok if {
	v := data.cis_rhel9.user_accounts_validation.violations with input as {"user_accounts": {"sudo_config": {"timestamp_timeout": 15}}}
	not "5.3.6" in ids(v)
}

test_user_accounts_sudo_timeout_zero_ok if {
	v := data.cis_rhel9.user_accounts_validation.violations with input as {"user_accounts": {"sudo_config": {"timestamp_timeout": 0}}}
	not "5.3.6" in ids(v)
}
