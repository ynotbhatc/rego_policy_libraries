package cis_windows_server_2019.account_policies_test

import rego.v1

# Regression tests for the 2026-10-17 validation pass.

good := {"account_policies": {
	"password_history_size": 24,
	"maximum_password_age": 365,
	"minimum_password_age": 1,
	"minimum_password_length": 14,
	"password_complexity_enabled": true,
	"relax_minimum_password_length": true,
	"store_plaintext_passwords": false,
	"lockout_duration": 15,
	"lockout_threshold": 5,
	"admin_lockout_enabled": true,
	"lockout_observation_window": 15,
}}

test_acct_good_input_compliant if {
	data.cis_windows_server_2019.account_policies.compliant with input as good
}

test_acct_string_numbers_accepted if {
	i := object.union(good, {"account_policies": {"password_history_size": "24", "lockout_threshold": "5"}})
	data.cis_windows_server_2019.account_policies.compliant with input as i
}

test_acct_lockout_threshold_8_flagged if {
	i := object.union(good, {"account_policies": {"lockout_threshold": 8}})
	v := data.cis_windows_server_2019.account_policies.lockout_policy_violations with input as i
	count(v) == 1
}

test_acct_lockout_threshold_6_flagged if {
	i := object.union(good, {"account_policies": {"lockout_threshold": 6}})
	not data.cis_windows_server_2019.account_policies.compliant with input as i
}

test_acct_missing_password_history_flagged if {
	i := {"account_policies": object.remove(good.account_policies, ["password_history_size"])}
	not data.cis_windows_server_2019.account_policies.compliant with input as i
	v := data.cis_windows_server_2019.account_policies.password_policy_violations with input as i
	"CIS 1.1.x: evidence missing - account_policies.password_history_size not collected" in v
}

test_acct_missing_lockout_window_flagged if {
	i := {"account_policies": object.remove(good.account_policies, ["lockout_observation_window", "lockout_duration"])}
	v := data.cis_windows_server_2019.account_policies.lockout_policy_violations with input as i
	count([m | some m in v; contains(m, "evidence missing")]) == 2
}
