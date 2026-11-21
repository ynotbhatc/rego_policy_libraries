package cis.windows.server2022_test

import rego.v1

# Regression tests for the 2026-10-17 validation pass.

test_win2022_compliant_defined_on_empty_input if {
	c := data.cis.windows.server2022.compliant with input as {}
	c == false
}

test_win2022_report_populated_on_failing_input if {
	r := data.cis.windows.server2022.windows_server_compliance with input as {"security_policy": {"password_history": 24}}
	count(r) == 46
	r.password_history_enforced == true
	r.password_min_length == false
	r.overall_compliant == false
}

test_win2022_guests_denied_array_ok if {
	i := {"user_rights": {"deny_network_access": ["Guests", "Local account"]}}
	data.cis.windows.server2022.deny_network_access_includes_guests with input as i
}

test_win2022_guests_missing_from_array_flagged if {
	i := {"user_rights": {"deny_network_access": ["Local account"]}}
	not data.cis.windows.server2022.deny_network_access_includes_guests with input as i
}

test_win2022_guests_denied_string_ok if {
	i := {"user_rights": {"deny_rdp_logon": "Guests, Local account"}}
	data.cis.windows.server2022.deny_rdp_logon_includes_guests with input as i
}

# #300 type traps: a non-number must not pass account_lockout_threshold.
test_account_lockout_threshold_number_type_traps if {
	data.cis.windows.server2022.account_lockout_threshold with input as {"security_policy": {"account_lockout_threshold": 5}}
	not data.cis.windows.server2022.account_lockout_threshold with input as {"security_policy": {"account_lockout_threshold": "1"}}
	not data.cis.windows.server2022.account_lockout_threshold with input as {"security_policy": {"account_lockout_threshold": null}}
	not data.cis.windows.server2022.account_lockout_threshold with input as {"security_policy": {"account_lockout_threshold": "not-a-number"}}
}
