package cis_windows_server_2019.security_options_test

import rego.v1

# Regression tests for the 2026-10-17 validation pass.

has(prefix, v) if {
	some m in v
	startswith(m, prefix)
}

test_secopt_absent_account_flags_flagged if {
	v := data.cis_windows_server_2019.security_options.account_violations with input as {"security_options": {}}
	count([m | some m in v; contains(m, "evidence missing")]) == 3
}

test_secopt_account_flags_false_ok if {
	i := {"security_options": {"administrator_account_enabled": false, "microsoft_accounts_allowed": false, "guest_account_enabled": false}}
	v := data.cis_windows_server_2019.security_options.account_violations with input as i
	not has("CIS 2.3.1.x", v)
	not has("CIS 2.3.1.1", v)
}

test_secopt_account_flag_true_flagged if {
	i := {"security_options": {"administrator_account_enabled": true, "microsoft_accounts_allowed": false, "guest_account_enabled": false}}
	v := data.cis_windows_server_2019.security_options.account_violations with input as i
	has("CIS 2.3.1.1", v)
}

test_secopt_ctrl_alt_del_absent_flagged if {
	v := data.cis_windows_server_2019.security_options.interactive_logon_violations with input as {"security_options": {}}
	has("CIS 2.3.7.1: evidence missing", v)
}

test_secopt_ntlm_high_bit_without_ntlmv2_flagged if {
	i := {"security_options": {"ntlm_min_session_security_client": 2147483648, "ntlm_min_session_security_server": 2147483648}}
	v := data.cis_windows_server_2019.security_options.network_violations with input as i
	has("CIS 2.3.11.7", v)
	has("CIS 2.3.11.8", v)
}

test_secopt_ntlm_required_bits_ok if {
	i := {"security_options": {"ntlm_min_session_security_client": 537395200, "ntlm_min_session_security_server": 537395200}}
	v := data.cis_windows_server_2019.security_options.network_violations with input as i
	not has("CIS 2.3.11.7", v)
	not has("CIS 2.3.11.8", v)
}

test_secopt_ntlm_extra_bits_ok if {
	i := {"security_options": {"ntlm_min_session_security_client": 2684878848, "ntlm_min_session_security_server": 537395200}}
	v := data.cis_windows_server_2019.security_options.network_violations with input as i
	not has("CIS 2.3.11.7", v)
}

test_secopt_ntlm_missing_flagged if {
	v := data.cis_windows_server_2019.security_options.network_violations with input as {"security_options": {}}
	has("CIS 2.3.11.7", v)
}
