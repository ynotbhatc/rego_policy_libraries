package cmmc.identification_authentication_test

import rego.v1

# Generated smoke test for frameworks/federal/cmmc/cmmc_identification_authentication.rego (scripts/gen_tests.py). Each rule states one thing the module was proven
# to do on empty input; a missing rule means the module does not do that, see docs/TEST_GENERATION.md.

test_cmmc_identification_authentication_loads_on_empty_input if {
	m := data.cmmc.identification_authentication with input as {}
	is_object(m)
}

test_cmmc_identification_authentication_report_wellformed_on_empty_input if {
	report := data.cmmc.identification_authentication.compliance_report with input as {}
	is_object(report)
	count(report) > 0
}

test_cmmc_identification_authentication_fail_closed_on_empty_input if {
	report := data.cmmc.identification_authentication.compliance_report with input as {}
	not object.get(report, "compliant", false) == true
}

# --- semantic review 2026-11-13: domain verdict must agree with practices ---

good_input_review := {"identity": {"unique_user_accounts": true, "shared_accounts_documented": true, "service_accounts_identified": true, "authentication_required": true, "mfa_privileged_accounts": true, "mfa_network_access": true, "replay_resistant_auth": true, "kerberos_or_pki": true, "automated_account_management": true, "inactive_account_disable_days": 35, "identifier_management_policy": true, "terminated_accounts_disabled_immediately": true, "password_min_length": 12, "password_complexity_uppercase": true, "password_complexity_lowercase": true, "password_complexity_numbers": true, "password_complexity_special": true, "password_history_count": 5, "temp_password_change_on_first_login": true, "temp_password_expiry_hours": 24, "passwords_hashed": true, "hash_algorithm": "ok", "passwords_transmitted_encrypted": true, "password_masking_enabled": true, "failed_login_no_detail": true}}

test_review_good_input_compliant if {
	r := data.cmmc.identification_authentication.compliance_report with input as good_input_review
	r.compliant
	r.failing == 0
}

test_review_shared_accounts_undocumented if {
	r := data.cmmc.identification_authentication.compliance_report with input as {"identity": {"unique_user_accounts": true, "shared_accounts_documented": false, "service_accounts_identified": true, "authentication_required": true, "mfa_privileged_accounts": true, "mfa_network_access": true, "replay_resistant_auth": true, "kerberos_or_pki": true, "automated_account_management": true, "inactive_account_disable_days": 35, "identifier_management_policy": true, "terminated_accounts_disabled_immediately": true, "password_min_length": 12, "password_complexity_uppercase": true, "password_complexity_lowercase": true, "password_complexity_numbers": true, "password_complexity_special": true, "password_history_count": 5, "temp_password_change_on_first_login": true, "temp_password_expiry_hours": 24, "passwords_hashed": true, "hash_algorithm": "ok", "passwords_transmitted_encrypted": true, "password_masking_enabled": true, "failed_login_no_detail": true}}
	r.failing > 0
	not r.compliant
	count(r.violations) > 0
	some v in r.violations
	startswith(v, "3.5.1")
}

test_review_no_kerberos_or_pki if {
	r := data.cmmc.identification_authentication.compliance_report with input as {"identity": {"unique_user_accounts": true, "shared_accounts_documented": true, "service_accounts_identified": true, "authentication_required": true, "mfa_privileged_accounts": true, "mfa_network_access": true, "replay_resistant_auth": true, "kerberos_or_pki": false, "automated_account_management": true, "inactive_account_disable_days": 35, "identifier_management_policy": true, "terminated_accounts_disabled_immediately": true, "password_min_length": 12, "password_complexity_uppercase": true, "password_complexity_lowercase": true, "password_complexity_numbers": true, "password_complexity_special": true, "password_history_count": 5, "temp_password_change_on_first_login": true, "temp_password_expiry_hours": 24, "passwords_hashed": true, "hash_algorithm": "ok", "passwords_transmitted_encrypted": true, "password_masking_enabled": true, "failed_login_no_detail": true}}
	r.failing > 0
	not r.compliant
	count(r.violations) > 0
	some v in r.violations
	startswith(v, "3.5.4")
}

test_review_lowercase_not_required if {
	r := data.cmmc.identification_authentication.compliance_report with input as {"identity": {"unique_user_accounts": true, "shared_accounts_documented": true, "service_accounts_identified": true, "authentication_required": true, "mfa_privileged_accounts": true, "mfa_network_access": true, "replay_resistant_auth": true, "kerberos_or_pki": true, "automated_account_management": true, "inactive_account_disable_days": 35, "identifier_management_policy": true, "terminated_accounts_disabled_immediately": true, "password_min_length": 12, "password_complexity_uppercase": true, "password_complexity_lowercase": false, "password_complexity_numbers": true, "password_complexity_special": true, "password_history_count": 5, "temp_password_change_on_first_login": true, "temp_password_expiry_hours": 24, "passwords_hashed": true, "hash_algorithm": "ok", "passwords_transmitted_encrypted": true, "password_masking_enabled": true, "failed_login_no_detail": true}}
	r.failing > 0
	not r.compliant
	count(r.violations) > 0
	some v in r.violations
	startswith(v, "3.5.7")
}

test_review_password_length_missing if {
	r := data.cmmc.identification_authentication.compliance_report with input as {"identity": {"unique_user_accounts": true, "shared_accounts_documented": true, "service_accounts_identified": true, "authentication_required": true, "mfa_privileged_accounts": true, "mfa_network_access": true, "replay_resistant_auth": true, "kerberos_or_pki": true, "automated_account_management": true, "inactive_account_disable_days": 35, "identifier_management_policy": true, "terminated_accounts_disabled_immediately": true, "password_complexity_uppercase": true, "password_complexity_lowercase": true, "password_complexity_numbers": true, "password_complexity_special": true, "password_history_count": 5, "temp_password_change_on_first_login": true, "temp_password_expiry_hours": 24, "passwords_hashed": true, "hash_algorithm": "ok", "passwords_transmitted_encrypted": true, "password_masking_enabled": true, "failed_login_no_detail": true}}
	r.failing > 0
	not r.compliant
	count(r.violations) > 0
	some v in r.violations
	startswith(v, "3.5.7")
}
