package stig.oracle_linux_8.account_auth_test

import rego.v1

# Validation fixes 2026-10-17: missing evidence is not a pass.

good := {
	"local_accounts_with_empty_passwords": [],
	"duplicate_uids": [],
	"password_policy": {"sha512": true, "minlen": 15, "mindays": 1, "inactive_days": 30, "minclass": 4, "ocredit": -1},
	"pam_config": {"lockout_attempts": 3},
}

test_account_auth_good_input_compliant if {
	data.stig.oracle_linux_8.account_auth.compliant with input as good
}

test_account_auth_empty_input_not_compliant if {
	not data.stig.oracle_linux_8.account_auth.compliant with input as {}
}

test_account_auth_missing_empty_password_list_is_open if {
	i := json.remove(good, ["/local_accounts_with_empty_passwords"])
	data.stig.oracle_linux_8.account_auth.status_ol08_00_020330 == "Open" with input as i
	not data.stig.oracle_linux_8.account_auth.compliant with input as i
}

test_account_auth_empty_password_present_is_open if {
	i := json.patch(good, [{"op": "replace", "path": "/local_accounts_with_empty_passwords", "value": ["bob"]}])
	data.stig.oracle_linux_8.account_auth.status_ol08_00_020330 == "Open" with input as i
}

test_account_auth_missing_duplicate_uids_is_open if {
	i := json.remove(good, ["/duplicate_uids"])
	data.stig.oracle_linux_8.account_auth.status_ol08_00_020240 == "Open" with input as i
}

test_account_auth_duplicate_uids_object_empty_is_not_a_finding if {
	i := json.patch(good, [{"op": "replace", "path": "/duplicate_uids", "value": {}}])
	data.stig.oracle_linux_8.account_auth.status_ol08_00_020240 == "Not_a_Finding" with input as i
}

test_account_auth_report_populated_on_failure if {
	r := data.stig.oracle_linux_8.account_auth.compliance_report with input as {}
	r.compliant == false
	r.cat_i_open == 1
	count(r.findings) == 11
}
