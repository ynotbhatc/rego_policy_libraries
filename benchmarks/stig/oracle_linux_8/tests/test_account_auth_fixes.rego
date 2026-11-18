package stig.oracle_linux_8.account_auth_test

import rego.v1

# Validation fixes 2026-10-17: missing evidence is not a pass.

good := {
	"local_accounts_with_empty_passwords": [],
	"duplicate_uids": [],
	"password_policy": {"sha512": true, "minlen": 15, "mindays": 1, "inactive_days": 30, "minclass": 4, "ocredit": -1},
	"pam_config": {"lockout_attempts": 3},
}

test_account_auth_empty_input_not_compliant if {
	not data.stig.oracle_linux_8.account_auth.compliant with input as {}
}

test_account_auth_missing_duplicate_uids_is_open if {
	i := json.remove(good, ["/duplicate_uids"])
	data.stig.oracle_linux_8.account_auth.status_ol08_00_020240 == "Open" with input as i
}
