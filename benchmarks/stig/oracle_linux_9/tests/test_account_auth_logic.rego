package stig.oracle_linux_9.account_auth_test

import rego.v1

import data.stig.oracle_linux_9.account_auth

# Validation 2026-10-17: missing evidence must not be a pass.

test_empty_input_empty_passwords_is_open if {
	account_auth.status_ol09_00_001130 == "Open" with input as {}
}

test_empty_list_empty_passwords_is_pass if {
	account_auth.status_ol09_00_001130 == "Not_a_Finding" with input as {"local_accounts_with_empty_passwords": []}
}

test_offender_empty_passwords_is_open if {
	account_auth.status_ol09_00_001130 == "Open" with input as {"local_accounts_with_empty_passwords": ["bob"]}
}

test_empty_input_duplicate_ids_open if {
	account_auth.status_ol09_00_003001 == "Open" with input as {}
	account_auth.status_ol09_00_003006 == "Open" with input as {}
}

test_empty_lists_duplicate_ids_pass if {
	account_auth.status_ol09_00_003001 == "Not_a_Finding" with input as {"duplicate_uids": []}
	account_auth.status_ol09_00_003006 == "Not_a_Finding" with input as {"duplicate_gids": []}
}

test_inactive_rule_title_matches_check if {
	contains(account_auth.finding_ol09_00_002416.rule_title, "35 days of inactivity")
}
