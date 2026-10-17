package stig.oracle_linux_9.file_permissions_test

import rego.v1

import data.stig.oracle_linux_9.file_permissions as fp

# Validation 2026-10-17: octal modes and missing evidence.

test_passwd_0600_is_within_0644 if {
	fp.passwd_permissions_ok with input as {"file_permissions": {"etc_passwd": {"mode": "0600"}}}
}

test_passwd_0644_and_644_ok if {
	fp.passwd_permissions_ok with input as {"file_permissions": {"etc_passwd": {"mode": "0644"}}}
	fp.passwd_permissions_ok with input as {"file_permissions": {"etc_passwd": {"mode": "644"}}}
}

test_passwd_0666_not_ok if {
	not fp.passwd_permissions_ok with input as {"file_permissions": {"etc_passwd": {"mode": "0666"}}}
	not fp.passwd_permissions_ok with input as {"file_permissions": {"etc_passwd": {"mode": "garbage"}}}
}

test_group_0640_within_0644 if {
	fp.group_permissions_ok with input as {"file_permissions": {"etc_group": {"mode": "0640"}}}
	not fp.group_permissions_ok with input as {"file_permissions": {"etc_group": {"mode": "0664"}}}
}

test_missing_evidence_is_open if {
	fp.status_ol09_00_002512 == "Open" with input as {}
	fp.status_ol09_00_002511 == "Open" with input as {}
	fp.status_ol09_00_002515 == "Open" with input as {}
}

test_empty_lists_pass if {
	fp.status_ol09_00_002512 == "Not_a_Finding" with input as {"file_permissions": {"unowned_files": []}}
	fp.status_ol09_00_002511 == "Not_a_Finding" with input as {"file_permissions": {"ungrouped_files": []}}
	fp.status_ol09_00_002515 == "Not_a_Finding" with input as {"file_permissions": {"insecure_home_dirs": []}}
}

test_offenders_are_open if {
	fp.status_ol09_00_002512 == "Open" with input as {"file_permissions": {"unowned_files": ["/tmp/x"]}}
}
