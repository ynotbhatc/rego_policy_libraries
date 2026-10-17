package cis_ubuntu_20_04.user_group_test

import rego.v1

# Validation fix pass 2026-10-17.

good := {"user_group": {
	"users_without_shadow": [], "users_with_empty_password": [], "passwd_groups_not_in_group_file": [],
	"duplicate_uids": {}, "duplicate_gids": {}, "duplicate_usernames": {}, "duplicate_groupnames": {},
	"root_path": "/usr/bin:/bin", "root_path_dirs": ["/usr/bin", "/bin"], "root_path_writable_dirs": [],
	"uid_zero_accounts": ["root"], "users_without_home_directory": [], "users_not_owning_home": [],
	"home_dirs_too_permissive": [], "users_with_netrc": [], "users_with_forward": [], "users_with_rhosts": [],
	"dotfiles_group_or_world_writable": [],
	"passwd_content": "root:x:0:0", "shadow_content": "root:*:1", "group_content": "root:x:0",
}}

test_full_evidence_compliant if {
	data.cis_ubuntu_20_04.user_group.compliant with input as good
}

test_empty_input_not_compliant if {
	not data.cis_ubuntu_20_04.user_group.compliant with input as {}
	r := data.cis_ubuntu_20_04.user_group.report with input as {}
	r.compliant == false
	r.total_violations == 21
}

test_each_missing_key_not_compliant if {
	every key in object.keys(good.user_group) {
		not data.cis_ubuntu_20_04.user_group.compliant with input as json.remove(good, [concat("/", ["user_group", key])])
	}
}

test_offender_still_reported if {
	inp := object.union(good, {"user_group": {"users_with_empty_password": ["bob"]}})
	"CIS 6.2.2: User bob has an empty password field in /etc/shadow" in data.cis_ubuntu_20_04.user_group.violations with input as inp
}
