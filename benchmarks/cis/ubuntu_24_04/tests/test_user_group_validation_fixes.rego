package cis_ubuntu_24_04.user_group_test

import rego.v1

# Regression tests for validation 2026-10-17 fixes.

good := {"user_group": {
	"users_without_shadow": [], "users_with_empty_password": [], "passwd_groups_not_in_group_file": [],
	"duplicate_uids": {}, "duplicate_gids": {}, "duplicate_usernames": {}, "duplicate_groupnames": {},
	"root_path": "/usr/sbin:/usr/bin", "root_path_dirs": ["/usr/sbin", "/usr/bin"],
	"root_path_writable_dirs": [], 	"uid_zero_accounts": ["root"], "users_without_home_directory": [], "users_not_owning_home": [],
	"home_dirs_too_permissive": [], "users_with_netrc": [], "users_with_forward": [], "users_with_rhosts": [],
	"dotfiles_group_or_world_writable": [],
}}

test_user_group_fully_evidenced_is_compliant if {
	data.cis_ubuntu_24_04.user_group.compliant with input as good
}

test_user_group_empty_object_is_not_compliant if {
	not data.cis_ubuntu_24_04.user_group.compliant with input as {"user_group": {}}
}

test_user_group_missing_section_is_violation if {
	i := json.remove(good, ["user_group/users_with_netrc"])
	"CIS 6.2: evidence missing — user_group.users_with_netrc not collected" in data.cis_ubuntu_24_04.user_group.violations with input as i
	not data.cis_ubuntu_24_04.user_group.compliant with input as i
}

test_user_group_each_section_required if {
	every k in data.cis_ubuntu_24_04.user_group.required_sections {
		not data.cis_ubuntu_24_04.user_group.compliant with input as json.remove(good, [concat("/", ["user_group", k])])
	}
}

test_user_group_offender_still_reported if {
	i := object.union(good, {"user_group": {"uid_zero_accounts": ["root", "toor"]}})
	"CIS 6.2.9: Account toor has UID 0 - only root should have UID 0" in data.cis_ubuntu_24_04.user_group.violations with input as i
}
