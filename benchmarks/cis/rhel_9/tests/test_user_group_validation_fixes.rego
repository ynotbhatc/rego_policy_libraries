package cis_rhel9.user_group_test

import rego.v1

# Validation fixes 2026-10-17: an empty user_group object is not evidence.

good := {"user_group": {
	"users_without_shadow": [], "users_with_empty_password": [], "passwd_groups_not_in_group_file": [],
	"uid_zero_accounts": ["root"], "users_without_home_directory": [], "users_not_owning_home": [],
	"home_dirs_too_permissive": [], "users_with_netrc": [], "users_with_forward": [], "users_with_rhosts": [],
	"dotfiles_group_or_world_writable": [],
	"duplicate_uids": {}, "duplicate_gids": {}, "duplicate_usernames": {}, "duplicate_groupnames": {},
	"root_path": "/usr/sbin:/usr/bin", "root_path_dirs": ["/usr/sbin", "/usr/bin"],
}}

test_user_group_good_input_compliant if {
	data.cis_rhel9.user_group.compliant with input as good
}

test_user_group_empty_object_not_compliant if {
	not data.cis_rhel9.user_group.compliant with input as {"user_group": {}}
}

test_user_group_each_missing_fact_is_violation if {
	every key in ["users_without_shadow", "users_with_empty_password", "uid_zero_accounts", "home_dirs_too_permissive", "dotfiles_group_or_world_writable", "duplicate_uids", "duplicate_groupnames", "root_path"] {
		not data.cis_rhel9.user_group.compliant with input as json.remove(good, [concat("", ["/user_group/", key])])
	}
}

test_user_group_real_finding_still_reported if {
	i := json.patch(good, [{"op": "replace", "path": "/user_group/users_with_empty_password", "value": ["bob"]}])
	"CIS 6.2.2: User bob has an empty password field in /etc/shadow" in data.cis_rhel9.user_group.violations with input as i
}
