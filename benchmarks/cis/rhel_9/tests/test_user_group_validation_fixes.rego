package cis_rhel9.user_group_test

import rego.v1

# Validation fixes 2026-10-17: an empty user_group object is not evidence.
# Re-pointed to CIS RHEL 9 v3.0.0 (2026-10-20): same test names, v3 recommendation ids.
# v2 6.2.x -> v3 7.2.x. uid_zero_accounts and root_path moved with their recommendations to v3 5.4.2.x
# (package cis_rhel9.pam), so they are no longer in this package's list.

good := {"user_group": {"users_without_shadow": [], "users_with_empty_password": [], "passwd_groups_not_in_group_file": [], "duplicate_uids": {}, "duplicate_gids": {}, "duplicate_usernames": {}, "duplicate_groupnames": {}, "users_without_home_directory": [], "users_not_owning_home": [], "home_dirs_too_permissive": [], "users_with_netrc": [], "users_with_forward": [], "users_with_rhosts": [], "dotfiles_group_or_world_writable": []}}

test_user_group_good_input_compliant if {
	data.cis_rhel9.user_group.compliant with input as good
}

test_user_group_empty_object_not_compliant if {
	not data.cis_rhel9.user_group.compliant with input as {"user_group": {}}
}

test_user_group_each_missing_fact_is_violation if {
	every key in ["users_without_shadow", "users_with_empty_password", "home_dirs_too_permissive", "dotfiles_group_or_world_writable", "duplicate_uids", "duplicate_groupnames"] {
		not data.cis_rhel9.user_group.compliant with input as json.remove(good, [concat("", ["/user_group/", key])])
	}
}

test_user_group_real_finding_still_reported if {
	i := json.patch(good, [{"op": "replace", "path": "/user_group/users_with_empty_password", "value": ["bob"]}])
	"7.2.2: not met — Ensure /etc/shadow password fields are not empty" in data.cis_rhel9.user_group.violations with input as i
}
