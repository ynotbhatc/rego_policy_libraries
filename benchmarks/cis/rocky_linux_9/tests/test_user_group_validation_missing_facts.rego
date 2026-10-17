package cis_rocky_linux_9.user_group_test

import rego.v1

good := {"user_group": {
	"users_without_shadow": [], "users_with_empty_password": [], "passwd_groups_not_in_group_file": [],
	"duplicate_uids": {}, "duplicate_gids": {}, "duplicate_usernames": {}, "duplicate_groupnames": {},
	"root_path": "/usr/sbin:/usr/bin", "uid_zero_accounts": ["root"],
	"users_without_home_directory": [], "users_not_owning_home": [], "home_dirs_too_permissive": [],
	"users_with_netrc": [], "users_with_forward": [], "users_with_rhosts": [],
	"dotfiles_group_or_world_writable": [],
}}

test_full_evidence_compliant if data.cis_rocky_linux_9.user_group.compliant with input as good

test_empty_user_group_not_compliant if {
	inp := {"user_group": {}}
	not data.cis_rocky_linux_9.user_group.compliant with input as inp
	v := data.cis_rocky_linux_9.user_group.violations with input as inp
	count([x | some x in v; contains(x, "evidence missing")]) == 16
}

test_single_missing_key_flagged if {
	inp := {"user_group": object.remove(good.user_group, ["users_with_rhosts"])}
	not data.cis_rocky_linux_9.user_group.compliant with input as inp
	v := data.cis_rocky_linux_9.user_group.violations with input as inp
	"CIS 6.2.15: evidence missing — user_group.users_with_rhosts not collected" in v
}

test_offender_still_flagged if {
	inp := {"user_group": object.union(good.user_group, {"uid_zero_accounts": ["root", "toor"]})}
	v := data.cis_rocky_linux_9.user_group.violations with input as inp
	"CIS 6.2.9: Account toor has UID 0 - only root should have UID 0" in v
}
