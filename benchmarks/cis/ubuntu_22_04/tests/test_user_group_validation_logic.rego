package cis_ubuntu_22_04.user_group_test

import rego.v1

# Validation fix 2026-10-17: compliant on empty input; absent offender lists / passwd content
# were treated as "no offenders".

pkg := data.cis_ubuntu_22_04.user_group

clean := {"user_group": {
	"users_without_shadow": [], "users_with_empty_password": [], "passwd_groups_not_in_group_file": [],
	"duplicate_uids": {}, "duplicate_gids": {}, "duplicate_usernames": {}, "duplicate_groupnames": {},
	"root_path": "/usr/local/sbin:/usr/bin", "root_path_dirs": ["/usr/local/sbin", "/usr/bin"], "root_path_writable_dirs": [],
	"uid_zero_accounts": ["root"], "users_without_home_directory": [], "users_not_owning_home": [],
	"home_dirs_too_permissive": [], "users_with_netrc": [], "users_with_forward": [], "users_with_rhosts": [],
	"dotfiles_group_or_world_writable": [],
	"passwd_content": "root:x:0:0:root:/root:/bin/bash\n", "shadow_content": "root:*:19000:0:99999:7:::\n", "group_content": "root:x:0:\n",
}}

test_empty_input_not_compliant if {
	not pkg.compliant with input as {}
	count(pkg.violations) == 21 with input as {}
}

test_clean_compliant if {
	pkg.compliant with input as clean
}

test_each_missing_fact_violates if {
	every key in ["users_without_shadow", "duplicate_uids", "root_path", "uid_zero_accounts", "dotfiles_group_or_world_writable", "passwd_content", "group_content"] {
		not pkg.compliant with input as {"user_group": object.remove(clean.user_group, [key])}
	}
}

test_missing_passwd_content_message if {
	v := pkg.violations with input as {"user_group": object.remove(clean.user_group, ["passwd_content"])}
	"CIS 6.2: evidence missing — user_group.passwd_content not collected" in v
}

test_legacy_plus_entry_still_detected if {
	inp := {"user_group": object.union(clean.user_group, {"passwd_content": "root:x:0:0::/root:/bin/bash\n+::::::\n"})}
	v := pkg.violations with input as inp
	"CIS 6.2: Legacy '+' entry found in /etc/passwd" in v
}

test_second_uid_zero_still_detected if {
	inp := {"user_group": object.union(clean.user_group, {"uid_zero_accounts": ["root", "toor"]})}
	v := pkg.violations with input as inp
	"CIS 6.2.9: Account toor has UID 0 - only root should have UID 0" in v
}
