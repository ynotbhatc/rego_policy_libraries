package cis_debian_11.user_group_test

import rego.v1

good := {"user_group": {
	"users_without_shadow": [], "users_with_empty_password": [], "passwd_groups_not_in_group_file": [],
	"duplicate_uids": {}, "duplicate_gids": {}, "duplicate_usernames": {}, "duplicate_groupnames": {},
	"root_path": "/usr/sbin:/usr/bin", "root_path_dirs": ["/usr/sbin", "/usr/bin"], "root_path_writable_dirs": [],
	"uid_zero_accounts": ["root"], "users_without_home_directory": [], "users_not_owning_home": [],
	"home_dirs_too_permissive": [], "users_with_netrc": [], "users_with_forward": [], "users_with_rhosts": [],
	"dotfiles_group_or_world_writable": [],
	"passwd_content": "root:x:0:0::/root:/bin/bash\n", "shadow_content": "root:!:1:::::\n", "group_content": "root:x:0:\n",
}}

test_good_compliant if {
	data.cis_debian_11.user_group.compliant with input as good
}

test_empty_input_not_compliant if {
	not data.cis_debian_11.user_group.compliant with input as {}
}

test_each_missing_fact_violates if {
	some k in data.cis_debian_11.user_group.required_facts
	i := object.union(object.remove(good, ["user_group"]), {"user_group": object.remove(good.user_group, [k])})
	not data.cis_debian_11.user_group.compliant with input as i
}

test_real_offender_still_reported if {
	i := json.patch(good, [{"op": "replace", "path": "/user_group/users_with_empty_password", "value": ["bob"]}])
	some m in data.cis_debian_11.user_group.violations with input as i
	contains(m, "bob")
}
