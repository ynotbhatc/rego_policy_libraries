# METADATA
# title: "DERIVED from CIS Ubuntu Linux 22.04 LTS Benchmark v3.0.0 — applied to Ubuntu 24.04 LTS (see README) - Section 6.2: User and Group Settings"
# custom:
#   class: security
#   framework: cis_ubuntu_24_04
#   source: cis
#   domains: [linux, ubuntu]
#   coverage:
#     checks: 24
#     cited: 17
#     density: sized
#     basis: size
#     tested: true
#     entrypoint: report
#     guard: self
#     as_of: v2.4.2
package cis_ubuntu_24_04.user_group

# DERIVED from CIS Ubuntu Linux 22.04 LTS Benchmark v3.0.0 — applied to Ubuntu 24.04 LTS (see README) - Section 6.2: User and Group Settings

import rego.v1

default compliant := false

# Every section below is an offender list or a path fact. An absent section is
# missing evidence, not an empty offender list, and `user_group: {}` is not evidence.
required_sections := {
	"users_without_shadow", "users_with_empty_password", "passwd_groups_not_in_group_file",
	"duplicate_uids", "duplicate_gids", "duplicate_usernames", "duplicate_groupnames",
	"root_path", "root_path_dirs", "root_path_writable_dirs",
	"uid_zero_accounts", "users_without_home_directory", "users_not_owning_home",
	"home_dirs_too_permissive", "users_with_netrc", "users_with_forward", "users_with_rhosts",
	"dotfiles_group_or_world_writable",
}

violations contains msg if {
	some section in required_sections
	object.get(object.get(input, "user_group", {}), section, null) == null
	msg := sprintf("CIS 6.2: evidence missing — user_group.%s not collected", [section])
}

compliant if {
	count(violations) == 0
}

# CIS 6.2.1: password hashes must be stored outside /etc/passwd
violations contains msg if {
	some user in input.user_group.users_without_shadow
	msg := sprintf("CIS 6.2.1: User %s in /etc/passwd does not use shadowed passwords", [user])
}

# CIS 6.2.2: password fields in /etc/shadow must be populated
violations contains msg if {
	some user in input.user_group.users_with_empty_password
	msg := sprintf("CIS 6.2.2: User %s has an empty password field in /etc/shadow", [user])
}

# CIS 6.2.3: every group named in /etc/passwd must also exist in /etc/group
violations contains msg if {
	some entry in input.user_group.passwd_groups_not_in_group_file
	msg := sprintf("CIS 6.2.3: Group %s from /etc/passwd does not exist in /etc/group", [entry])
}

# CIS 6.2.4: the local account database must not contain duplicate UIDs
violations contains msg if {
	some uid, users in input.user_group.duplicate_uids
	count(users) > 1
	msg := sprintf("CIS 6.2.4: Duplicate UID %s found for users: %s", [uid, concat(", ", users)])
}

# CIS 6.2.5: the local account database must not contain duplicate GIDs
violations contains msg if {
	some gid, groups in input.user_group.duplicate_gids
	count(groups) > 1
	msg := sprintf("CIS 6.2.5: Duplicate GID %s found for groups: %s", [gid, concat(", ", groups)])
}

# CIS 6.2.6: the local account database must not contain duplicate user names
violations contains msg if {
	some username, cnt in input.user_group.duplicate_usernames
	cnt > 1
	msg := sprintf("CIS 6.2.6: Duplicate username %s found %d times", [username, cnt])
}

# CIS 6.2.7: the local account database must not contain duplicate group names
violations contains msg if {
	some groupname, cnt in input.user_group.duplicate_groupnames
	cnt > 1
	msg := sprintf("CIS 6.2.7: Duplicate group name %s found %d times", [groupname, cnt])
}

# CIS 6.2.8: checked condition — root PATH Integrity
violations contains msg if {
	contains(input.user_group.root_path, "::")
	msg := "CIS 6.2.8: Root PATH contains empty directory (::)"
}

violations contains msg if {
	startswith(input.user_group.root_path, ":")
	msg := "CIS 6.2.8: Root PATH starts with colon"
}

violations contains msg if {
	endswith(input.user_group.root_path, ":")
	msg := "CIS 6.2.8: Root PATH ends with colon"
}

violations contains msg if {
	some dir in input.user_group.root_path_dirs
	dir == "."
	msg := "CIS 6.2.8: Root PATH contains current directory (.)"
}

violations contains msg if {
	some dir in input.user_group.root_path_writable_dirs
	msg := sprintf("CIS 6.2.8: Root PATH contains world-writable directory: %s", [dir])
}

# CIS 6.2.9: uid 0 must belong only to root
violations contains msg if {
	some user in input.user_group.uid_zero_accounts
	user != "root"
	msg := sprintf("CIS 6.2.9: Account %s has UID 0 - only root should have UID 0", [user])
}

# CIS 6.2.10: checked condition — local interactive user home directories exist
violations contains msg if {
	some user in input.user_group.users_without_home_directory
	msg := sprintf("CIS 6.2.10: User %s home directory does not exist", [user])
}

# CIS 6.2.11: checked condition — local interactive users own their home directories
violations contains msg if {
	some entry in input.user_group.users_not_owning_home
	msg := sprintf("CIS 6.2.11: User %s does not own their home directory %s", [entry.user, entry.home])
}

# CIS 6.2.12: local interactive user home directories must be mode 750 or more restrictive
violations contains msg if {
	some entry in input.user_group.home_dirs_too_permissive
	msg := sprintf("CIS 6.2.12: User %s home directory %s has permissions %s (should be 750 or more restrictive)", [entry.user, entry.home, entry.mode])
}

# CIS 6.2.13: local interactive users must not have .netrc files
violations contains msg if {
	some entry in input.user_group.users_with_netrc
	msg := sprintf("CIS 6.2.13: User %s has .netrc file: %s", [entry.user, entry.path])
}

# CIS 6.2.14: local interactive users must not have .forward files
violations contains msg if {
	some entry in input.user_group.users_with_forward
	msg := sprintf("CIS 6.2.14: User %s has .forward file: %s", [entry.user, entry.path])
}

# CIS 6.2.15: local interactive users must not have .rhosts files
violations contains msg if {
	some entry in input.user_group.users_with_rhosts
	msg := sprintf("CIS 6.2.15: User %s has .rhosts file: %s", [entry.user, entry.path])
}

# CIS 6.2.16: local interactive user dot files must be not group or world writable
violations contains msg if {
	some entry in input.user_group.dotfiles_group_or_world_writable
	msg := sprintf("CIS 6.2.16: User %s has group/world writable dot file: %s (mode: %s)", [entry.user, entry.file, entry.mode])
}

# Legacy entries
violations contains msg if {
	some line in split(input.user_group.passwd_content, "\n")
	startswith(trim_space(line), "+")
	msg := "CIS 6.2: Legacy '+' entry found in /etc/passwd"
}

violations contains msg if {
	some line in split(input.user_group.shadow_content, "\n")
	startswith(trim_space(line), "+")
	msg := "CIS 6.2: Legacy '+' entry found in /etc/shadow"
}

violations contains msg if {
	some line in split(input.user_group.group_content, "\n")
	startswith(trim_space(line), "+")
	msg := "CIS 6.2: Legacy '+' entry found in /etc/group"
}

report := {
	"compliant": compliant,
	"total_violations": count(violations),
	"violations": violations,
	"controls_checked": 16,
	"section": "6.2 User and Group Settings",
	"benchmark": "DERIVED from CIS Ubuntu Linux 22.04 LTS Benchmark v3.0.0 (applied to Ubuntu 24.04 LTS)",
}
