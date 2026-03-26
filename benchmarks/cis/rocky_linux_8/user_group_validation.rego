package cis_rocky_linux_8.user_group

# CIS Rocky Linux 8 Benchmark v2.0.0 - Section 6.2: User and Group Settings

import rego.v1

default compliant := false

compliant if {
	count(violations) == 0
}

# CIS 6.2.1: Ensure accounts in /etc/passwd use shadowed passwords
violations contains msg if {
	some user in input.user_group.users_without_shadow
	msg := sprintf("CIS 6.2.1: User %s in /etc/passwd does not use shadowed passwords", [user])
}

# CIS 6.2.2: Ensure /etc/shadow password fields are not empty
violations contains msg if {
	some user in input.user_group.users_with_empty_password
	msg := sprintf("CIS 6.2.2: User %s has an empty password field in /etc/shadow", [user])
}

# CIS 6.2.3: Ensure all groups in /etc/passwd exist in /etc/group
violations contains msg if {
	some entry in input.user_group.passwd_groups_not_in_group_file
	msg := sprintf("CIS 6.2.3: Group %s from /etc/passwd does not exist in /etc/group", [entry])
}

# CIS 6.2.4: Ensure no duplicate UIDs exist
violations contains msg if {
	some uid, users in input.user_group.duplicate_uids
	count(users) > 1
	msg := sprintf("CIS 6.2.4: Duplicate UID %s found for users: %s", [uid, concat(", ", users)])
}

# CIS 6.2.5: Ensure no duplicate GIDs exist
violations contains msg if {
	some gid, groups in input.user_group.duplicate_gids
	count(groups) > 1
	msg := sprintf("CIS 6.2.5: Duplicate GID %s found for groups: %s", [gid, concat(", ", groups)])
}

# CIS 6.2.6: Ensure no duplicate user names exist
violations contains msg if {
	some username, cnt in input.user_group.duplicate_usernames
	cnt > 1
	msg := sprintf("CIS 6.2.6: Duplicate username %s found %d times", [username, cnt])
}

# CIS 6.2.7: Ensure no duplicate group names exist
violations contains msg if {
	some groupname, cnt in input.user_group.duplicate_groupnames
	cnt > 1
	msg := sprintf("CIS 6.2.7: Duplicate group name %s found %d times", [groupname, cnt])
}

# CIS 6.2.8: Ensure root PATH Integrity
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

violations contains msg if {
	some dir in input.user_group.root_path_nonexistent_dirs
	msg := sprintf("CIS 6.2.8: Root PATH contains non-existent directory: %s", [dir])
}

# CIS 6.2.9: Ensure root is the only UID 0 account
violations contains msg if {
	some user in input.user_group.uid_zero_accounts
	user != "root"
	msg := sprintf("CIS 6.2.9: Account %s has UID 0 - only root should have UID 0", [user])
}

# CIS 6.2.10: Ensure local interactive user home directories exist
violations contains msg if {
	some user in input.user_group.users_without_home_directory
	msg := sprintf("CIS 6.2.10: User %s home directory does not exist", [user])
}

# CIS 6.2.11: Ensure local interactive users own their home directories
violations contains msg if {
	some entry in input.user_group.users_not_owning_home
	msg := sprintf("CIS 6.2.11: User %s does not own their home directory %s", [entry.user, entry.home])
}

# CIS 6.2.12: Ensure local interactive user home directories are mode 750 or more restrictive
violations contains msg if {
	some entry in input.user_group.home_dirs_too_permissive
	msg := sprintf("CIS 6.2.12: User %s home directory %s has permissions %s (should be 750 or more restrictive)", [entry.user, entry.home, entry.mode])
}

# CIS 6.2.13: Ensure no local interactive user has .netrc files
violations contains msg if {
	some entry in input.user_group.users_with_netrc
	msg := sprintf("CIS 6.2.13: User %s has .netrc file: %s", [entry.user, entry.path])
}

# CIS 6.2.14: Ensure no local interactive user has .forward files
violations contains msg if {
	some entry in input.user_group.users_with_forward
	msg := sprintf("CIS 6.2.14: User %s has .forward file: %s", [entry.user, entry.path])
}

# CIS 6.2.15: Ensure no local interactive user has .rhosts files
violations contains msg if {
	some entry in input.user_group.users_with_rhosts
	msg := sprintf("CIS 6.2.15: User %s has .rhosts file: %s", [entry.user, entry.path])
}

# CIS 6.2.16: Ensure local interactive user dot files are not group or world writable
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
	"benchmark": "CIS Rocky Linux 8 v2.0.0",
}
