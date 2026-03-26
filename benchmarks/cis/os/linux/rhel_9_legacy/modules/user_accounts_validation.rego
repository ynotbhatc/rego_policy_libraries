package cis_rhel9.user_accounts_validation

import rego.v1

# CIS RHEL 9 Benchmark v2.0.0 - Sections 5.3-5.4 & 6.2: User Accounts and Environment
# Validates user account security and environment configuration

# =============================================================================
# CIS 5.3.1 - Ensure sudo is installed
# =============================================================================

validate_sudo_installed if {
    input.user_accounts.packages.sudo.installed == true
}

violations contains {
    "control_id": "5.3.1",
    "title": "Ensure sudo is installed",
    "severity": "high",
    "description": "sudo package should be installed for privilege escalation",
    "status": "fail",
    "finding": "sudo package is not installed",
    "remediation": "Run: dnf install sudo"
} if {
    not validate_sudo_installed
}

# =============================================================================
# CIS 5.3.2 - Ensure sudo commands use pty
# =============================================================================

validate_sudo_use_pty if {
    input.user_accounts.sudo_config.use_pty == true
}

violations contains {
    "control_id": "5.3.2",
    "title": "Ensure sudo commands use pty",
    "severity": "medium",
    "description": "sudo should require use of a pseudo terminal",
    "status": "fail",
    "finding": "Defaults use_pty is not configured in /etc/sudoers",
    "remediation": "Edit /etc/sudoers or add file to /etc/sudoers.d/ with 'Defaults use_pty'"
} if {
    not validate_sudo_use_pty
}

# =============================================================================
# CIS 5.3.3 - Ensure sudo log file exists
# =============================================================================

validate_sudo_logfile if {
    input.user_accounts.sudo_config.logfile != ""
}

violations contains {
    "control_id": "5.3.3",
    "title": "Ensure sudo log file exists",
    "severity": "medium",
    "description": "sudo commands should be logged to a dedicated log file",
    "status": "fail",
    "finding": "Defaults logfile is not configured in /etc/sudoers",
    "remediation": "Edit /etc/sudoers or add file to /etc/sudoers.d/ with 'Defaults logfile=\"/var/log/sudo.log\"'"
} if {
    not validate_sudo_logfile
}

# =============================================================================
# CIS 5.3.4 - Ensure users must provide password for privilege escalation
# =============================================================================

validate_sudo_nopasswd if {
    count(input.user_accounts.sudo_config.nopasswd_entries) == 0
}

violations contains {
    "control_id": "5.3.4",
    "title": "Ensure users must provide password for privilege escalation",
    "severity": "high",
    "description": "sudo should require password authentication (no NOPASSWD)",
    "status": "fail",
    "finding": sprintf("NOPASSWD entries found in sudoers: %v", [input.user_accounts.sudo_config.nopasswd_entries]),
    "remediation": "Remove NOPASSWD from /etc/sudoers and /etc/sudoers.d/* files"
} if {
    not validate_sudo_nopasswd
}

# =============================================================================
# CIS 5.3.5 - Ensure re-authentication for privilege escalation is not disabled
# =============================================================================

validate_sudo_authenticate if {
    count(input.user_accounts.sudo_config.authenticate_disabled) == 0
}

violations contains {
    "control_id": "5.3.5",
    "title": "Ensure re-authentication for privilege escalation is not disabled",
    "severity": "high",
    "description": "sudo should not have !authenticate flag set",
    "status": "fail",
    "finding": sprintf("!authenticate entries found in sudoers: %v", [input.user_accounts.sudo_config.authenticate_disabled]),
    "remediation": "Remove !authenticate from /etc/sudoers and /etc/sudoers.d/* files"
} if {
    not validate_sudo_authenticate
}

# =============================================================================
# CIS 5.3.6 - Ensure sudo authentication timeout is configured correctly
# =============================================================================

validate_sudo_timeout if {
    to_number(input.user_accounts.sudo_config.timestamp_timeout) <= 15
}

violations contains {
    "control_id": "5.3.6",
    "title": "Ensure sudo authentication timeout is configured correctly",
    "severity": "medium",
    "description": "sudo timestamp timeout should be 15 minutes or less",
    "status": "fail",
    "finding": sprintf("sudo timestamp_timeout=%v (should be <= 15)", [input.user_accounts.sudo_config.timestamp_timeout]),
    "remediation": "Edit /etc/sudoers and set 'Defaults timestamp_timeout=15'"
} if {
    not validate_sudo_timeout
}

# =============================================================================
# CIS 5.3.7 - Ensure access to the su command is restricted
# =============================================================================

validate_su_restricted if {
    input.user_accounts.su_restricted == true
}

violations contains {
    "control_id": "5.3.7",
    "title": "Ensure access to the su command is restricted",
    "severity": "high",
    "description": "Access to su should be restricted to wheel group via pam_wheel",
    "status": "fail",
    "finding": "pam_wheel is not configured to restrict su access",
    "remediation": "Edit /etc/pam.d/su and uncomment: auth required pam_wheel.so use_uid"
} if {
    not validate_su_restricted
}

# =============================================================================
# CIS 6.2.1 - Ensure accounts in /etc/passwd use shadowed passwords
# =============================================================================

validate_shadowed_passwords if {
    count(input.user_accounts.users_without_shadowed_passwords) == 0
}

violations contains {
    "control_id": "6.2.1",
    "title": "Ensure accounts in /etc/passwd use shadowed passwords",
    "severity": "critical",
    "description": "All accounts should use shadowed passwords (x in password field)",
    "status": "fail",
    "finding": sprintf("Users without shadowed passwords: %v", [input.user_accounts.users_without_shadowed_passwords]),
    "remediation": "Run: pwconv to convert passwords to shadow format"
} if {
    not validate_shadowed_passwords
}

# =============================================================================
# CIS 6.2.2 - Ensure password fields are not empty
# =============================================================================

validate_no_empty_passwords if {
    count(input.user_accounts.users_with_empty_passwords) == 0
}

violations contains {
    "control_id": "6.2.2",
    "title": "Ensure password fields are not empty",
    "severity": "critical",
    "description": "No user should have an empty password field",
    "status": "fail",
    "finding": sprintf("Users with empty passwords: %v", [input.user_accounts.users_with_empty_passwords]),
    "remediation": "Run: passwd -l <username> to lock accounts with empty passwords"
} if {
    not validate_no_empty_passwords
}

# =============================================================================
# CIS 6.2.3 - Ensure all groups in /etc/passwd exist in /etc/group
# =============================================================================

validate_passwd_groups_exist if {
    count(input.user_accounts.passwd_groups_not_in_group_file) == 0
}

violations contains {
    "control_id": "6.2.3",
    "title": "Ensure all groups in /etc/passwd exist in /etc/group",
    "severity": "medium",
    "description": "All group IDs in /etc/passwd should have corresponding entries in /etc/group",
    "status": "fail",
    "finding": sprintf("GIDs in /etc/passwd without /etc/group entry: %v", [input.user_accounts.passwd_groups_not_in_group_file]),
    "remediation": "Create missing groups or correct user GIDs"
} if {
    not validate_passwd_groups_exist
}

# =============================================================================
# CIS 6.2.4 - Ensure shadow group is empty
# =============================================================================

validate_shadow_group_empty if {
    count(input.user_accounts.shadow_group_members) == 0
}

violations contains {
    "control_id": "6.2.4",
    "title": "Ensure shadow group is empty",
    "severity": "medium",
    "description": "The shadow group should not contain any users",
    "status": "fail",
    "finding": sprintf("Users in shadow group: %v", [input.user_accounts.shadow_group_members]),
    "remediation": "Remove all users from the shadow group in /etc/group"
} if {
    not validate_shadow_group_empty
}

# =============================================================================
# CIS 6.2.5 - Ensure no duplicate UIDs exist
# =============================================================================

validate_no_duplicate_uids if {
    count(input.user_accounts.duplicate_uids) == 0
}

violations contains {
    "control_id": "6.2.5",
    "title": "Ensure no duplicate UIDs exist",
    "severity": "high",
    "description": "All user UIDs should be unique",
    "status": "fail",
    "finding": sprintf("Duplicate UIDs found: %v", [input.user_accounts.duplicate_uids]),
    "remediation": "Change duplicate UIDs to unique values"
} if {
    not validate_no_duplicate_uids
}

# =============================================================================
# CIS 6.2.6 - Ensure no duplicate GIDs exist
# =============================================================================

validate_no_duplicate_gids if {
    count(input.user_accounts.duplicate_gids) == 0
}

violations contains {
    "control_id": "6.2.6",
    "title": "Ensure no duplicate GIDs exist",
    "severity": "high",
    "description": "All group GIDs should be unique",
    "status": "fail",
    "finding": sprintf("Duplicate GIDs found: %v", [input.user_accounts.duplicate_gids]),
    "remediation": "Change duplicate GIDs to unique values"
} if {
    not validate_no_duplicate_gids
}

# =============================================================================
# CIS 6.2.7 - Ensure no duplicate user names exist
# =============================================================================

validate_no_duplicate_usernames if {
    count(input.user_accounts.duplicate_usernames) == 0
}

violations contains {
    "control_id": "6.2.7",
    "title": "Ensure no duplicate user names exist",
    "severity": "high",
    "description": "All usernames should be unique",
    "status": "fail",
    "finding": sprintf("Duplicate usernames found: %v", [input.user_accounts.duplicate_usernames]),
    "remediation": "Remove or rename duplicate user accounts"
} if {
    not validate_no_duplicate_usernames
}

# =============================================================================
# CIS 6.2.8 - Ensure no duplicate group names exist
# =============================================================================

validate_no_duplicate_groupnames if {
    count(input.user_accounts.duplicate_groupnames) == 0
}

violations contains {
    "control_id": "6.2.8",
    "title": "Ensure no duplicate group names exist",
    "severity": "high",
    "description": "All group names should be unique",
    "status": "fail",
    "finding": sprintf("Duplicate group names found: %v", [input.user_accounts.duplicate_groupnames]),
    "remediation": "Remove or rename duplicate groups"
} if {
    not validate_no_duplicate_groupnames
}

# =============================================================================
# CIS 6.2.9 - Ensure root PATH Integrity
# =============================================================================

validate_root_path if {
    input.user_accounts.root_path_issues.contains_empty == false
    input.user_accounts.root_path_issues.contains_dot == false
    input.user_accounts.root_path_issues.contains_group_writable == false
    input.user_accounts.root_path_issues.contains_world_writable == false
}

violations contains {
    "control_id": "6.2.9",
    "title": "Ensure root PATH Integrity",
    "severity": "high",
    "description": "root's PATH should not contain empty entries, '.', or writable directories",
    "status": "fail",
    "finding": sprintf("root PATH issues: empty=%v dot=%v group_writable=%v world_writable=%v", [
        input.user_accounts.root_path_issues.contains_empty,
        input.user_accounts.root_path_issues.contains_dot,
        input.user_accounts.root_path_issues.contains_group_writable,
        input.user_accounts.root_path_issues.contains_world_writable
    ]),
    "remediation": "Correct root's PATH by removing ':', '.', and fixing directory permissions"
} if {
    not validate_root_path
}

# =============================================================================
# CIS 6.2.10 - Ensure root is the only UID 0 account
# =============================================================================

validate_only_root_uid_0 if {
    count(input.user_accounts.uid_0_accounts) == 1
    input.user_accounts.uid_0_accounts[0] == "root"
}

violations contains {
    "control_id": "6.2.10",
    "title": "Ensure root is the only UID 0 account",
    "severity": "critical",
    "description": "Only the root account should have UID 0",
    "status": "fail",
    "finding": sprintf("Accounts with UID 0: %v", [input.user_accounts.uid_0_accounts]),
    "remediation": "Remove or change UID for non-root accounts with UID 0"
} if {
    not validate_only_root_uid_0
}

# =============================================================================
# CIS 6.2.11 - Ensure local interactive user home directories exist
# =============================================================================

validate_home_directories_exist if {
    count(input.user_accounts.users_without_home_directory) == 0
}

violations contains {
    "control_id": "6.2.11",
    "title": "Ensure local interactive user home directories exist",
    "severity": "medium",
    "description": "All local interactive users should have a home directory that exists",
    "status": "fail",
    "finding": sprintf("Users with missing home directories: %v", [input.user_accounts.users_without_home_directory]),
    "remediation": "Create missing home directories: mkdir /home/<username> && chown <username>:<group> /home/<username>"
} if {
    not validate_home_directories_exist
}

# =============================================================================
# CIS 6.2.12 - Ensure local interactive user home directories are configured
# =============================================================================

validate_home_directory_permissions(user) if {
    user.home_mode_octal <= 750
    user.home_owner == user.username
}

violations contains {
    "control_id": "6.2.12",
    "title": "Ensure local interactive user home directories are configured",
    "severity": "medium",
    "description": "User home directories should be mode 750 or more restrictive and owned by the user",
    "status": "fail",
    "finding": sprintf("User %v home directory %v: mode=%v owner=%v", [
        user.username,
        user.home,
        user.home_mode,
        user.home_owner
    ]),
    "remediation": sprintf("Run: chmod 750 %v && chown %v:%v %v", [
        user.home,
        user.username,
        user.primary_group,
        user.home
    ])
} if {
    some user in input.user_accounts.interactive_users
    not validate_home_directory_permissions(user)
}

# =============================================================================
# CIS 6.2.13 - Ensure local interactive user dot files access is configured
# =============================================================================

validate_user_dot_files(user) if {
    count(user.group_writable_dot_files) == 0
    count(user.world_writable_dot_files) == 0
}

violations contains {
    "control_id": "6.2.13",
    "title": "Ensure local interactive user dot files access is configured",
    "severity": "medium",
    "description": "User dot files should not be group or world writable",
    "status": "fail",
    "finding": sprintf("User %v has writable dot files: group_writable=%v world_writable=%v", [
        user.username,
        user.group_writable_dot_files,
        user.world_writable_dot_files
    ]),
    "remediation": sprintf("Remove write permissions for group and other on dot files for user %v", [user.username])
} if {
    some user in input.user_accounts.interactive_users
    not validate_user_dot_files(user)
}

# =============================================================================
# CIS 6.2.14 - Ensure no local interactive user has .netrc files
# =============================================================================

validate_no_netrc_files if {
    count(input.user_accounts.users_with_netrc) == 0
}

violations contains {
    "control_id": "6.2.14",
    "title": "Ensure no local interactive user has .netrc files",
    "severity": "medium",
    "description": ".netrc files can contain passwords and should not be used",
    "status": "fail",
    "finding": sprintf("Users with .netrc files: %v", [input.user_accounts.users_with_netrc]),
    "remediation": "Remove .netrc files from user home directories"
} if {
    not validate_no_netrc_files
}

# =============================================================================
# CIS 6.2.15 - Ensure no local interactive user has .forward files
# =============================================================================

validate_no_forward_files if {
    count(input.user_accounts.users_with_forward) == 0
}

violations contains {
    "control_id": "6.2.15",
    "title": "Ensure no local interactive user has .forward files",
    "severity": "low",
    "description": ".forward files can be used to forward mail and should be removed",
    "status": "fail",
    "finding": sprintf("Users with .forward files: %v", [input.user_accounts.users_with_forward]),
    "remediation": "Remove .forward files from user home directories"
} if {
    not validate_no_forward_files
}

# =============================================================================
# CIS 6.2.16 - Ensure no local interactive user has .rhosts files
# =============================================================================

validate_no_rhosts_files if {
    count(input.user_accounts.users_with_rhosts) == 0
}

violations contains {
    "control_id": "6.2.16",
    "title": "Ensure no local interactive user has .rhosts files",
    "severity": "high",
    "description": ".rhosts files allow remote access without authentication and should be removed",
    "status": "fail",
    "finding": sprintf("Users with .rhosts files: %v", [input.user_accounts.users_with_rhosts]),
    "remediation": "Remove .rhosts files from user home directories"
} if {
    not validate_no_rhosts_files
}

# =============================================================================
# Summary Functions
# =============================================================================

# Collect all user account violations
user_accounts_violations := violations

# Count total user account controls
total_user_accounts_controls := 23

# Count passed user account controls
passed_user_accounts_controls := total_user_accounts_controls - count(user_accounts_violations)

# User accounts compliance percentage
user_accounts_compliance_percentage := (passed_user_accounts_controls / total_user_accounts_controls) * 100
