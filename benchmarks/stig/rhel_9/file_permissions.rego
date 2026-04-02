package stig.rhel_9.file_permissions

# DISA STIG for RHEL 9 - File Permissions Module
# STIG Version: V2R2 | Released: October 2024
# Covers: World-writable files, SUID/SGID, system file ownership, /etc permissions

import rego.v1

default compliant := false

# =============================================================================
# CAT I - HIGH SEVERITY
# =============================================================================

# RHEL-09-232010 | V-257870 | CAT I
# World-writable files must not exist
default no_world_writable_files := false

no_world_writable_files if {
	count(input.file_permissions.world_writable_files) == 0
}

no_world_writable_files if {
	not input.file_permissions.world_writable_files
}

status_rhel_09_232010 := "Not_a_Finding" if { no_world_writable_files } else := "Open"

finding_rhel_09_232010 := {
	"vuln_id": "V-257870",
	"stig_id": "RHEL-09-232010",
	"severity": "CAT I",
	"rule_title": "RHEL 9 must have no world-writable files or directories",
	"status": status_rhel_09_232010,
	"fix_text": "Remove world-writable permissions: find / -xdev -type f -perm -002 -exec chmod o-w {} \\;",
}

# RHEL-09-232015 | V-257871 | CAT I
# No unowned files or directories
default no_unowned_files := false

no_unowned_files if {
	count(input.file_permissions.unowned_files) == 0
}

no_unowned_files if {
	not input.file_permissions.unowned_files
}

status_rhel_09_232015 := "Not_a_Finding" if { no_unowned_files } else := "Open"

finding_rhel_09_232015 := {
	"vuln_id": "V-257871",
	"stig_id": "RHEL-09-232015",
	"severity": "CAT I",
	"rule_title": "RHEL 9 must have no files or directories not owned by a valid user",
	"status": status_rhel_09_232015,
	"fix_text": "Find and remediate unowned files: find / -nouser -xdev -print",
}

# RHEL-09-232020 | V-257872 | CAT I
# No ungrouped files or directories
default no_ungrouped_files := false

no_ungrouped_files if {
	count(input.file_permissions.ungrouped_files) == 0
}

no_ungrouped_files if {
	not input.file_permissions.ungrouped_files
}

status_rhel_09_232020 := "Not_a_Finding" if { no_ungrouped_files } else := "Open"

finding_rhel_09_232020 := {
	"vuln_id": "V-257872",
	"stig_id": "RHEL-09-232020",
	"severity": "CAT I",
	"rule_title": "RHEL 9 must have no files or directories not owned by a valid group",
	"status": status_rhel_09_232020,
	"fix_text": "Find and remediate ungrouped files: find / -nogroup -xdev -print",
}

# =============================================================================
# CAT II - MEDIUM SEVERITY
# =============================================================================

# RHEL-09-232025 | V-257873 | CAT II
# /etc/passwd must have mode 0644 or less
default passwd_permissions_ok := false

passwd_permissions_ok if {
	input.file_permissions.etc_passwd.mode
	mode := input.file_permissions.etc_passwd.mode
	bits := to_number(mode)
	bits <= 420 # 0644 octal = 420 decimal
}

passwd_permissions_ok if {
	input.file_permissions.etc_passwd.mode == "0644"
}

passwd_permissions_ok if {
	input.file_permissions.etc_passwd.mode == "644"
}

status_rhel_09_232025 := "Not_a_Finding" if { passwd_permissions_ok } else := "Open"

finding_rhel_09_232025 := {
	"vuln_id": "V-257873",
	"stig_id": "RHEL-09-232025",
	"severity": "CAT II",
	"rule_title": "RHEL 9 /etc/passwd file must have mode 0644 or less permissive",
	"status": status_rhel_09_232025,
	"fix_text": "Fix /etc/passwd permissions: chmod 0644 /etc/passwd",
}

# RHEL-09-232030 | V-257874 | CAT II
# /etc/shadow must have mode 0000
default shadow_permissions_ok := false

shadow_permissions_ok if {
	input.file_permissions.etc_shadow.mode == "0000"
}

shadow_permissions_ok if {
	input.file_permissions.etc_shadow.mode == "000"
}

shadow_permissions_ok if {
	input.file_permissions.etc_shadow.mode == "0"
}

status_rhel_09_232030 := "Not_a_Finding" if { shadow_permissions_ok } else := "Open"

finding_rhel_09_232030 := {
	"vuln_id": "V-257874",
	"stig_id": "RHEL-09-232030",
	"severity": "CAT II",
	"rule_title": "RHEL 9 /etc/shadow file must be owned by root",
	"status": status_rhel_09_232030,
	"fix_text": "Fix /etc/shadow permissions: chmod 0000 /etc/shadow",
}

# RHEL-09-232035 | V-257875 | CAT II
# /etc/group must have mode 0644 or less
default group_permissions_ok := false

group_permissions_ok if {
	input.file_permissions.etc_group.mode == "0644"
}

group_permissions_ok if {
	input.file_permissions.etc_group.mode == "644"
}

status_rhel_09_232035 := "Not_a_Finding" if { group_permissions_ok } else := "Open"

finding_rhel_09_232035 := {
	"vuln_id": "V-257875",
	"stig_id": "RHEL-09-232035",
	"severity": "CAT II",
	"rule_title": "RHEL 9 /etc/group file must have mode 0644 or less permissive",
	"status": status_rhel_09_232035,
	"fix_text": "Fix /etc/group permissions: chmod 0644 /etc/group",
}

# RHEL-09-232040 | V-257876 | CAT II
# /etc/gshadow must have mode 0000
default gshadow_permissions_ok := false

gshadow_permissions_ok if {
	input.file_permissions.etc_gshadow.mode == "0000"
}

gshadow_permissions_ok if {
	input.file_permissions.etc_gshadow.mode == "000"
}

status_rhel_09_232040 := "Not_a_Finding" if { gshadow_permissions_ok } else := "Open"

finding_rhel_09_232040 := {
	"vuln_id": "V-257876",
	"stig_id": "RHEL-09-232040",
	"severity": "CAT II",
	"rule_title": "RHEL 9 /etc/gshadow file must be owned by root",
	"status": status_rhel_09_232040,
	"fix_text": "Fix /etc/gshadow permissions: chmod 0000 /etc/gshadow",
}

# RHEL-09-232045 | V-257877 | CAT II
# All SUID executables must be documented
default suid_files_reviewed := false

suid_files_reviewed if {
	count(input.file_permissions.undocumented_suid_files) == 0
}

suid_files_reviewed if {
	not input.file_permissions.undocumented_suid_files
}

status_rhel_09_232045 := "Not_a_Finding" if { suid_files_reviewed } else := "Open"

finding_rhel_09_232045 := {
	"vuln_id": "V-257877",
	"stig_id": "RHEL-09-232045",
	"severity": "CAT II",
	"rule_title": "RHEL 9 must have no unauthorized SUID or SGID files",
	"status": status_rhel_09_232045,
	"fix_text": "Review SUID/SGID files: find / -xdev \\( -perm -4000 -o -perm -2000 \\) -type f",
}

# RHEL-09-232050 | V-257878 | CAT II
# Library files must have mode 0755 or less
default lib_permissions_ok := false

lib_permissions_ok if {
	input.file_permissions.library_files_ok == true
}

status_rhel_09_232050 := "Not_a_Finding" if { lib_permissions_ok } else := "Open"

finding_rhel_09_232050 := {
	"vuln_id": "V-257878",
	"stig_id": "RHEL-09-232050",
	"severity": "CAT II",
	"rule_title": "RHEL 9 library files must have mode 0755 or less permissive",
	"status": status_rhel_09_232050,
	"fix_text": "Fix library permissions: find /lib /lib64 /usr/lib /usr/lib64 -perm /022 -type f -exec chmod 755 {} \\;",
}

# RHEL-09-232055 | V-257879 | CAT II
# Library dirs must be owned by root
default lib_dirs_owned_root := false

lib_dirs_owned_root if {
	input.file_permissions.library_dirs_owned_root == true
}

status_rhel_09_232055 := "Not_a_Finding" if { lib_dirs_owned_root } else := "Open"

finding_rhel_09_232055 := {
	"vuln_id": "V-257879",
	"stig_id": "RHEL-09-232055",
	"severity": "CAT II",
	"rule_title": "RHEL 9 library files must be owned by root",
	"status": status_rhel_09_232055,
	"fix_text": "Fix library ownership: find /lib /lib64 /usr/lib /usr/lib64 ! -user root -exec chown root {} \\;",
}

# RHEL-09-232060 | V-257880 | CAT II
# System commands must have mode 0755 or less
default sys_commands_permissions_ok := false

sys_commands_permissions_ok if {
	input.file_permissions.system_commands_ok == true
}

status_rhel_09_232060 := "Not_a_Finding" if { sys_commands_permissions_ok } else := "Open"

finding_rhel_09_232060 := {
	"vuln_id": "V-257880",
	"stig_id": "RHEL-09-232060",
	"severity": "CAT II",
	"rule_title": "RHEL 9 system commands must have mode 0755 or less permissive",
	"status": status_rhel_09_232060,
	"fix_text": "Fix system command permissions: find /bin /sbin /usr/bin /usr/sbin -perm /022 -exec chmod 755 {} \\;",
}

# RHEL-09-232065 | V-257881 | CAT II
# All interactive local users must have home dir permissions set to 0750 or less
default home_dir_permissions_ok := false

home_dir_permissions_ok if {
	count(input.file_permissions.insecure_home_dirs) == 0
}

home_dir_permissions_ok if {
	not input.file_permissions.insecure_home_dirs
}

status_rhel_09_232065 := "Not_a_Finding" if { home_dir_permissions_ok } else := "Open"

finding_rhel_09_232065 := {
	"vuln_id": "V-257881",
	"stig_id": "RHEL-09-232065",
	"severity": "CAT II",
	"rule_title": "RHEL 9 local interactive user home directories must have mode 0750 or less permissive",
	"status": status_rhel_09_232065,
	"fix_text": "Fix home directory permissions: chmod 0750 /home/<username>",
}

# RHEL-09-232070 | V-257882 | CAT II
# /etc/cron.allow must be mode 0600
default cron_allow_permissions_ok := false

cron_allow_permissions_ok if {
	input.cron_allow.permissions == "0600"
}

cron_allow_permissions_ok if {
	input.cron_allow.permissions == "600"
}

cron_allow_permissions_ok if {
	not input.cron_allow.file_exists
}

status_rhel_09_232070 := "Not_a_Finding" if { cron_allow_permissions_ok } else := "Open"

finding_rhel_09_232070 := {
	"vuln_id": "V-257882",
	"stig_id": "RHEL-09-232070",
	"severity": "CAT II",
	"rule_title": "RHEL 9 cron configuration files must have mode 0600 or less permissive",
	"status": status_rhel_09_232070,
	"fix_text": "Fix cron.allow permissions: chmod 0600 /etc/cron.allow",
}

# =============================================================================
# COMPLIANCE AGGREGATION
# =============================================================================

cat_i_findings := [
	finding_rhel_09_232010,
	finding_rhel_09_232015,
	finding_rhel_09_232020,
]

cat_ii_findings := [
	finding_rhel_09_232025,
	finding_rhel_09_232030,
	finding_rhel_09_232035,
	finding_rhel_09_232040,
	finding_rhel_09_232045,
	finding_rhel_09_232050,
	finding_rhel_09_232055,
	finding_rhel_09_232060,
	finding_rhel_09_232065,
	finding_rhel_09_232070,
]

findings := array.concat(cat_i_findings, cat_ii_findings)

violations contains finding.stig_id if {
	some finding in findings
	finding.status == "Open"
}

open_cat_i contains f if {
	some f in cat_i_findings
	f.status == "Open"
}

compliant if {
	count(open_cat_i) == 0
}

compliance_report := {
	"module": "file_permissions",
	"total_findings": count(findings),
	"open_findings": count(violations),
	"cat_i_open": count(open_cat_i),
	"findings": findings,
	"compliant": compliant,
}
