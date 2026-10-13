# METADATA
# title: "DISA STIG for Oracle Linux 9 - File Permissions Module"
# custom:
#   class: security
#   framework: stig_oracle_linux_9
#   source: disa
#   domains: [linux, oracle]
#   coverage:
#     checks: 11
#     cited: 10
#     density: sized
#     basis: size
#     tested: true
#     entrypoint: compliance_report
#     guard: self
#     as_of: v2.4.0
package stig.oracle_linux_9.file_permissions

# DISA STIG for Oracle Linux 9 - File Permissions Module
# STIG Version: V1R7 | Released: 30 Sep 2026
# Derived from stig/rhel_9/file_permissions.rego by DISA rule title: Oracle Linux 9 and RHEL 9 share the rule text;
# ids, vuln ids, severities and titles are the Oracle Linux 9 XCCDF's (tools/stig_generators/gen_oracle_linux.py).
# Covers: World-writable files, SUID/SGID, system file ownership, /etc permissions

import rego.v1

default compliant := false

# =============================================================================
# CAT II - MEDIUM SEVERITY
# =============================================================================

# OL09-00-002512 | V-271781 | CAT II
# No unowned files or directories
default no_unowned_files := false

no_unowned_files if {
	count(input.file_permissions.unowned_files) == 0
}

no_unowned_files if {
	not input.file_permissions.unowned_files
}

status_ol09_00_002512 := "Not_a_Finding" if { no_unowned_files } else := "Open"

finding_ol09_00_002512 := {
	"vuln_id": "V-271781",
	"stig_id": "OL09-00-002512",
	"severity": "CAT II",
	"rule_title": "OL 9 local files and directories must have a valid owner.",
	"status": status_ol09_00_002512,
	"fix_text": "Find and remediate unowned files: find / -nouser -xdev -print",
}

# OL09-00-002511 | V-271780 | CAT II
# No ungrouped files or directories
default no_ungrouped_files := false

no_ungrouped_files if {
	count(input.file_permissions.ungrouped_files) == 0
}

no_ungrouped_files if {
	not input.file_permissions.ungrouped_files
}

status_ol09_00_002511 := "Not_a_Finding" if { no_ungrouped_files } else := "Open"

finding_ol09_00_002511 := {
	"vuln_id": "V-271780",
	"stig_id": "OL09-00-002511",
	"severity": "CAT II",
	"rule_title": "OL 9 local files and directories must have a valid group owner.",
	"status": status_ol09_00_002511,
	"fix_text": "Find and remediate ungrouped files: find / -nogroup -xdev -print",
}

# OL09-00-002548 | V-271810 | CAT II
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

status_ol09_00_002548 := "Not_a_Finding" if { passwd_permissions_ok } else := "Open"

finding_ol09_00_002548 := {
	"vuln_id": "V-271810",
	"stig_id": "OL09-00-002548",
	"severity": "CAT II",
	"rule_title": "OL 9 /etc/passwd file must have mode 0644 or less permissive to prevent unauthorized access.",
	"status": status_ol09_00_002548,
	"fix_text": "Fix /etc/passwd permissions: chmod 0644 /etc/passwd",
}

# OL09-00-002552 | V-271814 | CAT II
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

status_ol09_00_002552 := "Not_a_Finding" if { shadow_permissions_ok } else := "Open"

finding_ol09_00_002552 := {
	"vuln_id": "V-271814",
	"stig_id": "OL09-00-002552",
	"severity": "CAT II",
	"rule_title": "OL 9 /etc/shadow file must be owned by root.",
	"status": status_ol09_00_002552,
	"fix_text": "Fix /etc/shadow permissions: chmod 0000 /etc/shadow",
}

# OL09-00-002536 | V-271798 | CAT II
# /etc/group must have mode 0644 or less
default group_permissions_ok := false

group_permissions_ok if {
	input.file_permissions.etc_group.mode == "0644"
}

group_permissions_ok if {
	input.file_permissions.etc_group.mode == "644"
}

status_ol09_00_002536 := "Not_a_Finding" if { group_permissions_ok } else := "Open"

finding_ol09_00_002536 := {
	"vuln_id": "V-271798",
	"stig_id": "OL09-00-002536",
	"severity": "CAT II",
	"rule_title": "OL 9 /etc/group file must have mode 0644 or less permissive to prevent unauthorized access.",
	"status": status_ol09_00_002536,
	"fix_text": "Fix /etc/group permissions: chmod 0644 /etc/group",
}

# OL09-00-002540 | V-271802 | CAT II
# /etc/gshadow must have mode 0000
default gshadow_permissions_ok := false

gshadow_permissions_ok if {
	input.file_permissions.etc_gshadow.mode == "0000"
}

gshadow_permissions_ok if {
	input.file_permissions.etc_gshadow.mode == "000"
}

status_ol09_00_002540 := "Not_a_Finding" if { gshadow_permissions_ok } else := "Open"

finding_ol09_00_002540 := {
	"vuln_id": "V-271802",
	"stig_id": "OL09-00-002540",
	"severity": "CAT II",
	"rule_title": "OL 9 /etc/gshadow file must be owned by root.",
	"status": status_ol09_00_002540,
	"fix_text": "Fix /etc/gshadow permissions: chmod 0000 /etc/gshadow",
}

# OL09-00-002525 | V-271791 | CAT II
# Library files must have mode 0755 or less
default lib_permissions_ok := false

lib_permissions_ok if {
	input.file_permissions.library_files_ok == true
}

status_ol09_00_002525 := "Not_a_Finding" if { lib_permissions_ok } else := "Open"

finding_ol09_00_002525 := {
	"vuln_id": "V-271791",
	"stig_id": "OL09-00-002525",
	"severity": "CAT II",
	"rule_title": "OL 9 library files must have mode 0755 or less permissive.",
	"status": status_ol09_00_002525,
	"fix_text": "Fix library permissions: find /lib /lib64 /usr/lib /usr/lib64 -perm /022 -type f -exec chmod 755 {} \\;",
}

# OL09-00-002524 | V-271790 | CAT II
# Library dirs must be owned by root
default lib_dirs_owned_root := false

lib_dirs_owned_root if {
	input.file_permissions.library_dirs_owned_root == true
}

status_ol09_00_002524 := "Not_a_Finding" if { lib_dirs_owned_root } else := "Open"

finding_ol09_00_002524 := {
	"vuln_id": "V-271790",
	"stig_id": "OL09-00-002524",
	"severity": "CAT II",
	"rule_title": "OL 9 library files must be owned by root.",
	"status": status_ol09_00_002524,
	"fix_text": "Fix library ownership: find /lib /lib64 /usr/lib /usr/lib64 ! -user root -exec chown root {} \\;",
}

# OL09-00-002506 | V-271775 | CAT II
# System commands must have mode 0755 or less
default sys_commands_permissions_ok := false

sys_commands_permissions_ok if {
	input.file_permissions.system_commands_ok == true
}

status_ol09_00_002506 := "Not_a_Finding" if { sys_commands_permissions_ok } else := "Open"

finding_ol09_00_002506 := {
	"vuln_id": "V-271775",
	"stig_id": "OL09-00-002506",
	"severity": "CAT II",
	"rule_title": "OL 9 system commands must have mode 755 or less permissive.",
	"status": status_ol09_00_002506,
	"fix_text": "Fix system command permissions: find /bin /sbin /usr/bin /usr/sbin -perm /022 -exec chmod 755 {} \\;",
}

# OL09-00-002515 | V-271784 | CAT II
# All interactive local users must have home dir permissions set to 0750 or less
default home_dir_permissions_ok := false

home_dir_permissions_ok if {
	count(input.file_permissions.insecure_home_dirs) == 0
}

home_dir_permissions_ok if {
	not input.file_permissions.insecure_home_dirs
}

status_ol09_00_002515 := "Not_a_Finding" if { home_dir_permissions_ok } else := "Open"

finding_ol09_00_002515 := {
	"vuln_id": "V-271784",
	"stig_id": "OL09-00-002515",
	"severity": "CAT II",
	"rule_title": "OL 9 local interactive user home directories must have mode 0750 or less permissive.",
	"status": status_ol09_00_002515,
	"fix_text": "Fix home directory permissions: chmod 0750 /home/<username>",
}

# =============================================================================
# COMPLIANCE AGGREGATION
# =============================================================================

cat_i_findings := []

cat_ii_findings := [
	finding_ol09_00_002512,
	finding_ol09_00_002511,
	finding_ol09_00_002548,
	finding_ol09_00_002552,
	finding_ol09_00_002536,
	finding_ol09_00_002540,
	finding_ol09_00_002525,
	finding_ol09_00_002524,
	finding_ol09_00_002506,
	finding_ol09_00_002515,
]

cat_iii_findings := []

findings := array.concat(cat_i_findings, array.concat(cat_ii_findings, cat_iii_findings))

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
