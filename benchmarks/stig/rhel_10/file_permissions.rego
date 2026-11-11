# METADATA
# title: "DISA STIG for RHEL 10 - File Permissions Module"
# custom:
#   class: security
#   framework: stig_rhel_10
#   source: disa
#   domains: [linux, rhel]
#   coverage:
#     checks: 11
#     cited: 10
#     density: sized
#     basis: size
#     tested: true
#     entrypoint: compliance_report
#     guard: self
#     as_of: v2.4.2
package stig.rhel_10.file_permissions

# DISA STIG for RHEL 10 - File Permissions Module
# STIG Version: V1R2 | Released: 01 Jul 2026
# Derived from stig/rhel_9/file_permissions.rego by DISA rule title: RHEL 10 and RHEL 9 share the rule text;
# ids, vuln ids, severities and titles are the RHEL 10 XCCDF's (tools/stig_generators/gen_oracle_linux.py).
# Covers: World-writable files, SUID/SGID, system file ownership, /etc permissions

import rego.v1

default compliant := false

# =============================================================================
# SHARED HELPERS
# =============================================================================

# Shared helpers (defined in a source block whose rule RHEL 10 does not carry)

# true when mode grants nothing beyond max (both octal strings)
mode_within(mode, max) if bits.and(octal(mode), bits.and(bits.negate(octal(max)), 4095)) == 0

# Parse an octal permission string ("644", "0644", "0o644") to an integer; undefined if not octal.
octal(s) := n if {
	t := trim_prefix(lower(trim_space(sprintf("%v", [s]))), "0o")
	regex.match(`^[0-7]{1,4}$`, t)
	p := concat("", [substring("0000", 0, 4 - count(t)), t])
	ds := [to_number(substring(p, i, 1)) | some i in numbers.range(0, 3)]
	n := ((ds[0] * 512) + (ds[1] * 64)) + ((ds[2] * 8) + ds[3])
}

# =============================================================================
# CAT II - MEDIUM SEVERITY
# =============================================================================

# RHEL-10-400290 | V-281075 | CAT II
# No unowned files or directories
default no_unowned_files := false

no_unowned_files if {
	is_array(input.file_permissions.unowned_files)
	count(input.file_permissions.unowned_files) == 0
}

status_rhel_10_400290 := "Not_a_Finding" if no_unowned_files

else := "Open"

finding_rhel_10_400290 := {
	"vuln_id": "V-281075",
	"stig_id": "RHEL-10-400290",
	"severity": "CAT II",
	"rule_title": "RHEL 10 must be configured so that all local files and directories must have a valid owner.",
	"status": status_rhel_10_400290,
	"fix_text": "Find and remediate unowned files: find / -nouser -xdev -print",
}

# RHEL-10-400285 | V-281074 | CAT II
# No ungrouped files or directories
default no_ungrouped_files := false

no_ungrouped_files if {
	is_array(input.file_permissions.ungrouped_files)
	count(input.file_permissions.ungrouped_files) == 0
}

status_rhel_10_400285 := "Not_a_Finding" if no_ungrouped_files

else := "Open"

finding_rhel_10_400285 := {
	"vuln_id": "V-281074",
	"stig_id": "RHEL-10-400285",
	"severity": "CAT II",
	"rule_title": "RHEL 10 must be configured so that all local files and directories have a valid group owner.",
	"status": status_rhel_10_400285,
	"fix_text": "Find and remediate ungrouped files: find / -nogroup -xdev -print",
}

# RHEL-10-400265 | V-281070 | CAT II
# /etc/passwd must have mode 0644 or less
default passwd_permissions_ok := false

passwd_permissions_ok if {
	mode_within(input.file_permissions.etc_passwd.mode, "0644")
}

status_rhel_10_400265 := "Not_a_Finding" if passwd_permissions_ok

else := "Open"

finding_rhel_10_400265 := {
	"vuln_id": "V-281070",
	"stig_id": "RHEL-10-400265",
	"severity": "CAT II",
	"rule_title": "RHEL 10 must enforce mode \"0644\" or less permissive for the \"/etc/passwd\" file to prevent unauthorized access.",
	"status": status_rhel_10_400265,
	"fix_text": "Fix /etc/passwd permissions: chmod 0644 /etc/passwd",
}

# RHEL-10-400295 | V-281076 | CAT II
# /etc/shadow must have mode 0000
default shadow_permissions_ok := false

shadow_permissions_ok if {
	mode_within(input.file_permissions.etc_shadow.mode, "0000")
}

status_rhel_10_400295 := "Not_a_Finding" if shadow_permissions_ok

else := "Open"

finding_rhel_10_400295 := {
	"vuln_id": "V-281076",
	"stig_id": "RHEL-10-400295",
	"severity": "CAT II",
	"rule_title": "RHEL 10 must enforce mode \"0000\" for \"/etc/shadow\" to prevent unauthorized access.",
	"status": status_rhel_10_400295,
	"fix_text": "Fix /etc/shadow permissions: chmod 0000 /etc/shadow",
}

# RHEL-10-400245 | V-281066 | CAT II
# /etc/group must have mode 0644 or less
default group_permissions_ok := false

group_permissions_ok if {
	mode_within(input.file_permissions.etc_group.mode, "0644")
}

status_rhel_10_400245 := "Not_a_Finding" if group_permissions_ok

else := "Open"

finding_rhel_10_400245 := {
	"vuln_id": "V-281066",
	"stig_id": "RHEL-10-400245",
	"severity": "CAT II",
	"rule_title": "RHEL 10 must enforce mode \"0644\" or less permissive for the \"/etc/group\" file to prevent unauthorized access.",
	"status": status_rhel_10_400245,
	"fix_text": "Fix /etc/group permissions: chmod 0644 /etc/group",
}

# RHEL-10-400255 | V-281068 | CAT II
# /etc/gshadow must have mode 0000
default gshadow_permissions_ok := false

gshadow_permissions_ok if {
	mode_within(input.file_permissions.etc_gshadow.mode, "0000")
}

status_rhel_10_400255 := "Not_a_Finding" if gshadow_permissions_ok

else := "Open"

finding_rhel_10_400255 := {
	"vuln_id": "V-281068",
	"stig_id": "RHEL-10-400255",
	"severity": "CAT II",
	"rule_title": "RHEL 10 must enforce mode \"0000\" or less permissive for the \"/etc/gshadow\" file to prevent unauthorized access.",
	"status": status_rhel_10_400255,
	"fix_text": "Fix /etc/gshadow permissions: chmod 0000 /etc/gshadow",
}

# RHEL-10-400215 | V-281060 | CAT II
# Library files must have mode 0755 or less
default lib_permissions_ok := false

lib_permissions_ok if {
	input.file_permissions.library_files_ok == true
}

status_rhel_10_400215 := "Not_a_Finding" if lib_permissions_ok

else := "Open"

finding_rhel_10_400215 := {
	"vuln_id": "V-281060",
	"stig_id": "RHEL-10-400215",
	"severity": "CAT II",
	"rule_title": "RHEL 10 must enforce mode \"755\" or less permissive for library files.",
	"status": status_rhel_10_400215,
	"fix_text": "Fix library permissions: find /lib /lib64 /usr/lib /usr/lib64 -perm /022 -type f -exec chmod 755 {} \\;",
}

# RHEL-10-400110 | V-281039 | CAT II
# Library dirs must be owned by root
default lib_dirs_owned_root := false

lib_dirs_owned_root if {
	input.file_permissions.library_dirs_owned_root == true
}

status_rhel_10_400110 := "Not_a_Finding" if lib_dirs_owned_root

else := "Open"

finding_rhel_10_400110 := {
	"vuln_id": "V-281039",
	"stig_id": "RHEL-10-400110",
	"severity": "CAT II",
	"rule_title": "RHEL 10 must be configured so that library files are owned by \"root\".",
	"status": status_rhel_10_400110,
	"fix_text": "Fix library ownership: find /lib /lib64 /usr/lib /usr/lib64 ! -user root -exec chown root {} \\;",
}

# RHEL-10-400205 | V-281058 | CAT II
# System commands must have mode 0755 or less
default sys_commands_permissions_ok := false

sys_commands_permissions_ok if {
	input.file_permissions.system_commands_ok == true
}

status_rhel_10_400205 := "Not_a_Finding" if sys_commands_permissions_ok

else := "Open"

finding_rhel_10_400205 := {
	"vuln_id": "V-281058",
	"stig_id": "RHEL-10-400205",
	"severity": "CAT II",
	"rule_title": "RHEL 10 must enforce mode \"755\" or less permissive for system commands.",
	"status": status_rhel_10_400205,
	"fix_text": "Fix system command permissions: find /bin /sbin /usr/bin /usr/sbin -perm /022 -exec chmod 755 {} \\;",
}

# RHEL-10-400240 | V-281065 | CAT II
# All interactive local users must have home dir permissions set to 0750 or less
default home_dir_permissions_ok := false

home_dir_permissions_ok if {
	is_array(input.file_permissions.insecure_home_dirs)
	count(input.file_permissions.insecure_home_dirs) == 0
}

status_rhel_10_400240 := "Not_a_Finding" if home_dir_permissions_ok

else := "Open"

finding_rhel_10_400240 := {
	"vuln_id": "V-281065",
	"stig_id": "RHEL-10-400240",
	"severity": "CAT II",
	"rule_title": "RHEL 10 must enforce mode \"0750\" or less permissive for local interactive user home directories.",
	"status": status_rhel_10_400240,
	"fix_text": "Fix home directory permissions: chmod 0750 /home/<username>",
}

# =============================================================================
# COMPLIANCE AGGREGATION
# =============================================================================

# No CAT I rule in this module. array.concat rather than the literal `[]`: OPA >= 1.22
# types a literal empty array as having no members and rejects `some f in cat_i_findings`
# as an undefined ref, so the module fails to compile when it is loaded on its own
# (scripts/check_per_file_load.py).
cat_i_findings := array.concat([], [])

cat_ii_findings := [
	finding_rhel_10_400290,
	finding_rhel_10_400285,
	finding_rhel_10_400265,
	finding_rhel_10_400295,
	finding_rhel_10_400245,
	finding_rhel_10_400255,
	finding_rhel_10_400215,
	finding_rhel_10_400110,
	finding_rhel_10_400205,
	finding_rhel_10_400240,
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
