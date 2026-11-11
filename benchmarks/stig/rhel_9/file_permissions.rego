# METADATA
# title: "DISA STIG for RHEL 9 - File Permissions Module"
# custom:
#   class: security
#   framework: stig_rhel_9
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
package stig.rhel_9.file_permissions

# DISA STIG for RHEL 9 - File Permissions Module
# STIG Version: V2R10 | Released: 30 Sep 2026
# Rule ids, vuln ids, severities and titles stamped from the October 2026 SRG-STIG library XCCDF on 2026-11-10
# (tools/stig_generators/stamp_catalog.py); each finding is keyed on the fact its logic checks.
# Covers: World-writable files, SUID/SGID, system file ownership, /etc permissions

import rego.v1

default compliant := false

# Parse an octal permission string ("644", "0644", "0o644") to an integer; undefined if not octal.
octal(s) := n if {
	t := trim_prefix(lower(trim_space(sprintf("%v", [s]))), "0o")
	regex.match(`^[0-7]{1,4}$`, t)
	p := concat("", [substring("0000", 0, 4 - count(t)), t])
	ds := [to_number(substring(p, i, 1)) | some i in numbers.range(0, 3)]
	n := ((ds[0] * 512) + (ds[1] * 64)) + ((ds[2] * 8) + ds[3])
}

# true when mode grants nothing beyond max (both octal strings)
mode_within(mode, max) if bits.and(octal(mode), bits.and(bits.negate(octal(max)), 4095)) == 0

# =============================================================================
# CAT I - HIGH SEVERITY
# =============================================================================

# =============================================================================
# CAT II - MEDIUM SEVERITY
# =============================================================================

# RHEL-09-232255 | V-257931 | CAT II
# No unowned files or directories
default no_unowned_files := false

no_unowned_files if {
	is_array(input.file_permissions.unowned_files)
	count(input.file_permissions.unowned_files) == 0
}

status_rhel_09_232255 := "Not_a_Finding" if no_unowned_files

else := "Open"

finding_rhel_09_232255 := {
	"vuln_id": "V-257931",
	"stig_id": "RHEL-09-232255",
	"severity": "CAT II",
	"rule_title": "All RHEL 9 local files and directories must have a valid owner.",
	"status": status_rhel_09_232255,
	"fix_text": "Find and remediate unowned files: find / -nouser -xdev -print",
}

# RHEL-09-232250 | V-257930 | CAT II
# No ungrouped files or directories
default no_ungrouped_files := false

no_ungrouped_files if {
	is_array(input.file_permissions.ungrouped_files)
	count(input.file_permissions.ungrouped_files) == 0
}

status_rhel_09_232250 := "Not_a_Finding" if no_ungrouped_files

else := "Open"

finding_rhel_09_232250 := {
	"vuln_id": "V-257930",
	"stig_id": "RHEL-09-232250",
	"severity": "CAT II",
	"rule_title": "All RHEL 9 local files and directories must have a valid group owner.",
	"status": status_rhel_09_232250,
	"fix_text": "Find and remediate ungrouped files: find / -nogroup -xdev -print",
}

# RHEL-09-232075 | V-257895 | CAT II
# /etc/passwd must have mode 0644 or less
default passwd_permissions_ok := false

passwd_permissions_ok if {
	mode_within(input.file_permissions.etc_passwd.mode, "0644")
}

status_rhel_09_232075 := "Not_a_Finding" if passwd_permissions_ok

else := "Open"

finding_rhel_09_232075 := {
	"vuln_id": "V-257895",
	"stig_id": "RHEL-09-232075",
	"severity": "CAT II",
	"rule_title": "RHEL 9 /etc/passwd file must have mode 0644 or less permissive to prevent unauthorized access.",
	"status": status_rhel_09_232075,
	"fix_text": "Fix /etc/passwd permissions: chmod 0644 /etc/passwd",
}

# RHEL-09-232270 | V-257934 | CAT II
# /etc/shadow must have mode 0000
default shadow_permissions_ok := false

shadow_permissions_ok if {
	mode_within(input.file_permissions.etc_shadow.mode, "0000")
}

status_rhel_09_232270 := "Not_a_Finding" if shadow_permissions_ok

else := "Open"

finding_rhel_09_232270 := {
	"vuln_id": "V-257934",
	"stig_id": "RHEL-09-232270",
	"severity": "CAT II",
	"rule_title": "RHEL 9 /etc/shadow file must have mode 0000 to prevent unauthorized access.",
	"status": status_rhel_09_232270,
	"fix_text": "Fix /etc/shadow permissions: chmod 0000 /etc/shadow",
}

# RHEL-09-232055 | V-257891 | CAT II
# /etc/group must have mode 0644 or less
default group_permissions_ok := false

group_permissions_ok if {
	mode_within(input.file_permissions.etc_group.mode, "0644")
}

status_rhel_09_232055 := "Not_a_Finding" if group_permissions_ok

else := "Open"

finding_rhel_09_232055 := {
	"vuln_id": "V-257891",
	"stig_id": "RHEL-09-232055",
	"severity": "CAT II",
	"rule_title": "RHEL 9 /etc/group file must have mode 0644 or less permissive to prevent unauthorized access.",
	"status": status_rhel_09_232055,
	"fix_text": "Fix /etc/group permissions: chmod 0644 /etc/group",
}

# RHEL-09-232065 | V-257893 | CAT II
# /etc/gshadow must have mode 0000
default gshadow_permissions_ok := false

gshadow_permissions_ok if {
	mode_within(input.file_permissions.etc_gshadow.mode, "0000")
}

status_rhel_09_232065 := "Not_a_Finding" if gshadow_permissions_ok

else := "Open"

finding_rhel_09_232065 := {
	"vuln_id": "V-257893",
	"stig_id": "RHEL-09-232065",
	"severity": "CAT II",
	"rule_title": "RHEL 9 /etc/gshadow file must have mode 0000 or less permissive to prevent unauthorized access.",
	"status": status_rhel_09_232065,
	"fix_text": "Fix /etc/gshadow permissions: chmod 0000 /etc/gshadow",
}

# RHEL-09-232020 | V-257884 | CAT II
# Library files must have mode 0755 or less
default lib_permissions_ok := false

lib_permissions_ok if {
	input.file_permissions.library_files_ok == true
}

status_rhel_09_232020 := "Not_a_Finding" if lib_permissions_ok

else := "Open"

finding_rhel_09_232020 := {
	"vuln_id": "V-257884",
	"stig_id": "RHEL-09-232020",
	"severity": "CAT II",
	"rule_title": "RHEL 9 library files must have mode 755 or less permissive.",
	"status": status_rhel_09_232020,
	"fix_text": "Fix library permissions: find /lib /lib64 /usr/lib /usr/lib64 -perm /022 -type f -exec chmod 755 {} \\;",
}

# RHEL-09-232200 | V-257920 | CAT II
# Library dirs must be owned by root
default lib_dirs_owned_root := false

lib_dirs_owned_root if {
	input.file_permissions.library_dirs_owned_root == true
}

status_rhel_09_232200 := "Not_a_Finding" if lib_dirs_owned_root

else := "Open"

finding_rhel_09_232200 := {
	"vuln_id": "V-257920",
	"stig_id": "RHEL-09-232200",
	"severity": "CAT II",
	"rule_title": "RHEL 9 library files must be owned by root.",
	"status": status_rhel_09_232200,
	"fix_text": "Fix library ownership: find /lib /lib64 /usr/lib /usr/lib64 ! -user root -exec chown root {} \\;",
}

# RHEL-09-232010 | V-257882 | CAT II
# System commands must have mode 0755 or less
default sys_commands_permissions_ok := false

sys_commands_permissions_ok if {
	input.file_permissions.system_commands_ok == true
}

status_rhel_09_232010 := "Not_a_Finding" if sys_commands_permissions_ok

else := "Open"

finding_rhel_09_232010 := {
	"vuln_id": "V-257882",
	"stig_id": "RHEL-09-232010",
	"severity": "CAT II",
	"rule_title": "RHEL 9 system commands must have mode 755 or less permissive.",
	"status": status_rhel_09_232010,
	"fix_text": "Fix system command permissions: find /bin /sbin /usr/bin /usr/sbin -perm /022 -exec chmod 755 {} \\;",
}

# RHEL-09-232050 | V-257890 | CAT II
# All interactive local users must have home dir permissions set to 0750 or less
default home_dir_permissions_ok := false

home_dir_permissions_ok if {
	is_array(input.file_permissions.insecure_home_dirs)
	count(input.file_permissions.insecure_home_dirs) == 0
}

status_rhel_09_232050 := "Not_a_Finding" if home_dir_permissions_ok

else := "Open"

finding_rhel_09_232050 := {
	"vuln_id": "V-257890",
	"stig_id": "RHEL-09-232050",
	"severity": "CAT II",
	"rule_title": "All RHEL 9 local interactive user home directories must have mode 0750 or less permissive.",
	"status": status_rhel_09_232050,
	"fix_text": "Fix home directory permissions: chmod 0750 /home/<username>",
}

# =============================================================================
# COMPLIANCE AGGREGATION
# =============================================================================

# No CAT I rule in this module. array.concat rather than the literal `[]`: OPA >= 1.22 types a literal
# empty array as having no members and rejects iterating it (scripts/check_per_file_load.py).
cat_i_findings := array.concat([], [])

cat_ii_findings := [
	finding_rhel_09_232255,
	finding_rhel_09_232250,
	finding_rhel_09_232075,
	finding_rhel_09_232270,
	finding_rhel_09_232055,
	finding_rhel_09_232065,
	finding_rhel_09_232020,
	finding_rhel_09_232200,
	finding_rhel_09_232010,
	finding_rhel_09_232050,
]

# No CAT III rule in this module. array.concat rather than the literal `[]`: OPA >= 1.22 types a literal
# empty array as having no members and rejects iterating it (scripts/check_per_file_load.py).
cat_iii_findings := array.concat([], [])

findings := array.concat(cat_i_findings, array.concat(cat_ii_findings, cat_iii_findings))

violations contains finding.stig_id if {
	some finding in findings
	finding.status == "Open"
}

open_cat_i contains f if {
	some f in cat_i_findings
	f.status == "Open"
}

# `compliant`: no open finding at ANY category (CAT I, II or III).
# `cat_i_compliant`: the former CAT-I-only meaning, for gating on the critical subset.
default cat_i_compliant := false

open_all_findings := [f | some f in findings; f.status == "Open"]

compliant if {
	count(open_all_findings) == 0
}

cat_i_compliant if {
	count(open_cat_i) == 0
}

compliance_report := {
	"module": "file_permissions",
	"total_findings": count(findings),
	"open_findings": count(violations),
	"cat_i_open": count(open_cat_i),
	"findings": findings,
	"compliant": compliant,
	"cat_i_compliant": cat_i_compliant,
}
