# METADATA
# title: "DISA STIG for Oracle Linux 8 - File Permissions Module"
# custom:
#   class: security
#   framework: stig_oracle_linux_8
#   source: disa
#   domains: [linux, oracle]
#   coverage:
#     checks: 7
#     cited: 6
#     density: section
#     basis: role
#     tested: true
#     entrypoint: compliance_report
#     guard: self
#     as_of: v2.4.1
package stig.oracle_linux_8.file_permissions

# DISA STIG for Oracle Linux 8 - File Permissions Module
# STIG Version: V2R10 | Released: 30 Sep 2026
# Derived from stig/oracle_linux_9/file_permissions.rego by DISA rule title: Oracle Linux 8 and Oracle Linux 9 share the rule text;
# ids, vuln ids, severities and titles are the Oracle Linux 8 XCCDF's (tools/stig_generators/gen_oracle_linux.py).
# Covers: World-writable files, SUID/SGID, system file ownership, /etc permissions

import rego.v1

default compliant := false

# =============================================================================
# CAT II - MEDIUM SEVERITY
# =============================================================================

# OL08-00-010780 | V-248646 | CAT II
# No unowned files or directories
default no_unowned_files := false

no_unowned_files if {
	# Missing evidence is not a pass: the offender list must be collected (empty = none found).
	is_array(input.file_permissions.unowned_files)
	count(input.file_permissions.unowned_files) == 0
}

status_ol08_00_010780 := "Not_a_Finding" if { no_unowned_files } else := "Open"

finding_ol08_00_010780 := {
	"vuln_id": "V-248646",
	"stig_id": "OL08-00-010780",
	"severity": "CAT II",
	"rule_title": "All OL 8 files and directories must have a valid owner.",
	"status": status_ol08_00_010780,
	"fix_text": "Find and remediate unowned files: find / -nouser -xdev -print",
}

# OL08-00-010790 | V-248647 | CAT II
# No ungrouped files or directories
default no_ungrouped_files := false

no_ungrouped_files if {
	# Missing evidence is not a pass: the offender list must be collected (empty = none found).
	is_array(input.file_permissions.ungrouped_files)
	count(input.file_permissions.ungrouped_files) == 0
}

status_ol08_00_010790 := "Not_a_Finding" if { no_ungrouped_files } else := "Open"

finding_ol08_00_010790 := {
	"vuln_id": "V-248647",
	"stig_id": "OL08-00-010790",
	"severity": "CAT II",
	"rule_title": "All OL 8 files and directories must have a valid group owner.",
	"status": status_ol08_00_010790,
	"fix_text": "Find and remediate ungrouped files: find / -nogroup -xdev -print",
}

# OL08-00-010330 | V-248570 | CAT II
# Library files must have mode 0755 or less
default lib_permissions_ok := false

lib_permissions_ok if {
	input.file_permissions.library_files_ok == true
}

status_ol08_00_010330 := "Not_a_Finding" if { lib_permissions_ok } else := "Open"

finding_ol08_00_010330 := {
	"vuln_id": "V-248570",
	"stig_id": "OL08-00-010330",
	"severity": "CAT II",
	"rule_title": "OL 8 library files must have mode 755 or less permissive.",
	"status": status_ol08_00_010330,
	"fix_text": "Fix library permissions: find /lib /lib64 /usr/lib /usr/lib64 -perm /022 -type f -exec chmod 755 {} \\;",
}

# OL08-00-010340 | V-248571 | CAT II
# Library dirs must be owned by root
default lib_dirs_owned_root := false

lib_dirs_owned_root if {
	input.file_permissions.library_dirs_owned_root == true
}

status_ol08_00_010340 := "Not_a_Finding" if { lib_dirs_owned_root } else := "Open"

finding_ol08_00_010340 := {
	"vuln_id": "V-248571",
	"stig_id": "OL08-00-010340",
	"severity": "CAT II",
	"rule_title": "OL 8 library files must be owned by root.",
	"status": status_ol08_00_010340,
	"fix_text": "Fix library ownership: find /lib /lib64 /usr/lib /usr/lib64 ! -user root -exec chown root {} \\;",
}

# OL08-00-010300 | V-248567 | CAT II
# System commands must have mode 0755 or less
default sys_commands_permissions_ok := false

sys_commands_permissions_ok if {
	input.file_permissions.system_commands_ok == true
}

status_ol08_00_010300 := "Not_a_Finding" if { sys_commands_permissions_ok } else := "Open"

finding_ol08_00_010300 := {
	"vuln_id": "V-248567",
	"stig_id": "OL08-00-010300",
	"severity": "CAT II",
	"rule_title": "OL 8 system commands must have mode 755 or less permissive.",
	"status": status_ol08_00_010300,
	"fix_text": "Fix system command permissions: find /bin /sbin /usr/bin /usr/sbin -perm /022 -exec chmod 755 {} \\;",
}

# OL08-00-010730 | V-248639 | CAT II
# All interactive local users must have home dir permissions set to 0750 or less
default home_dir_permissions_ok := false

home_dir_permissions_ok if {
	# Missing evidence is not a pass: the offender list must be collected (empty = none found).
	is_array(input.file_permissions.insecure_home_dirs)
	count(input.file_permissions.insecure_home_dirs) == 0
}

status_ol08_00_010730 := "Not_a_Finding" if { home_dir_permissions_ok } else := "Open"

finding_ol08_00_010730 := {
	"vuln_id": "V-248639",
	"stig_id": "OL08-00-010730",
	"severity": "CAT II",
	"rule_title": "All OL 8 local interactive user home directories must have mode \"0750\" or less permissive.",
	"status": status_ol08_00_010730,
	"fix_text": "Fix home directory permissions: chmod 0750 /home/<username>",
}

# =============================================================================
# COMPLIANCE AGGREGATION
# =============================================================================

cat_i_findings := []

cat_ii_findings := [
	finding_ol08_00_010780,
	finding_ol08_00_010790,
	finding_ol08_00_010330,
	finding_ol08_00_010340,
	finding_ol08_00_010300,
	finding_ol08_00_010730,
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

# Evidence gate: a module with none of its facts collected is unevaluated, not compliant.
evidence_present if {
	object.get(input, "file_permissions", null) != null
}

# NOTE: `compliant` is scoped to CAT I findings only (module convention), and this module carries
# no CAT I findings. Whether CAT II should also gate it is an open scope decision, see the
# validation 2026-10-17 report.
compliant if {
	evidence_present
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
