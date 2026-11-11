# METADATA
# title: "DISA STIG for RHEL 9 - Audit Logging Module"
# custom:
#   class: security
#   framework: stig_rhel_9
#   source: disa
#   domains: [linux, rhel]
#   coverage:
#     checks: 14
#     cited: 13
#     density: sized
#     basis: size
#     tested: true
#     entrypoint: compliance_report
#     guard: self
#     as_of: v2.4.2
package stig.rhel_9.audit_logging

# DISA STIG for RHEL 9 - Audit Logging Module
# STIG Version: V2R10 | Released: 30 Sep 2026
# Rule ids, vuln ids, severities and titles stamped from the October 2026 SRG-STIG library XCCDF on 2026-11-10
# (tools/stig_generators/stamp_catalog.py); each finding is keyed on the fact its logic checks.
# Covers: auditd configuration, audit rules for system calls and file access

import rego.v1

default compliant := false

# Helper: check if audit rule exists
audit_rule_exists(pattern) if {
	some rule in input.audit_rules
	contains(rule, pattern)
}

# =============================================================================
# CAT I - HIGH SEVERITY
# =============================================================================

# =============================================================================
# CAT II - MEDIUM SEVERITY
# =============================================================================

# RHEL-09-653015 | V-258152 | CAT II
# auditd service must be running
default auditd_active := false

auditd_active if {
	input.services.auditd == "active"
}

status_rhel_09_653015 := "Not_a_Finding" if auditd_active

else := "Open"

finding_rhel_09_653015 := {
	"vuln_id": "V-258152",
	"stig_id": "RHEL-09-653015",
	"severity": "CAT II",
	"rule_title": "RHEL 9 audit service must be enabled.",
	"status": status_rhel_09_653015,
	"fix_text": "Enable and start auditd: systemctl enable --now auditd",
}

# RHEL-09-653055 | V-258160 | CAT II
# Audit log storage must be sufficient (max_log_file_action must not be ignore)
default audit_storage_ok := false

audit_storage_ok if {
	input.auditd_config.max_log_file_action != "ignore"
	input.auditd_config.max_log_file_action != "IGNORE"
}

status_rhel_09_653055 := "Not_a_Finding" if audit_storage_ok

else := "Open"

finding_rhel_09_653055 := {
	"vuln_id": "V-258160",
	"stig_id": "RHEL-09-653055",
	"severity": "CAT II",
	"rule_title": "RHEL 9 audit system must take appropriate action when the audit files have reached maximum size.",
	"status": status_rhel_09_653055,
	"fix_text": "Set max_log_file_action = keep_logs in /etc/audit/auditd.conf",
}

# RHEL-09-653025 | V-258154 | CAT II
# Admin space left action must be configured
default admin_space_left_action_ok := false

admin_space_left_action_ok if {
	action := input.auditd_config.admin_space_left_action
	action != "ignore"
	action != "IGNORE"
}

status_rhel_09_653025 := "Not_a_Finding" if admin_space_left_action_ok

else := "Open"

finding_rhel_09_653025 := {
	"vuln_id": "V-258154",
	"stig_id": "RHEL-09-653025",
	"severity": "CAT II",
	"rule_title": "RHEL 9 audit system must take appropriate action when the audit storage volume is full.",
	"status": status_rhel_09_653025,
	"fix_text": "Set admin_space_left_action = single in /etc/audit/auditd.conf",
}

# RHEL-09-653040 | V-258157 | CAT II
# space_left_action must notify admin
default space_left_action_ok := false

space_left_action_ok if {
	action := input.auditd_config.space_left_action
	action == "email"
}

space_left_action_ok if {
	action := input.auditd_config.space_left_action
	action == "syslog"
}

status_rhel_09_653040 := "Not_a_Finding" if space_left_action_ok

else := "Open"

finding_rhel_09_653040 := {
	"vuln_id": "V-258157",
	"stig_id": "RHEL-09-653040",
	"severity": "CAT II",
	"rule_title": "RHEL 9 must notify the system administrator (SA) and information system security officer (ISSO) (at a minimum) when allocated audit record storage volume reaches 75 percent utilization.",
	"status": status_rhel_09_653040,
	"fix_text": "Set space_left_action = email in /etc/audit/auditd.conf",
}

# RHEL-09-654010 | V-258176 | CAT II
# Audit rules: execve (b64) must be audited
default audit_execve_b64 := false

audit_execve_b64 if {
	audit_rule_exists("-a always,exit -F arch=b64 -S execve")
}

status_rhel_09_654010 := "Not_a_Finding" if audit_execve_b64

else := "Open"

finding_rhel_09_654010 := {
	"vuln_id": "V-258176",
	"stig_id": "RHEL-09-654010",
	"severity": "CAT II",
	"rule_title": "RHEL 9 must audit uses of the \"execve\" system call.",
	"status": status_rhel_09_654010,
	"fix_text": "Add audit rule: -a always,exit -F arch=b64 -S execve -k exec_commands",
}

# RHEL-09-654020 | V-258178 | CAT II
# Audit rules: chown must be audited
default audit_chown := false

audit_chown if {
	audit_rule_exists("-a always,exit -F arch=b64 -S chown")
}

status_rhel_09_654020 := "Not_a_Finding" if audit_chown

else := "Open"

finding_rhel_09_654020 := {
	"vuln_id": "V-258178",
	"stig_id": "RHEL-09-654020",
	"severity": "CAT II",
	"rule_title": "RHEL 9 must audit all uses of the chown, fchown, fchownat, and lchown system calls.",
	"status": status_rhel_09_654020,
	"fix_text": "Add audit rule for chown: -a always,exit -F arch=b64 -S chown,fchown,fchownat,lchown",
}

# RHEL-09-654015 | V-258177 | CAT II
# Audit rules: chmod must be audited
default audit_chmod := false

audit_chmod if {
	audit_rule_exists("-a always,exit -F arch=b64 -S chmod")
}

status_rhel_09_654015 := "Not_a_Finding" if audit_chmod

else := "Open"

finding_rhel_09_654015 := {
	"vuln_id": "V-258177",
	"stig_id": "RHEL-09-654015",
	"severity": "CAT II",
	"rule_title": "RHEL 9 must audit all uses of the chmod, fchmod, and fchmodat system calls.",
	"status": status_rhel_09_654015,
	"fix_text": "Add audit rule for chmod: -a always,exit -F arch=b64 -S chmod,fchmod,fchmodat",
}

# RHEL-09-654025 | V-258179 | CAT II
# Audit rules: setxattr must be audited
default audit_setxattr := false

audit_setxattr if {
	audit_rule_exists("-a always,exit -F arch=b64 -S setxattr")
}

status_rhel_09_654025 := "Not_a_Finding" if audit_setxattr

else := "Open"

finding_rhel_09_654025 := {
	"vuln_id": "V-258179",
	"stig_id": "RHEL-09-654025",
	"severity": "CAT II",
	"rule_title": "RHEL 9 must audit all uses of the setxattr, fsetxattr, lsetxattr, removexattr, fremovexattr, and lremovexattr system calls.",
	"status": status_rhel_09_654025,
	"fix_text": "Add audit rules for xattr operations",
}

# RHEL-09-654070 | V-258188 | CAT II
# Audit rules: open with EACCES must be audited
default audit_open_failure := false

audit_open_failure if {
	audit_rule_exists("-a always,exit -F arch=b64 -S open")
	audit_rule_exists("-F exit=-EACCES")
}

audit_open_failure if {
	audit_rule_exists("EACCES")
	audit_rule_exists("EPERM")
}

status_rhel_09_654070 := "Not_a_Finding" if audit_open_failure

else := "Open"

finding_rhel_09_654070 := {
	"vuln_id": "V-258188",
	"stig_id": "RHEL-09-654070",
	"severity": "CAT II",
	"rule_title": "RHEL 9 must audit all uses of the truncate, ftruncate, creat, open, openat, and open_by_handle_at system calls.",
	"status": status_rhel_09_654070,
	"fix_text": "Add audit rules for failed file access: -a always,exit -F arch=b64 -S open -F exit=-EACCES -k access",
}

# RHEL-09-654215 | V-258217 | CAT II
# Audit rules: sudoers modification must be audited
default audit_sudoers := false

audit_sudoers if {
	audit_rule_exists("-w /etc/sudoers")
}

status_rhel_09_654215 := "Not_a_Finding" if audit_sudoers

else := "Open"

finding_rhel_09_654215 := {
	"vuln_id": "V-258217",
	"stig_id": "RHEL-09-654215",
	"severity": "CAT II",
	"rule_title": "RHEL 9 must generate audit records for all account creations, modifications, disabling, and termination events that affect /etc/sudoers.",
	"status": status_rhel_09_654215,
	"fix_text": "Add audit rule: -w /etc/sudoers -p wa -k sudoers_change",
}

# RHEL-09-654240 | V-258222 | CAT II
# Audit rules: /etc/passwd modification must be audited
default audit_passwd_file := false

audit_passwd_file if {
	audit_rule_exists("-w /etc/passwd")
}

status_rhel_09_654240 := "Not_a_Finding" if audit_passwd_file

else := "Open"

finding_rhel_09_654240 := {
	"vuln_id": "V-258222",
	"stig_id": "RHEL-09-654240",
	"severity": "CAT II",
	"rule_title": "RHEL 9 must generate audit records for all account creations, modifications, disabling, and termination events that affect /etc/passwd.",
	"status": status_rhel_09_654240,
	"fix_text": "Add audit rule: -w /etc/passwd -p wa -k usermod",
}

# RHEL-09-654150 | V-258204 | CAT II
# Audit rules: privileged command use must be audited
default audit_privileged_cmds := false

audit_privileged_cmds if {
	audit_rule_exists("-a always,exit -F path=/usr/bin/sudo")
}

audit_privileged_cmds if {
	audit_rule_exists("privileged")
}

status_rhel_09_654150 := "Not_a_Finding" if audit_privileged_cmds

else := "Open"

finding_rhel_09_654150 := {
	"vuln_id": "V-258204",
	"stig_id": "RHEL-09-654150",
	"severity": "CAT II",
	"rule_title": "RHEL 9 must audit all uses of the sudo command.",
	"status": status_rhel_09_654150,
	"fix_text": "Add audit rule: -a always,exit -F path=/usr/bin/sudo -F perm=x -k priv_cmd",
}

# RHEL-09-654080 | V-258190 | CAT II
# Audit rules: module loading/unloading must be audited
default audit_modules := false

audit_modules if {
	audit_rule_exists("-a always,exit -F arch=b64 -S finit_module")
}

audit_modules if {
	audit_rule_exists("-a always,exit -F arch=b64 -S init_module")
}

status_rhel_09_654080 := "Not_a_Finding" if audit_modules

else := "Open"

finding_rhel_09_654080 := {
	"vuln_id": "V-258190",
	"stig_id": "RHEL-09-654080",
	"severity": "CAT II",
	"rule_title": "RHEL 9 must audit all uses of the init_module and finit_module system calls.",
	"status": status_rhel_09_654080,
	"fix_text": "Add audit rules for module operations",
}

# =============================================================================
# COMPLIANCE AGGREGATION
# =============================================================================

# No CAT I rule in this module. array.concat rather than the literal `[]`: OPA >= 1.22 types a literal
# empty array as having no members and rejects iterating it (scripts/check_per_file_load.py).
cat_i_findings := array.concat([], [])

cat_ii_findings := [
	finding_rhel_09_653015,
	finding_rhel_09_653055,
	finding_rhel_09_653025,
	finding_rhel_09_653040,
	finding_rhel_09_654010,
	finding_rhel_09_654020,
	finding_rhel_09_654015,
	finding_rhel_09_654025,
	finding_rhel_09_654070,
	finding_rhel_09_654215,
	finding_rhel_09_654240,
	finding_rhel_09_654150,
	finding_rhel_09_654080,
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
	"module": "audit_logging",
	"total_findings": count(findings),
	"open_findings": count(violations),
	"cat_i_open": count(open_cat_i),
	"findings": findings,
	"compliant": compliant,
	"cat_i_compliant": cat_i_compliant,
}
