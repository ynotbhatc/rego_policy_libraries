# METADATA
# title: "DISA STIG for Oracle Linux 9 - Audit Logging Module"
# custom:
#   class: security
#   framework: stig_oracle_linux_9
#   source: disa
#   domains: [linux, oracle]
#   coverage:
#     checks: 12
#     cited: 11
#     density: sized
#     basis: size
#     tested: true
#     entrypoint: compliance_report
#     guard: self
#     as_of: v2.4.0
package stig.oracle_linux_9.audit_logging

# DISA STIG for Oracle Linux 9 - Audit Logging Module
# STIG Version: V1R7 | Released: 30 Sep 2026
# Derived from stig/rhel_9/audit_logging.rego by DISA rule title: Oracle Linux 9 and RHEL 9 share the rule text;
# ids, vuln ids, severities and titles are the Oracle Linux 9 XCCDF's (tools/stig_generators/gen_oracle_linux.py).
# Covers: auditd configuration, audit rules for system calls and file access

import rego.v1

default compliant := false

# =============================================================================
# SHARED HELPERS
# =============================================================================

# Shared helpers (defined in a source block whose rule Oracle Linux 9 does not carry)

# Helper: check if audit rule exists
audit_rule_exists(pattern) if {
	some rule in input.audit_rules
	contains(rule, pattern)
}

# =============================================================================
# CAT II - MEDIUM SEVERITY
# =============================================================================

# OL09-00-000441 | V-271520 | CAT II
# auditd service must be running
default auditd_active := false

auditd_active if {
	input.services.auditd == "active"
}

status_ol09_00_000441 := "Not_a_Finding" if { auditd_active } else := "Open"

finding_ol09_00_000441 := {
	"vuln_id": "V-271520",
	"stig_id": "OL09-00-000441",
	"severity": "CAT II",
	"rule_title": "OL 9 audit service must be enabled.",
	"status": status_ol09_00_000441,
	"fix_text": "Enable and start auditd: systemctl enable --now auditd",
}

# OL09-00-000770 | V-271581 | CAT II
# Audit log storage must be sufficient (max_log_file_action must not be ignore)
default audit_storage_ok := false

audit_storage_ok if {
	input.auditd_config.max_log_file_action != "ignore"
	input.auditd_config.max_log_file_action != "IGNORE"
}

status_ol09_00_000770 := "Not_a_Finding" if { audit_storage_ok } else := "Open"

finding_ol09_00_000770 := {
	"vuln_id": "V-271581",
	"stig_id": "OL09-00-000770",
	"severity": "CAT II",
	"rule_title": "OL 9 audit system must take appropriate action when the audit files have reached maximum size.",
	"status": status_ol09_00_000770,
	"fix_text": "Set max_log_file_action = keep_logs in /etc/audit/auditd.conf",
}

# OL09-00-000765 | V-271580 | CAT II
# Admin space left action must be configured
default admin_space_left_action_ok := false

admin_space_left_action_ok if {
	action := input.auditd_config.admin_space_left_action
	action != "ignore"
	action != "IGNORE"
}

status_ol09_00_000765 := "Not_a_Finding" if { admin_space_left_action_ok } else := "Open"

finding_ol09_00_000765 := {
	"vuln_id": "V-271580",
	"stig_id": "OL09-00-000765",
	"severity": "CAT II",
	"rule_title": "OL 9 audit system must take appropriate action when the audit storage volume is full.",
	"status": status_ol09_00_000765,
	"fix_text": "Set admin_space_left_action = single in /etc/audit/auditd.conf",
}

# OL09-00-000715 | V-271570 | CAT II
# Audit rules: execve (b64) must be audited
default audit_execve_b64 := false

audit_execve_b64 if {
	audit_rule_exists("-a always,exit -F arch=b64 -S execve")
}

status_ol09_00_000715 := "Not_a_Finding" if { audit_execve_b64 } else := "Open"

finding_ol09_00_000715 := {
	"vuln_id": "V-271570",
	"stig_id": "OL09-00-000715",
	"severity": "CAT II",
	"rule_title": "OL 9 must audit uses of the execve system call.",
	"status": status_ol09_00_000715,
	"fix_text": "Add audit rule: -a always,exit -F arch=b64 -S execve -k exec_commands",
}

# OL09-00-000645 | V-271556 | CAT II
# Audit rules: chown must be audited
default audit_chown := false

audit_chown if {
	audit_rule_exists("-a always,exit -F arch=b64 -S chown")
}

status_ol09_00_000645 := "Not_a_Finding" if { audit_chown } else := "Open"

finding_ol09_00_000645 := {
	"vuln_id": "V-271556",
	"stig_id": "OL09-00-000645",
	"severity": "CAT II",
	"rule_title": "OL 9 must audit all uses of the chown, fchown, fchownat, and lchown system calls.",
	"status": status_ol09_00_000645,
	"fix_text": "Add audit rule for chown: -a always,exit -F arch=b64 -S chown,fchown,fchownat,lchown",
}

# OL09-00-000640 | V-271555 | CAT II
# Audit rules: chmod must be audited
default audit_chmod := false

audit_chmod if {
	audit_rule_exists("-a always,exit -F arch=b64 -S chmod")
}

status_ol09_00_000640 := "Not_a_Finding" if { audit_chmod } else := "Open"

finding_ol09_00_000640 := {
	"vuln_id": "V-271555",
	"stig_id": "OL09-00-000640",
	"severity": "CAT II",
	"rule_title": "OL 9 must audit all uses of the chmod, fchmod, and fchmodat system calls.",
	"status": status_ol09_00_000640,
	"fix_text": "Add audit rule for chmod: -a always,exit -F arch=b64 -S chmod,fchmod,fchmodat",
}

# OL09-00-000545 | V-271536 | CAT II
# Audit rules: setxattr must be audited
default audit_setxattr := false

audit_setxattr if {
	audit_rule_exists("-a always,exit -F arch=b64 -S setxattr")
}

status_ol09_00_000545 := "Not_a_Finding" if { audit_setxattr } else := "Open"

finding_ol09_00_000545 := {
	"vuln_id": "V-271536",
	"stig_id": "OL09-00-000545",
	"severity": "CAT II",
	"rule_title": "OL 9 must audit all uses of the setxattr, fsetxattr, lsetxattr, removexattr, fremovexattr, and lremovexattr system calls.",
	"status": status_ol09_00_000545,
	"fix_text": "Add audit rules for xattr operations",
}

# OL09-00-000500 | V-271527 | CAT II
# Audit rules: sudoers modification must be audited
default audit_sudoers := false

audit_sudoers if {
	audit_rule_exists("-w /etc/sudoers")
}

status_ol09_00_000500 := "Not_a_Finding" if { audit_sudoers } else := "Open"

finding_ol09_00_000500 := {
	"vuln_id": "V-271527",
	"stig_id": "OL09-00-000500",
	"severity": "CAT II",
	"rule_title": "OL 9 must generate audit records for all account creations, modifications, disabling, and termination events that affect /etc/sudoers.",
	"status": status_ol09_00_000500,
	"fix_text": "Add audit rule: -w /etc/sudoers -p wa -k sudoers_change",
}

# OL09-00-000525 | V-271532 | CAT II
# Audit rules: /etc/passwd modification must be audited
default audit_passwd_file := false

audit_passwd_file if {
	audit_rule_exists("-w /etc/passwd")
}

status_ol09_00_000525 := "Not_a_Finding" if { audit_passwd_file } else := "Open"

finding_ol09_00_000525 := {
	"vuln_id": "V-271532",
	"stig_id": "OL09-00-000525",
	"severity": "CAT II",
	"rule_title": "OL 9 must generate audit records for all account creations, modifications, disabling, and termination events that affect /etc/passwd.",
	"status": status_ol09_00_000525,
	"fix_text": "Add audit rule: -w /etc/passwd -p wa -k usermod",
}

# OL09-00-000670 | V-271561 | CAT II
# Audit rules: privileged command use must be audited
default audit_privileged_cmds := false

audit_privileged_cmds if {
	audit_rule_exists("-a always,exit -F path=/usr/bin/sudo")
}

audit_privileged_cmds if {
	audit_rule_exists("privileged")
}

status_ol09_00_000670 := "Not_a_Finding" if { audit_privileged_cmds } else := "Open"

finding_ol09_00_000670 := {
	"vuln_id": "V-271561",
	"stig_id": "OL09-00-000670",
	"severity": "CAT II",
	"rule_title": "OL 9 must audit all uses of the sudo command.",
	"status": status_ol09_00_000670,
	"fix_text": "Add audit rule: -a always,exit -F path=/usr/bin/sudo -F perm=x -k priv_cmd",
}

# OL09-00-000690 | V-271565 | CAT II
# Audit rules: module loading/unloading must be audited
default audit_modules := false

audit_modules if {
	audit_rule_exists("-a always,exit -F arch=b64 -S finit_module")
}

audit_modules if {
	audit_rule_exists("-a always,exit -F arch=b64 -S init_module")
}

status_ol09_00_000690 := "Not_a_Finding" if { audit_modules } else := "Open"

finding_ol09_00_000690 := {
	"vuln_id": "V-271565",
	"stig_id": "OL09-00-000690",
	"severity": "CAT II",
	"rule_title": "OL 9 must audit all uses of the init_module and finit_module system calls.",
	"status": status_ol09_00_000690,
	"fix_text": "Add audit rules for module operations",
}

# =============================================================================
# COMPLIANCE AGGREGATION
# =============================================================================

cat_i_findings := []

cat_ii_findings := [
	finding_ol09_00_000441,
	finding_ol09_00_000770,
	finding_ol09_00_000765,
	finding_ol09_00_000715,
	finding_ol09_00_000645,
	finding_ol09_00_000640,
	finding_ol09_00_000545,
	finding_ol09_00_000500,
	finding_ol09_00_000525,
	finding_ol09_00_000670,
	finding_ol09_00_000690,
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
	"module": "audit_logging",
	"total_findings": count(findings),
	"open_findings": count(violations),
	"cat_i_open": count(open_cat_i),
	"findings": findings,
	"compliant": compliant,
}
