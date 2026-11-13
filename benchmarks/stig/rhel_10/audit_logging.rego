# METADATA
# title: "DISA STIG for RHEL 10 - Audit Logging Module"
# custom:
#   class: security
#   framework: stig_rhel_10
#   source: disa
#   domains: [linux, rhel]
#   coverage:
#     checks: 12
#     cited: 11
#     density: sized
#     basis: size
#     tested: true
#     entrypoint: compliance_report
#     guard: self
#     as_of: v2.4.2
package stig.rhel_10.audit_logging

# DISA STIG for RHEL 10 - Audit Logging Module
# STIG Version: V1R2 | Released: 01 Jul 2026
# Derived from stig/rhel_9/audit_logging.rego by DISA rule title: RHEL 10 and RHEL 9 share the rule text;
# ids, vuln ids, severities and titles are the RHEL 10 XCCDF's (tools/stig_generators/gen_oracle_linux.py).
# Covers: auditd configuration, audit rules for system calls and file access

import rego.v1

default compliant := false

# =============================================================================
# SHARED HELPERS
# =============================================================================

# Shared helpers (defined in a source block whose rule RHEL 10 does not carry)

# Helper: check if audit rule exists
audit_rule_exists(pattern) if {
	some rule in input.audit_rules
	contains(rule, pattern)
}

# =============================================================================
# CAT II - MEDIUM SEVERITY
# =============================================================================

# RHEL-10-200661 | V-280994 | CAT II
# auditd service must be running
default auditd_active := false

auditd_active if {
	input.services.auditd == "active"
}

status_rhel_10_200661 := "Not_a_Finding" if auditd_active

else := "Open"

finding_rhel_10_200661 := {
	"vuln_id": "V-280994",
	"stig_id": "RHEL-10-200661",
	"severity": "CAT II",
	"rule_title": "RHEL 10 must enable the audit service.",
	"status": status_rhel_10_200661,
	"fix_text": "Enable and start auditd: systemctl enable --now auditd",
}

# RHEL-10-500205 | V-281113 | CAT II
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

status_rhel_10_500205 := "Not_a_Finding" if space_left_action_ok

else := "Open"

finding_rhel_10_500205 := {
	"vuln_id": "V-281113",
	"stig_id": "RHEL-10-500205",
	"severity": "CAT II",
	"rule_title": "RHEL 10 must notify the system administrator (SA) and information system security officer (ISSO) (at a minimum) when allocated audit record storage volume 75 percent utilization.",
	"status": status_rhel_10_500205,
	"fix_text": "Set space_left_action = email in /etc/audit/auditd.conf",
}

# RHEL-10-500300 | V-281116 | CAT II
# Audit rules: execve (b64) must be audited
default audit_execve_b64 := false

audit_execve_b64 if {
	audit_rule_exists("-a always,exit -F arch=b64 -S execve")
}

status_rhel_10_500300 := "Not_a_Finding" if audit_execve_b64

else := "Open"

finding_rhel_10_500300 := {
	"vuln_id": "V-281116",
	"stig_id": "RHEL-10-500300",
	"severity": "CAT II",
	"rule_title": "RHEL 10 must generate audit records for successful and unsuccessful uses of the \"execve\" system call.",
	"status": status_rhel_10_500300,
	"fix_text": "Add audit rule: -a always,exit -F arch=b64 -S execve -k exec_commands",
}

# RHEL-10-500790 | V-281164 | CAT II
# Audit rules: chown must be audited
default audit_chown := false

audit_chown if {
	audit_rule_exists("-a always,exit -F arch=b64 -S chown")
}

status_rhel_10_500790 := "Not_a_Finding" if audit_chown

else := "Open"

finding_rhel_10_500790 := {
	"vuln_id": "V-281164",
	"stig_id": "RHEL-10-500790",
	"severity": "CAT II",
	"rule_title": "RHEL 10 must generate audit records for all uses of the \"chown\", \"fchown\", \"fchownat\", and \"lchown\" syscalls.",
	"status": status_rhel_10_500790,
	"fix_text": "Add audit rule for chown: -a always,exit -F arch=b64 -S chown,fchown,fchownat,lchown",
}

# RHEL-10-500780 | V-281163 | CAT II
# Audit rules: chmod must be audited
default audit_chmod := false

audit_chmod if {
	audit_rule_exists("-a always,exit -F arch=b64 -S chmod")
}

status_rhel_10_500780 := "Not_a_Finding" if audit_chmod

else := "Open"

finding_rhel_10_500780 := {
	"vuln_id": "V-281163",
	"stig_id": "RHEL-10-500780",
	"severity": "CAT II",
	"rule_title": "RHEL 10 must generate audit records for all uses of the \"chmod\", \"fchmod\", \"fchmodat\", and \"fchmodat2\" syscalls.",
	"status": status_rhel_10_500780,
	"fix_text": "Add audit rule for chmod: -a always,exit -F arch=b64 -S chmod,fchmod,fchmodat",
}

# RHEL-10-500310 | V-281117 | CAT II
# Audit rules: setxattr must be audited
default audit_setxattr := false

audit_setxattr if {
	audit_rule_exists("-a always,exit -F arch=b64 -S setxattr")
}

status_rhel_10_500310 := "Not_a_Finding" if audit_setxattr

else := "Open"

finding_rhel_10_500310 := {
	"vuln_id": "V-281117",
	"stig_id": "RHEL-10-500310",
	"severity": "CAT II",
	"rule_title": "RHEL 10 must generate audit records for successful and unsuccessful uses of the \"setxattr\", \"fsetxattr\", \"lsetxattr\", \"removexattr\", \"fremovexattr\", and \"lremovexattr\" system calls.",
	"status": status_rhel_10_500310,
	"fix_text": "Add audit rules for xattr operations",
}

# RHEL-10-500390 | V-281125 | CAT II
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

status_rhel_10_500390 := "Not_a_Finding" if audit_open_failure

else := "Open"

finding_rhel_10_500390 := {
	"vuln_id": "V-281125",
	"stig_id": "RHEL-10-500390",
	"severity": "CAT II",
	"rule_title": "RHEL 10 must generate audit records for successful and unsuccessful uses of the \"truncate\", \"ftruncate\", \"creat\", \"open\", \"openat\", and \"open_by_handle_at\" system calls.",
	"status": status_rhel_10_500390,
	"fix_text": "Add audit rules for failed file access: -a always,exit -F arch=b64 -S open -F exit=-EACCES -k access",
}

# RHEL-10-500680 | V-281154 | CAT II
# Audit rules: sudoers modification must be audited
default audit_sudoers := false

audit_sudoers if {
	audit_rule_exists("-w /etc/sudoers")
}

status_rhel_10_500680 := "Not_a_Finding" if audit_sudoers

else := "Open"

finding_rhel_10_500680 := {
	"vuln_id": "V-281154",
	"stig_id": "RHEL-10-500680",
	"severity": "CAT II",
	"rule_title": "RHEL 10 must generate audit records for all account creations, modifications, disabling, and termination events that affect \"/etc/sudoers\".",
	"status": status_rhel_10_500680,
	"fix_text": "Add audit rule: -w /etc/sudoers -p wa -k sudoers_change",
}

# RHEL-10-500730 | V-281159 | CAT II
# Audit rules: /etc/passwd modification must be audited
default audit_passwd_file := false

audit_passwd_file if {
	audit_rule_exists("-w /etc/passwd")
}

status_rhel_10_500730 := "Not_a_Finding" if audit_passwd_file

else := "Open"

finding_rhel_10_500730 := {
	"vuln_id": "V-281159",
	"stig_id": "RHEL-10-500730",
	"severity": "CAT II",
	"rule_title": "RHEL 10 must generate audit records for all account creations, modifications, disabling, and termination events that affect \"/etc/passwd\".",
	"status": status_rhel_10_500730,
	"fix_text": "Add audit rule: -w /etc/passwd -p wa -k usermod",
}

# RHEL-10-500550 | V-281141 | CAT II
# Audit rules: privileged command use must be audited
default audit_privileged_cmds := false

audit_privileged_cmds if {
	audit_rule_exists("-a always,exit -F path=/usr/bin/sudo")
}

audit_privileged_cmds if {
	audit_rule_exists("privileged")
}

status_rhel_10_500550 := "Not_a_Finding" if audit_privileged_cmds

else := "Open"

finding_rhel_10_500550 := {
	"vuln_id": "V-281141",
	"stig_id": "RHEL-10-500550",
	"severity": "CAT II",
	"rule_title": "RHEL 10 must generate audit records for successful and unsuccessful uses of the \"sudo\" command.",
	"status": status_rhel_10_500550,
	"fix_text": "Add audit rule: -a always,exit -F path=/usr/bin/sudo -F perm=x -k priv_cmd",
}

# RHEL-10-500410 | V-281127 | CAT II
# Audit rules: module loading/unloading must be audited
default audit_modules := false

audit_modules if {
	audit_rule_exists("-a always,exit -F arch=b64 -S finit_module")
}

audit_modules if {
	audit_rule_exists("-a always,exit -F arch=b64 -S init_module")
}

status_rhel_10_500410 := "Not_a_Finding" if audit_modules

else := "Open"

finding_rhel_10_500410 := {
	"vuln_id": "V-281127",
	"stig_id": "RHEL-10-500410",
	"severity": "CAT II",
	"rule_title": "RHEL 10 must generate audit records for successful and unsuccessful uses of the \"init_module\" and \"finit_module\" system calls.",
	"status": status_rhel_10_500410,
	"fix_text": "Add audit rules for module operations",
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
	finding_rhel_10_200661,
	finding_rhel_10_500205,
	finding_rhel_10_500300,
	finding_rhel_10_500790,
	finding_rhel_10_500780,
	finding_rhel_10_500310,
	finding_rhel_10_500390,
	finding_rhel_10_500680,
	finding_rhel_10_500730,
	finding_rhel_10_500550,
	finding_rhel_10_500410,
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

# `compliant`: no open finding at ANY category (CAT I, II or III), as in the RHEL 8/9 modules.
# `cat_i_compliant`: the CAT-I-only meaning, for gating on the critical subset.
open_all_findings := [f | some f in findings; f.status == "Open"]

compliant if {
	count(open_all_findings) == 0
}

default cat_i_compliant := false

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
