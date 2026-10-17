# METADATA
# title: "DISA STIG for Oracle Linux 8 - Audit Logging Module"
# custom:
#   class: security
#   framework: stig_oracle_linux_8
#   source: disa
#   domains: [linux, oracle]
#   coverage:
#     checks: 9
#     cited: 8
#     density: section
#     basis: role
#     tested: true
#     entrypoint: compliance_report
#     guard: self
#     as_of: v2.4.2
package stig.oracle_linux_8.audit_logging

# DISA STIG for Oracle Linux 8 - Audit Logging Module
# STIG Version: V2R10 | Released: 30 Sep 2026
# Derived from stig/oracle_linux_9/audit_logging.rego by DISA rule title: Oracle Linux 8 and Oracle Linux 9 share the rule text;
# ids, vuln ids, severities and titles are the Oracle Linux 8 XCCDF's (tools/stig_generators/gen_oracle_linux.py).
# Covers: auditd configuration, audit rules for system calls and file access

import rego.v1

default compliant := false

# =============================================================================
# SHARED HELPERS
# =============================================================================

# Shared helpers (defined in a source block whose rule Oracle Linux 8 does not carry)

# Helper: check if audit rule exists
audit_rule_exists(pattern) if {
	some rule in input.audit_rules
	contains(rule, pattern)
}

# =============================================================================
# CAT II - MEDIUM SEVERITY
# =============================================================================

# OL08-00-030060 | V-248728 | CAT II
# Admin space left action must be configured
default admin_space_left_action_ok := false

admin_space_left_action_ok if {
	action := input.auditd_config.admin_space_left_action
	action != "ignore"
	action != "IGNORE"
}

status_ol08_00_030060 := "Not_a_Finding" if { admin_space_left_action_ok } else := "Open"

finding_ol08_00_030060 := {
	"vuln_id": "V-248728",
	"stig_id": "OL08-00-030060",
	"severity": "CAT II",
	"rule_title": "The OL 8 audit system must take appropriate action when the audit storage volume is full.",
	"status": status_ol08_00_030060,
	"fix_text": "Set admin_space_left_action = single in /etc/audit/auditd.conf",
}

# OL08-00-030480 | V-248790 | CAT II
# Audit rules: chown must be audited
default audit_chown := false

audit_chown if {
	audit_rule_exists("-a always,exit -F arch=b64 -S chown")
}

status_ol08_00_030480 := "Not_a_Finding" if { audit_chown } else := "Open"

finding_ol08_00_030480 := {
	"vuln_id": "V-248790",
	"stig_id": "OL08-00-030480",
	"severity": "CAT II",
	"rule_title": "OL 8 must generate audit records for any use of the \"chown\", \"fchown\", \"fchownat\", and \"lchown\" system calls.",
	"status": status_ol08_00_030480,
	"fix_text": "Add audit rule for chown: -a always,exit -F arch=b64 -S chown,fchown,fchownat,lchown",
}

# OL08-00-030490 | V-248791 | CAT II
# Audit rules: chmod must be audited
default audit_chmod := false

audit_chmod if {
	audit_rule_exists("-a always,exit -F arch=b64 -S chmod")
}

status_ol08_00_030490 := "Not_a_Finding" if { audit_chmod } else := "Open"

finding_ol08_00_030490 := {
	"vuln_id": "V-248791",
	"stig_id": "OL08-00-030490",
	"severity": "CAT II",
	"rule_title": "OL 8 must generate audit records for any use of the \"chmod\", \"fchmod\", and \"fchmodat\" system calls.",
	"status": status_ol08_00_030490,
	"fix_text": "Add audit rule for chmod: -a always,exit -F arch=b64 -S chmod,fchmod,fchmodat",
}

# OL08-00-030200 | V-248748 | CAT II
# Audit rules: setxattr must be audited
default audit_setxattr := false

audit_setxattr if {
	audit_rule_exists("-a always,exit -F arch=b64 -S setxattr")
}

status_ol08_00_030200 := "Not_a_Finding" if { audit_setxattr } else := "Open"

finding_ol08_00_030200 := {
	"vuln_id": "V-248748",
	"stig_id": "OL08-00-030200",
	"severity": "CAT II",
	"rule_title": "The OL 8 audit system must be configured to audit any use of the \"setxattr\", \"fsetxattr\", \"lsetxattr\", \"removexattr\", \"fremovexattr\", and \"lremovexattr\" system calls.",
	"status": status_ol08_00_030200,
	"fix_text": "Add audit rules for xattr operations",
}

# OL08-00-030171 | V-248745 | CAT II
# Audit rules: sudoers modification must be audited
default audit_sudoers := false

audit_sudoers if {
	audit_rule_exists("-w /etc/sudoers")
}

status_ol08_00_030171 := "Not_a_Finding" if { audit_sudoers } else := "Open"

finding_ol08_00_030171 := {
	"vuln_id": "V-248745",
	"stig_id": "OL08-00-030171",
	"severity": "CAT II",
	"rule_title": "OL 8 must generate audit records for all account creations, modifications, disabling, and termination events that affect \"/etc/sudoers\".",
	"status": status_ol08_00_030171,
	"fix_text": "Add audit rule: -w /etc/sudoers -p wa -k sudoers_change",
}

# OL08-00-030150 | V-248742 | CAT II
# Audit rules: /etc/passwd modification must be audited
default audit_passwd_file := false

audit_passwd_file if {
	audit_rule_exists("-w /etc/passwd")
}

status_ol08_00_030150 := "Not_a_Finding" if { audit_passwd_file } else := "Open"

finding_ol08_00_030150 := {
	"vuln_id": "V-248742",
	"stig_id": "OL08-00-030150",
	"severity": "CAT II",
	"rule_title": "OL 8 must generate audit records for all account creation events that affect \"/etc/passwd\".",
	"status": status_ol08_00_030150,
	"fix_text": "Add audit rule: -w /etc/passwd -p wa -k usermod",
}

# OL08-00-030550 | V-248797 | CAT II
# Audit rules: privileged command use must be audited
default audit_privileged_cmds := false

audit_privileged_cmds if {
	audit_rule_exists("-a always,exit -F path=/usr/bin/sudo")
}

audit_privileged_cmds if {
	audit_rule_exists("privileged")
}

status_ol08_00_030550 := "Not_a_Finding" if { audit_privileged_cmds } else := "Open"

finding_ol08_00_030550 := {
	"vuln_id": "V-248797",
	"stig_id": "OL08-00-030550",
	"severity": "CAT II",
	"rule_title": "OL 8 must generate audit records for any use of the \"sudo\" command.",
	"status": status_ol08_00_030550,
	"fix_text": "Add audit rule: -a always,exit -F path=/usr/bin/sudo -F perm=x -k priv_cmd",
}

# OL08-00-030360 | V-248773 | CAT II
# Audit rules: module loading/unloading must be audited
default audit_modules := false

audit_modules if {
	audit_rule_exists("-a always,exit -F arch=b64 -S finit_module")
}

audit_modules if {
	audit_rule_exists("-a always,exit -F arch=b64 -S init_module")
}

status_ol08_00_030360 := "Not_a_Finding" if { audit_modules } else := "Open"

finding_ol08_00_030360 := {
	"vuln_id": "V-248773",
	"stig_id": "OL08-00-030360",
	"severity": "CAT II",
	"rule_title": "OL 8 must generate audit records for any use of the \"init_module\" and \"finit_module\" system calls.",
	"status": status_ol08_00_030360,
	"fix_text": "Add audit rules for module operations",
}

# =============================================================================
# COMPLIANCE AGGREGATION
# =============================================================================

cat_i_findings := []

cat_ii_findings := [
	finding_ol08_00_030060,
	finding_ol08_00_030480,
	finding_ol08_00_030490,
	finding_ol08_00_030200,
	finding_ol08_00_030171,
	finding_ol08_00_030150,
	finding_ol08_00_030550,
	finding_ol08_00_030360,
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
	some key in {"auditd_config", "audit_rules"}
	object.get(input, key, null) != null
}

# NOTE: `compliant` is scoped to CAT I findings only (module convention), and this module carries
# no CAT I findings. Whether CAT II should also gate it is an open scope decision, see the
# validation 2026-10-17 report.
compliant if {
	evidence_present
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
