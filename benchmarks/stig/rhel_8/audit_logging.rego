package stig.rhel_8.audit_logging

# DISA STIG for RHEL 8 - Audit Logging Module
# STIG Version: V1R13 | Released: July 2024

import rego.v1

default compliant := false

audit_rule_exists(pattern) if {
	some rule in input.audit_rules
	contains(rule, pattern)
}

# =============================================================================
# CAT I
# =============================================================================

# RHEL-08-030000 | V-230400 | CAT I - auditd must be running
default auditd_active := false
auditd_active if { input.services.auditd == "active" }

status_rhel_08_030000 := "Not_a_Finding" if { auditd_active } else := "Open"
finding_rhel_08_030000 := {
	"vuln_id": "V-230400",
	"stig_id": "RHEL-08-030000",
	"severity": "CAT I",
	"rule_title": "RHEL 8 must have the auditd service started",
	"status": status_rhel_08_030000,
	"fix_text": "systemctl enable --now auditd",
}

# RHEL-08-030010 | V-230401 | CAT I - Audit log must not be auto-overwritten
default audit_no_overwrite := false
audit_no_overwrite if {
	input.auditd_config.max_log_file_action != "ignore"
	input.auditd_config.max_log_file_action != "IGNORE"
}

status_rhel_08_030010 := "Not_a_Finding" if { audit_no_overwrite } else := "Open"
finding_rhel_08_030010 := {
	"vuln_id": "V-230401",
	"stig_id": "RHEL-08-030010",
	"severity": "CAT I",
	"rule_title": "RHEL 8 audit logs must not automatically be overwritten",
	"status": status_rhel_08_030010,
	"fix_text": "Set max_log_file_action=keep_logs in /etc/audit/auditd.conf",
}

# =============================================================================
# CAT II
# =============================================================================

# RHEL-08-030020 | V-230402 | CAT II - Audit rules: execve b64
default audit_execve_b64 := false
audit_execve_b64 if { audit_rule_exists("-a always,exit -F arch=b64 -S execve") }

status_rhel_08_030020 := "Not_a_Finding" if { audit_execve_b64 } else := "Open"
finding_rhel_08_030020 := {
	"vuln_id": "V-230402",
	"stig_id": "RHEL-08-030020",
	"severity": "CAT II",
	"rule_title": "RHEL 8 must audit all uses of the execve syscall (b64)",
	"status": status_rhel_08_030020,
	"fix_text": "Add audit rule: -a always,exit -F arch=b64 -S execve",
}

# RHEL-08-030030 | V-230403 | CAT II - Audit rules: chown
default audit_chown := false
audit_chown if { audit_rule_exists("-a always,exit -F arch=b64 -S chown") }

status_rhel_08_030030 := "Not_a_Finding" if { audit_chown } else := "Open"
finding_rhel_08_030030 := {
	"vuln_id": "V-230403",
	"stig_id": "RHEL-08-030030",
	"severity": "CAT II",
	"rule_title": "RHEL 8 must audit all uses of the chown syscall",
	"status": status_rhel_08_030030,
	"fix_text": "Add audit rule for chown syscall",
}

# RHEL-08-030040 | V-230404 | CAT II - Audit rules: chmod
default audit_chmod := false
audit_chmod if { audit_rule_exists("-a always,exit -F arch=b64 -S chmod") }

status_rhel_08_030040 := "Not_a_Finding" if { audit_chmod } else := "Open"
finding_rhel_08_030040 := {
	"vuln_id": "V-230404",
	"stig_id": "RHEL-08-030040",
	"severity": "CAT II",
	"rule_title": "RHEL 8 must audit all uses of the chmod syscall",
	"status": status_rhel_08_030040,
	"fix_text": "Add audit rule for chmod syscall",
}

# RHEL-08-030050 | V-230405 | CAT II - Audit rules: sudoers
default audit_sudoers := false
audit_sudoers if { audit_rule_exists("-w /etc/sudoers") }

status_rhel_08_030050 := "Not_a_Finding" if { audit_sudoers } else := "Open"
finding_rhel_08_030050 := {
	"vuln_id": "V-230405",
	"stig_id": "RHEL-08-030050",
	"severity": "CAT II",
	"rule_title": "RHEL 8 must generate audit records for sudoers file changes",
	"status": status_rhel_08_030050,
	"fix_text": "Add: -w /etc/sudoers -p wa -k sudoers_change",
}

# RHEL-08-030060 | V-230406 | CAT II - Audit rules: /etc/passwd
default audit_passwd := false
audit_passwd if { audit_rule_exists("-w /etc/passwd") }

status_rhel_08_030060 := "Not_a_Finding" if { audit_passwd } else := "Open"
finding_rhel_08_030060 := {
	"vuln_id": "V-230406",
	"stig_id": "RHEL-08-030060",
	"severity": "CAT II",
	"rule_title": "RHEL 8 must audit changes to /etc/passwd",
	"status": status_rhel_08_030060,
	"fix_text": "Add: -w /etc/passwd -p wa -k passwd_change",
}

# RHEL-08-030070 | V-230407 | CAT II - Audit rules: sudo command
default audit_sudo := false
audit_sudo if { audit_rule_exists("-a always,exit -F path=/usr/bin/sudo") }

status_rhel_08_030070 := "Not_a_Finding" if { audit_sudo } else := "Open"
finding_rhel_08_030070 := {
	"vuln_id": "V-230407",
	"stig_id": "RHEL-08-030070",
	"severity": "CAT II",
	"rule_title": "RHEL 8 must audit the sudo command",
	"status": status_rhel_08_030070,
	"fix_text": "Add: -a always,exit -F path=/usr/bin/sudo -F perm=x",
}

# RHEL-08-030080 | V-230408 | CAT II - Audit rules immutable
default audit_immutable := false
audit_immutable if { audit_rule_exists("-e 2") }

status_rhel_08_030080 := "Not_a_Finding" if { audit_immutable } else := "Open"
finding_rhel_08_030080 := {
	"vuln_id": "V-230408",
	"stig_id": "RHEL-08-030080",
	"severity": "CAT II",
	"rule_title": "RHEL 8 audit configuration must be made immutable",
	"status": status_rhel_08_030080,
	"fix_text": "Add -e 2 as last line in /etc/audit/audit.rules",
}

# RHEL-08-030090 | V-230409 | CAT II - space_left_action must notify
default space_left_notify := false
space_left_notify if { input.auditd_config.space_left_action == "email" }
space_left_notify if { input.auditd_config.space_left_action == "syslog" }

status_rhel_08_030090 := "Not_a_Finding" if { space_left_notify } else := "Open"
finding_rhel_08_030090 := {
	"vuln_id": "V-230409",
	"stig_id": "RHEL-08-030090",
	"severity": "CAT II",
	"rule_title": "RHEL 8 audit system must notify SA when audit storage is approaching capacity",
	"status": status_rhel_08_030090,
	"fix_text": "Set space_left_action=email in /etc/audit/auditd.conf",
}

# =============================================================================
# COMPLIANCE AGGREGATION
# =============================================================================

cat_i_findings := [
	finding_rhel_08_030000,
	finding_rhel_08_030010,
]

cat_ii_findings := [
	finding_rhel_08_030020,
	finding_rhel_08_030030,
	finding_rhel_08_030040,
	finding_rhel_08_030050,
	finding_rhel_08_030060,
	finding_rhel_08_030070,
	finding_rhel_08_030080,
	finding_rhel_08_030090,
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

compliant if { count(open_cat_i) == 0 }

compliance_report := {
	"module": "audit_logging",
	"total_findings": count(findings),
	"open_findings": count(violations),
	"cat_i_open": count(open_cat_i),
	"findings": findings,
	"compliant": compliant,
}
