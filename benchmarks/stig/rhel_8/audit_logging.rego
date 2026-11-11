# METADATA
# title: "DISA STIG for RHEL 8 - Audit Logging Module"
# custom:
#   class: security
#   framework: stig_rhel_8
#   source: disa
#   domains: [linux, rhel]
#   coverage:
#     checks: 10
#     cited: 9
#     density: sized
#     basis: size
#     tested: true
#     entrypoint: compliance_report
#     guard: self
#     as_of: v2.4.2
package stig.rhel_8.audit_logging

# DISA STIG for RHEL 8 - Audit Logging Module
# STIG Version: V2R8 | Released: 01 Jul 2026
# Rule ids, vuln ids, severities and titles stamped from the October 2026 SRG-STIG library XCCDF on 2026-11-10
# (tools/stig_generators/stamp_catalog.py); each finding is keyed on the fact its logic checks.

import rego.v1

default compliant := false

audit_rule_exists(pattern) if {
	some rule in input.audit_rules
	contains(rule, pattern)
}

# =============================================================================
# CAT I
# =============================================================================

# =============================================================================
# CAT II - MEDIUM SEVERITY
# =============================================================================

# RHEL-08-030181 | V-244542 | CAT II - auditd must be running
default auditd_active := false

auditd_active if input.services.auditd == "active"

status_rhel_08_030181 := "Not_a_Finding" if auditd_active

else := "Open"

finding_rhel_08_030181 := {
	"vuln_id": "V-244542",
	"stig_id": "RHEL-08-030181",
	"severity": "CAT II",
	"rule_title": "RHEL 8 audit records must contain information to establish what type of events occurred, the source of events, where events occurred, and the outcome of events.",
	"status": status_rhel_08_030181,
	"fix_text": "systemctl enable --now auditd",
}

# RHEL-08-030000 | V-230386 | CAT II - Audit rules: execve b64
default audit_execve_b64 := false

audit_execve_b64 if audit_rule_exists("-a always,exit -F arch=b64 -S execve")

status_rhel_08_030000 := "Not_a_Finding" if audit_execve_b64

else := "Open"

finding_rhel_08_030000 := {
	"vuln_id": "V-230386",
	"stig_id": "RHEL-08-030000",
	"severity": "CAT II",
	"rule_title": "The RHEL 8 audit system must be configured to audit the execution of privileged functions and prevent all software from executing at higher privilege levels than users executing the software.",
	"status": status_rhel_08_030000,
	"fix_text": "Add audit rule: -a always,exit -F arch=b64 -S execve",
}

# RHEL-08-030480 | V-230455 | CAT II - Audit rules: chown
default audit_chown := false

audit_chown if audit_rule_exists("-a always,exit -F arch=b64 -S chown")

status_rhel_08_030480 := "Not_a_Finding" if audit_chown

else := "Open"

finding_rhel_08_030480 := {
	"vuln_id": "V-230455",
	"stig_id": "RHEL-08-030480",
	"severity": "CAT II",
	"rule_title": "Successful/unsuccessful uses of the chown, fchown, fchownat, and lchown system calls in RHEL 8 must generate an audit record.",
	"status": status_rhel_08_030480,
	"fix_text": "Add audit rule for chown syscall",
}

# RHEL-08-030490 | V-230456 | CAT II - Audit rules: chmod
default audit_chmod := false

audit_chmod if audit_rule_exists("-a always,exit -F arch=b64 -S chmod")

status_rhel_08_030490 := "Not_a_Finding" if audit_chmod

else := "Open"

finding_rhel_08_030490 := {
	"vuln_id": "V-230456",
	"stig_id": "RHEL-08-030490",
	"severity": "CAT II",
	"rule_title": "Successful/unsuccessful uses of the chmod, fchmod, and fchmodat system calls in RHEL 8 must generate an audit record.",
	"status": status_rhel_08_030490,
	"fix_text": "Add audit rule for chmod syscall",
}

# RHEL-08-030171 | V-230409 | CAT II - Audit rules: sudoers
default audit_sudoers := false

audit_sudoers if audit_rule_exists("-w /etc/sudoers")

status_rhel_08_030171 := "Not_a_Finding" if audit_sudoers

else := "Open"

finding_rhel_08_030171 := {
	"vuln_id": "V-230409",
	"stig_id": "RHEL-08-030171",
	"severity": "CAT II",
	"rule_title": "RHEL 8 must generate audit records for all account creations, modifications, disabling, and termination events that affect /etc/sudoers.",
	"status": status_rhel_08_030171,
	"fix_text": "Add: -w /etc/sudoers -p wa -k sudoers_change",
}

# RHEL-08-030150 | V-230406 | CAT II - Audit rules: /etc/passwd
default audit_passwd := false

audit_passwd if audit_rule_exists("-w /etc/passwd")

status_rhel_08_030150 := "Not_a_Finding" if audit_passwd

else := "Open"

finding_rhel_08_030150 := {
	"vuln_id": "V-230406",
	"stig_id": "RHEL-08-030150",
	"severity": "CAT II",
	"rule_title": "RHEL 8 must generate audit records for all account creations, modifications, disabling, and termination events that affect /etc/passwd.",
	"status": status_rhel_08_030150,
	"fix_text": "Add: -w /etc/passwd -p wa -k passwd_change",
}

# RHEL-08-030550 | V-230462 | CAT II - Audit rules: sudo command
default audit_sudo := false

audit_sudo if audit_rule_exists("-a always,exit -F path=/usr/bin/sudo")

status_rhel_08_030550 := "Not_a_Finding" if audit_sudo

else := "Open"

finding_rhel_08_030550 := {
	"vuln_id": "V-230462",
	"stig_id": "RHEL-08-030550",
	"severity": "CAT II",
	"rule_title": "Successful/unsuccessful uses of the sudo command in RHEL 8 must generate an audit record.",
	"status": status_rhel_08_030550,
	"fix_text": "Add: -a always,exit -F path=/usr/bin/sudo -F perm=x",
}

# RHEL-08-030121 | V-230402 | CAT II - Audit rules immutable
default audit_immutable := false

audit_immutable if audit_rule_exists("-e 2")

status_rhel_08_030121 := "Not_a_Finding" if audit_immutable

else := "Open"

finding_rhel_08_030121 := {
	"vuln_id": "V-230402",
	"stig_id": "RHEL-08-030121",
	"severity": "CAT II",
	"rule_title": "RHEL 8 audit system must protect auditing rules from unauthorized change.",
	"status": status_rhel_08_030121,
	"fix_text": "Add -e 2 as last line in /etc/audit/audit.rules",
}

# RHEL-08-030731 | V-244543 | CAT II - space_left_action must notify
default space_left_notify := false

space_left_notify if input.auditd_config.space_left_action == "email"
space_left_notify if input.auditd_config.space_left_action == "syslog"

status_rhel_08_030731 := "Not_a_Finding" if space_left_notify

else := "Open"

finding_rhel_08_030731 := {
	"vuln_id": "V-244543",
	"stig_id": "RHEL-08-030731",
	"severity": "CAT II",
	"rule_title": "RHEL 8 must notify the System Administrator (SA) and Information System Security Officer (ISSO) (at a minimum) when allocated audit record storage volume 75 percent utilization.",
	"status": status_rhel_08_030731,
	"fix_text": "Set space_left_action=email in /etc/audit/auditd.conf",
}

# =============================================================================
# COMPLIANCE AGGREGATION
# =============================================================================

# No CAT I rule in this module. array.concat rather than the literal `[]`: OPA >= 1.22 types a literal
# empty array as having no members and rejects iterating it (scripts/check_per_file_load.py).
cat_i_findings := array.concat([], [])

cat_ii_findings := [
	finding_rhel_08_030181,
	finding_rhel_08_030000,
	finding_rhel_08_030480,
	finding_rhel_08_030490,
	finding_rhel_08_030171,
	finding_rhel_08_030150,
	finding_rhel_08_030550,
	finding_rhel_08_030121,
	finding_rhel_08_030731,
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
