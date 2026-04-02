package stig.rhel_9.audit_logging

# DISA STIG for RHEL 9 - Audit Logging Module
# STIG Version: V2R2 | Released: October 2024
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

# RHEL-09-653010 | V-258010 | CAT I
# auditd service must be running
default auditd_active := false

auditd_active if {
	input.services.auditd == "active"
}

status_rhel_09_653010 := "Not_a_Finding" if { auditd_active } else := "Open"

finding_rhel_09_653010 := {
	"vuln_id": "V-258010",
	"stig_id": "RHEL-09-653010",
	"severity": "CAT I",
	"rule_title": "RHEL 9 must start the auditd service",
	"status": status_rhel_09_653010,
	"fix_text": "Enable and start auditd: systemctl enable --now auditd",
}

# RHEL-09-653015 | V-258011 | CAT I
# Audit log storage must be sufficient (max_log_file_action must not be ignore)
default audit_storage_ok := false

audit_storage_ok if {
	input.auditd_config.max_log_file_action != "ignore"
	input.auditd_config.max_log_file_action != "IGNORE"
}

status_rhel_09_653015 := "Not_a_Finding" if { audit_storage_ok } else := "Open"

finding_rhel_09_653015 := {
	"vuln_id": "V-258011",
	"stig_id": "RHEL-09-653015",
	"severity": "CAT I",
	"rule_title": "RHEL 9 audit logs must not automatically be overwritten",
	"status": status_rhel_09_653015,
	"fix_text": "Set max_log_file_action = keep_logs in /etc/audit/auditd.conf",
}

# =============================================================================
# CAT II - MEDIUM SEVERITY
# =============================================================================

# RHEL-09-653020 | V-258012 | CAT II
# audit log directory must be mode 0750 or less
default audit_log_dir_permissions_ok := false

audit_log_dir_permissions_ok if {
	input.auditd_config.log_dir_permissions == "0750"
}

audit_log_dir_permissions_ok if {
	input.auditd_config.log_dir_permissions == "750"
}

status_rhel_09_653020 := "Not_a_Finding" if { audit_log_dir_permissions_ok } else := "Open"

finding_rhel_09_653020 := {
	"vuln_id": "V-258012",
	"stig_id": "RHEL-09-653020",
	"severity": "CAT II",
	"rule_title": "RHEL 9 audit log directory must have a mode of 0750 or less permissive",
	"status": status_rhel_09_653020,
	"fix_text": "Fix audit log dir permissions: chmod 0750 /var/log/audit",
}

# RHEL-09-653025 | V-258013 | CAT II
# Admin space left action must be configured
default admin_space_left_action_ok := false

admin_space_left_action_ok if {
	action := input.auditd_config.admin_space_left_action
	action != "ignore"
	action != "IGNORE"
}

status_rhel_09_653025 := "Not_a_Finding" if { admin_space_left_action_ok } else := "Open"

finding_rhel_09_653025 := {
	"vuln_id": "V-258013",
	"stig_id": "RHEL-09-653025",
	"severity": "CAT II",
	"rule_title": "RHEL 9 audit system must take appropriate action when the audit storage volume is full",
	"status": status_rhel_09_653025,
	"fix_text": "Set admin_space_left_action = single in /etc/audit/auditd.conf",
}

# RHEL-09-653030 | V-258014 | CAT II
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

status_rhel_09_653030 := "Not_a_Finding" if { space_left_action_ok } else := "Open"

finding_rhel_09_653030 := {
	"vuln_id": "V-258014",
	"stig_id": "RHEL-09-653030",
	"severity": "CAT II",
	"rule_title": "RHEL 9 audit system must notify the System Administrator when the audit storage volume approaches capacity",
	"status": status_rhel_09_653030,
	"fix_text": "Set space_left_action = email in /etc/audit/auditd.conf",
}

# RHEL-09-654010 | V-258015 | CAT II
# Audit rules: execve (b64) must be audited
default audit_execve_b64 := false

audit_execve_b64 if {
	audit_rule_exists("-a always,exit -F arch=b64 -S execve")
}

status_rhel_09_654010 := "Not_a_Finding" if { audit_execve_b64 } else := "Open"

finding_rhel_09_654010 := {
	"vuln_id": "V-258015",
	"stig_id": "RHEL-09-654010",
	"severity": "CAT II",
	"rule_title": "RHEL 9 must audit all uses of the execve syscall",
	"status": status_rhel_09_654010,
	"fix_text": "Add audit rule: -a always,exit -F arch=b64 -S execve -k exec_commands",
}

# RHEL-09-654015 | V-258016 | CAT II
# Audit rules: execve (b32) must be audited
default audit_execve_b32 := false

audit_execve_b32 if {
	audit_rule_exists("-a always,exit -F arch=b32 -S execve")
}

status_rhel_09_654015 := "Not_a_Finding" if { audit_execve_b32 } else := "Open"

finding_rhel_09_654015 := {
	"vuln_id": "V-258016",
	"stig_id": "RHEL-09-654015",
	"severity": "CAT II",
	"rule_title": "RHEL 9 must audit all uses of the execve syscall (32-bit)",
	"status": status_rhel_09_654015,
	"fix_text": "Add audit rule: -a always,exit -F arch=b32 -S execve -k exec_commands",
}

# RHEL-09-654020 | V-258017 | CAT II
# Audit rules: chown must be audited
default audit_chown := false

audit_chown if {
	audit_rule_exists("-a always,exit -F arch=b64 -S chown")
}

status_rhel_09_654020 := "Not_a_Finding" if { audit_chown } else := "Open"

finding_rhel_09_654020 := {
	"vuln_id": "V-258017",
	"stig_id": "RHEL-09-654020",
	"severity": "CAT II",
	"rule_title": "RHEL 9 must audit all uses of the chown, fchown, fchownat, and lchown syscalls",
	"status": status_rhel_09_654020,
	"fix_text": "Add audit rule for chown: -a always,exit -F arch=b64 -S chown,fchown,fchownat,lchown",
}

# RHEL-09-654025 | V-258018 | CAT II
# Audit rules: chmod must be audited
default audit_chmod := false

audit_chmod if {
	audit_rule_exists("-a always,exit -F arch=b64 -S chmod")
}

status_rhel_09_654025 := "Not_a_Finding" if { audit_chmod } else := "Open"

finding_rhel_09_654025 := {
	"vuln_id": "V-258018",
	"stig_id": "RHEL-09-654025",
	"severity": "CAT II",
	"rule_title": "RHEL 9 must audit all uses of the chmod, fchmod, and fchmodat syscalls",
	"status": status_rhel_09_654025,
	"fix_text": "Add audit rule for chmod: -a always,exit -F arch=b64 -S chmod,fchmod,fchmodat",
}

# RHEL-09-654030 | V-258019 | CAT II
# Audit rules: setxattr must be audited
default audit_setxattr := false

audit_setxattr if {
	audit_rule_exists("-a always,exit -F arch=b64 -S setxattr")
}

status_rhel_09_654030 := "Not_a_Finding" if { audit_setxattr } else := "Open"

finding_rhel_09_654030 := {
	"vuln_id": "V-258019",
	"stig_id": "RHEL-09-654030",
	"severity": "CAT II",
	"rule_title": "RHEL 9 must audit all uses of the setxattr, fsetxattr, lsetxattr, removexattr, fremovexattr, and lremovexattr syscalls",
	"status": status_rhel_09_654030,
	"fix_text": "Add audit rules for xattr operations",
}

# RHEL-09-654035 | V-258020 | CAT II
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

status_rhel_09_654035 := "Not_a_Finding" if { audit_open_failure } else := "Open"

finding_rhel_09_654035 := {
	"vuln_id": "V-258020",
	"stig_id": "RHEL-09-654035",
	"severity": "CAT II",
	"rule_title": "RHEL 9 must audit all uses of the open, openat, and open_by_handle_at syscalls when returning EACCES or EPERM",
	"status": status_rhel_09_654035,
	"fix_text": "Add audit rules for failed file access: -a always,exit -F arch=b64 -S open -F exit=-EACCES -k access",
}

# RHEL-09-654040 | V-258021 | CAT II
# Audit rules: sudoers modification must be audited
default audit_sudoers := false

audit_sudoers if {
	audit_rule_exists("-w /etc/sudoers")
}

status_rhel_09_654040 := "Not_a_Finding" if { audit_sudoers } else := "Open"

finding_rhel_09_654040 := {
	"vuln_id": "V-258021",
	"stig_id": "RHEL-09-654040",
	"severity": "CAT II",
	"rule_title": "RHEL 9 must generate audit records for any successful/unsuccessful use of sudoers files",
	"status": status_rhel_09_654040,
	"fix_text": "Add audit rule: -w /etc/sudoers -p wa -k sudoers_change",
}

# RHEL-09-654045 | V-258022 | CAT II
# Audit rules: /etc/passwd modification must be audited
default audit_passwd_file := false

audit_passwd_file if {
	audit_rule_exists("-w /etc/passwd")
}

status_rhel_09_654045 := "Not_a_Finding" if { audit_passwd_file } else := "Open"

finding_rhel_09_654045 := {
	"vuln_id": "V-258022",
	"stig_id": "RHEL-09-654045",
	"severity": "CAT II",
	"rule_title": "RHEL 9 must audit all account and group changes",
	"status": status_rhel_09_654045,
	"fix_text": "Add audit rule: -w /etc/passwd -p wa -k usermod",
}

# RHEL-09-654050 | V-258023 | CAT II
# Audit rules: privileged command use must be audited
default audit_privileged_cmds := false

audit_privileged_cmds if {
	audit_rule_exists("-a always,exit -F path=/usr/bin/sudo")
}

audit_privileged_cmds if {
	audit_rule_exists("privileged")
}

status_rhel_09_654050 := "Not_a_Finding" if { audit_privileged_cmds } else := "Open"

finding_rhel_09_654050 := {
	"vuln_id": "V-258023",
	"stig_id": "RHEL-09-654050",
	"severity": "CAT II",
	"rule_title": "RHEL 9 must generate audit records when successful/unsuccessful uses of the sudo command occur",
	"status": status_rhel_09_654050,
	"fix_text": "Add audit rule: -a always,exit -F path=/usr/bin/sudo -F perm=x -k priv_cmd",
}

# RHEL-09-654055 | V-258024 | CAT II
# Audit rules: mount must be audited
default audit_mount := false

audit_mount if {
	audit_rule_exists("-a always,exit -F arch=b64 -S mount")
}

status_rhel_09_654055 := "Not_a_Finding" if { audit_mount } else := "Open"

finding_rhel_09_654055 := {
	"vuln_id": "V-258024",
	"stig_id": "RHEL-09-654055",
	"severity": "CAT II",
	"rule_title": "RHEL 9 must generate audit records when successful/unsuccessful attempts to use the mount command occur",
	"status": status_rhel_09_654055,
	"fix_text": "Add audit rule: -a always,exit -F arch=b64 -S mount -k mount",
}

# RHEL-09-654060 | V-258025 | CAT II
# Audit rules: module loading/unloading must be audited
default audit_modules := false

audit_modules if {
	audit_rule_exists("-a always,exit -F arch=b64 -S finit_module")
}

audit_modules if {
	audit_rule_exists("-a always,exit -F arch=b64 -S init_module")
}

status_rhel_09_654060 := "Not_a_Finding" if { audit_modules } else := "Open"

finding_rhel_09_654060 := {
	"vuln_id": "V-258025",
	"stig_id": "RHEL-09-654060",
	"severity": "CAT II",
	"rule_title": "RHEL 9 must generate audit records for kernel module loading/unloading",
	"status": status_rhel_09_654060,
	"fix_text": "Add audit rules for module operations",
}

# RHEL-09-654065 | V-258026 | CAT II
# Audit rules must be immutable
default audit_rules_immutable := false

audit_rules_immutable if {
	audit_rule_exists("-e 2")
}

status_rhel_09_654065 := "Not_a_Finding" if { audit_rules_immutable } else := "Open"

finding_rhel_09_654065 := {
	"vuln_id": "V-258026",
	"stig_id": "RHEL-09-654065",
	"severity": "CAT II",
	"rule_title": "RHEL 9 must make the audit configuration immutable",
	"status": status_rhel_09_654065,
	"fix_text": "Add -e 2 as the last line in /etc/audit/audit.rules",
}

# =============================================================================
# COMPLIANCE AGGREGATION
# =============================================================================

cat_i_findings := [
	finding_rhel_09_653010,
	finding_rhel_09_653015,
]

cat_ii_findings := [
	finding_rhel_09_653020,
	finding_rhel_09_653025,
	finding_rhel_09_653030,
	finding_rhel_09_654010,
	finding_rhel_09_654015,
	finding_rhel_09_654020,
	finding_rhel_09_654025,
	finding_rhel_09_654030,
	finding_rhel_09_654035,
	finding_rhel_09_654040,
	finding_rhel_09_654045,
	finding_rhel_09_654050,
	finding_rhel_09_654055,
	finding_rhel_09_654060,
	finding_rhel_09_654065,
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
