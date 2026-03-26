package cis_amazon_linux_2023.logging

# CIS Amazon Linux 2023 Section 4.2.x - Logging Configuration
# Validates rsyslog, journald, and log file permissions

import rego.v1

# =============================================================================
# MAIN COMPLIANCE RULES
# =============================================================================

default compliant := false

compliant if {
	count(violations) == 0
}

violations := array.concat(
	array.concat(
		[v | some v in rsyslog_violations],
		[v | some v in journald_violations],
	),
	[v | some v in log_file_violations],
)

# =============================================================================
# CIS 4.2.1.1 - RSYSLOG INSTALLATION
# =============================================================================

rsyslog_violations contains violation if {
	not input.rsyslog.installed
	violation := "CIS 4.2.1.1: rsyslog is not installed"
}

# =============================================================================
# CIS 4.2.1.2 - RSYSLOG SERVICE
# =============================================================================

rsyslog_violations contains violation if {
	input.rsyslog.installed
	not input.rsyslog.service_active
	violation := "CIS 4.2.1.2: rsyslog service is not active"
}

rsyslog_violations contains violation if {
	input.rsyslog.installed
	not input.rsyslog.service_enabled
	violation := "CIS 4.2.1.2: rsyslog service is not enabled"
}

# =============================================================================
# CIS 4.2.1.3 - JOURNALD FORWARDS TO RSYSLOG
# =============================================================================

journald_violations contains violation if {
	input.journald.forward_to_syslog != "yes"
	violation := sprintf("CIS 4.2.1.3: journald is not configured to forward to rsyslog (ForwardToSyslog: %s)", [
		input.journald.forward_to_syslog,
	])
}

# =============================================================================
# CIS 4.2.1.4 - RSYSLOG FILE PERMISSIONS
# =============================================================================

rsyslog_violations contains violation if {
	input.rsyslog.file_create_mode != "0640"
	input.rsyslog.file_create_mode != "0600"
	violation := sprintf("CIS 4.2.1.4: rsyslog $FileCreateMode is not secure (current: %s, expected: 0640 or 0600)", [
		input.rsyslog.file_create_mode,
	])
}

# =============================================================================
# CIS 4.2.1.5 - LOGGING CONFIGURED
# =============================================================================

rsyslog_violations contains violation if {
	input.rsyslog.logging_rules_count == 0
	violation := "CIS 4.2.1.5: No rsyslog logging rules configured"
}

rsyslog_violations contains violation if {
	input.rsyslog.logging_rules_count < 4
	violation := sprintf("CIS 4.2.1.5: Insufficient rsyslog logging rules configured (%d rules, expected at least 4)", [
		input.rsyslog.logging_rules_count,
	])
}

# =============================================================================
# CIS 4.2.1.6 - REMOTE LOGGING
# =============================================================================

# Note: Remote logging may not be required in all environments
# This is informational rather than a hard requirement
rsyslog_violations contains violation if {
	not input.rsyslog.remote_logging_configured
	# Only warn if explicitly required by your policy
	input.require_remote_logging == true
	violation := "CIS 4.2.1.6: rsyslog is not configured to send logs to remote host"
}

# =============================================================================
# CIS 4.2.2.1 - JOURNALD COMPRESSION
# =============================================================================

journald_violations contains violation if {
	input.journald.compress_enabled != "yes"
	violation := sprintf("CIS 4.2.2.1: journald compression is not enabled (Compress: %s)", [
		input.journald.compress_enabled,
	])
}

# =============================================================================
# CIS 4.2.2.2 - JOURNALD PERSISTENT STORAGE
# =============================================================================

journald_violations contains violation if {
	input.journald.storage_mode != "persistent"
	violation := sprintf("CIS 4.2.2.2: journald is not configured for persistent storage (Storage: %s)", [
		input.journald.storage_mode,
	])
}

# =============================================================================
# CIS 4.2.2.3 - JOURNALD SERVICE ACTIVE
# =============================================================================

journald_violations contains violation if {
	not input.journald.service_active
	violation := "CIS 4.2.2.3: systemd-journald service is not active"
}

# =============================================================================
# CIS 4.2.3 - LOG FILE PERMISSIONS
# =============================================================================

log_file_violations contains violation if {
	some file in input.log_file_permissions.analysis
	not file.fully_compliant
	file.exists
	violation := sprintf("CIS 4.2.3: Log file '%s' has incorrect permissions (mode: %s/%s, owner: %s/%s, group: %s/%s)", [
		file.file,
		file.actual_mode,
		file.expected_mode,
		file.actual_owner,
		file.expected_owner,
		file.actual_group,
		file.expected_group,
	])
}

# Files with excessive permissions
log_file_violations contains violation if {
	count(input.excessive_permissions.files) > 0
	some file in input.excessive_permissions.files
	violation := sprintf("CIS 4.2.3: Log file '%s' has excessive permissions (mode: %s, issue: %s)", [
		file.file,
		file.mode,
		file.issue,
	])
}

# =============================================================================
# LOGROTATE
# =============================================================================

rsyslog_violations contains violation if {
	not input.logrotate.installed
	violation := "CIS 4.2.x: logrotate is not installed (logs may fill disk)"
}

# =============================================================================
# COMPLIANCE CHECKS
# =============================================================================

compliance_summary := {
	"rsyslog_installed_and_enabled": input.compliance_checks.rsyslog_installed_and_enabled,
	"journald_active_and_configured": input.compliance_checks.journald_active_and_configured,
	"journald_forwards_to_rsyslog": input.compliance_checks.journald_forwards_to_rsyslog,
	"rsyslog_file_permissions_configured": input.compliance_checks.rsyslog_file_permissions_configured,
	"log_files_have_correct_permissions": input.compliance_checks.log_files_have_correct_permissions,
	"no_excessive_log_permissions": input.compliance_checks.no_excessive_log_permissions,
	"remote_logging_configured": input.compliance_checks.remote_logging_configured,
	"logrotate_installed": input.compliance_checks.logrotate_installed,
	"overall_compliant": count(violations) == 0,
}

# =============================================================================
# DETAILED REPORTING
# =============================================================================

# Non-compliant log files
non_compliant_log_files contains file if {
	some f in input.log_file_permissions.analysis
	not f.fully_compliant
	file := {
		"file": f.file,
		"actual_mode": f.actual_mode,
		"expected_mode": f.expected_mode,
		"mode_compliant": f.mode_compliant,
		"owner_compliant": f.owner_compliant,
		"group_compliant": f.group_compliant,
	}
}

# rsyslog configuration summary
rsyslog_summary := {
	"installed": input.rsyslog.installed,
	"service_active": input.rsyslog.service_active,
	"service_enabled": input.rsyslog.service_enabled,
	"file_create_mode": input.rsyslog.file_create_mode,
	"logging_rules_count": input.rsyslog.logging_rules_count,
	"remote_logging_configured": input.rsyslog.remote_logging_configured,
	"compliant": input.rsyslog.compliant,
}

# journald configuration summary
journald_summary := {
	"service_active": input.journald.service_active,
	"storage_mode": input.journald.storage_mode,
	"compress_enabled": input.journald.compress_enabled,
	"forward_to_syslog": input.journald.forward_to_syslog,
	"compliant": input.journald.compliant,
}

report := {
	"compliant": compliant,
	"total_violations": count(violations),
	"violations": violations,
	"compliance_summary": compliance_summary,
	"rsyslog_summary": rsyslog_summary,
	"journald_summary": journald_summary,
	"non_compliant_log_files": non_compliant_log_files,
	"excessive_permissions_count": input.excessive_permissions.count,
	"collection_timestamp": input.collection_timestamp,
}

