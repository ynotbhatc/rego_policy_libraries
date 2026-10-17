# METADATA
# title: "CIS Amazon Linux 2023 Section 4.2.x - Logging Configuration"
# custom:
#   class: security
#   framework: cis_amazon_linux_2023
#   source: cis
#   domains: [linux, amazon-linux]
#   coverage:
#     checks: 14
#     cited: 11
#     density: sized
#     basis: size
#     tested: true
#     entrypoint: report
#     guard: self
#     as_of: v2.4.1
package cis_amazon_linux_2023.logging

# CIS Amazon Linux 2023 Section 4.2.x - Logging Configuration
# Validates rsyslog, journald, and log file permissions

import rego.v1

# =============================================================================
# MAIN COMPLIANCE RULES
# =============================================================================

default compliant := false

# Parse an octal permission string ("644", "0644", "0o644") to an integer; undefined if not octal.
octal(s) := n if {
	t := trim_prefix(lower(trim_space(sprintf("%v", [s]))), "0o")
	regex.match(`^[0-7]{1,4}$`, t)
	p := concat("", [substring("0000", 0, 4 - count(t)), t])
	ds := [to_number(d) | some d in split(p, "")]
	n := ((ds[0] * 512) + (ds[1] * 64)) + ((ds[2] * 8) + ds[3])
}

# true when mode grants nothing beyond max (both octal strings)
mode_within(mode, max) if bits.and(octal(mode), bits.and(bits.negate(octal(max)), 4095)) == 0

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

rsyslog_violations contains "CIS 4.2.1.4: evidence missing - rsyslog.file_create_mode not collected ($FileCreateMode unset defaults to 0644)" if {
	not input.rsyslog.file_create_mode
}

rsyslog_violations contains violation if {
	mode := input.rsyslog.file_create_mode
	not mode_within(mode, "0640")
	violation := sprintf("CIS 4.2.1.4: rsyslog $FileCreateMode is not secure (current: %s, expected: 0640 or stricter)", [mode])
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
	count(object.get(input, ["excessive_permissions", "files"], [])) > 0
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
	"rsyslog_installed_and_enabled": object.get(input, ["compliance_checks", "rsyslog_installed_and_enabled"], null),
	"journald_active_and_configured": object.get(input, ["compliance_checks", "journald_active_and_configured"], null),
	"journald_forwards_to_rsyslog": object.get(input, ["compliance_checks", "journald_forwards_to_rsyslog"], null),
	"rsyslog_file_permissions_configured": object.get(input, ["compliance_checks", "rsyslog_file_permissions_configured"], null),
	"log_files_have_correct_permissions": object.get(input, ["compliance_checks", "log_files_have_correct_permissions"], null),
	"no_excessive_log_permissions": object.get(input, ["compliance_checks", "no_excessive_log_permissions"], null),
	"remote_logging_configured": object.get(input, ["compliance_checks", "remote_logging_configured"], null),
	"logrotate_installed": object.get(input, ["compliance_checks", "logrotate_installed"], null),
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
	"installed": object.get(input, ["rsyslog", "installed"], null),
	"service_active": object.get(input, ["rsyslog", "service_active"], null),
	"service_enabled": object.get(input, ["rsyslog", "service_enabled"], null),
	"file_create_mode": object.get(input, ["rsyslog", "file_create_mode"], null),
	"logging_rules_count": object.get(input, ["rsyslog", "logging_rules_count"], null),
	"remote_logging_configured": object.get(input, ["rsyslog", "remote_logging_configured"], null),
	"compliant": object.get(input, ["rsyslog", "compliant"], null),
}

# journald configuration summary
journald_summary := {
	"service_active": object.get(input, ["journald", "service_active"], null),
	"storage_mode": object.get(input, ["journald", "storage_mode"], null),
	"compress_enabled": object.get(input, ["journald", "compress_enabled"], null),
	"forward_to_syslog": object.get(input, ["journald", "forward_to_syslog"], null),
	"compliant": object.get(input, ["journald", "compliant"], null),
}

report := {
	"compliant": compliant,
	"total_violations": count(violations),
	"violations": violations,
	"compliance_summary": compliance_summary,
	"rsyslog_summary": rsyslog_summary,
	"journald_summary": journald_summary,
	"non_compliant_log_files": non_compliant_log_files,
	"excessive_permissions_count": object.get(input, ["excessive_permissions", "count"], null),
	"collection_timestamp": object.get(input, ["collection_timestamp"], null),
}

