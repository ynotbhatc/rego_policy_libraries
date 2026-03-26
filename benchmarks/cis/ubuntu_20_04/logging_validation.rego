package cis_ubuntu_20_04.logging

# CIS Ubuntu 20.04 LTS Benchmark v1.1.0 - Section 4.2: Logging Configuration

import rego.v1

default compliant := false

compliant if {
	count(violations) == 0
}

violations := array.concat(
	array.concat([v | some v in rsyslog_violations], [v | some v in journald_violations]),
	[v | some v in log_file_violations],
)

# CIS 4.2.1.1: rsyslog installed
rsyslog_violations contains msg if {
	not input.rsyslog.installed
	msg := "CIS 4.2.1.1: rsyslog is not installed"
}

# CIS 4.2.1.2: rsyslog service enabled and active
rsyslog_violations contains msg if {
	input.rsyslog.installed
	not input.rsyslog.service_active
	msg := "CIS 4.2.1.2: rsyslog service is not active"
}

rsyslog_violations contains msg if {
	input.rsyslog.installed
	not input.rsyslog.service_enabled
	msg := "CIS 4.2.1.2: rsyslog service is not enabled"
}

# CIS 4.2.1.3: journald forwards to rsyslog
journald_violations contains msg if {
	input.journald.forward_to_syslog != "yes"
	msg := sprintf("CIS 4.2.1.3: journald not configured to forward to rsyslog (ForwardToSyslog: %s)", [input.journald.forward_to_syslog])
}

# CIS 4.2.1.4: rsyslog default file permissions
rsyslog_violations contains msg if {
	input.rsyslog.file_create_mode != "0640"
	input.rsyslog.file_create_mode != "0600"
	msg := sprintf("CIS 4.2.1.4: rsyslog FileCreateMode not secure (current: %s, expected: 0640 or 0600)", [input.rsyslog.file_create_mode])
}

# CIS 4.2.1.5: Logging configured
rsyslog_violations contains msg if {
	input.rsyslog.logging_rules_count == 0
	msg := "CIS 4.2.1.5: No rsyslog logging rules configured"
}

rsyslog_violations contains msg if {
	input.rsyslog.logging_rules_count > 0
	input.rsyslog.logging_rules_count < 4
	msg := sprintf("CIS 4.2.1.5: Insufficient rsyslog logging rules (%d rules, expected at least 4)", [input.rsyslog.logging_rules_count])
}

# CIS 4.2.1.6: Remote logging (conditional)
rsyslog_violations contains msg if {
	not input.rsyslog.remote_logging_configured
	input.require_remote_logging == true
	msg := "CIS 4.2.1.6: rsyslog not configured to send logs to remote host"
}

# CIS 4.2.2.1: journald compression
journald_violations contains msg if {
	input.journald.compress_enabled != "yes"
	msg := sprintf("CIS 4.2.2.1: journald compression not enabled (Compress: %s)", [input.journald.compress_enabled])
}

# CIS 4.2.2.2: journald persistent storage
journald_violations contains msg if {
	input.journald.storage_mode != "persistent"
	msg := sprintf("CIS 4.2.2.2: journald not configured for persistent storage (Storage: %s)", [input.journald.storage_mode])
}

# CIS 4.2.2.3: systemd-journald active
journald_violations contains msg if {
	not input.journald.service_active
	msg := "CIS 4.2.2.3: systemd-journald service is not active"
}

# CIS 4.2.3: Log file permissions
log_file_violations contains msg if {
	some file in input.log_file_permissions.analysis
	not file.fully_compliant
	file.exists
	msg := sprintf("CIS 4.2.3: Log file '%s' has incorrect permissions (mode: %s/%s, owner: %s/%s, group: %s/%s)", [
		file.file,
		file.actual_mode, file.expected_mode,
		file.actual_owner, file.expected_owner,
		file.actual_group, file.expected_group,
	])
}

log_file_violations contains msg if {
	count(input.excessive_permissions.files) > 0
	some file in input.excessive_permissions.files
	msg := sprintf("CIS 4.2.3: Log file '%s' has excessive permissions (mode: %s, issue: %s)", [file.file, file.mode, file.issue])
}

# logrotate installed
rsyslog_violations contains msg if {
	not input.logrotate.installed
	msg := "CIS 4.2.x: logrotate is not installed (logs may fill disk)"
}

report := {
	"compliant": compliant,
	"total_violations": count(violations),
	"violations": violations,
	"rsyslog_violations": count(rsyslog_violations),
	"journald_violations": count(journald_violations),
	"log_file_violations": count(log_file_violations),
	"rsyslog": {
		"installed": input.rsyslog.installed,
		"service_active": input.rsyslog.service_active,
		"service_enabled": input.rsyslog.service_enabled,
		"file_create_mode": input.rsyslog.file_create_mode,
		"logging_rules_count": input.rsyslog.logging_rules_count,
	},
	"journald": {
		"service_active": input.journald.service_active,
		"storage_mode": input.journald.storage_mode,
		"compress_enabled": input.journald.compress_enabled,
		"forward_to_syslog": input.journald.forward_to_syslog,
	},
	"section": "4.2 Logging Configuration",
	"benchmark": "CIS Ubuntu 20.04 v1.1.0",
}
