# METADATA
# title: "CIS Ubuntu 22.04 LTS Benchmark v3.0.0 - Section 4.2: Logging Configuration"
# custom:
#   class: security
#   framework: cis_ubuntu_22_04
#   source: cis
#   domains: [linux, ubuntu]
#   coverage:
#     checks: 19
#     cited: 13
#     density: sized
#     basis: size
#     tested: true
#     entrypoint: report
#     guard: self
#     as_of: v2.4.2
package cis_ubuntu_22_04.logging

# CIS Ubuntu 22.04 LTS Benchmark v3.0.0 - Section 4.2: Logging Configuration

import rego.v1

default compliant := false

compliant if {
	count(violations) == 0
}

violations := array.concat(
	array.concat([v | some v in rsyslog_violations], [v | some v in journald_violations]),
	array.concat([v | some v in log_file_violations], [v | some v in logrotate_violations]),
)

# Helpers. Absent facts must not satisfy a check (fail closed).
# Parse an octal permission string ("644", "0644", "0o644") to an integer; undefined if not octal.
octal(s) := n if {
	t := trim_prefix(lower(trim_space(sprintf("%v", [s]))), "0o")
	regex.match(`^[0-7]{1,4}$`, t)
	p := concat("", [substring("0000", 0, 4 - count(t)), t])
	ds := [to_number(substring(p, i, 1)) | some i in numbers.range(0, 3)]
	n := ((ds[0] * 512) + (ds[1] * 64)) + ((ds[2] * 8) + ds[3])
}

# true when mode grants nothing beyond max (both octal strings)
mode_within(mode, max) if bits.and(octal(mode), bits.and(bits.negate(octal(max)), 4095)) == 0

journald_is(key, want) if input.journald[key] == want

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
	not journald_is("forward_to_syslog", "yes")
	msg := sprintf("CIS 4.2.1.3: journald not configured to forward to rsyslog (ForwardToSyslog: %v)", [object.get(input, ["journald", "forward_to_syslog"], "<not collected>")])
}

# CIS 4.2.1.4: rsyslog default file permissions
# octal compare: "640", "0640" and "0600" pass, anything granting more than 0640 (or unparsable/absent) fails
rsyslog_mode_ok if mode_within(input.rsyslog.file_create_mode, "0640")

rsyslog_violations contains msg if {
	not rsyslog_mode_ok
	msg := sprintf("CIS 4.2.1.4: rsyslog FileCreateMode not secure (current: %v, expected: 0640 or 0600)", [object.get(input, ["rsyslog", "file_create_mode"], "<not collected>")])
}

# CIS 4.2.1.5: Logging configured
rules_count_known if is_number(input.rsyslog.logging_rules_count)

rsyslog_violations contains msg if {
	not rules_count_known
	msg := "CIS 4.2.1.5: evidence missing — rsyslog.logging_rules_count not collected"
}

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
	not journald_is("compress_enabled", "yes")
	msg := sprintf("CIS 4.2.2.1: journald compression not enabled (Compress: %v)", [object.get(input, ["journald", "compress_enabled"], "<not collected>")])
}

# CIS 4.2.2.2: journald persistent storage
journald_violations contains msg if {
	not journald_is("storage_mode", "persistent")
	msg := sprintf("CIS 4.2.2.2: journald not configured for persistent storage (Storage: %v)", [object.get(input, ["journald", "storage_mode"], "<not collected>")])
}

# CIS 4.2.2.3: systemd-journald active
journald_violations contains msg if {
	not input.journald.service_active
	msg := "CIS 4.2.2.3: systemd-journald service is not active"
}

# CIS 4.2.3: Log file permissions
log_files_known if is_array(input.log_file_permissions.analysis)

log_file_violations contains msg if {
	not log_files_known
	msg := "CIS 4.2.3: evidence missing — log_file_permissions.analysis not collected"
}

excessive_known if is_array(input.excessive_permissions.files)

log_file_violations contains msg if {
	not excessive_known
	msg := "CIS 4.2.3: evidence missing — excessive_permissions.files not collected"
}

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
	count(object.get(input, ["excessive_permissions", "files"], [])) > 0
	some file in input.excessive_permissions.files
	msg := sprintf("CIS 4.2.3: Log file '%s' has excessive permissions (mode: %s, issue: %s)", [file.file, file.mode, file.issue])
}

# logrotate installed (reported in its own section, not under rsyslog; decisions 2026-10-19)
logrotate_violations contains msg if {
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
	"logrotate_violations": count(logrotate_violations),
	"rsyslog": {
		"installed": object.get(input, ["rsyslog", "installed"], null),
		"service_active": object.get(input, ["rsyslog", "service_active"], null),
		"service_enabled": object.get(input, ["rsyslog", "service_enabled"], null),
		"file_create_mode": object.get(input, ["rsyslog", "file_create_mode"], null),
		"logging_rules_count": object.get(input, ["rsyslog", "logging_rules_count"], null),
	},
	"journald": {
		"service_active": object.get(input, ["journald", "service_active"], null),
		"storage_mode": object.get(input, ["journald", "storage_mode"], null),
		"compress_enabled": object.get(input, ["journald", "compress_enabled"], null),
		"forward_to_syslog": object.get(input, ["journald", "forward_to_syslog"], null),
	},
	"section": "4.2 Logging Configuration",
	"benchmark": "CIS Ubuntu 22.04 v3.0.0",
}
