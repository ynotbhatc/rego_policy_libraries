# METADATA
# title: "CIS Ubuntu 20.04 LTS Benchmark v3.0.0 - Section 4.2: Logging Configuration"
# custom:
#   class: security
#   framework: cis_ubuntu_20_04
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
package cis_ubuntu_20_04.logging

# CIS Ubuntu 20.04 LTS Benchmark v3.0.0 - Section 4.2: Logging Configuration

import rego.v1

default compliant := false

compliant if {
	count(violations) == 0
}

violations := array.concat(
	array.concat([v | some v in rsyslog_violations], [v | some v in journald_violations]),
	[v | some v in log_file_violations],
)

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

# Missing evidence must not pass: fields judged by comparison need to be collected.
required_journald := {
	"forward_to_syslog": "4.2.1.3",
	"compress_enabled": "4.2.2.1",
	"storage_mode": "4.2.2.2",
}

journald_violations contains msg if {
	some key, ctl in required_journald
	not input.journald[key]
	msg := sprintf("CIS %s: evidence missing — journald.%s not collected", [ctl, key])
}

required_rsyslog := {
	"file_create_mode": "4.2.1.4",
	"logging_rules_count": "4.2.1.5",
}

rsyslog_violations contains msg if {
	some key, ctl in required_rsyslog
	not is_present(object.get(input, ["rsyslog", key], null))
	msg := sprintf("CIS %s: evidence missing — rsyslog.%s not collected", [ctl, key])
}

# 0 is a legitimate value (logging_rules_count), so test for null instead of truthiness
is_present(v) if v != null

log_file_violations contains msg if {
	not is_array(object.get(input, ["log_file_permissions", "analysis"], null))
	msg := "CIS 4.2.3: evidence missing — log_file_permissions.analysis not collected"
}

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
	not mode_within(input.rsyslog.file_create_mode, "0640")
	msg := sprintf("CIS 4.2.1.4: rsyslog FileCreateMode not secure (current: %s, expected: 0640 or more restrictive)", [input.rsyslog.file_create_mode])
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
	count(object.get(input, ["excessive_permissions", "files"], [])) > 0
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
	"benchmark": "CIS Ubuntu 20.04 v3.0.0",
}
