package cis_rhel9.logging_test

import rego.v1

# Validation fixes 2026-10-17: rsyslog FileCreateMode compared as octal; missing value is a violation.
# Re-pointed to CIS RHEL 9 v3.0.0 (2026-10-20): same test names, v3 recommendation ids.
# v2 4.2.1.4 -> v3 6.1.2.3. An unset mode while rsyslog is installed means rsyslog's 0644 default: not met.

rs(i) := [v | some v in data.cis_rhel9.logging.violations with input as i; startswith(v, "6.1.2.3: ")]

test_logging_filecreatemode_0600_ok if {
	count(rs({"rsyslog": {"installed": true, "file_create_mode": "0600", "logging_rules_count": 3}})) == 0
}

test_logging_filecreatemode_0400_ok if {
	count(rs({"rsyslog": {"installed": true, "file_create_mode": "400", "logging_rules_count": 3}})) == 0
}

test_logging_filecreatemode_0644_flagged if {
	count(rs({"rsyslog": {"installed": true, "file_create_mode": "0644", "logging_rules_count": 3}})) == 1
}

test_logging_filecreatemode_missing_flagged if {
	"6.1.2.3: not met — Ensure rsyslog log file creation mode is configured" in rs({"rsyslog": {"installed": true, "logging_rules_count": 3}})
	"6.1.2.3: evidence missing — rsyslog.installed/file_create_mode not collected" in rs({"rsyslog": {"logging_rules_count": 3}})
}
