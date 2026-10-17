package cis_rhel9.logging_test

import rego.v1

# Validation fixes 2026-10-17: rsyslog FileCreateMode compared as octal; missing value is a violation.

rs(i) := v if {
	v := data.cis_rhel9.logging.rsyslog_violations with input as i
}

test_logging_filecreatemode_0600_ok if {
	count([v | some v in rs({"rsyslog": {"file_create_mode": "0600", "logging_rules_count": 3}}); contains(v, "4.2.1.4")]) == 0
}

test_logging_filecreatemode_0400_ok if {
	count([v | some v in rs({"rsyslog": {"file_create_mode": "400", "logging_rules_count": 3}}); contains(v, "4.2.1.4")]) == 0
}

test_logging_filecreatemode_0644_flagged if {
	count([v | some v in rs({"rsyslog": {"file_create_mode": "0644", "logging_rules_count": 3}}); contains(v, "4.2.1.4")]) == 1
}

test_logging_filecreatemode_missing_flagged if {
	"CIS 4.2.1.4: evidence missing — rsyslog.file_create_mode not collected" in rs({"rsyslog": {"logging_rules_count": 3}})
}
