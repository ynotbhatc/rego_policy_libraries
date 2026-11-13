package cis_amazon_linux_2023.logging_test

import rego.v1

# Regression tests for the 2026-10-17 validation pass (octal FileCreateMode).

test_logging_rsyslog_mode_0600_ok if {
	v := data.cis_amazon_linux_2023.logging.rsyslog_violations with input as {"rsyslog": {"file_create_mode": "0600"}}
	count([m | some m in v; startswith(m, "CIS 4.2.1.4")]) == 0
}

test_logging_rsyslog_mode_0400_stricter_ok if {
	v := data.cis_amazon_linux_2023.logging.rsyslog_violations with input as {"rsyslog": {"file_create_mode": "0400"}}
	count([m | some m in v; startswith(m, "CIS 4.2.1.4")]) == 0
}

test_logging_rsyslog_mode_3_digit_ok if {
	v := data.cis_amazon_linux_2023.logging.rsyslog_violations with input as {"rsyslog": {"file_create_mode": "640"}}
	count([m | some m in v; startswith(m, "CIS 4.2.1.4")]) == 0
}

test_logging_rsyslog_mode_0644_flagged if {
	v := data.cis_amazon_linux_2023.logging.rsyslog_violations with input as {"rsyslog": {"file_create_mode": "0644"}}
	count([m | some m in v; startswith(m, "CIS 4.2.1.4")]) == 1
}

test_logging_rsyslog_mode_missing_flagged if {
	v := data.cis_amazon_linux_2023.logging.rsyslog_violations with input as {"rsyslog": {}}
	count([m | some m in v; startswith(m, "CIS 4.2.1.4")]) == 1
}

# Semantic review 2026-11-13: missing journald / rsyslog facts must raise findings.
test_missing_journald_facts_flagged if {
	v := data.cis_amazon_linux_2023.logging.journald_violations with input as {"journald": {"service_active": true}}
	some a in v
	startswith(a, "CIS 4.2.1.3")
	some b in v
	startswith(b, "CIS 4.2.2.1")
	some c in v
	startswith(c, "CIS 4.2.2.2")
}

test_journald_good_facts_not_flagged if {
	v := data.cis_amazon_linux_2023.logging.journald_violations with input as {"journald": {"service_active": true, "forward_to_syslog": "yes", "compress_enabled": "yes", "storage_mode": "persistent"}}
	count(v) == 0
}

test_missing_logging_rules_count_flagged if {
	v := data.cis_amazon_linux_2023.logging.rsyslog_violations with input as {"rsyslog": {"installed": true}}
	"CIS 4.2.1.5: evidence missing - rsyslog.logging_rules_count not collected" in v
}

test_excessive_permissions_without_mode_still_flagged if {
	v := data.cis_amazon_linux_2023.logging.log_file_violations with input as {"excessive_permissions": {"files": [{"file": "/var/log/x"}]}}
	count(v) == 1
}
