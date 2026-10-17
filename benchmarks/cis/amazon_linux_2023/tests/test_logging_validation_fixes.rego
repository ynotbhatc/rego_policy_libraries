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
