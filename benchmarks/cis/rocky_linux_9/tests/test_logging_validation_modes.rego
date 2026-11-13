package cis_rocky_linux_9.logging_test

import rego.v1

has(prefix, inp) if {
	v := data.cis_rocky_linux_9.logging.violations with input as inp
	some x in v
	startswith(x, prefix)
}

test_create_mode_640_ok if not has("CIS 4.2.1.4", {"rsyslog": {"file_create_mode": "0640"}})
test_create_mode_unpadded_640_ok if not has("CIS 4.2.1.4", {"rsyslog": {"file_create_mode": "640"}})
test_create_mode_0600_ok if not has("CIS 4.2.1.4", {"rsyslog": {"file_create_mode": "0600"}})
test_create_mode_0400_ok if not has("CIS 4.2.1.4", {"rsyslog": {"file_create_mode": "0400"}})
test_create_mode_0644_flagged if has("CIS 4.2.1.4", {"rsyslog": {"file_create_mode": "0644"}})
test_create_mode_absent_flagged if has("CIS 4.2.1.4", {"rsyslog": {}})

# Semantic review 2026-11-13: missing journald / rsyslog facts must raise findings.
test_missing_journald_facts_flagged if {
	v := data.cis_rocky_linux_9.logging.journald_violations with input as {"journald": {"service_active": true}}
	some a in v
	startswith(a, "CIS 4.2.1.3")
	some b in v
	startswith(b, "CIS 4.2.2.1")
	some c in v
	startswith(c, "CIS 4.2.2.2")
}

test_journald_good_facts_not_flagged if {
	v := data.cis_rocky_linux_9.logging.journald_violations with input as {"journald": {"service_active": true, "forward_to_syslog": "yes", "compress_enabled": "yes", "storage_mode": "persistent"}}
	count(v) == 0
}

test_missing_logging_rules_count_flagged if {
	v := data.cis_rocky_linux_9.logging.rsyslog_violations with input as {"rsyslog": {"installed": true}}
	"CIS 4.2.1.5: evidence missing - rsyslog.logging_rules_count not collected" in v
}

test_excessive_permissions_without_mode_still_flagged if {
	v := data.cis_rocky_linux_9.logging.log_file_violations with input as {"excessive_permissions": {"files": [{"file": "/var/log/x"}]}}
	count(v) == 1
}
