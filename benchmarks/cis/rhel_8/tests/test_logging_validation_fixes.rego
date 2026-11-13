package cis_rhel8.logging_test

import rego.v1

# Regression tests for validation 2026-10-17 fixes (octal mode comparison).

test_rsyslog_stricter_create_mode_accepted if {
	v := data.cis_rhel8.logging.rsyslog_violations with input as {"rsyslog": {"file_create_mode": "0400"}}
	not some_createmode_violation(v)
}

test_rsyslog_0640_and_0600_accepted if {
	every m in ["0640", "0600"] {
		v := data.cis_rhel8.logging.rsyslog_violations with input as {"rsyslog": {"file_create_mode": m}}
		not some_createmode_violation(v)
	}
}

test_rsyslog_looser_create_mode_flagged if {
	every m in ["0644", "0660", "0666"] {
		v := data.cis_rhel8.logging.rsyslog_violations with input as {"rsyslog": {"file_create_mode": m}}
		some_createmode_violation(v)
	}
}

some_createmode_violation(v) if {
	some x in v
	startswith(x, "CIS 4.2.1.4")
}

# Semantic review 2026-11-13: missing journald / rsyslog facts must raise findings.
test_missing_journald_facts_flagged if {
	v := data.cis_rhel8.logging.journald_violations with input as {"journald": {"service_active": true}}
	some a in v
	startswith(a, "CIS 4.2.1.3")
	some b in v
	startswith(b, "CIS 4.2.2.1")
	some c in v
	startswith(c, "CIS 4.2.2.2")
}

test_journald_good_facts_not_flagged if {
	v := data.cis_rhel8.logging.journald_violations with input as {"journald": {"service_active": true, "forward_to_syslog": "yes", "compress_enabled": "yes", "storage_mode": "persistent"}}
	count(v) == 0
}

test_missing_logging_rules_count_flagged if {
	v := data.cis_rhel8.logging.rsyslog_violations with input as {"rsyslog": {"installed": true}}
	"CIS 4.2.1.5: evidence missing - rsyslog.logging_rules_count not collected" in v
}

test_excessive_permissions_without_mode_still_flagged if {
	v := data.cis_rhel8.logging.log_file_violations with input as {"excessive_permissions": {"files": [{"file": "/var/log/x"}]}}
	count(v) == 1
}
