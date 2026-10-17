package cis_ubuntu_24_04.logging_test

import rego.v1

# Regression tests for validation 2026-10-17 fixes.

good := {
	"rsyslog": {"installed": true, "service_active": true, "service_enabled": true, "file_create_mode": "0640", "logging_rules_count": 6},
	"journald": {"service_active": true, "forward_to_syslog": "yes", "compress_enabled": "yes", "storage_mode": "persistent"},
	"logrotate": {"installed": true},
}

test_logging_fully_evidenced_is_compliant if {
	data.cis_ubuntu_24_04.logging.compliant with input as good
}

test_logging_missing_journald_settings_are_violations if {
	every k in ["forward_to_syslog", "compress_enabled", "storage_mode"] {
		i := json.remove(good, [concat("/", ["journald", k])])
		not data.cis_ubuntu_24_04.logging.compliant with input as i
	}
}

test_logging_journald_only_service_active_not_compliant if {
	j := {"rsyslog": good.rsyslog, "journald": {"service_active": true}, "logrotate": {"installed": true}}
	not data.cis_ubuntu_24_04.logging.compliant with input as j
	v := data.cis_ubuntu_24_04.logging.journald_violations with input as j
	count(v) == 3
}

test_logging_missing_file_create_mode_is_violation if {
	i := json.remove(good, ["rsyslog/file_create_mode"])
	not data.cis_ubuntu_24_04.logging.compliant with input as i
}

test_logging_missing_rule_count_is_violation if {
	i := json.remove(good, ["rsyslog/logging_rules_count"])
	not data.cis_ubuntu_24_04.logging.compliant with input as i
}

test_logging_stricter_file_create_mode_accepted if {
	data.cis_ubuntu_24_04.logging.compliant with input as object.union(good, {"rsyslog": {"file_create_mode": "0400"}})
}

test_logging_logrotate_not_counted_as_rsyslog if {
	i := object.union(good, {"logrotate": {"installed": false}})
	r := data.cis_ubuntu_24_04.logging.report with input as i
	r.rsyslog_violations == 0
	object.get(r, "logrotate_violations", -1) == 1
	r.total_violations == 1
}

test_logging_log_file_violation_survives_missing_owner_group if {
	i := object.union(good, {"log_file_permissions": {"analysis": [{"file": "/var/log/syslog", "exists": true, "fully_compliant": false, "actual_mode": "0666", "expected_mode": "0640"}]}})
	v := data.cis_ubuntu_24_04.logging.log_file_violations with input as i
	count(v) == 1
}
