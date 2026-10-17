package cis_ubuntu_20_04.logging_test

import rego.v1

# Validation fix pass 2026-10-17.

good := {
	"rsyslog": {"installed": true, "service_active": true, "service_enabled": true, "file_create_mode": "0640", "logging_rules_count": 5},
	"journald": {"forward_to_syslog": "yes", "compress_enabled": "yes", "storage_mode": "persistent", "service_active": true},
	"log_file_permissions": {"analysis": []},
	"logrotate": {"installed": true},
}

test_good_input_compliant if {
	data.cis_ubuntu_20_04.logging.compliant with input as good
}

test_missing_journald_object_flagged if {
	v := data.cis_ubuntu_20_04.logging.journald_violations with input as json.remove(good, ["journald"])
	count({m | some m in v; contains(m, "evidence missing")}) == 3
}

test_missing_rsyslog_mode_and_count_flagged if {
	v := data.cis_ubuntu_20_04.logging.rsyslog_violations with input as json.remove(good, ["rsyslog/file_create_mode", "rsyslog/logging_rules_count"])
	count({m | some m in v; contains(m, "evidence missing")}) == 2
}

test_missing_log_file_analysis_flagged if {
	not data.cis_ubuntu_20_04.logging.compliant with input as json.remove(good, ["log_file_permissions"])
}

test_file_create_mode_variants if {
	every m in ["640", "0600", "0o640", "0400"] {
		v := data.cis_ubuntu_20_04.logging.rsyslog_violations with input as object.union(good, {"rsyslog": {"file_create_mode": m}})
		count(v) == 0
	}
	v2 := data.cis_ubuntu_20_04.logging.rsyslog_violations with input as object.union(good, {"rsyslog": {"file_create_mode": "0644"}})
	count(v2) == 1
}
