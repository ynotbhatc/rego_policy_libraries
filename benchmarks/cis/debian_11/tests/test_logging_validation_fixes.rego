package cis_debian_11.logging_test

import rego.v1

good := {
	"rsyslog": {"installed": true, "service_active": true, "service_enabled": true, "file_create_mode": "0640", "logging_rules_count": 6},
	"journald": {"forward_to_syslog": "yes", "compress_enabled": "yes", "storage_mode": "persistent", "service_active": true},
	"log_file_permissions": {"analysis": []},
	"logrotate": {"installed": true},
}

test_good_compliant if {
	data.cis_debian_11.logging.compliant with input as good
}

test_missing_rsyslog_mode_violates if {
	i := json.patch(good, [{"op": "remove", "path": "/rsyslog/file_create_mode"}])
	not data.cis_debian_11.logging.compliant with input as i
}

test_missing_rule_count_violates if {
	i := json.patch(good, [{"op": "remove", "path": "/rsyslog/logging_rules_count"}])
	not data.cis_debian_11.logging.compliant with input as i
}

test_missing_forward_violates if {
	i := json.patch(good, [{"op": "remove", "path": "/journald/forward_to_syslog"}])
	some m in data.cis_debian_11.logging.journald_violations with input as i
	contains(m, "evidence missing")
}

test_missing_log_file_analysis_violates if {
	i := json.patch(good, [{"op": "remove", "path": "/log_file_permissions"}])
	not data.cis_debian_11.logging.compliant with input as i
}

test_mode_octal_forms if {
	i := json.patch(good, [{"op": "replace", "path": "/rsyslog/file_create_mode", "value": "640"}])
	data.cis_debian_11.logging.compliant with input as i
}

test_mode_0644_violates if {
	i := json.patch(good, [{"op": "replace", "path": "/rsyslog/file_create_mode", "value": "0644"}])
	not data.cis_debian_11.logging.compliant with input as i
}
