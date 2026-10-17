package cis_rhel8.auditd_test

import rego.v1

# Regression tests for validation 2026-10-17 fixes.

test_auditd_missing_service_entry_is_violation if {
	v := data.cis_rhel8.auditd.service_violations with input as {"packages": {"audit": {}}}
	"CIS 4.1.1.2: evidence missing — auditd.service not collected" in v
}

test_auditd_present_service_no_missing_violation if {
	v := data.cis_rhel8.auditd.service_violations with input as {"packages": {"audit": {}}, "services": {"auditd.service": {"status": "enabled", "state": "running"}}}
	count(v) == 0
}

test_auditd_config_mode_stricter_is_ok if {
	v := data.cis_rhel8.auditd.permission_violations with input as {"auditd": {"config_permissions": [{"stat": {"path": "/etc/audit/auditd.conf", "mode": "0600", "pw_name": "root"}}]}}
	count(v) == 0
}

test_auditd_config_mode_looser_is_violation if {
	v := data.cis_rhel8.auditd.permission_violations with input as {"auditd": {"config_permissions": [{"stat": {"path": "/etc/audit/auditd.conf", "mode": "0644", "pw_name": "root"}}]}}
	count(v) == 1
}

test_auditd_log_mode_octal_not_decimal if {
	v := data.cis_rhel8.auditd.permission_violations with input as {"auditd": {"log_permissions": {"mode": "0604"}}}
	count(v) == 1
}
