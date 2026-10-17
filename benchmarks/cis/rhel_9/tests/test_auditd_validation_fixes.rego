package cis_rhel9.auditd_test

import rego.v1

# Validation fixes 2026-10-17: missing auditd.service evidence and octal mode handling.

test_auditd_service_missing_is_violation if {
	v := data.cis_rhel9.auditd.service_violations with input as {"services": {}}
	"CIS 4.1.1.2: evidence missing — auditd.service not collected" in v
}

test_auditd_service_present_no_missing_violation if {
	v := data.cis_rhel9.auditd.service_violations with input as {"services": {"auditd.service": {"status": "enabled", "state": "running"}}}
	not "CIS 4.1.1.2: evidence missing — auditd.service not collected" in v
}

test_auditd_config_mode_stricter_is_ok if {
	v := data.cis_rhel9.auditd.permission_violations with input as {"auditd": {"config_permissions": [{"stat": {"path": "/etc/audit/auditd.conf", "mode": "0600", "pw_name": "root"}}]}}
	count(v) == 0
}

test_auditd_config_mode_without_leading_zero_is_ok if {
	v := data.cis_rhel9.auditd.permission_violations with input as {"auditd": {"config_permissions": [{"stat": {"path": "/etc/audit/auditd.conf", "mode": "640", "pw_name": "root"}}]}}
	count(v) == 0
}

test_auditd_config_mode_too_open_is_violation if {
	v := data.cis_rhel9.auditd.permission_violations with input as {"auditd": {"config_permissions": [{"stat": {"path": "/etc/audit/auditd.conf", "mode": "0644", "pw_name": "root"}}]}}
	count(v) == 1
}

test_auditd_log_mode_other_readable_is_violation if {
	v := data.cis_rhel9.auditd.permission_violations with input as {"auditd": {"log_permissions": {"mode": "0477"}}}
	count(v) == 1
}

test_auditd_log_dir_mode_group_write_is_violation if {
	v := data.cis_rhel9.auditd.permission_violations with input as {"auditd": {"log_dir_permissions": {"mode": "0770"}}}
	count(v) == 1
}
