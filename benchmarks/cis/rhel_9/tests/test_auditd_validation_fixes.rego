package cis_rhel9.auditd_test

import rego.v1

# Validation fixes 2026-10-17: missing auditd.service evidence and octal mode handling.
# Re-pointed to CIS RHEL 9 v3.0.0 (2026-10-20): same test names, v3 recommendation ids.
# v2 4.1.1.2 -> 6.2.1.4 (service), 4.1.4.x -> 6.2.4.1/6.2.4.2/6.2.4.5 (modes).

ids(vs, id) := [v | some v in vs; startswith(v, concat("", [id, ": "]))]

test_auditd_service_missing_is_violation if {
	vs := data.cis_rhel9.auditd.violations with input as {"services": {}}
	"6.2.1.4: evidence missing — services not collected" in vs
}

test_auditd_service_present_no_missing_violation if {
	vs := data.cis_rhel9.auditd.violations with input as {"services": {"auditd.service": {"status": "enabled", "state": "running"}}}
	count(ids(vs, "6.2.1.4")) == 0
}

test_auditd_config_mode_stricter_is_ok if {
	vs := data.cis_rhel9.auditd.violations with input as {"auditd": {"config_permissions": [{"stat": {"path": "/etc/audit/auditd.conf", "mode": "0600", "pw_name": "root"}}]}}
	count(ids(vs, "6.2.4.5")) == 0
}

test_auditd_config_mode_without_leading_zero_is_ok if {
	vs := data.cis_rhel9.auditd.violations with input as {"auditd": {"config_permissions": [{"stat": {"path": "/etc/audit/auditd.conf", "mode": "640", "pw_name": "root"}}]}}
	count(ids(vs, "6.2.4.5")) == 0
}

test_auditd_config_mode_too_open_is_violation if {
	vs := data.cis_rhel9.auditd.violations with input as {"auditd": {"config_permissions": [{"stat": {"path": "/etc/audit/auditd.conf", "mode": "0644", "pw_name": "root"}}]}}
	count(ids(vs, "6.2.4.5")) == 1
}

test_auditd_log_mode_other_readable_is_violation if {
	vs := data.cis_rhel9.auditd.violations with input as {"auditd": {"log_permissions": {"mode": "0477"}}}
	count(ids(vs, "6.2.4.2")) == 1
}

test_auditd_log_dir_mode_group_write_is_violation if {
	vs := data.cis_rhel9.auditd.violations with input as {"auditd": {"log_dir_permissions": {"mode": "0770"}}}
	count(ids(vs, "6.2.4.1")) == 1
}
