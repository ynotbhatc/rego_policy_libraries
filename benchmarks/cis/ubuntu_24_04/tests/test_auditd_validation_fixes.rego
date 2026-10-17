package cis_ubuntu_24_04.auditd_test

import rego.v1

# Regression tests for validation 2026-10-17 fixes.

good_log := {"mode": "0640", "pw_name": "root", "gr_name": "adm"}

test_auditd_log_mode_0604_is_violation if {
	v := data.cis_ubuntu_24_04.auditd.permission_violations with input as {"auditd": {"log_permissions": object.union(good_log, {"mode": "0604"})}}
	count(v) == 1
}

test_auditd_log_mode_stricter_and_exact_accepted if {
	every m in ["0640", "0600", "0440", "0400"] {
		v := data.cis_ubuntu_24_04.auditd.permission_violations with input as {"auditd": {"log_permissions": object.union(good_log, {"mode": m})}}
		count(v) == 0
	}
}

test_auditd_log_mode_looser_flagged if {
	every m in ["0644", "0660", "0750"] {
		v := data.cis_ubuntu_24_04.auditd.permission_violations with input as {"auditd": {"log_permissions": object.union(good_log, {"mode": m})}}
		count(v) == 1
	}
}

test_auditd_missing_service_entry_is_violation if {
	v := data.cis_ubuntu_24_04.auditd.service_violations with input as {"packages": {"auditd": true}, "services": {}}
	"CIS 4.1.1.2: evidence missing — auditd.service not collected" in v
}

test_auditd_missing_log_owner_is_violation if {
	v := data.cis_ubuntu_24_04.auditd.permission_violations with input as {"auditd": {"log_permissions": {"mode": "0640", "gr_name": "adm"}}}
	"CIS 4.1.4.1: evidence missing — auditd.log_permissions.pw_name not collected" in v
}

test_auditd_complete_log_permissions_no_permission_violations if {
	v := data.cis_ubuntu_24_04.auditd.permission_violations with input as {"auditd": {"log_permissions": good_log}}
	count(v) == 0
}
