package cis_ubuntu_20_04.auditd_test

import rego.v1

# Validation fix pass 2026-10-17.

good := {
	"packages": {"auditd": true},
	"services": {"auditd.service": {"status": "enabled", "state": "running"}},
	"bootloader": {"grub_config": "linux audit=1 audit_backlog_limit=8192"},
	"auditd": {
		"config": "max_log_file = 8\nmax_log_file_action = keep_logs\nspace_left_action = email\nadmin_space_left_action = halt",
		"active_rules": ["-e 2"],
		"log_permissions": {"mode": "0600", "pw_name": "root", "gr_name": "root"},
	},
}

test_log_mode_0604_flagged if {
	inp := object.union(good, {"auditd": {"log_permissions": {"mode": "0604"}}})
	some msg in data.cis_ubuntu_20_04.auditd.permission_violations with input as inp
	startswith(msg, "CIS 4.1.4.1")
}

test_log_mode_0600_and_0640_not_flagged if {
	v1 := data.cis_ubuntu_20_04.auditd.permission_violations with input as object.union(good, {"auditd": {"log_permissions": {"mode": "0600"}}})
	v2 := data.cis_ubuntu_20_04.auditd.permission_violations with input as object.union(good, {"auditd": {"log_permissions": {"mode": "640"}}})
	count(v1) == 0
	count(v2) == 0
}

test_missing_services_is_violation if {
	inp := json.remove(good, ["services"])
	some msg in data.cis_ubuntu_20_04.auditd.service_violations with input as inp
	contains(msg, "evidence missing")
}

test_missing_bootloader_and_config_are_violations if {
	inp := json.remove(good, ["bootloader", "auditd/config"])
	v := data.cis_ubuntu_20_04.auditd.config_violations with input as inp
	count({m | some m in v; contains(m, "evidence missing")}) == 2
}

test_missing_log_permissions_is_violation if {
	inp := json.remove(good, ["auditd/log_permissions"])
	some msg in data.cis_ubuntu_20_04.auditd.permission_violations with input as inp
	contains(msg, "evidence missing")
}
