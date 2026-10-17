package cis_amazon_linux_2023.auditd_test

import rego.v1

# Regression tests for the 2026-10-17 validation pass (octal modes, fail-closed evidence).

good := {"auditd": {
	"log_permissions": {"mode": "0600", "pw_name": "root", "gr_name": "root"},
	"log_dir_permissions": {"mode": "0750"},
	"config_permissions": [{"stat": {"path": "/etc/audit/auditd.conf", "mode": "0600", "pw_name": "root"}}],
}}

has(msg_prefix, v) if {
	some m in v
	startswith(m, msg_prefix)
}

test_auditd_log_mode_0624_flagged if {
	v := data.cis_amazon_linux_2023.auditd.violations with input as object.union(good, {"auditd": {"log_permissions": {"mode": "0624", "pw_name": "root", "gr_name": "root"}}})
	has("CIS 4.1.4.1", v)
}

test_auditd_log_mode_0600_not_flagged if {
	v := data.cis_amazon_linux_2023.auditd.permission_violations with input as good
	count(v) == 0
}

test_auditd_log_dir_mode_0705_flagged if {
	v := data.cis_amazon_linux_2023.auditd.violations with input as object.union(good, {"auditd": {"log_dir_permissions": {"mode": "0705"}}})
	has("CIS 4.1.4.3", v)
}

test_auditd_config_mode_0600_allowed if {
	v := data.cis_amazon_linux_2023.auditd.permission_violations with input as good
	not has("CIS 4.1.4.4", v)
}

test_auditd_config_mode_0644_flagged if {
	i := {"auditd": {
		"log_permissions": good.auditd.log_permissions,
		"log_dir_permissions": good.auditd.log_dir_permissions,
		"config_permissions": [{"stat": {"path": "/etc/audit/auditd.conf", "mode": "0644", "pw_name": "root"}}],
	}}
	v := data.cis_amazon_linux_2023.auditd.permission_violations with input as i
	has("CIS 4.1.4.4", v)
}

test_auditd_missing_service_entry_flagged if {
	v := data.cis_amazon_linux_2023.auditd.service_violations with input as {"services": {}}
	has("CIS 4.1.1.2", v)
}

test_auditd_missing_owner_group_flagged if {
	i := {"auditd": {"log_permissions": {"mode": "0600"}}}
	v := data.cis_amazon_linux_2023.auditd.permission_violations with input as i
	count([m | some m in v; startswith(m, "CIS 4.1.4.2")]) == 2
}

test_auditd_missing_permission_evidence_flagged if {
	v := data.cis_amazon_linux_2023.auditd.permission_violations with input as {"auditd": {}}
	has("CIS 4.1.4.1", v)
	has("CIS 4.1.4.3", v)
	has("CIS 4.1.4.4", v)
}

test_auditd_controls_checked_truthful if {
	r := data.cis_amazon_linux_2023.auditd.report with input as {}
	r.controls_checked == 18
}
