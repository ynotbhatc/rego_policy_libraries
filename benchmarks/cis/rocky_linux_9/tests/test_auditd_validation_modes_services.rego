package cis_rocky_linux_9.auditd_test

import rego.v1

has(prefix, inp) if {
	v := data.cis_rocky_linux_9.auditd.violations with input as inp
	some x in v
	startswith(x, prefix)
}

test_log_mode_0444_flagged if has("CIS 4.1.4.1", {"auditd": {"log_permissions": {"mode": "0444"}}})

test_log_mode_0640_ok if not has("CIS 4.1.4.1", {"auditd": {"log_permissions": {"mode": "0640"}}})

test_log_mode_0600_ok if not has("CIS 4.1.4.1", {"auditd": {"log_permissions": {"mode": "0600"}}})

test_log_mode_unparsable_flagged if has("CIS 4.1.4.1", {"auditd": {"log_permissions": {"mode": "rw-r-----"}}})

test_log_dir_0707_flagged if has("CIS 4.1.4.3", {"auditd": {"log_dir_permissions": {"mode": "0707"}}})

test_log_dir_0750_ok if not has("CIS 4.1.4.3", {"auditd": {"log_dir_permissions": {"mode": "0750"}}})

test_config_0600_not_flagged if not has("CIS 4.1.4.4", {"auditd": {"config_permissions": [{"stat": {"path": "/etc/audit/auditd.conf", "mode": "0600", "pw_name": "root"}}]}})

test_config_0644_flagged if has("CIS 4.1.4.4", {"auditd": {"config_permissions": [{"stat": {"path": "/etc/audit/auditd.conf", "mode": "0644", "pw_name": "root"}}]}})

test_missing_service_fact_flagged if {
	has("CIS 4.1.1.2: auditd service not enabled", {"packages": {"audit": {}}})
	has("CIS 4.1.1.2: auditd service not running", {"packages": {"audit": {}}})
}

test_enabled_running_service_ok if {
	inp := {"services": {"auditd.service": {"status": "enabled", "state": "running"}}}
	not has("CIS 4.1.1.2", inp)
}

test_missing_rule_message_identifies_rule if has("CIS 4.1.3.x: Missing audit rule for: -a always,exit -F arch=b64 -S mount", {"auditd": {"active_rules": []}})
