package cis_debian_11.auditd_test

import rego.v1

good := {
	"packages": {"auditd": true},
	"services": {"auditd.service": {"status": "enabled", "state": "running"}},
	"bootloader": {"grub_config": "linux /vmlinuz audit=1 audit_backlog_limit=8192"},
	"auditd": {
		"config": "max_log_file = 8\nmax_log_file_action = keep_logs\nspace_left_action = email\nadmin_space_left_action = halt\n",
		"active_rules": ["-e 2"],
		"log_permissions": {"mode": "0600", "pw_name": "root", "gr_name": "root"},
	},
}

msgs(i) := {m | some m in data.cis_debian_11.auditd.config_violations with input as i}

test_space_left_action_not_satisfied_by_admin_variant if {
	i := object.union(good, {"auditd": {"config": "max_log_file = 8\nmax_log_file_action = keep_logs\nspace_left_action = ignore\nadmin_space_left_action = halt\n"}})
	some m in msgs(i)
	contains(m, "space_left_action not appropriate (should be email")
}

test_max_log_file_not_satisfied_by_action_key if {
	i := object.union(good, {"auditd": {"config": "max_log_file_action = keep_logs\nspace_left_action = email\nadmin_space_left_action = halt\n"}})
	some m in msgs(i)
	contains(m, "4.1.2.1")
}

test_commented_directive_ignored if {
	i := object.union(good, {"auditd": {"config": "# max_log_file_action = keep_logs\nmax_log_file = 8\nmax_log_file_action = delete\nspace_left_action = email\nadmin_space_left_action = halt\n"}})
	some m in msgs(i)
	contains(m, "set to delete")
}

test_missing_service_evidence_violates if {
	i := object.remove(good, ["services"])
	some m in data.cis_debian_11.auditd.service_violations with input as i
	contains(m, "evidence missing")
}

test_missing_log_permissions_violates if {
	i := json.patch(good, [{"op": "remove", "path": "/auditd/log_permissions"}])
	some m in data.cis_debian_11.auditd.permission_violations with input as i
	contains(m, "evidence missing")
}

test_log_mode_octal if {
	i := json.patch(good, [{"op": "replace", "path": "/auditd/log_permissions/mode", "value": "0660"}])
	some m in data.cis_debian_11.auditd.permission_violations with input as i
	contains(m, "too permissive")
}

test_log_mode_0640_ok if {
	i := json.patch(good, [{"op": "replace", "path": "/auditd/log_permissions/mode", "value": "0640"}])
	count(data.cis_debian_11.auditd.permission_violations) == 0 with input as i
}

test_backlog_too_small_violates if {
	i := json.patch(good, [{"op": "replace", "path": "/bootloader/grub_config", "value": "audit=1 audit_backlog_limit=64"}])
	some m in msgs(i)
	contains(m, "4.1.1.4")
}

test_missing_syscall_rules_counted_separately if {
	r := data.cis_debian_11.auditd.report with input as good
	r.rules_violations > 4
	r.controls_checked == count(data.cis_debian_11.auditd.required_rules) + 14
}

test_unset_space_left_action_violates if {
	i := object.union(good, {"auditd": {"config": "max_log_file = 8\nmax_log_file_action = keep_logs\n"}})
	some m in msgs(i)
	contains(m, "space_left_action not appropriate (should be email")
	some m2 in msgs(i)
	contains(m2, "admin_space_left_action not appropriate")
}
