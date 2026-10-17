package cis_ubuntu_22_04.auditd_test

import rego.v1

# Validation fix 2026-10-17: decimal mode compare, missing service entry passed, commented
# auditd.conf lines counted, identical syscall-rule messages.

pkg := data.cis_ubuntu_22_04.auditd

good_conf := "max_log_file = 8\nmax_log_file_action = keep_logs\nspace_left_action = email\nadmin_space_left_action = halt\n"

good := {
	"packages": {"auditd": true},
	"services": {"auditd.service": {"status": "enabled", "state": "running"}},
	"bootloader": {"grub_config": "linux /vmlinuz audit=1 audit_backlog_limit=8192"},
	"auditd": {"config": good_conf, "active_rules": ["-e 2"], "log_permissions": {"mode": "0640", "pw_name": "root", "gr_name": "root"}},
}

with_auditd(a) := object.union(object.remove(good, ["auditd"]), {"auditd": a})

test_mode_0630_violates if {
	v := pkg.permission_violations with input as with_auditd({"config": good_conf, "active_rules": ["-e 2"], "log_permissions": {"mode": "0630", "pw_name": "root", "gr_name": "root"}})
	count(v) == 1
}

test_mode_0640_and_0600_ok if {
	count(pkg.permission_violations) == 0 with input as good
	count(pkg.permission_violations) == 0 with input as with_auditd({"config": good_conf, "log_permissions": {"mode": "600", "pw_name": "root", "gr_name": "adm"}})
}

test_missing_log_permissions_violates if {
	count(pkg.permission_violations) == 1 with input as with_auditd({"config": good_conf})
}

test_missing_service_entry_violates if {
	v := pkg.service_violations with input as object.remove(good, ["services"])
	count(v) == 2
}

test_service_missing_state_violates if {
	v := pkg.service_violations with input as object.union(object.remove(good, ["services"]), {"services": {"auditd.service": {"status": "enabled"}}})
	count(v) == 1
}

test_commented_conf_lines_do_not_count if {
	conf := "# space_left_action = email\n# admin_space_left_action = halt\n#max_log_file = 8\n"
	v := pkg.config_violations with input as with_auditd({"config": conf})
	count(v) == 3
}

test_good_config_clean if {
	count(pkg.config_violations) == 0 with input as good
}

test_missing_grub_config_violates if {
	v := pkg.config_violations with input as object.remove(good, ["bootloader"])
	"CIS 4.1.1.3: evidence missing — bootloader.grub_config not collected" in v
}

test_syscall_rule_messages_distinct if {
	v := pkg.rules_violations with input as with_auditd({"config": good_conf, "active_rules": []})
	syscall_msgs := {m | some m in v; contains(m, "-S")}
	count(syscall_msgs) > 5
}
