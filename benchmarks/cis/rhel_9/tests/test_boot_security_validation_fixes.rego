package cis_rhel9.boot_security_test

import rego.v1

# Validation fixes 2026-10-17: missing grub.cfg owner/group/mode evidence; octal mode.
# Re-pointed to CIS RHEL 9 v3.0.0 (2026-10-20): same test names, v3 recommendation ids.
# good: every 1.4 / 1.5 / 6.3 recommendation satisfied (the generator's merged passing input).

good := {"boot_security": {"grub_password_set": true, "grub_password_hashed": true, "grub_cfg_mode": "0600", "grub_cfg_owner": "root", "grub_cfg_group": "root", "grub_files": [{"path": "/boot/grub2/grub.cfg", "mode": "0600", "owner": "root", "group": "root"}, {"path": "/boot/grub2/grubenv", "mode": "0600", "owner": "root", "group": "root"}], "rescue_auth_required": true, "emergency_auth_required": true, "kernel_args": ["ro crashkernel=1G audit=1"], "core_dumps_disabled_limits": true, "systemd_coredump_process_size_max": "0", "systemd_coredump_storage": "none", "aide_installed": true, "aide_cron_configured": false, "aide_timer_configured": true, "aide_audit_tool_options": {"auditctl": "p+i+n+u+g+s+b+acl+xattrs+sha512", "auditd": "p+i+n+u+g+s+b+acl+xattrs+sha512", "ausearch": "p+i+n+u+g+s+b+acl+xattrs+sha512", "aureport": "p+i+n+u+g+s+b+acl+xattrs+sha512", "autrace": "p+i+n+u+g+s+b+acl+xattrs+sha512", "augenrules": "p+i+n+u+g+s+b+acl+xattrs+sha512"}, "aide_report_urls": ["syslog:LOG_LOCAL0"]}, "sysctl_parameters": {"analysis": [{"parameter": "fs.protected_hardlinks", "current_value": "1"}, {"parameter": "fs.protected_symlinks", "current_value": "1"}, {"parameter": "fs.suid_dumpable", "current_value": "0"}, {"parameter": "kernel.dmesg_restrict", "current_value": "1"}, {"parameter": "kernel.kptr_restrict", "current_value": "1"}, {"parameter": "kernel.randomize_va_space", "current_value": "2"}, {"parameter": "kernel.yama.ptrace_scope", "current_value": "1"}], "persisted": {"fs.protected_hardlinks": "1", "fs.protected_symlinks": "1", "fs.suid_dumpable": "0", "kernel.dmesg_restrict": "1", "kernel.kptr_restrict": "1", "kernel.randomize_va_space": "2", "kernel.yama.ptrace_scope": "1"}}}

test_boot_good_input_compliant if {
	data.cis_rhel9.boot_security.compliant with input as good
}

test_boot_missing_owner_is_violation if {
	i := json.remove(good, ["/boot_security/grub_cfg_owner"])
	not data.cis_rhel9.boot_security.compliant with input as i
}

test_boot_missing_group_is_violation if {
	i := json.remove(good, ["/boot_security/grub_cfg_group"])
	not data.cis_rhel9.boot_security.compliant with input as i
}

test_boot_missing_mode_is_violation if {
	i := json.remove(good, ["/boot_security/grub_cfg_mode"])
	not data.cis_rhel9.boot_security.compliant with input as i
}

test_boot_mode_0400_and_600_without_zero_ok if {
	i := json.patch(good, [{"op": "replace", "path": "/boot_security/grub_cfg_mode", "value": "400"}])
	data.cis_rhel9.boot_security.compliant with input as i
	i2 := json.patch(good, [{"op": "replace", "path": "/boot_security/grub_cfg_mode", "value": "600"}])
	data.cis_rhel9.boot_security.compliant with input as i2
}

test_boot_mode_0644_is_violation if {
	i := json.patch(good, [{"op": "replace", "path": "/boot_security/grub_cfg_mode", "value": "0644"}])
	not data.cis_rhel9.boot_security.compliant with input as i
}

test_boot_mode_0700_is_violation if {
	i := json.patch(good, [{"op": "replace", "path": "/boot_security/grub_cfg_mode", "value": "0700"}])
	not data.cis_rhel9.boot_security.compliant with input as i
}

# v2.0.0 single_user_auth_required (the mapper's combined rescue+emergency fact) decides 1.4.3 / 1.4.4
# when the per-unit facts were not collected; a per-unit fact, when present, wins.
test_boot_v2_single_user_auth_decides_rescue_and_emergency if {
	base := json.remove(good, ["/boot_security/rescue_auth_required", "/boot_security/emergency_auth_required"])
	data.cis_rhel9.boot_security.compliant with input as json.patch(base, [{"op": "add", "path": "/boot_security/single_user_auth_required", "value": true}])
	vs := data.cis_rhel9.boot_security.violations with input as json.patch(base, [{"op": "add", "path": "/boot_security/single_user_auth_required", "value": false}])
	"1.4.3: not met — Ensure authentication is required when booting into rescue mode" in vs
	"1.4.4: not met — Ensure authentication is required when booting into emergency mode" in vs
	vs2 := data.cis_rhel9.boot_security.violations with input as json.patch(good, [{"op": "add", "path": "/boot_security/single_user_auth_required", "value": true}, {"op": "replace", "path": "/boot_security/rescue_auth_required", "value": false}])
	"1.4.3: not met — Ensure authentication is required when booting into rescue mode" in vs2
}

# v2.0.0 boot_security sysctl fields carry the running value when the analysis list lacks the parameter
test_boot_v2_sysctl_alias_used_only_without_analysis_entry if {
	keep := [e | some e in good.sysctl_parameters.analysis; e.parameter != "kernel.randomize_va_space"]
	base := json.patch(good, [{"op": "replace", "path": "/sysctl_parameters/analysis", "value": keep}])
	vs := data.cis_rhel9.boot_security.violations with input as json.patch(base, [{"op": "add", "path": "/boot_security/aslr_value", "value": "2"}])
	count([v | some v in vs; startswith(v, "1.5.6: ")]) == 0
	vs2 := data.cis_rhel9.boot_security.violations with input as json.patch(base, [{"op": "add", "path": "/boot_security/aslr_value", "value": "0"}])
	"1.5.6: not met — Ensure kernel.randomize_va_space is configured" in vs2
}

# 1.4.5: the boot entries' args win; /etc/default/grub (v2.0.0 bootloader.grub_config) is read only without them
test_boot_v2_grub_config_decides_confirm_spawn_without_kernel_args if {
	base := json.remove(good, ["/boot_security/kernel_args"])
	vs := data.cis_rhel9.boot_security.violations with input as object.union(base, {"bootloader": {"grub_config": "GRUB_CMDLINE_LINUX=\"systemd.confirm_spawn=1\""}})
	"1.4.5: not met — Ensure systemd ability to spawn an interactive boot process is disabled" in vs
	data.cis_rhel9.boot_security.compliant with input as object.union(base, {"bootloader": {"grub_config": "GRUB_CMDLINE_LINUX=\"quiet\""}})
}
