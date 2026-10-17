package cis_debian_11.boot_security_test

import rego.v1

good := {
	"aide": {"installed": true, "cron_configured": true, "database_exists": true},
	"grub": {"password_configured": true, "config_mode": "0400", "config_owner": "root", "sulogin_configured": true},
	"process_hardening": {"core_dumps_enabled": false, "fs_suid_dumpable": "0", "aslr_enabled": true, "prelink_installed": false, "ptrace_scope_restricted": true},
	"apparmor": {"bootloader_enabled": true, "grub_cmdline": "security=apparmor"},
}

test_good_is_compliant if {
	data.cis_debian_11.boot_security.compliant with input as good
}

test_mode_400_unpadded_ok if {
	i := json.patch(good, [{"op": "replace", "path": "/grub/config_mode", "value": "400"}])
	data.cis_debian_11.boot_security.compliant with input as i
}

test_mode_0o600_ok if {
	i := json.patch(good, [{"op": "replace", "path": "/grub/config_mode", "value": "0o600"}])
	data.cis_debian_11.boot_security.compliant with input as i
}

test_mode_0644_violates if {
	i := json.patch(good, [{"op": "replace", "path": "/grub/config_mode", "value": "0644"}])
	not data.cis_debian_11.boot_security.compliant with input as i
}

test_missing_mode_violates if {
	i := json.patch(good, [{"op": "remove", "path": "/grub/config_mode"}])
	some m in data.cis_debian_11.boot_security.grub_violations with input as i
	contains(m, "evidence missing")
}

test_missing_owner_violates if {
	i := json.patch(good, [{"op": "remove", "path": "/grub/config_owner"}])
	not data.cis_debian_11.boot_security.compliant with input as i
}

test_missing_suid_dumpable_violates if {
	i := json.patch(good, [{"op": "remove", "path": "/process_hardening/fs_suid_dumpable"}])
	some m in data.cis_debian_11.boot_security.process_hardening_violations with input as i
	contains(m, "evidence missing")
}

test_numeric_zero_suid_dumpable_ok if {
	i := json.patch(good, [{"op": "replace", "path": "/process_hardening/fs_suid_dumpable", "value": 0}])
	data.cis_debian_11.boot_security.compliant with input as i
}
