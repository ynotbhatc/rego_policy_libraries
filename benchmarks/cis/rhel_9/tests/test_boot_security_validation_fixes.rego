package cis_rhel9.boot_security_test

import rego.v1

# Validation fixes 2026-10-17: missing grub.cfg owner/group/mode evidence; octal mode.

good := {"boot_security": {
	"aide_installed": true, "aide_cron_configured": true, "aide_database_initialized": true,
	"grub_password_set": true, "grub_password_hashed": true,
	"grub_cfg_mode": "0600", "grub_cfg_owner": "root", "grub_cfg_group": "root",
	"single_user_auth_required": true,
	"core_dumps_disabled_sysctl": true, "core_dumps_disabled_limits": true,
	"aslr_value": "2",
}}

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
}

test_boot_mode_0644_is_violation if {
	i := json.patch(good, [{"op": "replace", "path": "/boot_security/grub_cfg_mode", "value": "0644"}])
	not data.cis_rhel9.boot_security.compliant with input as i
}

test_boot_mode_0700_is_violation if {
	i := json.patch(good, [{"op": "replace", "path": "/boot_security/grub_cfg_mode", "value": "0700"}])
	not data.cis_rhel9.boot_security.compliant with input as i
}
