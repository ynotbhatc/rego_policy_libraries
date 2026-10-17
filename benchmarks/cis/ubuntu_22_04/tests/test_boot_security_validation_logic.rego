package cis_ubuntu_22_04.boot_security_test

import rego.v1

# Validation fix 2026-10-17: exact-string mode compare ("600" != "0600"), absent grub/process
# evidence and absent grub_cmdline passed.

pkg := data.cis_ubuntu_22_04.boot_security

good := {
	"aide": {"installed": true, "cron_configured": true, "database_exists": true},
	"grub": {"password_configured": true, "config_mode": "0600", "config_owner": "root", "sulogin_configured": true},
	"process_hardening": {"core_dumps_enabled": false, "fs_suid_dumpable": "0", "aslr_enabled": true, "prelink_installed": false, "ptrace_scope_restricted": true},
	"apparmor": {"bootloader_enabled": true, "grub_cmdline": "quiet security=apparmor"},
}

with_grub(g) := object.union(object.remove(good, ["grub"]), {"grub": g})

grub_base := {"password_configured": true, "config_owner": "root", "sulogin_configured": true}

test_good_compliant if {
	pkg.compliant with input as good
}

test_mode_600_without_leading_zero_ok if {
	pkg.compliant with input as with_grub(object.union(grub_base, {"config_mode": "600"}))
}

test_mode_400_ok if {
	pkg.compliant with input as with_grub(object.union(grub_base, {"config_mode": "0400"}))
}

test_mode_group_readable_violates if {
	not pkg.compliant with input as with_grub(object.union(grub_base, {"config_mode": "0640"}))
}

test_missing_mode_violates if {
	not pkg.compliant with input as with_grub(grub_base)
}

test_missing_owner_violates if {
	not pkg.compliant with input as with_grub({"password_configured": true, "config_mode": "0600", "sulogin_configured": true})
}

test_missing_suid_dumpable_violates if {
	ph := object.remove(good.process_hardening, ["fs_suid_dumpable"])
	not pkg.compliant with input as object.union(object.remove(good, ["process_hardening"]), {"process_hardening": ph})
}

test_missing_core_dump_flag_violates if {
	ph := object.remove(good.process_hardening, ["core_dumps_enabled"])
	not pkg.compliant with input as object.union(object.remove(good, ["process_hardening"]), {"process_hardening": ph})
}

test_missing_apparmor_cmdline_violates if {
	not pkg.compliant with input as object.union(object.remove(good, ["apparmor"]), {"apparmor": {"bootloader_enabled": true}})
}
