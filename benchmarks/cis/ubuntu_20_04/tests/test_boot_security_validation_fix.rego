package cis_ubuntu_20_04.boot_security_test

import rego.v1

# Validation fix pass 2026-10-17.

test_grub_mode_400_and_600_variants_accepted if {
	every m in ["400", "0400", "600", "0600", "0o600"] {
		v := data.cis_ubuntu_20_04.boot_security.grub_violations with input as {"grub": {"config_mode": m, "config_owner": "root", "password_configured": true, "sulogin_configured": true}}
		count(v) == 0
	}
}

test_grub_mode_644_and_unparsable_flagged if {
	every m in ["0644", "0640", "rw-r--r--"] {
		v := data.cis_ubuntu_20_04.boot_security.grub_violations with input as {"grub": {"config_mode": m, "config_owner": "root", "password_configured": true, "sulogin_configured": true}}
		count(v) == 1
	}
}

test_grub_missing_mode_and_owner_flagged if {
	v := data.cis_ubuntu_20_04.boot_security.grub_violations with input as {"grub": {"password_configured": true, "sulogin_configured": true}}
	count({m | some m in v; contains(m, "evidence missing")}) == 2
}

# Semantic review 2026-11-13: missing process-hardening facts must not pass.
test_missing_process_hardening_facts_flagged if {
	v := data.cis_ubuntu_20_04.boot_security.process_hardening_violations with input as {}
	"CIS 1.5.1: evidence missing — process_hardening.core_dumps_enabled not collected" in v
	"CIS 1.5.3: evidence missing — process_hardening.prelink_installed not collected" in v
	some x in v
	startswith(x, "CIS 1.5.1: fs.suid_dumpable is")
}

test_present_process_hardening_facts_clean if {
	v := data.cis_ubuntu_20_04.boot_security.process_hardening_violations with input as {"process_hardening": {"core_dumps_enabled": false, "fs_suid_dumpable": "0", "prelink_installed": false, "aslr_enabled": true, "ptrace_scope_restricted": true}}
	count(v) == 0
}
