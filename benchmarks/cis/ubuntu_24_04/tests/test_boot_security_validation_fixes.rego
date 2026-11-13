package cis_ubuntu_24_04.boot_security_test

import rego.v1

# Regression tests for validation 2026-10-17 fixes (octal mode comparison).

grub_mode_violations(mode) := v if {
	v := [x |
		some x in data.cis_ubuntu_24_04.boot_security.grub_violations with input as {"grub": {"config_mode": mode, "config_owner": "root"}}
		contains(x, "1.4.2")
	]
}

test_grub_mode_exact_and_stricter_accepted if {
	every m in ["0400", "0600", "0200", "0000", "600", "0o600"] {
		count(grub_mode_violations(m)) == 0
	}
}

test_grub_mode_looser_flagged if {
	every m in ["0644", "0640", "0700", "0601"] {
		count(grub_mode_violations(m)) == 1
	}
}

test_grub_missing_mode_is_violation if {
	v := data.cis_ubuntu_24_04.boot_security.grub_violations with input as {"grub": {"config_owner": "root"}}
	"CIS 1.4.2: evidence missing — grub.config_mode not collected" in v
}

# Semantic review 2026-11-13: missing process-hardening facts must not pass.
test_missing_process_hardening_facts_flagged if {
	v := data.cis_ubuntu_24_04.boot_security.process_hardening_violations with input as {}
	"CIS 1.5.1: evidence missing — process_hardening.core_dumps_enabled not collected" in v
	"CIS 1.5.3: evidence missing — process_hardening.prelink_installed not collected" in v
	some x in v
	startswith(x, "CIS 1.5.1: fs.suid_dumpable is")
}

test_present_process_hardening_facts_clean if {
	v := data.cis_ubuntu_24_04.boot_security.process_hardening_violations with input as {"process_hardening": {"core_dumps_enabled": false, "fs_suid_dumpable": "0", "prelink_installed": false, "aslr_enabled": true, "ptrace_scope_restricted": true}}
	count(v) == 0
}

test_missing_grub_config_owner_flagged if {
	v := data.cis_ubuntu_24_04.boot_security.grub_violations with input as {}
	"CIS 1.4.2: evidence missing — grub.config_owner not collected" in v
}
