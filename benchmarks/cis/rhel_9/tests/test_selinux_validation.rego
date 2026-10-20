package cis_rhel9.selinux_test

import rego.v1

import data.cis_rhel9.selinux

# Unit tests for benchmarks/cis/rhel_9/selinux_validation.rego (package cis_rhel9.selinux).
# Closes issue #75.
# Re-pointed to CIS RHEL 9 v3.0.0 (2026-10-20): same test names, v3 recommendation ids.
# v2 1.6.1.x -> v3 1.3.1.x: 1.6.1.1->1.3.1.1, .2->.2, .3->.3, .4->.4, .5->.5, .6->.6 (now Manual),
# 1.6.1.7 (setroubleshoot)->1.3.1.8, 1.6.1.8 (mcstrans)->1.3.1.7. The configured mode (selinux.config_mode,
# or the mapper's ansible_facts.ansible_selinux.config_mode) is checked with the running mode.

test_1_6_1_1_selinux_not_installed if {
	violations := selinux.violations with input as {"selinux": {"installed": false}}
	"1.3.1.1: not met — Ensure SELinux is installed" in violations
}

test_1_6_1_2_selinux_disabled_in_grub if {
	violations := selinux.violations with input as {"selinux": {"installed": true, "grub_cmdline": "ro crashkernel=1G quiet selinux=0"}}
	"1.3.1.2: not met — Ensure SELinux is not disabled in bootloader configuration" in violations
}

test_1_6_1_2_enforcing_disabled_in_grub if {
	violations := selinux.violations with input as {"selinux": {"installed": true, "grub_cmdline": "ro quiet enforcing=0"}}
	"1.3.1.2: not met — Ensure SELinux is not disabled in bootloader configuration" in violations
}

test_1_6_1_3_policy_not_configured if {
	violations := selinux.violations with input as {"selinux": {"installed": true, "status": "enabled", "mode": "enforcing"}}
	"1.3.1.3: evidence missing — selinux.policy not collected" in violations
}

test_1_6_1_3_policy_not_targeted_or_mls if {
	violations := selinux.violations with input as {"selinux": {"installed": true, "status": "enabled", "mode": "enforcing", "policy": "minimum"}}
	"1.3.1.3: not met — Ensure SELinux policy is configured" in violations
}

test_1_6_1_4_selinux_not_enabled if {
	violations := selinux.violations with input as {"selinux": {"installed": true, "status": "disabled", "mode": "disabled", "config_mode": "disabled", "policy": "targeted"}}
	"1.3.1.4: not met — Ensure the SELinux mode is not disabled" in violations
}

test_1_6_1_4_mode_disabled if {
	violations := selinux.violations with input as {"selinux": {"installed": true, "status": "enabled", "mode": "disabled", "config_mode": "enforcing", "policy": "targeted"}}
	"1.3.1.4: not met — Ensure the SELinux mode is not disabled" in violations
}

test_1_6_1_5_mode_not_enforcing if {
	violations := selinux.violations with input as {"selinux": {"installed": true, "status": "enabled", "mode": "permissive", "config_mode": "permissive", "policy": "targeted"}}
	"1.3.1.5: not met — Ensure the SELinux mode is enforcing" in violations
	not "1.3.1.4: not met — Ensure the SELinux mode is not disabled" in violations
}

test_1_6_1_6_unconfined_services if {
	violations := selinux.violations with input as {"selinux": {"installed": true, "unconfined_services": ["httpd_t", "unconfined_service_t"]}}
	some msg in violations
	startswith(msg, "1.3.1.6: manual review not attested")
	v2 := selinux.violations with input as {"attest": {"no_unconfined_services": true}}
	count([m | some m in v2; startswith(m, "1.3.1.6: ")]) == 0
}

test_1_6_1_7_setroubleshoot_installed if {
	violations := selinux.violations with input as {"selinux": {"setroubleshoot_installed": true}}
	"1.3.1.8: not met — Ensure SETroubleshoot is not installed" in violations
}

test_1_6_1_8_mcstrans_installed if {
	violations := selinux.violations with input as {"selinux": {"mcstrans_installed": true}}
	"1.3.1.7: not met — Ensure the MCS Translation Service (mcstrans) is not installed" in violations
}

# the mapper does not copy the configured mode into selinux; ansible_selinux.config_mode is read instead
test_config_mode_from_ansible_selinux if {
	inp := {"selinux": {"mode": "enforcing"}, "ansible_facts": {"ansible_selinux": {"config_mode": "permissive"}}}
	violations := selinux.violations with input as inp
	"1.3.1.5: not met — Ensure the SELinux mode is enforcing" in violations
	count([m | some m in violations; startswith(m, "1.3.1.4: ")]) == 0
}

test_fully_compliant_no_violations if {
	compliant_input := {
		"selinux": {
			"installed": true,
			"grub_cmdline": "ro crashkernel=1G quiet rhgb",
			"status": "enabled",
			"mode": "enforcing",
			"config_mode": "enforcing",
			"policy": "targeted",
			"setroubleshoot_installed": false,
			"mcstrans_installed": false,
		},
		"attest": {"no_unconfined_services": true},
	}
	count(selinux.violations) == 0 with input as compliant_input
	selinux.compliant == true with input as compliant_input
}

# On empty input every recommendation fails closed: violations is a populated set and compliant is false.
test_violations_populated_on_empty_input if {
	violations := selinux.violations with input as {}
	is_set(violations)
	count(violations) > 0
}

test_not_compliant_on_empty_input if {
	selinux.compliant == false with input as {}
}
