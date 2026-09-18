package cis_rhel9.selinux_test

import rego.v1

import data.cis_rhel9.selinux

# Unit tests for benchmarks/cis/rhel_9/selinux_validation.rego (package cis_rhel9.selinux).
# Closes issue #75.
#
# The module exposes two public rules:
#   - selinux.violations  (a set of message strings)
#   - selinux.compliant   (boolean; default false, true only when violations is empty)
# It does NOT define a compliance_report object, so step-3's report assertion is
# adapted to the module's actual aggregate: violations is a POPULATED set on empty
# input, and compliant is false there (fail-closed).

# --- CIS 1.6.1.1: SELinux not installed -------------------------------------
test_1_6_1_1_selinux_not_installed if {
	violations := selinux.violations with input as {"selinux": {"installed": false}}
	"CIS 1.6.1.1: SELinux (libselinux) not installed" in violations
}

# --- CIS 1.6.1.2: selinux=0 in bootloader -----------------------------------
test_1_6_1_2_selinux_disabled_in_grub if {
	violations := selinux.violations with input as {"selinux": {
		"installed": true,
		"grub_cmdline": "ro crashkernel=1G quiet selinux=0",
	}}
	"CIS 1.6.1.2: SELinux is disabled in bootloader configuration (selinux=0)" in violations
}

# --- CIS 1.6.1.2: enforcing=0 in bootloader ---------------------------------
test_1_6_1_2_enforcing_disabled_in_grub if {
	violations := selinux.violations with input as {"selinux": {
		"installed": true,
		"grub_cmdline": "ro quiet enforcing=0",
	}}
	"CIS 1.6.1.2: SELinux enforcing is disabled in bootloader configuration (enforcing=0)" in violations
}

# --- CIS 1.6.1.3: policy not configured -------------------------------------
test_1_6_1_3_policy_not_configured if {
	violations := selinux.violations with input as {"selinux": {
		"installed": true,
		"status": "enabled",
		"mode": "enforcing",
	}}
	"CIS 1.6.1.3: SELinux policy not configured" in violations
}

# --- CIS 1.6.1.3: policy set to a non-approved value ------------------------
test_1_6_1_3_policy_not_targeted_or_mls if {
	violations := selinux.violations with input as {"selinux": {
		"installed": true,
		"status": "enabled",
		"mode": "enforcing",
		"policy": "minimum",
	}}
	some msg in violations
	contains(msg, "CIS 1.6.1.3")
	contains(msg, "policy is minimum")
}

# --- CIS 1.6.1.4: SELinux not enabled ---------------------------------------
test_1_6_1_4_selinux_not_enabled if {
	violations := selinux.violations with input as {"selinux": {
		"installed": true,
		"status": "disabled",
		"policy": "targeted",
	}}
	"CIS 1.6.1.4: SELinux is not enabled" in violations
}

# --- CIS 1.6.1.4: mode disabled ---------------------------------------------
test_1_6_1_4_mode_disabled if {
	violations := selinux.violations with input as {"selinux": {
		"installed": true,
		"status": "enabled",
		"mode": "disabled",
		"policy": "targeted",
	}}
	"CIS 1.6.1.4: SELinux mode is disabled" in violations
}

# --- CIS 1.6.1.5: mode not enforcing (permissive) ---------------------------
test_1_6_1_5_mode_not_enforcing if {
	violations := selinux.violations with input as {"selinux": {
		"installed": true,
		"status": "enabled",
		"mode": "permissive",
		"policy": "targeted",
	}}
	some msg in violations
	contains(msg, "CIS 1.6.1.5")
	contains(msg, "mode is permissive")
}

# --- CIS 1.6.1.6: unconfined services present -------------------------------
test_1_6_1_6_unconfined_services if {
	violations := selinux.violations with input as {"selinux": {
		"installed": true,
		"status": "enabled",
		"mode": "enforcing",
		"policy": "targeted",
		"unconfined_services": ["httpd_t", "unconfined_service_t"],
	}}
	some msg in violations
	contains(msg, "CIS 1.6.1.6")
	contains(msg, "2 unconfined services")
}

# --- CIS 1.6.1.7: SETroubleshoot installed ----------------------------------
test_1_6_1_7_setroubleshoot_installed if {
	violations := selinux.violations with input as {"selinux": {"setroubleshoot_installed": true}}
	"CIS 1.6.1.7: SETroubleshoot is installed - should be removed on production systems" in violations
}

# --- CIS 1.6.1.8: mcstrans installed ----------------------------------------
test_1_6_1_8_mcstrans_installed if {
	violations := selinux.violations with input as {"selinux": {"mcstrans_installed": true}}
	"CIS 1.6.1.8: MCS Translation Service (mcstrans) is installed - should be removed" in violations
}

# --- CIS 1.6: files with incorrect SELinux context --------------------------
test_1_6_incorrect_file_context if {
	violations := selinux.violations with input as {"selinux": {
		"installed": true,
		"status": "enabled",
		"mode": "enforcing",
		"policy": "targeted",
		"files_with_incorrect_context": ["/etc/passwd", "/var/www/html/index.html"],
	}}
	some msg in violations
	contains(msg, "2 files with incorrect SELinux context")
}

# --- CIS 1.6: high number of SELinux denials --------------------------------
test_1_6_high_denial_count if {
	denials := numbers.range(1, 101) # 101 elements, > 100 threshold
	count(denials) == 101
	violations := selinux.violations with input as {"selinux": {
		"installed": true,
		"status": "enabled",
		"mode": "enforcing",
		"policy": "targeted",
		"recent_denials": denials,
	}}
	some msg in violations
	contains(msg, "High number of SELinux denials")
}

# --- Fully compliant host: no violations ------------------------------------
test_fully_compliant_no_violations if {
	compliant_input := {"selinux": {
		"installed": true,
		"grub_cmdline": "ro crashkernel=1G quiet rhgb",
		"status": "enabled",
		"mode": "enforcing",
		"policy": "targeted",
		"unconfined_services": [],
		"setroubleshoot_installed": false,
		"mcstrans_installed": false,
		"files_with_incorrect_context": [],
		"recent_denials": [],
	}}
	count(selinux.violations) == 0 with input as compliant_input
	selinux.compliant == true with input as compliant_input
}

# --- Aggregate behavior on EMPTY input (module has no compliance_report) -----
# On empty input the CIS 1.6.1.1 rule fires, so violations is a populated set
# and compliant is false (fail-closed) — the module never silently passes.
test_violations_populated_on_empty_input if {
	violations := selinux.violations with input as {}
	is_set(violations)
	count(violations) > 0
}

test_not_compliant_on_empty_input if {
	selinux.compliant == false with input as {}
}
