# METADATA
# title: "CIS Ubuntu 22.04 LTS Benchmark v3.0.0 - Sections 1.2, 1.7, 1.8: Initial System Setup"
# custom:
#   class: security
#   framework: cis_ubuntu_22_04
#   source: cis
#   domains: [linux, ubuntu]
#   coverage:
#     checks: 29
#     cited: 22
#     density: sized
#     basis: size
#     tested: true
#     entrypoint: report
#     guard: self
#     as_of: v2.4.2
package cis_ubuntu_22_04.initial_setup

# CIS Ubuntu 22.04 LTS Benchmark v3.0.0 - Sections 1.2, 1.7, 1.8: Initial System Setup

import rego.v1

default compliant := false

compliant if {
	count(violations) == 0
}

# Modes are octal: compare permission bits, not strings ("644" and "0644" are the same mode).
# Parse an octal permission string ("644", "0644", "0o644") to an integer; undefined if not octal.
octal(s) := n if {
	t := trim_prefix(lower(trim_space(sprintf("%v", [s]))), "0o")
	regex.match(`^[0-7]{1,4}$`, t)
	p := concat("", [substring("0000", 0, 4 - count(t)), t])
	ds := [to_number(substring(p, i, 1)) | some i in numbers.range(0, 3)]
	n := ((ds[0] * 512) + (ds[1] * 64)) + ((ds[2] * 8) + ds[3])
}

# true when mode grants nothing beyond max (both octal strings)
mode_within(mode, max) if bits.and(octal(mode), bits.and(bits.negate(octal(max)), 4095)) == 0

# Fail closed: a mode/owner/flag that was not collected is a violation, not a pass.
mode_ok(key, max) if mode_within(input.initial_setup[key], max)

owner_root(key) if input.initial_setup[key] == "root"

flag_known(key) if is_boolean(input.initial_setup[key])

violations contains msg if {
	some key in ["core_dumps_enabled", "prelink_installed", "gdm_installed"]
	not flag_known(key)
	msg := sprintf("CIS 1.5/1.8: evidence missing — initial_setup.%s not collected", [key])
}

violations contains msg if {
	some key, file in {"motd_contains_sensitive_info": "motd_exists", "issue_contains_sensitive_info": "issue_exists", "issue_net_contains_sensitive_info": "issue_net_exists"}
	input.initial_setup[file]
	not flag_known(key)
	msg := sprintf("CIS 1.7: evidence missing — initial_setup.%s not collected", [key])
}

# CIS 1.2: Configure Software Updates (Ubuntu uses apt)

# CIS 1.2.1: Ensure package manager repositories are configured
repos_present if count(input.initial_setup.enabled_repos) > 0

gpg_keys_present if count(input.initial_setup.gpg_keys) > 0

violations contains msg if {
	not repos_present
	msg := "CIS 1.2.1: No apt package repositories are enabled (or enabled_repos not collected)"
}

# CIS 1.2.2: Ensure APT GPG keys are configured
violations contains msg if {
	not gpg_keys_present
	msg := "CIS 1.2.2: No GPG keys configured for apt package verification (or gpg_keys not collected)"
}

# CIS 1.3: Filesystem Integrity Checking (AIDE)
violations contains msg if {
	not input.initial_setup.aide_installed
	msg := "CIS 1.3.1: AIDE is not installed"
}

violations contains msg if {
	input.initial_setup.aide_installed
	not input.initial_setup.aide_cron_configured
	msg := "CIS 1.3.2: AIDE is not configured to run on a schedule (cron job missing)"
}

# CIS 1.4: Secure Boot Settings (GRUB)
violations contains msg if {
	not input.initial_setup.grub_password_configured
	msg := "CIS 1.4.1: GRUB boot loader password is not configured"
}

violations contains msg if {
	not mode_ok("grub_config_mode", "0600")
	msg := sprintf("CIS 1.4.2: GRUB configuration file has mode %v, should be 0400 or 0600 (or mode not collected)", [object.get(input, ["initial_setup", "grub_config_mode"], "<missing>")])
}

violations contains msg if {
	not input.initial_setup.grub_owner_root
	msg := "CIS 1.4.2: GRUB configuration file is not owned by root"
}

# CIS 1.5: Additional Process Hardening
violations contains msg if {
	input.initial_setup.core_dumps_enabled
	msg := "CIS 1.5.1: Core dumps are not restricted (hard limit should be 0)"
}

violations contains msg if {
	not input.initial_setup.aslr_enabled
	msg := "CIS 1.5.2: Address Space Layout Randomization (ASLR) is not enabled"
}

violations contains msg if {
	input.initial_setup.prelink_installed
	msg := "CIS 1.5.3: prelink is installed (disables ASLR effectiveness)"
}

violations contains msg if {
	not input.initial_setup.ptrace_scope_restricted
	msg := "CIS 1.5.4: ptrace scope is not restricted (kernel.yama.ptrace_scope should be >= 1)"
}

# CIS 1.7: Command Line Warning Banners
violations contains msg if {
	not input.initial_setup.motd_exists
	msg := "CIS 1.7.1: /etc/motd does not exist"
}

violations contains msg if {
	input.initial_setup.motd_exists
	not mode_ok("motd_mode", "0644")
	msg := sprintf("CIS 1.7.1: /etc/motd has mode %v, should be 0644 (or mode not collected)", [object.get(input, ["initial_setup", "motd_mode"], "<missing>")])
}

violations contains msg if {
	input.initial_setup.motd_contains_sensitive_info
	msg := "CIS 1.7.1: /etc/motd contains sensitive system information"
}

violations contains msg if {
	not input.initial_setup.issue_exists
	msg := "CIS 1.7.2: /etc/issue does not exist"
}

violations contains msg if {
	input.initial_setup.issue_exists
	not mode_ok("issue_mode", "0644")
	msg := sprintf("CIS 1.7.2: /etc/issue has mode %v, should be 0644 (or mode not collected)", [object.get(input, ["initial_setup", "issue_mode"], "<missing>")])
}

violations contains msg if {
	input.initial_setup.issue_contains_sensitive_info
	msg := "CIS 1.7.2: /etc/issue contains sensitive system information"
}

violations contains msg if {
	not input.initial_setup.issue_net_exists
	msg := "CIS 1.7.3: /etc/issue.net does not exist"
}

violations contains msg if {
	input.initial_setup.issue_net_exists
	not mode_ok("issue_net_mode", "0644")
	msg := sprintf("CIS 1.7.3: /etc/issue.net has mode %v, should be 0644 (or mode not collected)", [object.get(input, ["initial_setup", "issue_net_mode"], "<missing>")])
}

violations contains msg if {
	input.initial_setup.issue_net_contains_sensitive_info
	msg := "CIS 1.7.3: /etc/issue.net contains sensitive system information"
}

violations contains msg if {
	not owner_root("motd_owner")
	msg := sprintf("CIS 1.7.4: /etc/motd owned by %v, should be root (or owner not collected)", [object.get(input, ["initial_setup", "motd_owner"], "<missing>")])
}

violations contains msg if {
	not owner_root("issue_owner")
	msg := sprintf("CIS 1.7.5: /etc/issue owned by %v, should be root (or owner not collected)", [object.get(input, ["initial_setup", "issue_owner"], "<missing>")])
}

violations contains msg if {
	not owner_root("issue_net_owner")
	msg := sprintf("CIS 1.7.6: /etc/issue.net owned by %v, should be root (or owner not collected)", [object.get(input, ["initial_setup", "issue_net_owner"], "<missing>")])
}

# CIS 1.8: GNOME Display Manager
idle_delay_ok if input.initial_setup.gdm_idle_delay <= 900

violations contains msg if {
	input.initial_setup.gdm_installed
	input.initial_setup.server_environment
	not input.initial_setup.gui_required
	msg := "CIS 1.8.1: GNOME Display Manager (GDM) installed on server without GUI requirement"
}

violations contains msg if {
	input.initial_setup.gdm_installed
	input.initial_setup.gui_required
	not input.initial_setup.gdm_banner_configured
	msg := "CIS 1.8.2: GDM login banner is not configured"
}

violations contains msg if {
	input.initial_setup.gdm_installed
	input.initial_setup.gui_required
	not input.initial_setup.gdm_screen_lock_enabled
	msg := "CIS 1.8.3: GDM automatic screen lock is not enabled"
}

violations contains msg if {
	input.initial_setup.gdm_installed
	input.initial_setup.gui_required
	input.initial_setup.gdm_screen_lock_enabled
	not idle_delay_ok
	msg := sprintf("CIS 1.8.4: GDM idle delay is %v seconds, should be 900 or less (or not collected)", [object.get(input, ["initial_setup", "gdm_idle_delay"], "<missing>")])
}

report := {
	"compliant": compliant,
	"total_violations": count(violations),
	"violations": violations,
	"controls_checked": 24,
	"section": "1.2-1.8 Initial System Setup",
	"benchmark": "CIS Ubuntu 22.04 v3.0.0",
}
