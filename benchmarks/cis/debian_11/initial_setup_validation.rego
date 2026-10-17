# METADATA
# title: "DERIVED from CIS Ubuntu Linux 20.04 LTS Benchmark v3.0.0 — applied to Debian 11 (provenance: see README) - Sections 1.2, 1.7, 1.8:..."
# custom:
#   class: security
#   framework: cis_debian_11
#   source: cis
#   domains: [linux, debian]
#   coverage:
#     checks: 27
#     cited: 20
#     density: sized
#     basis: size
#     tested: true
#     entrypoint: report
#     guard: self
#     as_of: v2.4.1
package cis_debian_11.initial_setup

# DERIVED from CIS Ubuntu Linux 20.04 LTS Benchmark v3.0.0 — applied to Debian 11 (provenance: see README) - Sections 1.2, 1.7, 1.8: Initial System Setup

import rego.v1

default compliant := false

compliant if {
	count(violations) == 0
}

# Parse an octal permission string ("644", "0644", "0o644") to an integer; undefined if not octal.
octal(s) := n if {
	t := trim_prefix(lower(trim_space(sprintf("%v", [s]))), "0o")
	regex.match(`^[0-7]{1,4}$`, t)
	p := concat("", [substring("0000", 0, 4 - count(t)), t])
	ds := [to_number(d) | some d in split(p, "")]
	n := ((ds[0] * 512) + (ds[1] * 64)) + ((ds[2] * 8) + ds[3])
}

# true when mode grants nothing beyond max (both octal strings)
mode_within(mode, max) if bits.and(octal(mode), bits.and(bits.negate(octal(max)), 4095)) == 0

has_key(obj, k) if {
	_ = obj[k]
}

# Missing evidence fails closed: every fact below must be collected.
violations contains msg if {
	some k in ["enabled_repos", "gpg_keys", "aide_installed", "grub_password_configured", "grub_config_mode", "grub_owner_root", "core_dumps_enabled", "aslr_enabled", "prelink_installed", "ptrace_scope_restricted", "motd_exists", "issue_exists", "issue_net_exists", "motd_owner", "issue_owner", "issue_net_owner", "gdm_installed"]
	not has_key(object.get(input, "initial_setup", {}), k)
	msg := sprintf("CIS 1.x: evidence missing — initial_setup.%s not collected", [k])
}

# a file that exists needs its mode collected
violations contains msg if {
	some f in ["motd", "issue", "issue_net"]
	input.initial_setup[sprintf("%s_exists", [f])]
	not has_key(input.initial_setup, sprintf("%s_mode", [f]))
	msg := sprintf("CIS 1.7.x: evidence missing — initial_setup.%s_mode not collected", [f])
}

violations contains msg if {
	input.initial_setup.gdm_installed
	input.initial_setup.gui_required
	input.initial_setup.gdm_screen_lock_enabled
	not has_key(input.initial_setup, "gdm_idle_delay")
	msg := "CIS 1.8.4: evidence missing — initial_setup.gdm_idle_delay not collected"
}

# CIS 1.2: Configure Software Updates (Ubuntu uses apt)

# CIS 1.2.1: Ensure package manager repositories are configured
violations contains msg if {
	count(input.initial_setup.enabled_repos) == 0
	msg := "CIS 1.2.1: No apt package repositories are enabled"
}

# CIS 1.2.2: Ensure APT GPG keys are configured
violations contains msg if {
	count(input.initial_setup.gpg_keys) == 0
	msg := "CIS 1.2.2: No GPG keys configured for apt package verification"
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
	not mode_within(input.initial_setup.grub_config_mode, "0600")
	msg := sprintf("CIS 1.4.2: GRUB configuration file has mode %s, should be 0400 or 0600", [input.initial_setup.grub_config_mode])
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
	not mode_within(input.initial_setup.motd_mode, "0644")
	msg := sprintf("CIS 1.7.1: /etc/motd has mode %s, should be 0644", [input.initial_setup.motd_mode])
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
	not mode_within(input.initial_setup.issue_mode, "0644")
	msg := sprintf("CIS 1.7.2: /etc/issue has mode %s, should be 0644", [input.initial_setup.issue_mode])
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
	not mode_within(input.initial_setup.issue_net_mode, "0644")
	msg := sprintf("CIS 1.7.3: /etc/issue.net has mode %s, should be 0644", [input.initial_setup.issue_net_mode])
}

violations contains msg if {
	input.initial_setup.issue_net_contains_sensitive_info
	msg := "CIS 1.7.3: /etc/issue.net contains sensitive system information"
}

violations contains msg if {
	input.initial_setup.motd_owner != "root"
	msg := sprintf("CIS 1.7.4: /etc/motd owned by %s, should be root", [input.initial_setup.motd_owner])
}

violations contains msg if {
	input.initial_setup.issue_owner != "root"
	msg := sprintf("CIS 1.7.5: /etc/issue owned by %s, should be root", [input.initial_setup.issue_owner])
}

violations contains msg if {
	input.initial_setup.issue_net_owner != "root"
	msg := sprintf("CIS 1.7.6: /etc/issue.net owned by %s, should be root", [input.initial_setup.issue_net_owner])
}

# CIS 1.8: GNOME Display Manager
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
	input.initial_setup.gdm_idle_delay > 900
	msg := sprintf("CIS 1.8.4: GDM idle delay is %d seconds, should be 900 or less", [input.initial_setup.gdm_idle_delay])
}

report := {
	"compliant": compliant,
	"total_violations": count(violations),
	"violations": violations,
	"controls_checked": 24,
	"section": "1.2-1.8 Initial System Setup",
	"benchmark": "DERIVED from CIS Ubuntu Linux 20.04 LTS Benchmark v3.0.0 (applied to Debian 11)",
}
