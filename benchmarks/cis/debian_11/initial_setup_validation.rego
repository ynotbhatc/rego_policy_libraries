package cis_debian_11.initial_setup

# CIS Debian Linux 11 Benchmark v1.0.0 - Sections 1.2, 1.7, 1.8: Initial System Setup

import rego.v1

default compliant := false

compliant if {
	count(violations) == 0
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
	input.initial_setup.grub_config_mode != "0400"
	input.initial_setup.grub_config_mode != "0600"
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
	input.initial_setup.motd_mode != "0644"
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
	input.initial_setup.issue_mode != "0644"
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
	input.initial_setup.issue_net_mode != "0644"
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
	"benchmark": "CIS Debian 11 v1.0.0",
}
