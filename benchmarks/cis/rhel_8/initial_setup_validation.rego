package cis_rhel8.initial_setup

# CIS RHEL 8 Benchmark v3.0.0 - Sections 1.2, 1.7, 1.8, 1.9: Initial System Setup

import rego.v1

default compliant := false

compliant if {
	count(violations) == 0
}

# CIS 1.2: Configure Software Updates

# CIS 1.2.1: Ensure GPG keys are configured
violations contains msg if {
	count(input.initial_setup.gpg_keys) == 0
	msg := "CIS 1.2.1: No GPG keys configured for package verification"
}

# CIS 1.2.2: Ensure package manager repositories are configured
violations contains msg if {
	count(input.initial_setup.enabled_repos) == 0
	msg := "CIS 1.2.2: No package repositories are enabled"
}

violations contains msg if {
	some repo in input.initial_setup.repos_without_gpgcheck
	msg := sprintf("CIS 1.2.2: Repository %s does not have gpgcheck enabled", [repo])
}

# CIS 1.2.3: Ensure gpgcheck is globally activated
violations contains msg if {
	not input.initial_setup.global_gpgcheck_enabled
	msg := "CIS 1.2.3: Global gpgcheck is not enabled in /etc/dnf/dnf.conf"
}

# CIS 1.7: Command Line Warning Banners

# CIS 1.7.1: Ensure message of the day is configured properly
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
	msg := "CIS 1.7.1: /etc/motd contains sensitive system information (OS version, kernel, etc.)"
}

# CIS 1.7.2: Ensure local login warning banner is configured properly
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

# CIS 1.7.3: Ensure remote login warning banner is configured properly
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

# CIS 1.7.4: Ensure permissions on /etc/motd are configured
violations contains msg if {
	input.initial_setup.motd_owner != "root"
	msg := sprintf("CIS 1.7.4: /etc/motd owned by %s, should be root", [input.initial_setup.motd_owner])
}

# CIS 1.7.5: Ensure permissions on /etc/issue are configured
violations contains msg if {
	input.initial_setup.issue_owner != "root"
	msg := sprintf("CIS 1.7.5: /etc/issue owned by %s, should be root", [input.initial_setup.issue_owner])
}

# CIS 1.7.6: Ensure permissions on /etc/issue.net are configured
violations contains msg if {
	input.initial_setup.issue_net_owner != "root"
	msg := sprintf("CIS 1.7.6: /etc/issue.net owned by %s, should be root", [input.initial_setup.issue_net_owner])
}

# CIS 1.8: GNOME Display Manager

# CIS 1.8.1: Ensure GNOME Display Manager is removed (if not required)
violations contains msg if {
	input.initial_setup.gdm_installed
	input.initial_setup.server_environment
	not input.initial_setup.gui_required
	msg := "CIS 1.8.1: GNOME Display Manager (GDM) installed on server without GUI requirement"
}

# CIS 1.8.2: Ensure GDM login banner is configured
violations contains msg if {
	input.initial_setup.gdm_installed
	input.initial_setup.gui_required
	not input.initial_setup.gdm_banner_configured
	msg := "CIS 1.8.2: GDM login banner is not configured"
}

# CIS 1.8.3: Ensure GDM disable-user-list option is enabled
violations contains msg if {
	input.initial_setup.gdm_installed
	input.initial_setup.gui_required
	not input.initial_setup.gdm_disable_user_list
	msg := "CIS 1.8.3: GDM user list is not disabled"
}

# CIS 1.8.4: Ensure GDM screen locks when the user is idle
violations contains msg if {
	input.initial_setup.gdm_installed
	input.initial_setup.gui_required
	not input.initial_setup.gdm_screen_lock_enabled
	msg := "CIS 1.8.4: GDM automatic screen lock is not enabled"
}

violations contains msg if {
	input.initial_setup.gdm_installed
	input.initial_setup.gui_required
	input.initial_setup.gdm_screen_lock_enabled
	input.initial_setup.gdm_idle_delay > 900
	msg := sprintf("CIS 1.8.4: GDM idle delay is %d seconds, should be 900 or less", [input.initial_setup.gdm_idle_delay])
}

# CIS 1.8.5: Ensure GDM screen locks cannot be overridden
violations contains msg if {
	input.initial_setup.gdm_installed
	input.initial_setup.gui_required
	input.initial_setup.gdm_lock_override_allowed
	msg := "CIS 1.8.5: GDM screen lock can be overridden by users"
}

# CIS 1.8.6: Ensure GDM automatic mounting of removable media is disabled
violations contains msg if {
	input.initial_setup.gdm_installed
	input.initial_setup.gui_required
	not input.initial_setup.gdm_automount_disabled
	msg := "CIS 1.8.6: GDM automatic mounting of removable media is not disabled"
}

violations contains msg if {
	input.initial_setup.gdm_installed
	input.initial_setup.gui_required
	not input.initial_setup.gdm_automount_open_disabled
	msg := "CIS 1.8.6: GDM automatic opening of removable media is not disabled"
}

# CIS 1.8.7: Ensure GDM disabling automatic mounting of removable media is not overridden
violations contains msg if {
	input.initial_setup.gdm_installed
	input.initial_setup.gui_required
	input.initial_setup.gdm_automount_override_allowed
	msg := "CIS 1.8.7: GDM automount settings can be overridden by users"
}

# CIS 1.8.8: Ensure GDM autorun-never is enabled
violations contains msg if {
	input.initial_setup.gdm_installed
	input.initial_setup.gui_required
	not input.initial_setup.gdm_autorun_never_enabled
	msg := "CIS 1.8.8: GDM autorun-never is not enabled"
}

# CIS 1.8.9: Ensure GDM autorun-never is not overridden
violations contains msg if {
	input.initial_setup.gdm_installed
	input.initial_setup.gui_required
	input.initial_setup.gdm_autorun_override_allowed
	msg := "CIS 1.8.9: GDM autorun-never can be overridden by users"
}

# CIS 1.8.10: Ensure XDMCP is not enabled
violations contains msg if {
	input.initial_setup.gdm_installed
	input.initial_setup.gdm_xdmcp_enabled
	msg := "CIS 1.8.10: GDM XDMCP is enabled - should be disabled for security"
}

# CIS 1.9: Ensure system-wide crypto policy is not legacy
violations contains msg if {
	input.initial_setup.crypto_policy
	input.initial_setup.crypto_policy == "LEGACY"
	msg := "CIS 1.9: System-wide crypto policy is set to LEGACY - should use DEFAULT, FUTURE, or FIPS"
}

violations contains msg if {
	not input.initial_setup.crypto_policy
	msg := "CIS 1.9: System-wide crypto policy is not configured"
}

report := {
	"compliant": compliant,
	"total_violations": count(violations),
	"violations": violations,
	"controls_checked": 22,
	"section": "1.2, 1.7-1.9 Initial System Setup",
	"benchmark": "CIS RHEL 8 v3.0.0",
}
