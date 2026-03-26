package cis_rhel8.selinux

# CIS RHEL 8 Benchmark v3.0.0 - Section 1.6: Mandatory Access Controls (SELinux)

import rego.v1

default compliant := false

selinux_enabled if {
	input.selinux.status == "enabled"
}

selinux_enforcing if {
	input.selinux.mode == "enforcing"
}

# CIS 1.6.1.1: SELinux installed
violations contains msg if {
	not input.selinux.installed
	msg := "CIS 1.6.1.1: SELinux (libselinux) not installed"
}

# CIS 1.6.1.2: SELinux not disabled in bootloader
violations contains msg if {
	input.selinux.installed
	contains(input.selinux.grub_cmdline, "selinux=0")
	msg := "CIS 1.6.1.2: SELinux is disabled in bootloader configuration (selinux=0)"
}

violations contains msg if {
	input.selinux.installed
	contains(input.selinux.grub_cmdline, "enforcing=0")
	msg := "CIS 1.6.1.2: SELinux enforcing is disabled in bootloader configuration (enforcing=0)"
}

# CIS 1.6.1.3: SELinux policy configured
violations contains msg if {
	input.selinux.installed
	not input.selinux.policy
	msg := "CIS 1.6.1.3: SELinux policy not configured"
}

violations contains msg if {
	input.selinux.installed
	input.selinux.policy
	not input.selinux.policy in ["targeted", "mls"]
	msg := sprintf("CIS 1.6.1.3: SELinux policy is %s, should be 'targeted' or 'mls'", [input.selinux.policy])
}

# CIS 1.6.1.4: SELinux mode enabled
violations contains msg if {
	input.selinux.installed
	not selinux_enabled
	msg := "CIS 1.6.1.4: SELinux is not enabled"
}

violations contains msg if {
	input.selinux.installed
	selinux_enabled
	input.selinux.mode == "disabled"
	msg := "CIS 1.6.1.4: SELinux mode is disabled"
}

# CIS 1.6.1.5: SELinux mode enforcing
violations contains msg if {
	input.selinux.installed
	selinux_enabled
	not selinux_enforcing
	msg := sprintf("CIS 1.6.1.5: SELinux mode is %s, should be enforcing", [input.selinux.mode])
}

# CIS 1.6.1.6: No unconfined services
violations contains msg if {
	input.selinux.installed
	selinux_enabled
	count(input.selinux.unconfined_services) > 0
	msg := sprintf("CIS 1.6.1.6: Found %d unconfined services: %s",
		[count(input.selinux.unconfined_services), concat(", ", input.selinux.unconfined_services)])
}

# CIS 1.6.1.7: SETroubleshoot not installed
violations contains msg if {
	input.selinux.setroubleshoot_installed
	msg := "CIS 1.6.1.7: SETroubleshoot is installed - should be removed on production systems"
}

# CIS 1.6.1.8: MCS Translation Service (mcstrans) not installed
violations contains msg if {
	input.selinux.mcstrans_installed
	msg := "CIS 1.6.1.8: MCS Translation Service (mcstrans) is installed - should be removed"
}

# Files with incorrect SELinux context
violations contains msg if {
	input.selinux.installed
	selinux_enabled
	count(input.selinux.files_with_incorrect_context) > 0
	msg := sprintf("CIS 1.6: Found %d files with incorrect SELinux context",
		[count(input.selinux.files_with_incorrect_context)])
}

# High number of denials
violations contains msg if {
	input.selinux.installed
	selinux_enforcing
	input.selinux.recent_denials
	count(input.selinux.recent_denials) > 100
	msg := sprintf("CIS 1.6: High number of SELinux denials (%d) - review /var/log/audit/audit.log",
		[count(input.selinux.recent_denials)])
}

compliant if {
	count(violations) == 0
}

report := {
	"compliant": compliant,
	"violations": violations,
	"total_violations": count(violations),
	"controls_checked": 8,
	"section": "1.6 Mandatory Access Controls",
	"benchmark": "CIS RHEL 8 v3.0.0",
}
