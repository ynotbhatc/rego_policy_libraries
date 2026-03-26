package cis_debian_11.apparmor

# CIS Debian Linux 11 Benchmark v1.0.0 - Section 1.6: Mandatory Access Controls
# Ubuntu uses AppArmor instead of SELinux

import rego.v1

default compliant := false

compliant if {
	count(violations) == 0
}

violations := array.concat(
	[v | some v in install_violations],
	array.concat([v | some v in service_violations], [v | some v in profile_violations]),
)

# CIS 1.6.1.1: Ensure AppArmor is installed
install_violations contains msg if {
	not input.apparmor.installed
	msg := "CIS 1.6.1.1: AppArmor is not installed"
}

install_violations contains msg if {
	not input.apparmor.utils_installed
	msg := "CIS 1.6.1.1: apparmor-utils is not installed"
}

# CIS 1.6.1.2: Ensure AppArmor is enabled in the bootloader configuration
service_violations contains msg if {
	not input.apparmor.bootloader_enabled
	msg := "CIS 1.6.1.2: AppArmor is not enabled in bootloader (apparmor=1 security=apparmor missing from GRUB_CMDLINE_LINUX)"
}

service_violations contains msg if {
	input.apparmor.bootloader_enabled
	not contains(input.apparmor.grub_cmdline, "security=apparmor")
	msg := "CIS 1.6.1.2: AppArmor security= parameter not set to apparmor in bootloader"
}

# CIS 1.6.1.3: Ensure all AppArmor Profiles are in enforce or complain mode
profile_violations contains msg if {
	input.apparmor.unloaded_profiles > 0
	msg := sprintf("CIS 1.6.1.3: %d AppArmor profiles are not loaded", [input.apparmor.unloaded_profiles])
}

profile_violations contains msg if {
	some profile in input.apparmor.profiles
	profile.mode == "unloaded"
	msg := sprintf("CIS 1.6.1.3: AppArmor profile '%s' is not loaded", [profile.name])
}

# CIS 1.6.1.4: Ensure all AppArmor Profiles are enforcing
profile_violations contains msg if {
	input.apparmor.complain_profiles > 0
	msg := sprintf("CIS 1.6.1.4: %d AppArmor profiles are in complain mode (should be enforce)", [input.apparmor.complain_profiles])
}

profile_violations contains msg if {
	some profile in input.apparmor.profiles
	profile.mode == "complain"
	msg := sprintf("CIS 1.6.1.4: AppArmor profile '%s' is in complain mode, should be enforce", [profile.name])
}

# AppArmor service must be active
service_violations contains msg if {
	not input.apparmor.service_active
	msg := "CIS 1.6.1.2: AppArmor service is not active"
}

service_violations contains msg if {
	not input.apparmor.service_enabled
	msg := "CIS 1.6.1.2: AppArmor service is not enabled"
}

# AppArmor status
apparmor_status := {
	"installed": input.apparmor.installed,
	"service_active": input.apparmor.service_active,
	"enforce_profiles": input.apparmor.enforce_profiles,
	"complain_profiles": input.apparmor.complain_profiles,
	"unloaded_profiles": input.apparmor.unloaded_profiles,
}

report := {
	"compliant": compliant,
	"total_violations": count(violations),
	"violations": violations,
	"install_violations": count(install_violations),
	"service_violations": count(service_violations),
	"profile_violations": count(profile_violations),
	"apparmor_status": apparmor_status,
	"controls_checked": 4,
	"section": "1.6 Mandatory Access Controls (AppArmor)",
	"benchmark": "CIS Debian 11 v1.0.0",
}
