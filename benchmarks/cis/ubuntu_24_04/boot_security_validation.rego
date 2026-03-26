package cis_ubuntu_24_04.boot_security

# CIS Ubuntu 24.04 LTS Benchmark v1.0.0 - Sections 1.3-1.5: Boot Security and Process Hardening

import rego.v1

default compliant := false

compliant if {
	count(violations) == 0
}

violations := array.concat(
	array.concat([v | some v in aide_violations], [v | some v in grub_violations]),
	array.concat([v | some v in process_hardening_violations], [v | some v in apparmor_boot_violations]),
)

# CIS 1.3.1: AIDE installed
aide_violations contains msg if {
	not input.aide.installed
	msg := "CIS 1.3.1: AIDE (Advanced Intrusion Detection Environment) is not installed"
}

# CIS 1.3.2: AIDE scheduled
aide_violations contains msg if {
	input.aide.installed
	not input.aide.cron_configured
	not input.aide.systemd_timer_configured
	msg := "CIS 1.3.2: AIDE is not scheduled to run regularly (no cron job or systemd timer)"
}

aide_violations contains msg if {
	input.aide.installed
	not input.aide.database_exists
	msg := "CIS 1.3.1: AIDE database has not been initialized (run aideinit)"
}

# CIS 1.4.1: GRUB boot loader password
grub_violations contains msg if {
	not input.grub.password_configured
	msg := "CIS 1.4.1: GRUB boot loader password is not configured"
}

# CIS 1.4.2: GRUB config file permissions
grub_violations contains msg if {
	input.grub.config_mode != "0400"
	input.grub.config_mode != "0600"
	msg := sprintf("CIS 1.4.2: GRUB configuration file has mode %s, should be 0400 or 0600", [input.grub.config_mode])
}

grub_violations contains msg if {
	input.grub.config_owner != "root"
	msg := sprintf("CIS 1.4.2: GRUB configuration file is owned by %s, should be root", [input.grub.config_owner])
}

# CIS 1.4.3: Single user mode authentication
grub_violations contains msg if {
	not input.grub.sulogin_configured
	msg := "CIS 1.4.3: Single user mode does not require authentication (sulogin not configured)"
}

# CIS 1.5.1: Core dumps restricted
process_hardening_violations contains msg if {
	input.process_hardening.core_dumps_enabled
	msg := "CIS 1.5.1: Core dumps are not restricted (/etc/security/limits.conf * hard core 0 missing)"
}

process_hardening_violations contains msg if {
	input.process_hardening.fs_suid_dumpable != "0"
	msg := sprintf("CIS 1.5.1: fs.suid_dumpable is %s, should be 0", [input.process_hardening.fs_suid_dumpable])
}

# CIS 1.5.2: ASLR enabled
process_hardening_violations contains msg if {
	not input.process_hardening.aslr_enabled
	msg := "CIS 1.5.2: Address Space Layout Randomization (ASLR) is not enabled (kernel.randomize_va_space != 2)"
}

# CIS 1.5.3: prelink disabled
process_hardening_violations contains msg if {
	input.process_hardening.prelink_installed
	msg := "CIS 1.5.3: prelink is installed - remove it as it can reduce ASLR effectiveness"
}

# CIS 1.5.4: ptrace scope
process_hardening_violations contains msg if {
	not input.process_hardening.ptrace_scope_restricted
	msg := "CIS 1.5.4: ptrace scope is not restricted (kernel.yama.ptrace_scope should be >= 1)"
}

# AppArmor boot configuration (Ubuntu-specific)
apparmor_boot_violations contains msg if {
	not input.apparmor.bootloader_enabled
	msg := "CIS 1.6.1.2: AppArmor is not enabled in bootloader configuration"
}

apparmor_boot_violations contains msg if {
	input.apparmor.bootloader_enabled
	not contains(input.apparmor.grub_cmdline, "security=apparmor")
	msg := "CIS 1.6.1.2: AppArmor security= parameter not set in bootloader"
}

report := {
	"compliant": compliant,
	"total_violations": count(violations),
	"violations": violations,
	"aide_violations": count(aide_violations),
	"grub_violations": count(grub_violations),
	"process_hardening_violations": count(process_hardening_violations),
	"controls_checked": 12,
	"section": "1.3-1.5 Boot Security and Process Hardening",
	"benchmark": "CIS Ubuntu 24.04 v1.0.0",
}
