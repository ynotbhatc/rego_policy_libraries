# METADATA
# title: "CIS Sections 1.3, 1.4, 1.5: Boot Security, Filesystem Integrity, Process Hardening"
# custom:
#   class: security
#   framework: cis_amazon_linux_2023
#   source: cis
#   domains: [linux, amazon-linux]
#   coverage:
#     checks: 24
#     cited: 10
#     density: sized
#     basis: size
#     tested: true
#     entrypoint: none
#     guard: self
#     as_of: v2.4.2
package cis_amazon_linux_2023.boot_security

import rego.v1

# CIS Sections 1.3, 1.4, 1.5: Boot Security, Filesystem Integrity, Process Hardening
# Boot loader, AIDE, and system hardening configuration validation

default compliant := false

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

# CIS 1.3: Filesystem Integrity Checking

# CIS 1.3.1: Ensure AIDE is installed
violations contains msg if {
    not input.boot_security.aide_installed
    msg := "CIS 1.3.1: AIDE is not installed"
}

# CIS 1.3.2: Ensure filesystem integrity is regularly checked
violations contains msg if {
    input.boot_security.aide_installed
    not input.boot_security.aide_cron_configured
    not input.boot_security.aide_timer_configured
    msg := "CIS 1.3.2: AIDE filesystem integrity checks are not scheduled (no cron job or systemd timer)"
}

violations contains msg if {
    input.boot_security.aide_installed
    not input.boot_security.aide_database_initialized
    msg := "CIS 1.3.2: AIDE database is not initialized - run 'aide --init'"
}

# CIS 1.4: Secure Boot Settings

# CIS 1.4.1: Ensure bootloader password is set
violations contains msg if {
    not input.boot_security.grub_password_set
    msg := "CIS 1.4.1: GRUB bootloader password is not set"
}

violations contains msg if {
    input.boot_security.grub_password_set
    not input.boot_security.grub_password_hashed
    msg := "CIS 1.4.1: GRUB bootloader password is not hashed (or hashing evidence not collected)"
}

# CIS 1.4.2: Ensure permissions on bootloader config are configured
violations contains msg if {
    not input.boot_security.grub_cfg_mode
    msg := "CIS 1.4.2: evidence missing - boot_security.grub_cfg_mode not collected"
}

violations contains msg if {
    mode := input.boot_security.grub_cfg_mode
    not mode_within(mode, "0600")
    msg := sprintf("CIS 1.4.2: /boot/grub2/grub.cfg has mode %s, should be 0600 or stricter",
        [mode])
}

violations contains msg if {
    not input.boot_security.grub_cfg_owner
    msg := "CIS 1.4.2: evidence missing - boot_security.grub_cfg_owner not collected"
}

violations contains msg if {
    input.boot_security.grub_cfg_owner != "root"
    msg := sprintf("CIS 1.4.2: /boot/grub2/grub.cfg owned by %s, should be root",
        [input.boot_security.grub_cfg_owner])
}

violations contains msg if {
    not input.boot_security.grub_cfg_group
    msg := "CIS 1.4.2: evidence missing - boot_security.grub_cfg_group not collected"
}

violations contains msg if {
    input.boot_security.grub_cfg_group != "root"
    msg := sprintf("CIS 1.4.2: /boot/grub2/grub.cfg group is %s, should be root",
        [input.boot_security.grub_cfg_group])
}

# CIS 1.4.3: Ensure authentication required for single user mode
violations contains msg if {
    not input.boot_security.single_user_auth_required
    msg := "CIS 1.4.3: Authentication not required for single user mode"
}

# CIS 1.5: Additional Process Hardening

# CIS 1.5.1: Ensure core dumps are restricted
violations contains msg if {
    not input.boot_security.core_dumps_disabled_sysctl
    msg := "CIS 1.5.1: Core dumps not disabled via sysctl (fs.suid_dumpable should be 0)"
}

violations contains msg if {
    not input.boot_security.core_dumps_disabled_limits
    msg := "CIS 1.5.1: Core dumps not disabled via limits.conf (hard core should be 0)"
}

violations contains msg if {
    input.boot_security.systemd_coredump_storage
    input.boot_security.systemd_coredump_storage != "none"
    msg := sprintf("CIS 1.5.1: systemd-coredump Storage is %s, should be 'none'",
        [input.boot_security.systemd_coredump_storage])
}

violations contains msg if {
    input.boot_security.systemd_coredump_process_size_max
    input.boot_security.systemd_coredump_process_size_max != "0"
    msg := "CIS 1.5.1: systemd-coredump ProcessSizeMax should be 0"
}

# CIS 1.5.2: Ensure address space layout randomization (ASLR) is enabled
violations contains msg if {
    input.boot_security.aslr_value
    to_number(input.boot_security.aslr_value) != 2
    msg := sprintf("CIS 1.5.2: kernel.randomize_va_space is %s, should be 2",
        [input.boot_security.aslr_value])
}

violations contains msg if {
    not input.boot_security.aslr_value
    msg := "CIS 1.5.2: kernel.randomize_va_space not configured (should be 2)"
}

# CIS 1.5.3: Ensure prelink is not installed
violations contains msg if {
    input.boot_security.prelink_installed
    msg := "CIS 1.5.3: prelink is installed - should be removed"
}

# CIS 1.5.4: Ensure Automatic Error Reporting is not enabled
violations contains msg if {
    input.boot_security.abrtd_enabled
    msg := "CIS 1.5.4: Automatic Bug Reporting Tool (abrtd) is enabled - should be disabled"
}

violations contains msg if {
    input.boot_security.abrt_installed
    msg := "CIS 1.5.4: ABRT packages are installed - should be removed from production systems"
}

# Additional checks for kernel parameters
violations contains msg if {
    input.boot_security.kernel_kptr_restrict
    to_number(input.boot_security.kernel_kptr_restrict) != 1
    msg := sprintf("CIS 1.5: kernel.kptr_restrict is %s, should be 1 for additional hardening",
        [input.boot_security.kernel_kptr_restrict])
}

violations contains msg if {
    input.boot_security.kernel_dmesg_restrict
    to_number(input.boot_security.kernel_dmesg_restrict) != 1
    msg := "CIS 1.5: kernel.dmesg_restrict should be 1 to restrict dmesg access"
}

# Check for kdump
violations contains msg if {
    input.boot_security.kdump_enabled
    msg := "CIS 1.5: kdump service is enabled - consider disabling on production systems unless needed for troubleshooting"
}

# Compliance check
compliant if {
    count(violations) == 0
}
