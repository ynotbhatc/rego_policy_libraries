package cis_amazon_linux_2023.boot_security

import rego.v1

# CIS Sections 1.3, 1.4, 1.5: Boot Security, Filesystem Integrity, Process Hardening
# Boot loader, AIDE, and system hardening configuration validation

default compliant := false

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
    input.boot_security.grub_password_hashed == false
    msg := "CIS 1.4.1: GRUB bootloader password is not hashed"
}

# CIS 1.4.2: Ensure permissions on bootloader config are configured
violations contains msg if {
    input.boot_security.grub_cfg_mode
    input.boot_security.grub_cfg_mode != "0600"
    input.boot_security.grub_cfg_mode != "0400"
    msg := sprintf("CIS 1.4.2: /boot/grub2/grub.cfg has mode %s, should be 0600 or 0400",
        [input.boot_security.grub_cfg_mode])
}

violations contains msg if {
    input.boot_security.grub_cfg_owner != "root"
    msg := sprintf("CIS 1.4.2: /boot/grub2/grub.cfg owned by %s, should be root",
        [input.boot_security.grub_cfg_owner])
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
