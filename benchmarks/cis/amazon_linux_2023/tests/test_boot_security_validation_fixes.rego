package cis_amazon_linux_2023.boot_security_test

import rego.v1

# Regression tests for the 2026-10-17 validation pass.

has(prefix, v) if {
	some m in v
	startswith(m, prefix)
}

base := {"boot_security": {
	"grub_password_set": true,
	"grub_password_hashed": true,
	"grub_cfg_mode": "0600",
	"grub_cfg_owner": "root",
	"grub_cfg_group": "root",
}}

test_boot_unhashed_missing_flag_flagged if {
	v := data.cis_amazon_linux_2023.boot_security.violations with input as {"boot_security": {"grub_password_set": true}}
	has("CIS 1.4.1: GRUB bootloader password is not hashed", v)
}

test_boot_hashed_ok if {
	v := data.cis_amazon_linux_2023.boot_security.violations with input as base
	not has("CIS 1.4.1", v)
	not has("CIS 1.4.2", v)
}

test_boot_grub_cfg_missing_owner_group_mode_flagged if {
	v := data.cis_amazon_linux_2023.boot_security.violations with input as {"boot_security": {"grub_password_set": true, "grub_password_hashed": true}}
	count([m | some m in v; startswith(m, "CIS 1.4.2")]) == 3
}

test_boot_grub_cfg_mode_0644_flagged if {
	v := data.cis_amazon_linux_2023.boot_security.violations with input as object.union(base, {"boot_security": {"grub_cfg_mode": "0644"}})
	has("CIS 1.4.2: /boot/grub2/grub.cfg has mode", v)
}

test_boot_grub_cfg_mode_0400_ok if {
	v := data.cis_amazon_linux_2023.boot_security.violations with input as object.union(base, {"boot_security": {"grub_cfg_mode": "0400"}})
	not has("CIS 1.4.2", v)
}
