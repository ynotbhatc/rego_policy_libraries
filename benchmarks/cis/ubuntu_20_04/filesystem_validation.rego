package cis_ubuntu_20_04.filesystem

# CIS Ubuntu 20.04 - Section 1.1 Filesystem Configuration
# This module implements full validation logic for filesystem partitioning, mount options, and USB storage

import rego.v1

# =============================================================================
# MAIN COMPLIANCE RULES
# =============================================================================

default compliant := false

compliant if {
	count(violations) == 0
}

# =============================================================================
# FILESYSTEM MODULE VIOLATIONS (CIS 1.1.1.x)
# =============================================================================

filesystem_module_violations contains violation if {
	some module in input.disabled_filesystem_modules.modules
	not module.compliant
	violation := sprintf("CIS 1.1.1.x: Filesystem module '%s' is not disabled (loaded: %v, disabled: %v)", [
		module.module,
		module.loaded,
		module.disabled,
	])
}

# =============================================================================
# PARTITION VIOLATIONS (CIS 1.1.2 - 1.1.10)
# =============================================================================

partition_violations contains violation if {
	some partition in input.required_partitions.partitions
	not partition.exists
	violation := sprintf("CIS 1.1.%s: Separate partition for %s does not exist", [
		partition.cis_id,
		partition.mount_point,
	])
}

# =============================================================================
# MOUNT OPTION VIOLATIONS (CIS 1.1.x)
# =============================================================================

mount_option_violations contains violation if {
	some mount in input.mount_options.mounts
	not mount.compliant
	missing_opts := concat(", ", mount.missing_options)
	violation := sprintf("CIS %s: %s is missing mount options: %s", [
		mount.cis_id,
		mount.mount_point,
		missing_opts,
	])
}

# =============================================================================
# STICKY BIT VIOLATIONS (CIS 1.1.22)
# =============================================================================

sticky_bit_violations contains violation if {
	some dir in input.sticky_bit_check.world_writable_dirs
	not dir.has_sticky_bit
	violation := sprintf("CIS 1.1.22: World-writable directory %s does not have sticky bit set", [dir.path])
}

# =============================================================================
# USB STORAGE VIOLATIONS (CIS 1.1.24)
# =============================================================================

usb_storage_violation contains violation if {
	input.usb_storage_disabled.loaded == true
	violation := "CIS 1.1.24: USB storage driver is loaded (should be disabled)"
}

usb_storage_violation contains violation if {
	input.usb_storage_disabled.disabled == false
	violation := "CIS 1.1.24: USB storage driver is not disabled in modprobe"
}

# =============================================================================
# AGGREGATE ALL VIOLATIONS
# =============================================================================

violations := array.concat(
	array.concat(
		array.concat([violation | some violation in filesystem_module_violations], [violation | some violation in partition_violations]),
		[violation | some violation in mount_option_violations],
	),
	array.concat([violation | some violation in sticky_bit_violations], [violation | some violation in usb_storage_violation]),
)

# =============================================================================
# COMPLIANCE REPORT
# =============================================================================

compliance_report := {
	"section": "1.1",
	"description": "Filesystem Configuration",
	"compliant": compliant,
	"total_violations": count(violations),
	"violations": violations,
}
