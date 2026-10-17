# METADATA
# title: "CIS Ubuntu 24.04 - Section 1.1 Filesystem Configuration"
# custom:
#   class: security
#   framework: cis_ubuntu_24_04
#   source: cis
#   domains: [linux, ubuntu]
#   coverage:
#     checks: 8
#     cited: 4
#     density: section
#     basis: role
#     tested: true
#     entrypoint: compliance_report
#     guard: self
#     as_of: v2.4.2
package cis_ubuntu_24_04.filesystem

# CIS Ubuntu 24.04 - Section 1.1 Filesystem Configuration
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
		object.get(module, "module", "unknown"),
		object.get(module, "loaded", "unknown"),
		object.get(module, "disabled", "unknown"),
	])
}

# =============================================================================
# PARTITION VIOLATIONS (CIS 1.1.2 - 1.1.10)
# =============================================================================

partition_violations contains violation if {
	some partition in input.required_partitions.partitions
	not partition.exists
	violation := sprintf("CIS 1.1.%s: Separate partition for %s does not exist", [
		object.get(partition, "cis_id", "x"),
		object.get(partition, "mount_point", "unknown"),
	])
}

# =============================================================================
# MOUNT OPTION VIOLATIONS (CIS 1.1.x)
# =============================================================================

mount_option_violations contains violation if {
	some mount in input.mount_options.mounts
	not mount.compliant
	missing_opts := concat(", ", object.get(mount, "missing_options", []))
	violation := sprintf("CIS %s: %s is missing mount options: %s", [
		object.get(mount, "cis_id", "1.1.x"),
		object.get(mount, "mount_point", "unknown"),
		missing_opts,
	])
}

# =============================================================================
# STICKY BIT VIOLATIONS (CIS 1.1.22)
# =============================================================================

sticky_bit_violations contains violation if {
	some dir in input.sticky_bit_check.world_writable_dirs
	not dir.has_sticky_bit
	violation := sprintf("CIS 1.1.22: World-writable directory %s does not have sticky bit set", [object.get(dir, "path", "unknown")])
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

usb_storage_violation contains violation if {
	count(object.get(input, "usb_storage_disabled", {})) > 0
	object.get(input.usb_storage_disabled, "disabled", null) == null
	violation := "CIS 1.1.24: evidence missing — usb_storage_disabled.disabled not collected"
}

# =============================================================================
# EVIDENCE GATES: a section that was not collected is a violation, not a pass
# =============================================================================

filesystem_module_violations contains "CIS 1.1.1.x: evidence missing — disabled_filesystem_modules.modules not collected" if {
	count(object.get(object.get(input, "disabled_filesystem_modules", {}), "modules", [])) == 0
}

partition_violations contains "CIS 1.1.2: evidence missing — required_partitions.partitions not collected" if {
	count(object.get(object.get(input, "required_partitions", {}), "partitions", [])) == 0
}

mount_option_violations contains "CIS 1.1.x: evidence missing — mount_options.mounts not collected" if {
	count(object.get(object.get(input, "mount_options", {}), "mounts", [])) == 0
}

sticky_bit_violations contains "CIS 1.1.22: evidence missing — sticky_bit_check.world_writable_dirs not collected" if {
	object.get(object.get(input, "sticky_bit_check", {}), "world_writable_dirs", null) == null
}

usb_storage_violation contains "CIS 1.1.24: evidence missing — usb_storage_disabled not collected" if {
	count(object.get(input, "usb_storage_disabled", {})) == 0
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
