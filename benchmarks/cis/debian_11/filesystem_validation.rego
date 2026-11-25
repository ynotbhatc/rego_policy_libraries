# METADATA
# title: "CIS Debian 11 - Section 1.1 Filesystem Configuration"
# custom:
#   class: security
#   framework: cis_debian_11
#   source: cis
#   domains: [linux, debian]
#   coverage:
#     checks: 12
#     cited: 4
#     density: sized
#     basis: size
#     tested: true
#     entrypoint: compliance_report
#     guard: self
#     as_of: v2.4.2
package cis_debian_11.filesystem

# CIS Debian 11 - Section 1.1 Filesystem Configuration
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
	not input.disabled_filesystem_modules.modules
	violation := "CIS 1.1.1.x: evidence missing — disabled_filesystem_modules.modules not collected"
}

filesystem_module_violations contains violation if {
	some module in input.disabled_filesystem_modules.modules
	module.compliant == false
	violation := sprintf("CIS 1.1.1.x: Filesystem module '%s' is not disabled (loaded: %v, disabled: %v)", [
		object.get(module, "module", "not collected"),
		object.get(module, "loaded", "not collected"),
		object.get(module, "disabled", "not collected"),
	])
}

# =============================================================================
# PARTITION VIOLATIONS (CIS 1.1.2 - 1.1.10)
# =============================================================================

partition_violations contains violation if {
	not input.required_partitions.partitions
	violation := "CIS 1.1.2: evidence missing — required_partitions.partitions not collected"
}

partition_violations contains violation if {
	some partition in input.required_partitions.partitions
	partition.exists == false
	violation := sprintf("CIS 1.1.%s: Separate partition for %s does not exist", [
		object.get(partition, "cis_id", "not collected"),
		object.get(partition, "mount_point", "not collected"),
	])
}

# =============================================================================
# MOUNT OPTION VIOLATIONS (CIS 1.1.x)
# =============================================================================

mount_option_violations contains violation if {
	not input.mount_options.mounts
	violation := "CIS 1.1.x: evidence missing — mount_options.mounts not collected"
}

mount_option_violations contains violation if {
	some mount in input.mount_options.mounts
	mount.compliant == false
	missing_opts := concat(", ", object.get(mount, "missing_options", []))
	violation := sprintf("CIS %s: %s is missing mount options: %s", [
		object.get(mount, "cis_id", "not collected"),
		object.get(mount, "mount_point", "not collected"),
		missing_opts,
	])
}

# =============================================================================
# STICKY BIT VIOLATIONS (CIS 1.1.22)
# =============================================================================

sticky_bit_violations contains violation if {
	not input.sticky_bit_check.world_writable_dirs
	violation := "CIS 1.1.22: evidence missing — sticky_bit_check.world_writable_dirs not collected"
}

sticky_bit_violations contains violation if {
	some dir in input.sticky_bit_check.world_writable_dirs
	dir.has_sticky_bit == false
	violation := sprintf("CIS 1.1.22: World-writable directory %s does not have sticky bit set", [object.get(dir, "path", "not collected")])
}

# =============================================================================
# USB STORAGE VIOLATIONS (CIS 1.1.24)
# =============================================================================

usb_storage_violation contains violation if {
	not is_object(object.get(input, "usb_storage_disabled", null))
	violation := "CIS 1.1.24: evidence missing — usb_storage_disabled not collected"
}

usb_storage_violation contains violation if {
	input.usb_storage_disabled.loaded == true
	violation := "CIS 1.1.24: USB storage driver is loaded (should be disabled)"
}

usb_storage_violation contains violation if {
	input.usb_storage_disabled.disabled == false
	violation := "CIS 1.1.24: USB storage driver is not disabled in modprobe"
}

# yes/no fields of collected rows: every row must answer with a boolean
filesystem_module_violations contains msg if {
	some i, row in input.disabled_filesystem_modules.modules
	some key in ["compliant"]
	msg := sprintf("CIS 1.1.1.x: evidence missing — disabled_filesystem_modules.modules[%d].%s %s", [i, key, row_flag_problem(row, key)])
}

# yes/no fields of collected rows: every row must answer with a boolean
partition_violations contains msg if {
	some i, row in input.required_partitions.partitions
	some key in ["exists"]
	msg := sprintf("CIS 1.1.2: evidence missing — required_partitions.partitions[%d].%s %s", [i, key, row_flag_problem(row, key)])
}

# yes/no fields of collected rows: every row must answer with a boolean
mount_option_violations contains msg if {
	some i, row in input.mount_options.mounts
	some key in ["compliant"]
	msg := sprintf("CIS 1.1.x: evidence missing — mount_options.mounts[%d].%s %s", [i, key, row_flag_problem(row, key)])
}

# yes/no fields of collected rows: every row must answer with a boolean
sticky_bit_violations contains msg if {
	some i, row in input.sticky_bit_check.world_writable_dirs
	some key in ["has_sticky_bit"]
	msg := sprintf("CIS 1.1.22: evidence missing — sticky_bit_check.world_writable_dirs[%d].%s %s", [i, key, row_flag_problem(row, key)])
}

# both USB storage facts are read, so both must be boolean answers (a section that was not collected is reported above)
usb_storage_violation contains msg if {
	is_object(input.usb_storage_disabled)
	some key in ["loaded", "disabled"]
	msg := flag_evidence("CIS 1.1.24", ["usb_storage_disabled", key])
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

# ---------------------------------------------------------------------------
# Evidence rule: a yes/no fact is answered only by a JSON boolean. A missing fact, null, a string
# ("true", "false", "no") or a number is an evidence problem: the control fails and the finding names it.
# ---------------------------------------------------------------------------
flag_problem(path) := "not collected" if is_null(object.get(input, path, null))

flag_problem(path) := sprintf("is not a boolean (got %s)", [type_name(v)]) if {
	v := object.get(input, path, null)
	not is_null(v)
	not is_boolean(v)
}

flag_evidence(prefix, path) := sprintf("%s: evidence missing — %s %s", [prefix, concat(".", path), flag_problem(path)])

# the same for a yes/no field of one collected row
row_flag_problem(row, key) := "not collected" if is_null(object.get(row, key, null))

row_flag_problem(row, key) := sprintf("is not a boolean (got %s)", [type_name(v)]) if {
	v := object.get(row, key, null)
	not is_null(v)
	not is_boolean(v)
}

compliance_report := {
	"section": "1.1",
	"description": "Filesystem Configuration",
	"compliant": compliant,
	"total_violations": count(violations),
	"violations": violations,
}
