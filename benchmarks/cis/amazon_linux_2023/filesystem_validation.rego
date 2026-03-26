package cis_amazon_linux_2023.filesystem

# CIS Amazon Linux 2023 Section 1.1.x - Filesystem Configuration
# Validates filesystem configuration including disabled modules, partitions, and mount options

import rego.v1

# =============================================================================
# MAIN COMPLIANCE RULES
# =============================================================================

# Overall filesystem compliance
default compliant := false

compliant if {
	count(violations) == 0
}

# Aggregate all violations
violations := array.concat(
	array.concat(
		array.concat([violation | some violation in filesystem_module_violations], [violation | some violation in partition_violations]),
		[violation | some violation in mount_option_violations],
	),
	array.concat([violation | some violation in sticky_bit_violations], [violation | some violation in usb_storage_violation]),
)

# =============================================================================
# CIS 1.1.1.x - DISABLED FILESYSTEM MODULES
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

# Helper: Check if all filesystem modules are compliant
all_filesystem_modules_disabled if {
	input.disabled_filesystem_modules.all_compliant == true
}

# =============================================================================
# CIS 1.1.2.x - SEPARATE PARTITIONS
# =============================================================================

partition_violations contains violation if {
	some partition in input.separate_partitions.analysis
	not partition.is_separate_partition
	violation := sprintf("CIS 1.1.2.x: Required partition '%s' is not a separate partition", [
		partition.mount_point,
	])
}

partition_violations contains violation if {
	some partition in input.separate_partitions.analysis
	partition.is_separate_partition
	not partition.has_all_required_options
	count(partition.missing_options) > 0
	violation := sprintf("CIS 1.1.2.x: Partition '%s' is missing required mount options: %v", [
		partition.mount_point,
		partition.missing_options,
	])
}

# Helper: Check if all required partitions exist
all_required_partitions_exist if {
	input.separate_partitions.all_present == true
}

# Helper: Check if all partitions have correct mount options
all_partitions_compliant if {
	input.separate_partitions.all_compliant == true
}

# =============================================================================
# CIS 1.1.2.1.x - /tmp PARTITION
# =============================================================================

mount_option_violations contains violation if {
	input.mount_options.tmp.exists
	not input.mount_options.tmp.has_nodev
	violation := "CIS 1.1.2.1.2: /tmp partition does not have 'nodev' option set"
}

mount_option_violations contains violation if {
	input.mount_options.tmp.exists
	not input.mount_options.tmp.has_nosuid
	violation := "CIS 1.1.2.1.4: /tmp partition does not have 'nosuid' option set"
}

mount_option_violations contains violation if {
	input.mount_options.tmp.exists
	not input.mount_options.tmp.has_noexec
	violation := "CIS 1.1.2.1.3: /tmp partition does not have 'noexec' option set"
}

# =============================================================================
# CIS 1.1.2.2.x - /dev/shm PARTITION
# =============================================================================

mount_option_violations contains violation if {
	input.mount_options.dev_shm.exists
	not input.mount_options.dev_shm.has_nodev
	violation := "CIS 1.1.2.2.2: /dev/shm does not have 'nodev' option set"
}

mount_option_violations contains violation if {
	input.mount_options.dev_shm.exists
	not input.mount_options.dev_shm.has_nosuid
	violation := "CIS 1.1.2.2.4: /dev/shm does not have 'nosuid' option set"
}

mount_option_violations contains violation if {
	input.mount_options.dev_shm.exists
	not input.mount_options.dev_shm.has_noexec
	violation := "CIS 1.1.2.2.3: /dev/shm does not have 'noexec' option set"
}

# =============================================================================
# CIS 1.1.22 - STICKY BIT ON WORLD-WRITABLE DIRECTORIES
# =============================================================================

sticky_bit_violations contains violation if {
	some directory in input.sticky_bit.analysis
	not directory.compliant
	directory.exists
	violation := sprintf("CIS 1.1.22: Directory '%s' is world-writable without sticky bit (mode: %s)", [
		directory.directory,
		directory.mode,
	])
}

sticky_bit_violations contains violation if {
	count(input.sticky_bit.world_writable_without_sticky) > 0
	some path in input.sticky_bit.world_writable_without_sticky
	violation := sprintf("CIS 1.1.22: World-writable directory without sticky bit found: %s", [path])
}

# Helper: Check if sticky bit is compliant
sticky_bit_compliant if {
	input.sticky_bit.all_compliant == true
}

# =============================================================================
# CIS 1.1.1.8 - USB STORAGE
# =============================================================================

usb_storage_violation contains violation if {
	input.usb_storage.loaded == true
	violation := "CIS 1.1.1.8: USB storage module is loaded (should be disabled)"
}

usb_storage_violation contains violation if {
	input.usb_storage.disabled == false
	input.usb_storage.status != "disabled"
	violation := sprintf("CIS 1.1.1.8: USB storage module is not disabled (status: %s)", [
		input.usb_storage.status,
	])
}

# =============================================================================
# COMPLIANCE CHECKS
# =============================================================================

# Section-level compliance checks
compliance_summary := {
	"all_filesystem_modules_disabled": input.compliance_checks.all_fs_modules_disabled,
	"all_required_partitions_present": input.compliance_checks.all_required_partitions_present,
	"all_mount_options_correct": input.compliance_checks.all_mount_options_correct,
	"tmp_partition_secure": input.compliance_checks.tmp_partition_secure,
	"dev_shm_secure": input.compliance_checks.dev_shm_secure,
	"sticky_bit_compliant": input.compliance_checks.sticky_bit_compliant,
	"usb_storage_compliant": input.compliance_checks.usb_storage_compliant,
	"overall_compliant": count(violations) == 0,
}

# =============================================================================
# DETAILED REPORTING
# =============================================================================

# Non-compliant filesystem modules
non_compliant_modules contains module if {
	some mod in input.disabled_filesystem_modules.modules
	not mod.compliant
	module := {
		"module": mod.module,
		"loaded": mod.loaded,
		"disabled": mod.disabled,
	}
}

# Non-compliant partitions
non_compliant_partitions contains partition if {
	some part in input.separate_partitions.analysis
	not part.compliant
	partition := {
		"mount_point": part.mount_point,
		"is_separate_partition": part.is_separate_partition,
		"missing_options": part.missing_options,
	}
}

# Detailed compliance report
report := {
	"compliant": compliant,
	"total_violations": count(violations),
	"violations": violations,
	"compliance_summary": compliance_summary,
	"non_compliant_modules": non_compliant_modules,
	"non_compliant_partitions": non_compliant_partitions,
	"collection_timestamp": input.collection_timestamp,
}

