package cis_rhel8.filesystem

# CIS RHEL 8 Benchmark v3.0.0 - Section 1.1: Filesystem Configuration
# Validates filesystem configuration: disabled modules, partitions, mount options

import rego.v1

default compliant := false

compliant if {
	count(violations) == 0
}

violations := array.concat(
	array.concat(
		array.concat([v | some v in filesystem_module_violations], [v | some v in partition_violations]),
		[v | some v in mount_option_violations],
	),
	array.concat([v | some v in sticky_bit_violations], [v | some v in usb_storage_violation]),
)

# CIS 1.1.1.x: Disabled filesystem modules
filesystem_module_violations contains sprintf("CIS 1.1.1.x: Filesystem module '%s' is not disabled (loaded: %v, disabled: %v)", [module.module, module.loaded, module.disabled]) if {
	some module in input.disabled_filesystem_modules.modules
	not module.compliant
}

# CIS 1.1.2.x: Separate partitions
partition_violations contains sprintf("CIS 1.1.2.x: Required partition '%s' is not a separate partition", [partition.mount_point]) if {
	some partition in input.separate_partitions.analysis
	not partition.is_separate_partition
}

partition_violations contains sprintf("CIS 1.1.2.x: Partition '%s' is missing required mount options: %v", [partition.mount_point, partition.missing_options]) if {
	some partition in input.separate_partitions.analysis
	partition.is_separate_partition
	not partition.has_all_required_options
	count(partition.missing_options) > 0
}

# CIS 1.1.2.1.x: /tmp partition mount options
mount_option_violations contains "CIS 1.1.2.1.2: /tmp partition does not have 'nodev' option set" if {
	input.mount_options.tmp.exists
	not input.mount_options.tmp.has_nodev
}

mount_option_violations contains "CIS 1.1.2.1.3: /tmp partition does not have 'noexec' option set" if {
	input.mount_options.tmp.exists
	not input.mount_options.tmp.has_noexec
}

mount_option_violations contains "CIS 1.1.2.1.4: /tmp partition does not have 'nosuid' option set" if {
	input.mount_options.tmp.exists
	not input.mount_options.tmp.has_nosuid
}

# CIS 1.1.2.2.x: /dev/shm mount options
mount_option_violations contains "CIS 1.1.2.2.2: /dev/shm does not have 'nodev' option set" if {
	input.mount_options.dev_shm.exists
	not input.mount_options.dev_shm.has_nodev
}

mount_option_violations contains "CIS 1.1.2.2.3: /dev/shm does not have 'noexec' option set" if {
	input.mount_options.dev_shm.exists
	not input.mount_options.dev_shm.has_noexec
}

mount_option_violations contains "CIS 1.1.2.2.4: /dev/shm does not have 'nosuid' option set" if {
	input.mount_options.dev_shm.exists
	not input.mount_options.dev_shm.has_nosuid
}

# CIS 1.1.22: Sticky bit on world-writable directories
sticky_bit_violations contains sprintf("CIS 1.1.22: Directory '%s' is world-writable without sticky bit (mode: %s)", [directory.directory, directory.mode]) if {
	some directory in input.sticky_bit.analysis
	not directory.compliant
	directory.exists
}

sticky_bit_violations contains sprintf("CIS 1.1.22: World-writable directory without sticky bit: %s", [path]) if {
	count(input.sticky_bit.world_writable_without_sticky) > 0
	some path in input.sticky_bit.world_writable_without_sticky
}

# CIS 1.1.1.8: USB storage disabled
usb_storage_violation contains "CIS 1.1.1.8: USB storage module is loaded (should be disabled)" if {
	input.usb_storage.loaded == true
}

usb_storage_violation contains sprintf("CIS 1.1.1.8: USB storage module is not disabled (status: %s)", [input.usb_storage.status]) if {
	input.usb_storage.disabled == false
	input.usb_storage.status != "disabled"
}

non_compliant_modules contains {"module": mod.module, "loaded": mod.loaded, "disabled": mod.disabled} if {
	some mod in input.disabled_filesystem_modules.modules
	not mod.compliant
}

non_compliant_partitions contains {"mount_point": part.mount_point, "is_separate_partition": part.is_separate_partition, "missing_options": part.missing_options} if {
	some part in input.separate_partitions.analysis
	not part.compliant
}

report := {
	"compliant": compliant,
	"total_violations": count(violations),
	"violations": violations,
	"non_compliant_modules": non_compliant_modules,
	"non_compliant_partitions": non_compliant_partitions,
	"section": "1.1 Filesystem Configuration",
	"benchmark": "CIS RHEL 8 v3.0.0",
}
