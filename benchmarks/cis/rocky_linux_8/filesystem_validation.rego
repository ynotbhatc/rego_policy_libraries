package cis_rocky_linux_8.filesystem

# CIS Rocky Linux 8 Section 1.1 - Filesystem Configuration
# Validates filesystem modules, partitions, and mount options

import rego.v1

# =============================================================================
# MAIN COMPLIANCE RULES
# =============================================================================

default compliant := false

compliant if {
	count(violations) == 0
}

# Aggregate all violations
violations contains violation if {
	some violation in filesystem_module_violations
}

violations contains violation if {
	some violation in partition_violations
}

# =============================================================================
# FILESYSTEM MODULE CHECKS
# =============================================================================

filesystem_module_violations contains violation if {
	input.disabled_filesystem_modules
	some module in ["cramfs", "squashfs", "udf"]
	not module_disabled(module)
	violation := sprintf("CIS 1.1.1.x: Filesystem module '%s' is not disabled", [module])
}

module_disabled(module) if {
	input.disabled_filesystem_modules[module] == true
}

# =============================================================================
# PARTITION CHECKS
# =============================================================================

partition_violations contains violation if {
	not tmp_partition_exists
	violation := "CIS 1.1.2: /tmp is not configured on a separate partition"
}

partition_violations contains violation if {
	not var_partition_exists
	violation := "CIS 1.1.6: /var is not configured on a separate partition"
}

tmp_partition_exists if {
	some mount in input.mounts
	mount.mount == "/tmp"
}

var_partition_exists if {
	some mount in input.mounts
	mount.mount == "/var"
}
