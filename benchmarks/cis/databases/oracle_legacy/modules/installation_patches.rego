# METADATA
# title: "CIS Oracle Database 19c Benchmark - Section 1"
# custom:
#   class: security
#   framework: cis_databases
#   source: cis
#   domains: [database, oracle]
#   coverage:
#     checks: 14
#     cited: 3
#     density: sized
#     basis: size
#     tested: true
#     entrypoint: report
#     guard: self
#     as_of: v2.4.2
package cis_oracle.installation_patches

# CIS Oracle Database 19c Benchmark - Section 1
# Installation and Patches
# Validates Oracle version and patch levels

import rego.v1

# =============================================================================
# MAIN COMPLIANCE RULES
# =============================================================================

default compliant := false

compliant if {
	count(violations) == 0
}

violations := [v | some v in installation_violations]

# =============================================================================
# CIS 1.1 - ORACLE VERSION AND PATCHES
# =============================================================================

installation_violations contains violation if {
	not input.oracle_version.supported
	violation := sprintf("CIS 1.1: Oracle version %s is not supported (end of support: %s)", [
		input.oracle_version.version,
		input.oracle_version.end_of_support,
	])
}

installation_violations contains violation if {
	input.oracle_version.version
	not regex.match(`^(19|21|23)([^0-9]|$)`, lower(sprintf("%v", [input.oracle_version.version])))
	violation := sprintf("CIS 1.1: Oracle version %s is not a recommended version (use 19c, 21c, or 23c)", [
		input.oracle_version.version,
	])
}

installation_violations contains violation if {
	some patch in input.critical_patches.missing_patches
	violation := sprintf("CIS 1.1: Critical patch %s (released %s) is not installed - %s", [
		patch.patch_id,
		patch.release_date,
		patch.description,
	])
}

installation_violations contains violation if {
	input.critical_patches.days_since_last_patch > 90
	violation := sprintf("CIS 1.1: Last patch was applied %d days ago (should be < 90 days)", [
		input.critical_patches.days_since_last_patch,
	])
}

installation_violations contains violation if {
	input.critical_patches.critical_missing > 0
	violation := sprintf("CIS 1.1: %d critical security patches are missing", [
		input.critical_patches.critical_missing,
	])
}

# =============================================================================
# ORACLE HOME PERMISSIONS
# =============================================================================

# Parse an octal permission string ("644", "0644", "0o644") to an integer; undefined if not octal.
octal(s) := n if {
	t := trim_prefix(lower(trim_space(sprintf("%v", [s]))), "0o")
	regex.match(`^[0-7]{1,4}$`, t)
	p := concat("", [substring("0000", 0, 4 - count(t)), t])
	ds := [to_number(d) | some d in split(p, "")]
	n := ((ds[0] * 512) + (ds[1] * 64)) + ((ds[2] * 8) + ds[3])
}

# true when mode grants nothing beyond max (both octal strings)
mode_within(mode, max) if bits.and(octal(mode), bits.and(bits.negate(octal(max)), 4095)) == 0

# Evidence: oracle_home must carry permissions, owner and group
installation_violations contains violation if {
	some key in ["permissions", "owner", "group"]
	not oracle_home_has(key)
	violation := sprintf("CIS 1.1: evidence missing — oracle_home.%s not collected", [key])
}

oracle_home_has(key) if input.oracle_home[key]

installation_violations contains violation if {
	input.oracle_inventory.exists
	not input.oracle_inventory.permissions
	violation := "CIS 1.1: evidence missing — oracle_inventory.permissions not collected"
}

installation_violations contains violation if {
	input.oracle_home.permissions
	not mode_within(input.oracle_home.permissions, "0755")
	violation := sprintf("CIS 1.1: ORACLE_HOME permissions %s are too permissive (should be 755 or stricter, or not parseable as an octal mode)", [
		input.oracle_home.permissions,
	])
}

installation_violations contains violation if {
	input.oracle_home.owner != "oracle"
	violation := sprintf("CIS 1.1: ORACLE_HOME owner is '%s' (should be 'oracle')", [
		input.oracle_home.owner,
	])
}

installation_violations contains violation if {
	not contains(input.oracle_home.group, "dba")
	not contains(input.oracle_home.group, "oinstall")
	violation := sprintf("CIS 1.1: ORACLE_HOME group is '%s' (should be 'dba' or 'oinstall')", [
		input.oracle_home.group,
	])
}

# =============================================================================
# ORACLE INVENTORY
# =============================================================================

installation_violations contains violation if {
	not input.oracle_inventory.exists
	violation := "CIS 1.1: Oracle inventory (oraInventory) does not exist or is not accessible"
}

installation_violations contains violation if {
	input.oracle_inventory.exists
	input.oracle_inventory.permissions
	not mode_within(input.oracle_inventory.permissions, "0755")
	violation := sprintf("CIS 1.1: Oracle inventory permissions %s are too permissive", [
		input.oracle_inventory.permissions,
	])
}

# =============================================================================
# REPORTING
# =============================================================================

report := {
	"compliant": compliant,
	"total_violations": count(violations),
	"violations": violations,
	"oracle_version": {
		"version": object.get(input, ["oracle_version", "version"], null),
		"supported": object.get(input, ["oracle_version", "supported"], null),
		"end_of_support": object.get(input, ["oracle_version", "end_of_support"], null),
	},
	"patch_status": {
		"last_patch_date": object.get(input, ["critical_patches", "last_patch_date"], null),
		"days_since_last_patch": object.get(input, ["critical_patches", "days_since_last_patch"], null),
		"critical_missing": object.get(input, ["critical_patches", "critical_missing"], null),
		"total_missing": count(object.get(input, ["critical_patches", "missing_patches"], [])),
	},
	"risk_level": risk_level,
	"collection_timestamp": object.get(input, ["collection_timestamp"], null),
}

risk_level := "critical" if {
	input.critical_patches.critical_missing > 0
} else := "critical" if {
	not input.oracle_version.supported
} else := "high" if {
	input.critical_patches.days_since_last_patch > 180
} else := "medium" if {
	count(object.get(input, ["critical_patches", "missing_patches"], [])) > 0
} else := "low"
