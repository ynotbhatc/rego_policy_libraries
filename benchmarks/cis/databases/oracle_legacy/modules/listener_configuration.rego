package cis_oracle.listener_configuration

# CIS Oracle Database 19c Benchmark - Section 2.1
# Listener Configuration
# Validates Oracle listener security settings

import rego.v1

# =============================================================================
# MAIN COMPLIANCE RULES
# =============================================================================

default compliant := false

compliant if {
	count(violations) == 0
}

violations := [v | some v in listener_violations]

# =============================================================================
# CIS 2.1.1 - ENSURE 'EXTPROC' IS NOT PRESENT IN LISTENER.ORA
# =============================================================================

listener_violations contains violation if {
	some listener in input.listeners
	some service in listener.services
	contains(lower(service), "extproc")
	violation := sprintf("CIS 2.1.1: Listener '%s' has 'extproc' service enabled (CRITICAL: allows arbitrary code execution)", [
		listener.name,
	])
}

listener_violations contains violation if {
	input.listener_ora.contains_extproc
	violation := "CIS 2.1.1: EXTPROC is present in listener.ora (should be removed)"
}

# =============================================================================
# CIS 2.1.2 - ENSURE 'ADMIN_RESTRICTIONS' IS SET TO 'ON'
# =============================================================================

listener_violations contains violation if {
	some listener in input.listeners
	listener.admin_restrictions != "ON"
	violation := sprintf("CIS 2.1.2: Listener '%s' has ADMIN_RESTRICTIONS_%s=%s (should be 'ON')", [
		listener.name,
		listener.name,
		listener.admin_restrictions,
	])
}

listener_violations contains violation if {
	not input.listener_ora.admin_restrictions_enabled
	violation := "CIS 2.1.2: ADMIN_RESTRICTIONS is not set to ON in listener.ora"
}

# =============================================================================
# CIS 2.1.3 - ENSURE LISTENER LOGGING IS CONFIGURED
# =============================================================================

listener_violations contains violation if {
	some listener in input.listeners
	not listener.logging_enabled
	violation := sprintf("CIS 2.1.3: Listener '%s' does not have logging enabled", [
		listener.name,
	])
}

listener_violations contains violation if {
	some listener in input.listeners
	listener.logging_enabled
	listener.log_directory == ""
	violation := sprintf("CIS 2.1.3: Listener '%s' logging directory is not configured", [
		listener.name,
	])
}

# =============================================================================
# CIS 2.1.4 - ENSURE LISTENER IS NOT USING DEFAULT PORT
# =============================================================================

listener_violations contains violation if {
	some listener in input.listeners
	listener.port == 1521
	violation := sprintf("CIS 2.1.4: Listener '%s' is using default port 1521 (security through obscurity)", [
		listener.name,
	])
}

# =============================================================================
# CIS 2.1.5 - ENSURE LISTENER SECURITY SETTINGS
# =============================================================================

listener_violations contains violation if {
	some listener in input.listeners
	listener.password_protected == false
	violation := sprintf("CIS 2.1.5: Listener '%s' is not password protected", [
		listener.name,
	])
}

listener_violations contains violation if {
	some listener in input.listeners
	listener.secure_protocol != "TCPS"
	listener.secure_protocol != "TCP"
	violation := sprintf("CIS 2.1.5: Listener '%s' is using insecure protocol '%s'", [
		listener.name,
		listener.secure_protocol,
	])
}

# =============================================================================
# CIS 2.1.6 - ENSURE VALID_NODE_CHECKING IS ENABLED
# =============================================================================

listener_violations contains violation if {
	some listener in input.listeners
	listener.valid_node_checking_enabled == false
	violation := sprintf("CIS 2.1.6: Listener '%s' does not have VALID_NODE_CHECKING enabled", [
		listener.name,
	])
}

# =============================================================================
# LISTENER FILE PERMISSIONS
# =============================================================================

listener_violations contains violation if {
	input.listener_ora.file_permissions
	not regex.match("^[0-6][0-4][0-0]$", input.listener_ora.file_permissions)
	violation := sprintf("CIS 2.1: listener.ora has insecure permissions %s (should be 640 or stricter)", [
		input.listener_ora.file_permissions,
	])
}

listener_violations contains violation if {
	input.listener_ora.owner != "oracle"
	violation := sprintf("CIS 2.1: listener.ora owner is '%s' (should be 'oracle')", [
		input.listener_ora.owner,
	])
}

# =============================================================================
# REPORTING
# =============================================================================

report := {
	"compliant": compliant,
	"total_violations": count(violations),
	"violations": violations,
	"listener_summary": {
		"total_listeners": count(input.listeners),
		"extproc_enabled": count([l | some l in input.listeners; some s in l.services; contains(lower(s), "extproc")]),
		"admin_restrictions_off": count([l | some l in input.listeners; l.admin_restrictions != "ON"]),
		"using_default_port": count([l | some l in input.listeners; l.port == 1521]),
		"not_password_protected": count([l | some l in input.listeners; l.password_protected == false]),
	},
	"risk_level": risk_level,
	"collection_timestamp": input.collection_timestamp,
}

risk_level := "critical" if {
	some listener in input.listeners
	some service in listener.services
	contains(lower(service), "extproc")
} else := "high" if {
	count([l | some l in input.listeners; l.admin_restrictions != "ON"]) > 0
} else := "medium" if {
	count(violations) > 0
} else := "low"
