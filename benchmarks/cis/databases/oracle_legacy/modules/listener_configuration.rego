# METADATA
# title: "CIS Oracle Database 19c Benchmark - Section 2.1"
# custom:
#   class: security
#   framework: cis_databases
#   source: cis
#   domains: [database, oracle]
#   coverage:
#     checks: 16
#     cited: 8
#     density: sized
#     basis: size
#     tested: true
#     entrypoint: report
#     guard: self
#     as_of: v2.4.2
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
# EVIDENCE: at least one listener must be reported
# =============================================================================

listeners_present if count(input.listeners) > 0

listener_violations contains violation if {
	not listeners_present
	violation := "CIS 2.1: evidence missing — listeners not collected"
}

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

# A listener without the setting is not compliant (absent field must not pass)
admin_on(listener) if listener.admin_restrictions == "ON"

# =============================================================================
# CIS 2.1.2 - ENSURE 'ADMIN_RESTRICTIONS' IS SET TO 'ON'
# =============================================================================

listener_violations contains violation if {
	some listener in input.listeners
	not admin_on(listener)
	violation := sprintf("CIS 2.1.2: Listener '%s' has ADMIN_RESTRICTIONS_%s=%s (should be 'ON')", [
		listener.name,
		listener.name,
		object.get(listener, "admin_restrictions", "<not set>"),
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
	violation := sprintf("CIS 2.1.5: Listener '%s' is using insecure protocol '%s'", [
		listener.name,
		listener.secure_protocol,
	])
}

listener_violations contains violation if {
	some listener in input.listeners
	not listener.secure_protocol
	violation := sprintf("CIS 2.1.5: Listener '%s' evidence missing — secure_protocol not collected", [
		listener.name,
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

# Parse an octal permission string ("644", "0644", "0o644") to an integer; undefined if not octal.
octal(s) := n if {
	t := trim_prefix(lower(trim_space(sprintf("%v", [s]))), "0o")
	regex.match(`^[0-7]{1,4}$`, t)
	p := concat("", [substring("0000", 0, 4 - count(t)), t])
	ds := [to_number(substring(p, i, 1)) | some i in numbers.range(0, 3)]
	n := ((ds[0] * 512) + (ds[1] * 64)) + ((ds[2] * 8) + ds[3])
}

# true when mode grants nothing beyond max (both octal strings)
mode_within(mode, max) if bits.and(octal(mode), bits.and(bits.negate(octal(max)), 4095)) == 0

listener_violations contains violation if {
	input.listener_ora.file_permissions
	not mode_within(input.listener_ora.file_permissions, "0640")
	violation := sprintf("CIS 2.1: listener.ora has insecure permissions %s (should be 640 or stricter)", [
		input.listener_ora.file_permissions,
	])
}

listener_violations contains violation if {
	some key in ["file_permissions", "owner"]
	not listener_ora_has(key)
	violation := sprintf("CIS 2.1: evidence missing — listener_ora.%s not collected", [key])
}

listener_ora_has(key) if input.listener_ora[key]

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
		"total_listeners": count(object.get(input, ["listeners"], [])),
		"extproc_enabled": count([l | some l in object.get(input, ["listeners"], []); some s in l.services; contains(lower(s), "extproc")]),
		"admin_restrictions_off": count([l | some l in object.get(input, ["listeners"], []); not admin_on(l)]),
		"using_default_port": count([l | some l in object.get(input, ["listeners"], []); l.port == 1521]),
		"not_password_protected": count([l | some l in object.get(input, ["listeners"], []); l.password_protected == false]),
	},
	"risk_level": risk_level,
	"collection_timestamp": object.get(input, ["collection_timestamp"], null),
}

risk_level := "critical" if {
	some listener in input.listeners
	some service in listener.services
	contains(lower(service), "extproc")
} else := "high" if {
	count([l | some l in input.listeners; not admin_on(l)]) > 0
} else := "medium" if {
	count(violations) > 0
} else := "low"
