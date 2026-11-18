# METADATA
# title: "CMMC 2.0 — Configuration Management Domain (CM)"
# custom:
#   class: compliance
#   framework: cmmc
#   source: dod
#   domains: [us-federal, defense]
#   coverage:
#     checks: 22
#     cited: 9
#     density: sized
#     basis: size
#     tested: true
#     entrypoint: compliance_report
#     guard: self
#     as_of: v2.4.2
package cmmc.configuration_management

import rego.v1

# =============================================================================
# CMMC 2.0 — Configuration Management Domain (CM)
# Practices CM.L2-3.4.1 through CM.L2-3.4.9
#
# Input shape:
#   input.systems[]             - managed systems
#   input.configuration         - configuration management program
#   input.software              - software inventory and management
#   input.cmmc_level            - target maturity level
# =============================================================================

# Inventory iterated by 3.4.1, 3.4.2, 3.4.6 and 3.4.7: a non-empty array, or
# each of those practices gets an "evidence missing" finding.
_systems := s if {
	s := input.systems
	is_array(s)
	count(s) > 0
}

_name(x) := object.get(x, "name", "<unnamed>") if is_object(x)

else := "<not an object>"

_per_system_practices := {"3.4.1", "3.4.2", "3.4.6", "3.4.7"}

# CM.L2-3.4.1 — Establish baseline configurations
violation_cm_1 contains msg if {
	input.cmmc_level >= 2
	some system in _systems
	not system.baseline_configuration_documented
	msg := sprintf(
		"CMMC CM.L2-3.4.1: System '%v' has no documented baseline configuration. Baselines must be established for all CUI systems.",
		[system.name],
	)
}

# CM.L2-3.4.2 — Establish and enforce security configuration settings
violation_cm_2 contains msg if {
	input.cmmc_level >= 2
	some system in _systems
	not system.security_configuration_enforced
	msg := sprintf(
		"CMMC CM.L2-3.4.2: System '%v' does not enforce security configuration settings. STIGs or CIS Benchmarks must be applied.",
		[system.name],
	)
}

# CM.L2-3.4.3 — Track, review, approve/disapprove changes to systems
violation_cm_3 contains msg if {
	input.cmmc_level >= 2
	not input.configuration.change_control_process
	msg := "CMMC CM.L2-3.4.3: No change control process. All changes to CUI systems must go through an approval process."
}

violation_cm_3 contains msg if {
	input.cmmc_level >= 2
	not input.configuration.changes_reviewed_before_implementation
	msg := "CMMC CM.L2-3.4.3: Changes are not reviewed before implementation. Security impact analysis is required for all changes."
}

# CM.L2-3.4.4 — Analyze impact of changes prior to implementation
violation_cm_4 contains msg if {
	input.cmmc_level >= 2
	not input.configuration.security_impact_analysis
	msg := "CMMC CM.L2-3.4.4: No security impact analysis process. Changes must be analyzed for security impact before implementation."
}

# CM.L2-3.4.5 — Define, document, approve, and enforce access restrictions for change
violation_cm_5 contains msg if {
	input.cmmc_level >= 2
	not input.configuration.change_access_restricted
	msg := "CMMC CM.L2-3.4.5: Change access is not restricted. Only authorized personnel should be able to make changes to CUI systems."
}

# CM.L2-3.4.6 — Employ principle of least functionality
violation_cm_6 contains msg if {
	input.cmmc_level >= 2
	some system in _systems
	is_array(system.unnecessary_services)
	count(system.unnecessary_services) > 0
	msg := sprintf(
		"CMMC CM.L2-3.4.6: System '%v' has unnecessary services running: %v. Disable all non-essential services.",
		[system.name, system.unnecessary_services],
	)
}

violation_cm_6 contains msg if {
	input.cmmc_level >= 2
	some system in _systems
	not is_array(object.get(system, "unnecessary_services", null))
	msg := sprintf("CMMC CM.L2-3.4.6: evidence missing - system '%v' has no 'unnecessary_services' list; least functionality cannot be shown", [_name(system)])
}

# CM.L2-3.4.7 — Restrict, disable, or prevent the use of nonessential programs
violation_cm_7 contains msg if {
	input.cmmc_level >= 2
	not input.software.application_whitelist_enabled
	msg := "CMMC CM.L2-3.4.7: Application whitelisting is not enabled. Only authorized software should be permitted to execute."
}

violation_cm_7 contains msg if {
	input.cmmc_level >= 2
	some system in _systems
	is_array(system.unauthorized_software)
	count(system.unauthorized_software) > 0
	msg := sprintf(
		"CMMC CM.L2-3.4.7: Unauthorized software detected on '%v': %v. Remove or authorize these programs.",
		[system.name, system.unauthorized_software],
	)
}

violation_cm_7 contains msg if {
	input.cmmc_level >= 2
	some system in _systems
	not is_array(object.get(system, "unauthorized_software", null))
	msg := sprintf("CMMC CM.L2-3.4.7: evidence missing - system '%v' has no 'unauthorized_software' list; nonessential programs cannot be shown restricted", [_name(system)])
}

# CM.L2-3.4.8 — Apply deny-by-exception policy for software usage
violation_cm_8 contains msg if {
	input.cmmc_level >= 2
	not input.software.deny_by_default
	msg := "CMMC CM.L2-3.4.8: Software policy is allow-by-default. Implement deny-by-exception (whitelist approach) for software execution."
}

# CM.L2-3.4.9 — Control and monitor user-installed software
violation_cm_9 contains msg if {
	input.cmmc_level >= 2
	not input.software.user_install_controlled
	msg := "CMMC CM.L2-3.4.9: User-installed software is not controlled. Users must be prevented from installing unauthorized software."
}

_by_practice := {
	"3.4.1": violation_cm_1, "3.4.2": violation_cm_2, "3.4.3": violation_cm_3,
	"3.4.4": violation_cm_4, "3.4.5": violation_cm_5, "3.4.6": violation_cm_6,
	"3.4.7": violation_cm_7, "3.4.8": violation_cm_8, "3.4.9": violation_cm_9,
}

violations contains msg if {
	some vs in _by_practice
	some msg in vs
}

# Input contract: every CM practice is gated on cmmc_level >= 2. This finding
# names no practice (data.cmmc reports the missing level itself).
violations contains "CMMC CM input contract: FAIL-CLOSED - input.cmmc_level was not supplied; the configuration-management practices were not evaluated and the domain is reported non-compliant" if {
	not input.cmmc_level
}

# The per-system practices iterate input.systems; with no systems they never
# run, so an absent/empty inventory is a finding for each of them.
violations contains msg if {
	input.cmmc_level >= 2
	not _systems
	some id in _per_system_practices
	msg := sprintf("CMMC CM.L2-%v: evidence missing - input.systems not supplied, not an array or empty; per-system configuration checks cannot be evaluated", [id])
}

# fail-closed: non-empty violations (including the no-facts notice) make this false, never undefined
default compliant := false

compliant if count(violations) == 0

_ids := ["3.4.1", "3.4.2", "3.4.3", "3.4.4", "3.4.5", "3.4.6", "3.4.7", "3.4.8", "3.4.9"]

# A practice is decided only at Level 2 or above and fails on any finding naming it.
practices := [{"id": id, "level": 2, "compliant": _practice_ok(id)} | some id in _ids]

_practice_ok(id) if {
	input.cmmc_level >= 2
	count(_by_practice[id]) == 0
	not _inventory_missing(id)
}

else := false

_inventory_missing(id) if {
	id in _per_system_practices
	not _systems
}

compliance_report := {
	"domain": "Configuration Management (CM)",
	"cmmc_level": object.get(input, "cmmc_level", 0),
	"compliant": compliant,
	"violation_count": count(violations),
	"violations": violations,
	"practices": practices,
	"total_practices": count(practices),
	"passing": count([p | some p in practices; p.compliant == true]),
}
