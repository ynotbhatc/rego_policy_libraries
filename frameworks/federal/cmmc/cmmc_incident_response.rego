# METADATA
# title: "CMMC 2.0 — Incident Response Domain (IR)"
# custom:
#   class: compliance
#   framework: cmmc
#   source: dod
#   domains: [us-federal, defense]
#   coverage:
#     checks: 12
#     cited: 3
#     density: sized
#     basis: size
#     tested: true
#     entrypoint: compliance_report
#     guard: self
#     as_of: v2.5.0
package cmmc.incident_response

import rego.v1

# =============================================================================
# CMMC 2.0 — Incident Response Domain (IR)
# Practices IR.L2-3.6.1 through IR.L2-3.6.3
#
# Input shape:
#   input.incident_response     - IR program configuration
#   input.cmmc_level            - target maturity level
# =============================================================================

# A missing plan age fails closed: an undated plan cannot be shown to be current.
plan_reviewed_within(days) if input.incident_response.plan_age_days <= days

# IR.L2-3.6.1 — Establish an operational incident-handling capability
violation_ir_1 contains msg if {
	is_number(input.cmmc_level)
	input.cmmc_level >= 2
	not input.incident_response.plan_documented
	msg := "CMMC IR.L2-3.6.1: No documented incident response plan. An operational IR capability covering preparation, detection, containment, and recovery is required."
}

violation_ir_1 contains msg if {
	is_number(input.cmmc_level)
	input.cmmc_level >= 2
	input.incident_response.plan_documented
	not input.incident_response.plan_tested
	msg := "CMMC IR.L2-3.6.1: Incident response plan has not been tested. Plans must be exercised at least annually."
}

violation_ir_1 contains msg if {
	is_number(input.cmmc_level)
	input.cmmc_level >= 2
	input.incident_response.plan_documented
	not plan_reviewed_within(365)
	msg := sprintf(
		"CMMC IR.L2-3.6.1: Incident response plan is %v days old. Plans must be reviewed and updated annually.",
		[object.get(input.incident_response, "plan_age_days", "of unknown")],
	)
}

# IR.L2-3.6.2 — Track, document, and report incidents
violation_ir_2 contains msg if {
	is_number(input.cmmc_level)
	input.cmmc_level >= 2
	not input.incident_response.incident_tracking_system
	msg := "CMMC IR.L2-3.6.2: No incident tracking system. All incidents affecting CUI must be tracked and documented."
}

violation_ir_2 contains msg if {
	is_number(input.cmmc_level)
	input.cmmc_level >= 2
	not input.incident_response.reporting_to_dod_required_when_applicable
	msg := "CMMC IR.L2-3.6.2: DoD incident reporting procedure not defined. CUI incidents must be reported to appropriate authorities within 72 hours."
}

# IR.L2-3.6.3 — Test the organizational incident response capability
violation_ir_3 contains msg if {
	is_number(input.cmmc_level)
	input.cmmc_level >= 2
	not input.incident_response.tabletop_exercise_completed
	msg := "CMMC IR.L2-3.6.3: No tabletop exercise completed. Incident response capability must be tested through exercises."
}

_by_practice := {"3.6.1": violation_ir_1, "3.6.2": violation_ir_2, "3.6.3": violation_ir_3}

violations contains msg if {
	some vs in _by_practice
	some msg in vs
}

# Fail-closed: without the facts this module keys on, it reports a violation rather than silence.
# Every IR practice is gated on cmmc_level >= 2; without the level nothing runs.
# This finding names no practice (data.cmmc reports the missing level itself).
violations contains "CMMC IR input contract: FAIL-CLOSED - input.cmmc_level was not supplied or is not a number (evidence missing); the incident-response practices were not evaluated and the domain is reported non-compliant" if {
	not is_number(object.get(input, "cmmc_level", null))
}

violations contains msg if {
	not is_object(object.get(input, "incident_response", null))
	some id in ["3.6.1", "3.6.2", "3.6.3"]
	msg := sprintf("CMMC IR.L2-%v: evidence missing - input.incident_response not supplied (or not an object); this practice cannot be evaluated", [id])
}

# fail-closed: non-empty violations (including the no-facts notice) make this false, never undefined
default compliant := false

compliant if count(violations) == 0

_ids := ["3.6.1", "3.6.2", "3.6.3"]

practices := [{"id": id, "level": 2, "compliant": _practice_ok(id)} | some id in _ids]

_practice_ok(id) if {
	is_number(input.cmmc_level)
	input.cmmc_level >= 2
	is_object(object.get(input, "incident_response", null))
	count(_by_practice[id]) == 0
}

else := false

compliance_report := {
	"domain": "Incident Response (IR)",
	"cmmc_level": object.get(input, "cmmc_level", 0),
	"compliant": compliant,
	"violation_count": count(violations),
	"violations": violations,
	"practices": practices,
	"total_practices": count(practices),
	"passing": count([p | some p in practices; p.compliant == true]),
}
