# METADATA
# title: "CMMC 2.0 — Domain 3.7: Maintenance"
# custom:
#   class: compliance
#   framework: cmmc
#   source: dod
#   domains: [us-federal, defense]
#   coverage:
#     checks: 22
#     cited: 6
#     density: sized
#     basis: size
#     tested: true
#     entrypoint: compliance_report
#     guard: self
#     as_of: v2.5.0
package cmmc.maintenance

import rego.v1

# =============================================================================
# CMMC 2.0 — Domain 3.7: Maintenance
# NIST SP 800-171 Rev 2 — 6 Practices
# =============================================================================

# 3.7.1 — Perform maintenance on organizational systems. (L2)
default compliant_3_7_1 := false

compliant_3_7_1 if {
	input.maintenance.maintenance_policy_exists == true
	input.maintenance.scheduled_maintenance == true
	input.maintenance.maintenance_records_kept == true
}

violation_3_7_1 contains msg if {
	not input.maintenance.maintenance_policy_exists == true
	finding := "3.7.1: No documented maintenance policy for organizational systems"
	msg := concat("", [finding, _ev_input("maintenance.maintenance_policy_exists")])
}

violation_3_7_1 contains msg if {
	not input.maintenance.scheduled_maintenance == true
	finding := "3.7.1: System maintenance is not performed on a scheduled basis"
	msg := concat("", [finding, _ev_input("maintenance.scheduled_maintenance")])
}

violation_3_7_1 contains msg if {
	not input.maintenance.maintenance_records_kept == true
	finding := "3.7.1: Maintenance activities are not recorded and retained"
	msg := concat("", [finding, _ev_input("maintenance.maintenance_records_kept")])
}

# 3.7.2 — Provide controls on the tools, techniques, mechanisms, and personnel
#          that perform maintenance. (L2)
default compliant_3_7_2 := false

compliant_3_7_2 if {
	input.maintenance.maintenance_personnel_authorized == true
	input.maintenance.remote_maintenance_controlled == true
	input.maintenance.maintenance_tools_approved == true
}

violation_3_7_2 contains msg if {
	not input.maintenance.maintenance_personnel_authorized == true
	finding := "3.7.2: Maintenance personnel are not formally authorized and vetted"
	msg := concat("", [finding, _ev_input("maintenance.maintenance_personnel_authorized")])
}

violation_3_7_2 contains msg if {
	not input.maintenance.remote_maintenance_controlled == true
	finding := "3.7.2: Remote maintenance access is not controlled or monitored"
	msg := concat("", [finding, _ev_input("maintenance.remote_maintenance_controlled")])
}

violation_3_7_2 contains msg if {
	not input.maintenance.maintenance_tools_approved == true
	finding := "3.7.2: Maintenance tools are not reviewed and approved prior to use"
	msg := concat("", [finding, _ev_input("maintenance.maintenance_tools_approved")])
}

# 3.7.3 — Ensure equipment removed for maintenance is sanitized. (L2)
default compliant_3_7_3 := false

compliant_3_7_3 if {
	input.maintenance.equipment_sanitization_procedure == true
	input.maintenance.removal_authorization_required == true
}

violation_3_7_3 contains msg if {
	not input.maintenance.equipment_sanitization_procedure == true
	finding := "3.7.3: No procedure for sanitizing equipment removed for off-site maintenance"
	msg := concat("", [finding, _ev_input("maintenance.equipment_sanitization_procedure")])
}

violation_3_7_3 contains msg if {
	not input.maintenance.removal_authorization_required == true
	finding := "3.7.3: Equipment removal for maintenance does not require authorization"
	msg := concat("", [finding, _ev_input("maintenance.removal_authorization_required")])
}

# 3.7.4 — Check media containing diagnostic and test programs for malicious
#          code before use. (L2)
default compliant_3_7_4 := false

compliant_3_7_4 if {
	input.maintenance.media_scanning_before_use == true
	input.maintenance.diagnostic_media_controlled == true
}

violation_3_7_4 contains msg if {
	not input.maintenance.media_scanning_before_use == true
	finding := "3.7.4: Diagnostic/test media is not scanned for malicious code before use"
	msg := concat("", [finding, _ev_input("maintenance.media_scanning_before_use")])
}

violation_3_7_4 contains msg if {
	not input.maintenance.diagnostic_media_controlled == true
	finding := "3.7.4: Diagnostic and test program media is not controlled"
	msg := concat("", [finding, _ev_input("maintenance.diagnostic_media_controlled")])
}

# 3.7.5 — Require MFA to establish nonlocal maintenance sessions via external
#          networks and terminate connections when sessions are complete. (L2)
default compliant_3_7_5 := false

compliant_3_7_5 if {
	input.maintenance.remote_maintenance_mfa == true
	input.maintenance.remote_session_auto_terminate == true
	input.maintenance.remote_maintenance_encrypted == true
}

violation_3_7_5 contains msg if {
	not input.maintenance.remote_maintenance_mfa == true
	finding := "3.7.5: MFA is not required for remote/nonlocal maintenance sessions"
	msg := concat("", [finding, _ev_input("maintenance.remote_maintenance_mfa")])
}

violation_3_7_5 contains msg if {
	not input.maintenance.remote_session_auto_terminate == true
	finding := "3.7.5: Remote maintenance sessions are not terminated when complete"
	msg := concat("", [finding, _ev_input("maintenance.remote_session_auto_terminate")])
}

violation_3_7_5 contains msg if {
	not input.maintenance.remote_maintenance_encrypted == true
	finding := "3.7.5: Remote maintenance connections are not encrypted"
	msg := concat("", [finding, _ev_input("maintenance.remote_maintenance_encrypted")])
}

# 3.7.6 — Supervise the maintenance activities of personnel without required
#          access authorization. (L2)
default compliant_3_7_6 := false

compliant_3_7_6 if {
	input.maintenance.unauthorized_personnel_supervised == true
	input.maintenance.escort_required_for_visitors == true
}

violation_3_7_6 contains msg if {
	not input.maintenance.unauthorized_personnel_supervised == true
	finding := "3.7.6: Maintenance personnel without access authorization are not supervised"
	msg := concat("", [finding, _ev_input("maintenance.unauthorized_personnel_supervised")])
}

violation_3_7_6 contains msg if {
	not input.maintenance.escort_required_for_visitors == true
	finding := "3.7.6: Escort is not required for maintenance personnel in CUI areas"
	msg := concat("", [finding, _ev_input("maintenance.escort_required_for_visitors")])
}

# ---------------------------------------------------------------------------
# Aggregate
# ---------------------------------------------------------------------------

base_violations := array.concat(
	array.concat(
		[v | some v in violation_3_7_1],
		[v | some v in violation_3_7_2],
	),
	array.concat(
		array.concat(
			[v | some v in violation_3_7_3],
			[v | some v in violation_3_7_4],
		),
		array.concat(
			[v | some v in violation_3_7_5],
			[v | some v in violation_3_7_6],
		),
	),
)

practices := [
	{"id": "3.7.1", "level": 2, "compliant": compliant_3_7_1},
	{"id": "3.7.2", "level": 2, "compliant": compliant_3_7_2},
	{"id": "3.7.3", "level": 2, "compliant": compliant_3_7_3},
	{"id": "3.7.4", "level": 2, "compliant": compliant_3_7_4},
	{"id": "3.7.5", "level": 2, "compliant": compliant_3_7_5},
	{"id": "3.7.6", "level": 2, "compliant": compliant_3_7_6},
]

# ---------------------------------------------------------------------------
# Unmet practices without a specific finding (fail closed)
#   A practice whose compliant_N rule is false because a required fact is
#   missing must surface a violation, so the domain verdict can never be true
#   while a practice fails.
# ---------------------------------------------------------------------------

violation_unmet contains msg if {
	some p in practices
	not p.compliant == true
	count([v | some v in base_violations; startswith(v, sprintf("%v:", [p.id]))]) == 0
	msg := sprintf("%v: evidence missing or requirement not met — all facts required by this practice must be present and passing", [p.id])
}

all_violations := array.concat(base_violations, sort(violation_unmet))

passing_count := count([p | some p in practices; p.compliant == true])

default compliant := false

compliant if count(all_violations) == 0

compliance_report := {
	"domain": "Maintenance",
	"domain_id": "3.7",
	"total_practices": 6,
	"passing": passing_count,
	"failing": 6 - passing_count,
	"compliant": compliant,
	"violations": all_violations,
	"practices": practices,
}

# ---------------------------------------------------------------------------
# Evidence rule: only the boolean true passes a yes/no fact. A fact that is
# absent, null or not a boolean fails its check, and the finding names the
# evidence problem.
# ---------------------------------------------------------------------------

default _facts := {}

_facts := input

_evidence_note(value, name) := "" if {
	is_boolean(value)
} else := sprintf(" (evidence missing: %s not collected)", [name]) if {
	value == null
} else := sprintf(" (evidence invalid: %s is not a boolean, got %s)", [name, type_name(value)])

_ev_input(path) := _evidence_note(object.get(_facts, split(path, "."), null), concat(".", ["input", path]))

_ev_item(item, path) := _evidence_note(object.get(item, split(path, "."), null), path) if {
	is_object(item)
} else := sprintf(" (evidence invalid: item is not an object, got %s; %s not collected)", [type_name(item), path])
