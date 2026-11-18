# METADATA
# title: "NIST SP 800-53 Rev 5 — Physical and Environmental Protection (PE) Family"
# custom:
#   class: compliance
#   framework: nist_sp_800_53
#   source: nist
#   domains: [us-federal, security-controls]
#   coverage:
#     checks: 28
#     cited: 22
#     density: sized
#     basis: size
#     tested: true
#     entrypoint: compliance_report
#     guard: self
#     as_of: v2.5.0
package nist.sp800_53.physical_environmental

import rego.v1

# NIST SP 800-53 Rev 5 — Physical and Environmental Protection (PE) Family, base controls PE-1 to PE-23 (PE-7 withdrawn) (no enhancements).
# Facts live under input.pe_controls. Every control fails closed: a fact that is missing or of the wrong type is
# reported as missing evidence. Booleans pass only on true; numbers are checked with is_number before comparing.

default compliant := false

# ---------------------------------------------------------------------------------------------------------------
# Helpers. Paths are dotted and relative to input.pe_controls.
# ---------------------------------------------------------------------------------------------------------------

_get(path) := object.get(input, array.concat(["pe_controls"], split(path, ".")), null)

_path(p) := concat("", ["input.pe_controls.", p])

# Required booleans that are absent or not a boolean ("true", 1 and null are not evidence).
_bool_missing(paths) := {_path(p) |
	some p in paths
	not is_boolean(_get(p))
}

# Required booleans that are present and false.
_bool_false(paths) := {sprintf("%s is false", [_path(p)]) |
	some p in paths
	_get(p) == false
}

# Organization-defined frequency (IR-2/IR-3 shape): <base>.days_since_last against <base>.odp.frequency_days.
_freq_missing(base) := {_path(concat(".", [base, k])) |
	some k in ["days_since_last", "odp.frequency_days"]
	not is_number(_get(concat(".", [base, k])))
}

_overdue(base, what) := msg if {
	obs := _get(concat(".", [base, "days_since_last"]))
	odp := _get(concat(".", [base, "odp.frequency_days"]))
	is_number(obs)
	is_number(odp)
	obs > odp
	msg := sprintf("%s last done %v days ago; the organization-defined frequency is %v days", [what, obs, odp])
}

# Organizational controls with no machine-checkable evidence: {"attested": true, "by": "...", "date": "..."}.
_attested(name) if {
	a := _get(concat(".", [name, "attestation"]))
	a.attested == true
	is_string(a.by)
	trim_space(a.by) != ""
	is_string(a.date)
	trim_space(a.date) != ""
}

_missing_msg(id, paths) := sprintf("NIST %s: evidence missing — %s not collected", [id, concat(", ", sort(paths))])

# ---------------------------------------------------------------------------------------------------------------
# PE-1 Policy and Procedures
# Facts: policy.documented, procedures.documented, policy.official_designated (booleans);
#        policy.review.days_since_last + policy.review.odp.frequency_days;
#        procedures.review.days_since_last + procedures.review.odp.frequency_days.
# One finding listing every unmet element.
# ---------------------------------------------------------------------------------------------------------------

_pe1_bools := ["policy.documented", "procedures.documented", "policy.official_designated"]

_pe1_missing := (_bool_missing(_pe1_bools) | _freq_missing("policy.review")) | _freq_missing("procedures.review")

_pe1_overdue := {m | m := _overdue("policy.review", "Policy review")} | {m | m := _overdue("procedures.review", "Procedures review")}

_pe1_unmet := ({sprintf("evidence missing: %s not collected", [p]) | some p in _pe1_missing} | _bool_false(_pe1_bools)) | _pe1_overdue

violation contains msg if {
	count(_pe1_unmet) > 0
	msg := sprintf("NIST PE-1: Physical and environmental protection policy and procedures requirements not met — %s", [concat("; ", sort(_pe1_unmet))])
}

# ---------------------------------------------------------------------------------------------------------------
# PE-2 Physical Access Authorizations
# Facts: physical_access_authorizations.access_list_approved_and_maintained, .credentials_issued,
#        .removed_when_no_longer_required (booleans); physical_access_authorizations.access_list_review
#        .days_since_last + .access_list_review.odp.frequency_days (review of the facility access list).
# ---------------------------------------------------------------------------------------------------------------

_pe2_bools := [
	"physical_access_authorizations.access_list_approved_and_maintained",
	"physical_access_authorizations.credentials_issued",
	"physical_access_authorizations.removed_when_no_longer_required",
]

_pe2_missing := _bool_missing(_pe2_bools) | _freq_missing("physical_access_authorizations.access_list_review")

violation contains msg if {
	count(_pe2_missing) > 0
	msg := _missing_msg("PE-2", _pe2_missing)
}

violation contains msg if {
	count(_pe2_missing) == 0
	failed := _bool_false(_pe2_bools) | {m | m := _overdue("physical_access_authorizations.access_list_review", "Facility access list review")}
	count(failed) > 0
	msg := sprintf("NIST PE-2: Physical access authorizations not maintained and reviewed — %s", [concat("; ", sort(failed))])
}

# ---------------------------------------------------------------------------------------------------------------
# PE-3 Physical Access Control
# Facts (booleans) under physical_access_control: authorizations_verified_at_entry, ingress_egress_controlled,
#   audit_logs_maintained, public_areas_controlled, visitors_escorted_and_monitored, access_devices_secured;
#   physical_access_control.device_inventory.days_since_last + .device_inventory.odp.frequency_days (inventory of
#   physical access devices); physical_access_control.key_change.days_since_last + .key_change.odp.frequency_days
#   (change of combinations and keys). The event-driven key change (lost keys, transfers) is not evaluated.
# ---------------------------------------------------------------------------------------------------------------

_pe3_bools := [
	"physical_access_control.authorizations_verified_at_entry",
	"physical_access_control.ingress_egress_controlled",
	"physical_access_control.audit_logs_maintained",
	"physical_access_control.public_areas_controlled",
	"physical_access_control.visitors_escorted_and_monitored",
	"physical_access_control.access_devices_secured",
]

_pe3_missing := (_bool_missing(_pe3_bools) | _freq_missing("physical_access_control.device_inventory")) | _freq_missing("physical_access_control.key_change")

_pe3_overdue := {m | m := _overdue("physical_access_control.device_inventory", "Physical access device inventory")} | {m | m := _overdue("physical_access_control.key_change", "Change of combinations and keys")}

violation contains msg if {
	count(_pe3_missing) > 0
	msg := _missing_msg("PE-3", _pe3_missing)
}

violation contains msg if {
	count(_pe3_missing) == 0
	failed := _bool_false(_pe3_bools) | _pe3_overdue
	count(failed) > 0
	msg := sprintf("NIST PE-3: Physical access control not enforced — %s", [concat("; ", sort(failed))])
}

# ---------------------------------------------------------------------------------------------------------------
# PE-6 Monitoring Physical Access
# Facts: monitoring_physical_access.access_monitored, .results_coordinated_with_incident_response (booleans);
#        monitoring_physical_access.log_review.days_since_last + .log_review.odp.frequency_days (review of
#        physical access logs). Event-triggered reviews are not evaluated.
# ---------------------------------------------------------------------------------------------------------------

_pe6_bools := [
	"monitoring_physical_access.access_monitored",
	"monitoring_physical_access.results_coordinated_with_incident_response",
]

_pe6_missing := _bool_missing(_pe6_bools) | _freq_missing("monitoring_physical_access.log_review")

violation contains msg if {
	count(_pe6_missing) > 0
	msg := _missing_msg("PE-6", _pe6_missing)
}

violation contains msg if {
	count(_pe6_missing) == 0
	failed := _bool_false(_pe6_bools) | {m | m := _overdue("monitoring_physical_access.log_review", "Physical access log review")}
	count(failed) > 0
	msg := sprintf("NIST PE-6: Physical access not monitored and reviewed — %s", [concat("; ", sort(failed))])
}

# ---------------------------------------------------------------------------------------------------------------
# PE-8 Visitor Access Records
# Facts: visitor_access_records.retention_days against visitor_access_records.odp.retention_days (records kept
#        for less than the organization-defined period is a finding); visitor_access_records.review
#        .days_since_last + .review.odp.frequency_days; visitor_access_records.anomalies_reported (boolean).
# ---------------------------------------------------------------------------------------------------------------

_pe8_kept := _get("visitor_access_records.retention_days")

_pe8_odp := _get("visitor_access_records.odp.retention_days")

_pe8_missing := (({_path("visitor_access_records.retention_days") | not is_number(_pe8_kept)} | {_path("visitor_access_records.odp.retention_days") | not is_number(_pe8_odp)}) | _freq_missing("visitor_access_records.review")) | _bool_missing(["visitor_access_records.anomalies_reported"])

violation contains msg if {
	count(_pe8_missing) > 0
	msg := _missing_msg("PE-8", _pe8_missing)
}

violation contains msg if {
	count(_pe8_missing) == 0
	short := {sprintf("visitor records kept %v days; the organization-defined period is %v days", [_pe8_kept, _pe8_odp]) | _pe8_kept < _pe8_odp}
	failed := (short | {m | m := _overdue("visitor_access_records.review", "Visitor access record review")}) | _bool_false(["visitor_access_records.anomalies_reported"])
	count(failed) > 0
	msg := sprintf("NIST PE-8: Visitor access records not kept, reviewed or acted on — %s", [concat("; ", sort(failed))])
}

# ---------------------------------------------------------------------------------------------------------------
# PE-11 Emergency Power
# Facts (booleans) under emergency_power: ups_provided (an uninterruptible power supply serves the system),
#   supports_odp_action (its capacity covers the organization-defined orderly shutdown or transition to
#   long-term alternate power). The long-term alternate power supply itself is an enhancement, not evaluated.
# ---------------------------------------------------------------------------------------------------------------

_pe11_bools := ["emergency_power.ups_provided", "emergency_power.supports_odp_action"]

_pe11_missing := _bool_missing(_pe11_bools)

violation contains msg if {
	count(_pe11_missing) > 0
	msg := _missing_msg("PE-11", _pe11_missing)
}

violation contains msg if {
	count(_pe11_missing) == 0
	failed := _bool_false(_pe11_bools)
	count(failed) > 0
	msg := sprintf("NIST PE-11: Uninterruptible power supply not adequate — %s", [concat("; ", sort(failed))])
}

# ---------------------------------------------------------------------------------------------------------------
# PE-14 Environmental Controls
# Facts: environmental_controls.levels_within_odp (boolean: temperature, humidity or other organization-defined
#        levels are held at the organization-defined acceptable levels); environmental_controls.monitoring
#        .days_since_last + .monitoring.odp.frequency_days (monitoring of the levels).
# ---------------------------------------------------------------------------------------------------------------

_pe14_bools := ["environmental_controls.levels_within_odp"]

_pe14_missing := _bool_missing(_pe14_bools) | _freq_missing("environmental_controls.monitoring")

violation contains msg if {
	count(_pe14_missing) > 0
	msg := _missing_msg("PE-14", _pe14_missing)
}

violation contains msg if {
	count(_pe14_missing) == 0
	failed := _bool_false(_pe14_bools) | {m | m := _overdue("environmental_controls.monitoring", "Environmental level monitoring")}
	count(failed) > 0
	msg := sprintf("NIST PE-14: Environmental controls not maintained or monitored — %s", [concat("; ", sort(failed))])
}

# ---------------------------------------------------------------------------------------------------------------
# PE-4 Access Control for Transmission — organizational control, no machine-checkable evidence.
# Facts: transmission_access.attestation {"attested": true, "by": <name>, "date": <date>}.
# ---------------------------------------------------------------------------------------------------------------

violation contains msg if {
	not _attested("transmission_access")
	msg := "NIST PE-4: Physical access control over system distribution and transmission lines not attested — input.pe_controls.transmission_access.attestation needs attested: true, by and date (organizational control, no machine-checkable evidence)"
}

# ---------------------------------------------------------------------------------------------------------------
# PE-5 Access Control for Output Devices — organizational control, no machine-checkable evidence.
# Facts: output_devices.attestation {"attested": true, "by": <name>, "date": <date>}.
# ---------------------------------------------------------------------------------------------------------------

violation contains msg if {
	not _attested("output_devices")
	msg := "NIST PE-5: Physical access control over output from the organization-defined output devices not attested — input.pe_controls.output_devices.attestation needs attested: true, by and date (organizational control, no machine-checkable evidence)"
}

# ---------------------------------------------------------------------------------------------------------------
# PE-9 Power Equipment and Cabling — organizational control, no machine-checkable evidence.
# Facts: power_equipment.attestation {"attested": true, "by": <name>, "date": <date>}.
# ---------------------------------------------------------------------------------------------------------------

violation contains msg if {
	not _attested("power_equipment")
	msg := "NIST PE-9: Protection of power equipment and power cabling from damage and destruction not attested — input.pe_controls.power_equipment.attestation needs attested: true, by and date (organizational control, no machine-checkable evidence)"
}

# ---------------------------------------------------------------------------------------------------------------
# PE-10 Emergency Shutoff — organizational control, no machine-checkable evidence.
# Facts: emergency_shutoff.attestation {"attested": true, "by": <name>, "date": <date>}.
# ---------------------------------------------------------------------------------------------------------------

violation contains msg if {
	not _attested("emergency_shutoff")
	msg := "NIST PE-10: Emergency power shutoff capability, its placement and its protection from unauthorized activation not attested — input.pe_controls.emergency_shutoff.attestation needs attested: true, by and date (organizational control, no machine-checkable evidence)"
}

# ---------------------------------------------------------------------------------------------------------------
# PE-12 Emergency Lighting — organizational control, no machine-checkable evidence.
# Facts: emergency_lighting.attestation {"attested": true, "by": <name>, "date": <date>}.
# ---------------------------------------------------------------------------------------------------------------

violation contains msg if {
	not _attested("emergency_lighting")
	msg := "NIST PE-12: Automatic emergency lighting covering emergency exits and evacuation routes not attested — input.pe_controls.emergency_lighting.attestation needs attested: true, by and date (organizational control, no machine-checkable evidence)"
}

# ---------------------------------------------------------------------------------------------------------------
# PE-13 Fire Protection — organizational control, no machine-checkable evidence.
# Facts: fire_protection.attestation {"attested": true, "by": <name>, "date": <date>}.
# ---------------------------------------------------------------------------------------------------------------

violation contains msg if {
	not _attested("fire_protection")
	msg := "NIST PE-13: Fire detection and suppression systems supported by an independent energy source not attested — input.pe_controls.fire_protection.attestation needs attested: true, by and date (organizational control, no machine-checkable evidence)"
}

# ---------------------------------------------------------------------------------------------------------------
# PE-15 Water Damage Protection — organizational control, no machine-checkable evidence.
# Facts: water_damage_protection.attestation {"attested": true, "by": <name>, "date": <date>}.
# ---------------------------------------------------------------------------------------------------------------

violation contains msg if {
	not _attested("water_damage_protection")
	msg := "NIST PE-15: Accessible, working master shutoff or isolation valves known to key personnel not attested — input.pe_controls.water_damage_protection.attestation needs attested: true, by and date (organizational control, no machine-checkable evidence)"
}

# ---------------------------------------------------------------------------------------------------------------
# PE-16 Delivery and Removal — organizational control, no machine-checkable evidence.
# Facts: delivery_removal.attestation {"attested": true, "by": <name>, "date": <date>}.
# ---------------------------------------------------------------------------------------------------------------

violation contains msg if {
	not _attested("delivery_removal")
	msg := "NIST PE-16: Authorization and control of system components entering and exiting the facility, with records not attested — input.pe_controls.delivery_removal.attestation needs attested: true, by and date (organizational control, no machine-checkable evidence)"
}

# ---------------------------------------------------------------------------------------------------------------
# PE-17 Alternate Work Site — organizational control, no machine-checkable evidence.
# Facts: alternate_work_site.attestation {"attested": true, "by": <name>, "date": <date>}.
# ---------------------------------------------------------------------------------------------------------------

violation contains msg if {
	not _attested("alternate_work_site")
	msg := "NIST PE-17: Alternate work sites determined, their controls employed and assessed, and incident communication provided not attested — input.pe_controls.alternate_work_site.attestation needs attested: true, by and date (organizational control, no machine-checkable evidence)"
}

# ---------------------------------------------------------------------------------------------------------------
# PE-18 Location of System Components — organizational control, no machine-checkable evidence.
# Facts: component_location.attestation {"attested": true, "by": <name>, "date": <date>}.
# ---------------------------------------------------------------------------------------------------------------

violation contains msg if {
	not _attested("component_location")
	msg := "NIST PE-18: Positioning of system components to minimize physical and environmental hazards and unauthorized access not attested — input.pe_controls.component_location.attestation needs attested: true, by and date (organizational control, no machine-checkable evidence)"
}

# ---------------------------------------------------------------------------------------------------------------
# PE-19 Information Leakage — organizational control, no machine-checkable evidence.
# Facts: information_leakage.attestation {"attested": true, "by": <name>, "date": <date>}.
# ---------------------------------------------------------------------------------------------------------------

violation contains msg if {
	not _attested("information_leakage")
	msg := "NIST PE-19: Protection of the system from information leakage through electromagnetic emanations not attested — input.pe_controls.information_leakage.attestation needs attested: true, by and date (organizational control, no machine-checkable evidence)"
}

# ---------------------------------------------------------------------------------------------------------------
# PE-20 Asset Monitoring and Tracking — organizational control, no machine-checkable evidence.
# Facts: asset_monitoring.attestation {"attested": true, "by": <name>, "date": <date>}.
# ---------------------------------------------------------------------------------------------------------------

violation contains msg if {
	not _attested("asset_monitoring")
	msg := "NIST PE-20: Tracking and monitoring of the location and movement of the organization-defined assets not attested — input.pe_controls.asset_monitoring.attestation needs attested: true, by and date (organizational control, no machine-checkable evidence)"
}

# ---------------------------------------------------------------------------------------------------------------
# PE-21 Electromagnetic Pulse Protection — organizational control, no machine-checkable evidence.
# Facts: emp_protection.attestation {"attested": true, "by": <name>, "date": <date>}.
# ---------------------------------------------------------------------------------------------------------------

violation contains msg if {
	not _attested("emp_protection")
	msg := "NIST PE-21: Protection of the organization-defined systems against electromagnetic pulse damage not attested — input.pe_controls.emp_protection.attestation needs attested: true, by and date (organizational control, no machine-checkable evidence)"
}

# ---------------------------------------------------------------------------------------------------------------
# PE-22 Component Marking — organizational control, no machine-checkable evidence.
# Facts: component_marking.attestation {"attested": true, "by": <name>, "date": <date>}.
# ---------------------------------------------------------------------------------------------------------------

violation contains msg if {
	not _attested("component_marking")
	msg := "NIST PE-22: Marking of hardware components with the impact or classification level they may process not attested — input.pe_controls.component_marking.attestation needs attested: true, by and date (organizational control, no machine-checkable evidence)"
}

# ---------------------------------------------------------------------------------------------------------------
# PE-23 Facility Location — organizational control, no machine-checkable evidence.
# Facts: facility_location.attestation {"attested": true, "by": <name>, "date": <date>}.
# ---------------------------------------------------------------------------------------------------------------

violation contains msg if {
	not _attested("facility_location")
	msg := "NIST PE-23: Facility site planning that considers physical and environmental hazards not attested — input.pe_controls.facility_location.attestation needs attested: true, by and date (organizational control, no machine-checkable evidence)"
}

compliant if count(violation) == 0

# The base control ids this family evaluates (PE-7 is withdrawn); each has exactly one finding when it fails.
evaluated_controls := {
	"PE-1", "PE-2", "PE-3", "PE-4", "PE-5", "PE-6", "PE-8", "PE-9", "PE-10", "PE-11", "PE-12",
	"PE-13", "PE-14", "PE-15", "PE-16", "PE-17", "PE-18", "PE-19", "PE-20", "PE-21", "PE-22", "PE-23",
}

compliance_report := {
	"family": "PE",
	"name": "Physical and Environmental Protection",
	"controls_evaluated": count(evaluated_controls),
	"violations": violation,
	"violation_count": count(violation),
	"compliant": compliant,
}
