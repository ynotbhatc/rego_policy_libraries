# METADATA
# title: "NIST SP 800-53 Rev 5 — Physical and Environmental Protection (PE) Family"
# custom:
#   class: compliance
#   framework: nist_sp_800_53
#   source: nist
#   domains: [us-federal, security-controls]
#   coverage:
#     checks: 46
#     cited: 31
#     density: sized
#     basis: size
#     tested: true
#     entrypoint: compliance_report
#     guard: self
#     as_of: v2.5.0
package nist.sp800_53.physical_environmental

import rego.v1

# NIST SP 800-53 Rev 5 — Physical and Environmental Protection (PE) Family, base controls PE-1 to PE-23 (PE-7
# withdrawn), the NIST SP 800-53B Moderate-baseline enhancements PE-6(1) and PE-13(1), and the High-baseline
# enhancements PE-3(1), PE-6(4), PE-8(1), PE-11(1), PE-13(2), PE-14(2) and PE-15(1). An enhancement is its own
# requirement with its own finding; a base control never fails for an enhancement.
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

# An attestation that is absent or of the wrong shape (not an object, attested not a boolean, by or date not a
# string) is missing evidence; one that is well-formed but false or unsigned keeps the plain "not attested" text.
_att_shaped(name) if {
	a := _get(concat(".", [name, "attestation"]))
	is_object(a)
	is_boolean(a.attested)
	is_string(a.by)
	is_string(a.date)
}

_att_text(name, text) := text if {
	_att_shaped(name)
} else := sprintf("evidence missing — %s not collected; %s", [_path(concat(".", [name, "attestation"])), text])

# Counts that must be zero (exceptions from physical security records). A non-number or a negative number is
# missing evidence.
_count_ok(x) if {
	is_number(x)
	x >= 0
}

_zero_missing(paths) := {_path(p) |
	some p in paths
	not _count_ok(_get(p))
}

_zero_unmet(checks) := {sprintf(c[1], [n]) |
	some c in checks
	n := _get(c[0])
	is_number(n)
	_count_ok(n)
	n > 0
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
#   long-term alternate power). The long-term alternate power supply is PE-11(1), evaluated separately.
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
	msg := sprintf("NIST PE-4: %s", [_att_text("transmission_access", "Physical access control over system distribution and transmission lines not attested — input.pe_controls.transmission_access.attestation needs attested: true, by and date (organizational control, no machine-checkable evidence)")])
}

# ---------------------------------------------------------------------------------------------------------------
# PE-5 Access Control for Output Devices — organizational control, no machine-checkable evidence.
# Facts: output_devices.attestation {"attested": true, "by": <name>, "date": <date>}.
# ---------------------------------------------------------------------------------------------------------------

violation contains msg if {
	not _attested("output_devices")
	msg := sprintf("NIST PE-5: %s", [_att_text("output_devices", "Physical access control over output from the organization-defined output devices not attested — input.pe_controls.output_devices.attestation needs attested: true, by and date (organizational control, no machine-checkable evidence)")])
}

# ---------------------------------------------------------------------------------------------------------------
# PE-9 Power Equipment and Cabling — organizational control, no machine-checkable evidence.
# Facts: power_equipment.attestation {"attested": true, "by": <name>, "date": <date>}.
# ---------------------------------------------------------------------------------------------------------------

violation contains msg if {
	not _attested("power_equipment")
	msg := sprintf("NIST PE-9: %s", [_att_text("power_equipment", "Protection of power equipment and power cabling from damage and destruction not attested — input.pe_controls.power_equipment.attestation needs attested: true, by and date (organizational control, no machine-checkable evidence)")])
}

# ---------------------------------------------------------------------------------------------------------------
# PE-10 Emergency Shutoff — organizational control, no machine-checkable evidence.
# Facts: emergency_shutoff.attestation {"attested": true, "by": <name>, "date": <date>}.
# ---------------------------------------------------------------------------------------------------------------

violation contains msg if {
	not _attested("emergency_shutoff")
	msg := sprintf("NIST PE-10: %s", [_att_text("emergency_shutoff", "Emergency power shutoff capability, its placement and its protection from unauthorized activation not attested — input.pe_controls.emergency_shutoff.attestation needs attested: true, by and date (organizational control, no machine-checkable evidence)")])
}

# ---------------------------------------------------------------------------------------------------------------
# PE-12 Emergency Lighting — organizational control, no machine-checkable evidence.
# Facts: emergency_lighting.attestation {"attested": true, "by": <name>, "date": <date>}.
# ---------------------------------------------------------------------------------------------------------------

violation contains msg if {
	not _attested("emergency_lighting")
	msg := sprintf("NIST PE-12: %s", [_att_text("emergency_lighting", "Automatic emergency lighting covering emergency exits and evacuation routes not attested — input.pe_controls.emergency_lighting.attestation needs attested: true, by and date (organizational control, no machine-checkable evidence)")])
}

# ---------------------------------------------------------------------------------------------------------------
# PE-13 Fire Protection — organizational control, no machine-checkable evidence.
# Facts: fire_protection.attestation {"attested": true, "by": <name>, "date": <date>}.
# ---------------------------------------------------------------------------------------------------------------

violation contains msg if {
	not _attested("fire_protection")
	msg := sprintf("NIST PE-13: %s", [_att_text("fire_protection", "Fire detection and suppression systems supported by an independent energy source not attested — input.pe_controls.fire_protection.attestation needs attested: true, by and date (organizational control, no machine-checkable evidence)")])
}

# ---------------------------------------------------------------------------------------------------------------
# PE-15 Water Damage Protection — organizational control, no machine-checkable evidence.
# Facts: water_damage_protection.attestation {"attested": true, "by": <name>, "date": <date>}.
# ---------------------------------------------------------------------------------------------------------------

violation contains msg if {
	not _attested("water_damage_protection")
	msg := sprintf("NIST PE-15: %s", [_att_text("water_damage_protection", "Accessible, working master shutoff or isolation valves known to key personnel not attested — input.pe_controls.water_damage_protection.attestation needs attested: true, by and date (organizational control, no machine-checkable evidence)")])
}

# ---------------------------------------------------------------------------------------------------------------
# PE-16 Delivery and Removal — organizational control, no machine-checkable evidence.
# Facts: delivery_removal.attestation {"attested": true, "by": <name>, "date": <date>}.
# ---------------------------------------------------------------------------------------------------------------

violation contains msg if {
	not _attested("delivery_removal")
	msg := sprintf("NIST PE-16: %s", [_att_text("delivery_removal", "Authorization and control of system components entering and exiting the facility, with records not attested — input.pe_controls.delivery_removal.attestation needs attested: true, by and date (organizational control, no machine-checkable evidence)")])
}

# ---------------------------------------------------------------------------------------------------------------
# PE-17 Alternate Work Site — organizational control, no machine-checkable evidence.
# Facts: alternate_work_site.attestation {"attested": true, "by": <name>, "date": <date>}.
# ---------------------------------------------------------------------------------------------------------------

violation contains msg if {
	not _attested("alternate_work_site")
	msg := sprintf("NIST PE-17: %s", [_att_text("alternate_work_site", "Alternate work sites determined, their controls employed and assessed, and incident communication provided not attested — input.pe_controls.alternate_work_site.attestation needs attested: true, by and date (organizational control, no machine-checkable evidence)")])
}

# ---------------------------------------------------------------------------------------------------------------
# PE-18 Location of System Components — organizational control, no machine-checkable evidence.
# Facts: component_location.attestation {"attested": true, "by": <name>, "date": <date>}.
# ---------------------------------------------------------------------------------------------------------------

violation contains msg if {
	not _attested("component_location")
	msg := sprintf("NIST PE-18: %s", [_att_text("component_location", "Positioning of system components to minimize physical and environmental hazards and unauthorized access not attested — input.pe_controls.component_location.attestation needs attested: true, by and date (organizational control, no machine-checkable evidence)")])
}

# ---------------------------------------------------------------------------------------------------------------
# PE-19 Information Leakage — organizational control, no machine-checkable evidence.
# Facts: information_leakage.attestation {"attested": true, "by": <name>, "date": <date>}.
# ---------------------------------------------------------------------------------------------------------------

violation contains msg if {
	not _attested("information_leakage")
	msg := sprintf("NIST PE-19: %s", [_att_text("information_leakage", "Protection of the system from information leakage through electromagnetic emanations not attested — input.pe_controls.information_leakage.attestation needs attested: true, by and date (organizational control, no machine-checkable evidence)")])
}

# ---------------------------------------------------------------------------------------------------------------
# PE-20 Asset Monitoring and Tracking — organizational control, no machine-checkable evidence.
# Facts: asset_monitoring.attestation {"attested": true, "by": <name>, "date": <date>}.
# ---------------------------------------------------------------------------------------------------------------

violation contains msg if {
	not _attested("asset_monitoring")
	msg := sprintf("NIST PE-20: %s", [_att_text("asset_monitoring", "Tracking and monitoring of the location and movement of the organization-defined assets not attested — input.pe_controls.asset_monitoring.attestation needs attested: true, by and date (organizational control, no machine-checkable evidence)")])
}

# ---------------------------------------------------------------------------------------------------------------
# PE-21 Electromagnetic Pulse Protection — organizational control, no machine-checkable evidence.
# Facts: emp_protection.attestation {"attested": true, "by": <name>, "date": <date>}.
# ---------------------------------------------------------------------------------------------------------------

violation contains msg if {
	not _attested("emp_protection")
	msg := sprintf("NIST PE-21: %s", [_att_text("emp_protection", "Protection of the organization-defined systems against electromagnetic pulse damage not attested — input.pe_controls.emp_protection.attestation needs attested: true, by and date (organizational control, no machine-checkable evidence)")])
}

# ---------------------------------------------------------------------------------------------------------------
# PE-22 Component Marking — organizational control, no machine-checkable evidence.
# Facts: component_marking.attestation {"attested": true, "by": <name>, "date": <date>}.
# ---------------------------------------------------------------------------------------------------------------

violation contains msg if {
	not _attested("component_marking")
	msg := sprintf("NIST PE-22: %s", [_att_text("component_marking", "Marking of hardware components with the impact or classification level they may process not attested — input.pe_controls.component_marking.attestation needs attested: true, by and date (organizational control, no machine-checkable evidence)")])
}

# ---------------------------------------------------------------------------------------------------------------
# PE-23 Facility Location — organizational control, no machine-checkable evidence.
# Facts: facility_location.attestation {"attested": true, "by": <name>, "date": <date>}.
# ---------------------------------------------------------------------------------------------------------------

violation contains msg if {
	not _attested("facility_location")
	msg := sprintf("NIST PE-23: %s", [_att_text("facility_location", "Facility site planning that considers physical and environmental hazards not attested — input.pe_controls.facility_location.attestation needs attested: true, by and date (organizational control, no machine-checkable evidence)")])
}

# ---------------------------------------------------------------------------------------------------------------
# PE-6(1) Intrusion Alarms and Surveillance Equipment: physical access to the facility is monitored with intrusion
# alarms and surveillance equipment.
# Facts: monitoring_physical_access.intrusion_alarms_and_surveillance.intrusion_alarms_monitored,
#        .surveillance_monitored (booleans: the alarm and video systems report as armed/recording and monitored,
#        from the physical security system's health status).
# ---------------------------------------------------------------------------------------------------------------

_pe6_1_bools := [
	"monitoring_physical_access.intrusion_alarms_and_surveillance.intrusion_alarms_monitored",
	"monitoring_physical_access.intrusion_alarms_and_surveillance.surveillance_monitored",
]

_pe6_1_missing := _bool_missing(_pe6_1_bools)

violation contains msg if {
	count(_pe6_1_missing) > 0
	msg := _missing_msg("PE-6(1)", _pe6_1_missing)
}

violation contains msg if {
	count(_pe6_1_missing) == 0
	failed := _bool_false(_pe6_1_bools)
	count(failed) > 0
	msg := sprintf("NIST PE-6(1): Physical access not monitored with intrusion alarms and surveillance equipment — %s", [concat("; ", sort(failed))])
}

# ---------------------------------------------------------------------------------------------------------------
# PE-13(1) Detection Systems — Automatic Activation and Notification: fire detection activates automatically and
# notifies the organization-defined personnel and emergency responders.
# Facts: fire_protection.detection.automatic_activation, .notifies_personnel, .notifies_emergency_responders
#        (booleans, from the fire alarm panel configuration and its last acceptance or inspection test).
# ---------------------------------------------------------------------------------------------------------------

_pe13_1_bools := [
	"fire_protection.detection.automatic_activation",
	"fire_protection.detection.notifies_personnel",
	"fire_protection.detection.notifies_emergency_responders",
]

_pe13_1_missing := _bool_missing(_pe13_1_bools)

violation contains msg if {
	count(_pe13_1_missing) > 0
	msg := _missing_msg("PE-13(1)", _pe13_1_missing)
}

violation contains msg if {
	count(_pe13_1_missing) == 0
	failed := _bool_false(_pe13_1_bools)
	count(failed) > 0
	msg := sprintf("NIST PE-13(1): Fire detection does not activate automatically and notify personnel and emergency responders — %s", [concat("; ", sort(failed))])
}

# ===============================================================================================================
# High-baseline enhancements (NIST SP 800-53B High and the FedRAMP High baseline).
# ===============================================================================================================

# ---------------------------------------------------------------------------------------------------------------
# PE-3(1) System Access: physical access authorizations to the system are enforced at the organization-defined
# physical spaces (server rooms, cages, racks) in addition to the facility access controls.
# Facts: physical_access_control.system_access.spaces_without_access_enforcement (number of the
#        organization-defined spaces with no system-level physical access control, from the access control system;
#        must be 0).
# ---------------------------------------------------------------------------------------------------------------

_pe3_1 := [["physical_access_control.system_access.spaces_without_access_enforcement", "%v organization-defined physical spaces do not enforce physical access authorizations to the system"]]

_pe3_1_missing := _zero_missing([c[0] | some c in _pe3_1])

violation contains msg if {
	count(_pe3_1_missing) > 0
	msg := _missing_msg("PE-3(1)", _pe3_1_missing)
}

violation contains msg if {
	count(_pe3_1_missing) == 0
	failed := _zero_unmet(_pe3_1)
	count(failed) > 0
	msg := sprintf("NIST PE-3(1): %s", [concat("; ", sort(failed))])
}

# ---------------------------------------------------------------------------------------------------------------
# PE-6(4) Monitoring Physical Access to Systems: physical access to the system is monitored at the
# organization-defined physical spaces in addition to the facility monitoring.
# Facts: monitoring_physical_access.system_access_monitoring.spaces_not_monitored (number of the
#        organization-defined spaces with no system-level physical access monitoring, such as badge-reader logging
#        or cameras on the cage or rack; must be 0).
# ---------------------------------------------------------------------------------------------------------------

_pe6_4 := [["monitoring_physical_access.system_access_monitoring.spaces_not_monitored", "%v organization-defined physical spaces without monitoring of physical access to the system"]]

_pe6_4_missing := _zero_missing([c[0] | some c in _pe6_4])

violation contains msg if {
	count(_pe6_4_missing) > 0
	msg := _missing_msg("PE-6(4)", _pe6_4_missing)
}

violation contains msg if {
	count(_pe6_4_missing) == 0
	failed := _zero_unmet(_pe6_4)
	count(failed) > 0
	msg := sprintf("NIST PE-6(4): %s", [concat("; ", sort(failed))])
}

# ---------------------------------------------------------------------------------------------------------------
# PE-8(1) Automated Records Maintenance and Review: visitor access records are maintained and reviewed with the
# organization-defined automated mechanisms.
# Facts: visitor_access_records.automation.maintained_automatically, .reviewed_automatically (booleans, from the
#        visitor management system configuration).
# ---------------------------------------------------------------------------------------------------------------

_pe8_1_bools := [
	"visitor_access_records.automation.maintained_automatically",
	"visitor_access_records.automation.reviewed_automatically",
]

_pe8_1_missing := _bool_missing(_pe8_1_bools)

violation contains msg if {
	count(_pe8_1_missing) > 0
	msg := _missing_msg("PE-8(1)", _pe8_1_missing)
}

violation contains msg if {
	count(_pe8_1_missing) == 0
	failed := _bool_false(_pe8_1_bools)
	count(failed) > 0
	msg := sprintf("NIST PE-8(1): Visitor access records not maintained and reviewed with automated mechanisms — %s", [concat("; ", sort(failed))])
}

# ---------------------------------------------------------------------------------------------------------------
# PE-11(1) Alternate Power Supply — Minimal Operational Capability: an alternate power supply (generator) keeps
# minimally required operations running through an extended loss of primary power, and is activated in the
# organization-selected way (manually or automatically).
# Facts: emergency_power.alternate_supply.provided, .maintains_minimal_capability (booleans, the latter from the
#        last load test); emergency_power.alternate_supply.activation ("manually" or "automatically", the transfer
#        switch configuration) against emergency_power.alternate_supply.odp.activation (the organization's
#        selection). A manual supply where the organization selected automatic activation is a finding; an
#        automatic supply meets either selection. Any other value is evidence missing.
# ---------------------------------------------------------------------------------------------------------------

_pe11_1_bools := ["emergency_power.alternate_supply.provided", "emergency_power.alternate_supply.maintains_minimal_capability"]

_pe11_1_modes := {"manually", "automatically"}

_pe11_1_act := _get("emergency_power.alternate_supply.activation")

_pe11_1_odp := _get("emergency_power.alternate_supply.odp.activation")

_pe11_1_missing := (_bool_missing(_pe11_1_bools) | {_path("emergency_power.alternate_supply.activation") | not _pe11_1_act in _pe11_1_modes}) | {_path("emergency_power.alternate_supply.odp.activation") | not _pe11_1_odp in _pe11_1_modes}

violation contains msg if {
	count(_pe11_1_missing) > 0
	msg := _missing_msg("PE-11(1)", _pe11_1_missing)
}

violation contains msg if {
	count(_pe11_1_missing) == 0
	mode := {"the alternate power supply is activated manually; the organization-defined activation is automatic" | _pe11_1_odp == "automatically"; _pe11_1_act == "manually"}
	failed := _bool_false(_pe11_1_bools) | mode
	count(failed) > 0
	msg := sprintf("NIST PE-11(1): Alternate power supply does not maintain minimal operational capability as required — %s", [concat("; ", sort(failed))])
}

# ---------------------------------------------------------------------------------------------------------------
# PE-13(2) Suppression Systems — Automatic Activation and Notification: fire suppression activates automatically
# and notifies the organization-defined personnel and emergency responders. Automatic activation is required in
# every case, which also covers the requirement for automatic suppression when the facility is not staffed
# continuously.
# Facts: fire_protection.suppression.automatic_activation, .notifies_personnel, .notifies_emergency_responders
#        (booleans, from the suppression panel configuration and its last inspection test).
# ---------------------------------------------------------------------------------------------------------------

_pe13_2_bools := [
	"fire_protection.suppression.automatic_activation",
	"fire_protection.suppression.notifies_personnel",
	"fire_protection.suppression.notifies_emergency_responders",
]

_pe13_2_missing := _bool_missing(_pe13_2_bools)

violation contains msg if {
	count(_pe13_2_missing) > 0
	msg := _missing_msg("PE-13(2)", _pe13_2_missing)
}

violation contains msg if {
	count(_pe13_2_missing) == 0
	failed := _bool_false(_pe13_2_bools)
	count(failed) > 0
	msg := sprintf("NIST PE-13(2): Fire suppression does not activate automatically and notify personnel and emergency responders — %s", [concat("; ", sort(failed))])
}

# ---------------------------------------------------------------------------------------------------------------
# PE-14(2) Monitoring with Alarms and Notifications: environmental monitoring raises an alarm or notification to
# the organization-defined personnel or roles on changes potentially harmful to personnel or equipment.
# Facts: environmental_controls.alarms.alarm_on_harmful_change, .notifies_defined_personnel (booleans, from the
#        environmental monitoring system's alert configuration).
# ---------------------------------------------------------------------------------------------------------------

_pe14_2_bools := ["environmental_controls.alarms.alarm_on_harmful_change", "environmental_controls.alarms.notifies_defined_personnel"]

_pe14_2_missing := _bool_missing(_pe14_2_bools)

violation contains msg if {
	count(_pe14_2_missing) > 0
	msg := _missing_msg("PE-14(2)", _pe14_2_missing)
}

violation contains msg if {
	count(_pe14_2_missing) == 0
	failed := _bool_false(_pe14_2_bools)
	count(failed) > 0
	msg := sprintf("NIST PE-14(2): Environmental monitoring does not alarm or notify the organization-defined personnel — %s", [concat("; ", sort(failed))])
}

# ---------------------------------------------------------------------------------------------------------------
# PE-15(1) Automation Support: the presence of water near the system is detected and the organization-defined
# personnel or roles are alerted by the organization-defined automated mechanisms.
# Facts: water_damage_protection.detection.automated_detection, .alerts_defined_personnel (booleans, from the leak
#        detection system's sensor and alert configuration).
# ---------------------------------------------------------------------------------------------------------------

_pe15_1_bools := ["water_damage_protection.detection.automated_detection", "water_damage_protection.detection.alerts_defined_personnel"]

_pe15_1_missing := _bool_missing(_pe15_1_bools)

violation contains msg if {
	count(_pe15_1_missing) > 0
	msg := _missing_msg("PE-15(1)", _pe15_1_missing)
}

violation contains msg if {
	count(_pe15_1_missing) == 0
	failed := _bool_false(_pe15_1_bools)
	count(failed) > 0
	msg := sprintf("NIST PE-15(1): Water near the system not detected and alerted with automated mechanisms — %s", [concat("; ", sort(failed))])
}

compliant if count(violation) == 0

# The control and enhancement ids this family evaluates (PE-7 is withdrawn); each has exactly one finding when it
# fails.
evaluated_controls := {
	"PE-1", "PE-2", "PE-3", "PE-3(1)", "PE-4", "PE-5", "PE-6", "PE-6(1)", "PE-6(4)", "PE-8", "PE-8(1)", "PE-9",
	"PE-10", "PE-11", "PE-11(1)", "PE-12", "PE-13", "PE-13(1)", "PE-13(2)", "PE-14", "PE-14(2)", "PE-15",
	"PE-15(1)", "PE-16", "PE-17", "PE-18", "PE-19", "PE-20", "PE-21", "PE-22", "PE-23",
}

compliance_report := {
	"family": "PE",
	"name": "Physical and Environmental Protection",
	"controls_evaluated": count(evaluated_controls),
	"violations": violation,
	"violation_count": count(violation),
	"compliant": compliant,
}
