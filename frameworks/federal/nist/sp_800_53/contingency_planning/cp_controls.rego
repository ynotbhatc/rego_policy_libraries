# METADATA
# title: "NIST SP 800-53 Rev 5 — Contingency Planning (CP) Family"
# custom:
#   class: compliance
#   framework: nist_sp_800_53
#   source: nist
#   domains: [us-federal, security-controls]
#   coverage:
#     checks: 12
#     cited: 12
#     density: sized
#     basis: size
#     tested: true
#     entrypoint: compliance_report
#     guard: self
#     as_of: v2.5.0
package nist.sp800_53.contingency_planning

import rego.v1

# NIST SP 800-53 Rev 5 — Contingency Planning (CP) Family. Every active base control (CP-1 to CP-4, CP-6 to
# CP-13; CP-5 is withdrawn). Enhancements are not evaluated: a control never fails for an enhancement.

default compliant := false

# ---------------------------------------------------------------------------------------------------------------
# Evidence helpers. Every control reads its facts under input.cp_controls.<name>; `path` is the list of keys below
# that root. A fact that is absent, null or of the wrong type is missing evidence, never a pass.
# ---------------------------------------------------------------------------------------------------------------

_root := "cp_controls"

_path_str(path) := concat(".", array.concat(["input", _root], path))

_obj(path) := v if {
	v := object.get(input, array.concat([_root], path), {})
	is_object(v)
} else := {}

# Boolean facts: `checks` is a list of [key, description of the unmet state]. Absent or null is missing evidence;
# any other value except the boolean true ("true", 1, false) is a finding.
_bool_missing(path, checks) := {concat(".", [_path_str(path), c[0]]) |
	some c in checks
	object.get(_obj(path), c[0], null) == null
}

_bool_failed(path, checks) := {sprintf("%s (%s.%s is not true)", [c[1], _path_str(path), c[0]]) |
	some c in checks
	v := object.get(_obj(path), c[0], null)
	v != null
	not v == true
}

# Numeric facts: an observed value at <path>.<obs> and the organization-defined parameter at <path>.odp.<odp>.
# Either one not a number (absent, null, "1") is missing evidence.
_num_missing(path, obs, odp) := {concat(".", [_path_str(path), pair[0]]) |
	o := _obj(path)
	some pair in [[obs, object.get(o, obs, null)], [concat(".", ["odp", odp]), object.get(o, ["odp", odp], null)]]
	not is_number(pair[1])
}

# The observed value may not exceed the organization-defined value (ages, recovery times). `fmt` takes the
# observed value and the organization-defined value, in that order.
_over(path, obs, odp, fmt) := {sprintf(fmt, [o[obs], o.odp[odp]]) |
	o := _obj(path)
	is_number(o[obs])
	is_number(o.odp[odp])
	o[obs] > o.odp[odp]
}

# The observed value may not fall below the organization-defined value (retention periods).
_under(path, obs, odp, fmt) := {sprintf(fmt, [o[obs], o.odp[odp]]) |
	o := _obj(path)
	is_number(o[obs])
	is_number(o.odp[odp])
	o[obs] < o.odp[odp]
}

# Organization-defined frequencies (the IR-2/IR-3 pattern): <path>.days_since_last against
# <path>.odp.frequency_days.
_freq_missing(path) := _num_missing(path, "days_since_last", "frequency_days")

_freq_over(path, fmt) := _over(path, "days_since_last", "frequency_days", fmt)

# The text of a control's one finding, after its "NIST <id>: " prefix: the unmet elements, then the evidence
# that was not collected.
_detail(missing, failed) := sprintf("evidence missing — %s not collected", [concat(", ", sort(missing))]) if {
	count(missing) > 0
	count(failed) == 0
}

_detail(missing, failed) := concat("; ", sort(failed)) if {
	count(missing) == 0
	count(failed) > 0
}

_detail(missing, failed) := sprintf("%s; evidence missing — %s not collected", [concat("; ", sort(failed)), concat(", ", sort(missing))]) if {
	count(missing) > 0
	count(failed) > 0
}

# -1 Policy and Procedures: policy documented, procedures documented, an official designated, and policy and
# procedures each reviewed within their organization-defined frequency. One finding lists every unmet element.
# Facts (input.cp_controls.policy_procedures): policy_documented, procedures_documented, official_designated
# (booleans); policy_review.days_since_last + policy_review.odp.frequency_days;
# procedures_review.days_since_last + procedures_review.odp.frequency_days.
_pp_bools := [
	["policy_documented", "policy not documented"],
	["procedures_documented", "procedures not documented"],
	["official_designated", "no official designated to manage the policy and procedures"],
]

_pp_missing := (_bool_missing(["policy_procedures"], _pp_bools) | _freq_missing(["policy_procedures", "policy_review"])) | _freq_missing(["policy_procedures", "procedures_review"])

_pp_failed := (_bool_failed(["policy_procedures"], _pp_bools) | _freq_over(["policy_procedures", "policy_review"], "policy last reviewed %v days ago; the organization-defined frequency is %v days")) | _freq_over(["policy_procedures", "procedures_review"], "procedures last reviewed %v days ago; the organization-defined frequency is %v days")

violation contains msg if {
	count(_pp_missing | _pp_failed) > 0
	msg := sprintf("NIST CP-1: %s", [_detail(_pp_missing, _pp_failed)])
}

# Attestation: for organizational controls with no machine-checkable evidence, the only accepted evidence is
# {"attested": true, "by": <non-empty string>, "date": <non-empty string>} at input.cp_controls.<name>.attestation.
_attested(a) if {
	a.attested == true
	is_string(a.by)
	trim_space(a.by) != ""
	is_string(a.date)
	trim_space(a.date) != ""
}

_att_note := "this control has no machine-checkable evidence and is met only by an attestation {attested: true, by: <name>, date: <date>}"

# The text of an attestation control's finding, or undefined when the attestation is complete.
_att_detail(name) := sprintf("evidence missing — %s not collected; %s", [_path_str([name, "attestation"]), _att_note]) if {
	object.get(_obj([name]), "attestation", null) == null
}

_att_detail(name) := sprintf("%s is not a complete attestation; %s", [_path_str([name, "attestation"]), _att_note]) if {
	a := object.get(_obj([name]), "attestation", null)
	a != null
	not _attested(a)
}

# CP-2 Contingency Plan: a plan that identifies essential functions and contingency requirements, gives recovery
# objectives, restoration priorities and metrics, assigns roles with contact information, covers continuity
# during disruption and full restoration, and addresses sharing of contingency information; reviewed and approved
# by the organization-defined personnel; distributed to key contingency personnel; coordinated with incident
# handling; reviewed at the organization-defined frequency; updated for changes and problems found; changes
# communicated; lessons learned incorporated; protected from unauthorized disclosure and modification.
# Facts (input.cp_controls.contingency_plan): plan_documented (all a. elements present), approved,
# distributed_to_key_personnel, coordinated_with_incident_handling, updated_for_changes, changes_communicated,
# lessons_learned_incorporated, protected_from_unauthorized_disclosure_and_modification (booleans);
# review.days_since_last + review.odp.frequency_days.
_cp2_bools := [
	["plan_documented", "no contingency plan covering essential functions, recovery objectives, roles, continuity, restoration and information sharing"],
	["approved", "contingency plan not reviewed and approved by the organization-defined personnel"],
	["distributed_to_key_personnel", "contingency plan not distributed to key contingency personnel and organizational elements"],
	["coordinated_with_incident_handling", "contingency planning not coordinated with incident handling"],
	["updated_for_changes", "contingency plan not updated for organizational, system or environment changes and problems found"],
	["changes_communicated", "contingency plan changes not communicated to key contingency personnel and organizational elements"],
	["lessons_learned_incorporated", "lessons learned from contingency plan testing, training or execution not incorporated"],
	["protected_from_unauthorized_disclosure_and_modification", "contingency plan not protected from unauthorized disclosure and modification"],
]

_cp2_missing := _bool_missing(["contingency_plan"], _cp2_bools) | _freq_missing(["contingency_plan", "review"])

_cp2_failed := _bool_failed(["contingency_plan"], _cp2_bools) | _freq_over(["contingency_plan", "review"], "contingency plan last reviewed %v days ago; the organization-defined frequency is %v days")

violation contains msg if {
	count(_cp2_missing | _cp2_failed) > 0
	msg := sprintf("NIST CP-2: %s", [_detail(_cp2_missing, _cp2_failed)])
}

# CP-3 Contingency Training: training consistent with assigned roles within the organization-defined period of
# assuming a contingency role, when system changes require it, and at the organization-defined frequency
# thereafter; training content reviewed and updated at the organization-defined frequency.
# Facts (input.cp_controls.contingency_training): training_on_system_changes (boolean);
# max_days_to_initial_training (longest observed time from assuming a role to training) +
# odp.initial_training_days; refresher.days_since_last + refresher.odp.frequency_days;
# content_update.days_since_last + content_update.odp.frequency_days.
_cp3_bools := [["training_on_system_changes", "contingency training not provided when system changes require it"]]

_cp3_missing := ((_bool_missing(["contingency_training"], _cp3_bools) | _num_missing(["contingency_training"], "max_days_to_initial_training", "initial_training_days")) | _freq_missing(["contingency_training", "refresher"])) | _freq_missing(["contingency_training", "content_update"])

_cp3_failed := ((_bool_failed(["contingency_training"], _cp3_bools) | _over(["contingency_training"], "max_days_to_initial_training", "initial_training_days", "contingency training given up to %v days after a role was assumed; the organization-defined period is %v days")) | _freq_over(["contingency_training", "refresher"], "contingency training last provided %v days ago; the organization-defined frequency is %v days")) | _freq_over(["contingency_training", "content_update"], "contingency training content last updated %v days ago; the organization-defined frequency is %v days")

violation contains msg if {
	count(_cp3_missing | _cp3_failed) > 0
	msg := sprintf("NIST CP-3: %s", [_detail(_cp3_missing, _cp3_failed)])
}

# CP-4 Contingency Plan Testing: the plan tested at the organization-defined frequency with the
# organization-defined tests; results reviewed; corrective actions initiated where needed.
# Facts (input.cp_controls.plan_testing): defined_tests_used, results_reviewed, corrective_actions_initiated
# (booleans; corrective_actions_initiated is true when no action was needed); days_since_last + odp.frequency_days.
_cp4_bools := [
	["defined_tests_used", "contingency plan not tested with the organization-defined tests"],
	["results_reviewed", "contingency plan test results not reviewed"],
	["corrective_actions_initiated", "corrective actions from contingency plan testing not initiated"],
]

_cp4_missing := _bool_missing(["plan_testing"], _cp4_bools) | _freq_missing(["plan_testing"])

_cp4_failed := _bool_failed(["plan_testing"], _cp4_bools) | _freq_over(["plan_testing"], "contingency plan last tested %v days ago; the organization-defined frequency is %v days")

violation contains msg if {
	count(_cp4_missing | _cp4_failed) > 0
	msg := sprintf("NIST CP-4: %s", [_detail(_cp4_missing, _cp4_failed)])
}

# CP-6 Alternate Storage Site: an alternate storage site with agreements permitting storage and retrieval of
# backup information, providing controls equivalent to the primary site.
# Facts (input.cp_controls.alternate_storage_site): established, agreements_in_place, equivalent_controls
# (booleans).
_cp6_bools := [
	["established", "no alternate storage site established"],
	["agreements_in_place", "no agreements permit storage and retrieval of backup information at the alternate storage site"],
	["equivalent_controls", "alternate storage site does not provide controls equivalent to the primary site"],
]

_cp6_missing := _bool_missing(["alternate_storage_site"], _cp6_bools)

_cp6_failed := _bool_failed(["alternate_storage_site"], _cp6_bools)

violation contains msg if {
	count(_cp6_missing | _cp6_failed) > 0
	msg := sprintf("NIST CP-6: %s", [_detail(_cp6_missing, _cp6_failed)])
}

# CP-7 Alternate Processing Site: an alternate processing site with agreements permitting transfer and resumption
# of the organization-defined operations within the organization-defined period; equipment and supplies available
# there or under contract; controls equivalent to the primary site.
# Facts (input.cp_controls.alternate_processing_site): established, agreements_in_place,
# equipment_and_supplies_available_or_contracted, equivalent_controls (booleans); resumption_hours (demonstrated
# or planned time to resume) + odp.resumption_hours.
_cp7_bools := [
	["established", "no alternate processing site established"],
	["agreements_in_place", "no agreements permit transfer and resumption of operations at the alternate processing site"],
	["equipment_and_supplies_available_or_contracted", "equipment and supplies at the alternate processing site neither available nor under contract"],
	["equivalent_controls", "alternate processing site does not provide controls equivalent to the primary site"],
]

_cp7_missing := _bool_missing(["alternate_processing_site"], _cp7_bools) | _num_missing(["alternate_processing_site"], "resumption_hours", "resumption_hours")

_cp7_failed := _bool_failed(["alternate_processing_site"], _cp7_bools) | _over(["alternate_processing_site"], "resumption_hours", "resumption_hours", "operations resume at the alternate processing site in %v hours; the organization-defined period is %v hours")

violation contains msg if {
	count(_cp7_missing | _cp7_failed) > 0
	msg := sprintf("NIST CP-7: %s", [_detail(_cp7_missing, _cp7_failed)])
}

# CP-8 Telecommunications Services: alternate telecommunications services with agreements permitting resumption
# of the organization-defined operations within the organization-defined period when primary services are
# unavailable at the primary or alternate sites.
# Facts (input.cp_controls.telecommunications): alternate_services_established, agreements_in_place (booleans);
# resumption_hours + odp.resumption_hours.
_cp8_bools := [
	["alternate_services_established", "no alternate telecommunications services established"],
	["agreements_in_place", "no agreements permit resumption of operations over the alternate telecommunications services"],
]

_cp8_missing := _bool_missing(["telecommunications"], _cp8_bools) | _num_missing(["telecommunications"], "resumption_hours", "resumption_hours")

_cp8_failed := _bool_failed(["telecommunications"], _cp8_bools) | _over(["telecommunications"], "resumption_hours", "resumption_hours", "operations resume over alternate telecommunications in %v hours; the organization-defined period is %v hours")

violation contains msg if {
	count(_cp8_missing | _cp8_failed) > 0
	msg := sprintf("NIST CP-8: %s", [_detail(_cp8_missing, _cp8_failed)])
}

# CP-9 System Backup: backups of user-level information, system-level information and system documentation, each
# at its organization-defined frequency; confidentiality, integrity and availability of backups protected.
# Facts (input.cp_controls.backup): confidentiality_protected, integrity_protected, availability_protected
# (booleans); user_level, system_level, documentation — each .days_since_last + .odp.frequency_days.
_cp9_bools := [
	["confidentiality_protected", "confidentiality of backup information not protected"],
	["integrity_protected", "integrity of backup information not protected"],
	["availability_protected", "availability of backup information not protected"],
]

_cp9_kinds := [
	["user_level", "user-level information"],
	["system_level", "system-level information"],
	["documentation", "system documentation"],
]

_cp9_freq_missing := {m | some k in _cp9_kinds; some m in _freq_missing(["backup", k[0]])}

_cp9_freq_failed := {m |
	some k in _cp9_kinds
	some m in _freq_over(["backup", k[0]], concat("", ["backup of ", k[1], " last taken %v days ago; the organization-defined frequency is %v days"]))
}

_cp9_missing := _bool_missing(["backup"], _cp9_bools) | _cp9_freq_missing

_cp9_failed := _bool_failed(["backup"], _cp9_bools) | _cp9_freq_failed

violation contains msg if {
	count(_cp9_missing | _cp9_failed) > 0
	msg := sprintf("NIST CP-9: %s", [_detail(_cp9_missing, _cp9_failed)])
}

# CP-10 System Recovery and Reconstitution: recovery and reconstitution to a known state within the
# organization-defined period consistent with recovery time and recovery point objectives.
# Facts (input.cp_controls.recovery): recovers_to_known_state (boolean); recovery_hours (demonstrated recovery
# time, e.g. from the last restore test) + odp.recovery_hours.
_cp10_bools := [["recovers_to_known_state", "system recovery does not return the system to a known state"]]

_cp10_missing := _bool_missing(["recovery"], _cp10_bools) | _num_missing(["recovery"], "recovery_hours", "recovery_hours")

_cp10_failed := _bool_failed(["recovery"], _cp10_bools) | _over(["recovery"], "recovery_hours", "recovery_hours", "system recovery took %v hours; the organization-defined period is %v hours")

violation contains msg if {
	count(_cp10_missing | _cp10_failed) > 0
	msg := sprintf("NIST CP-10: %s", [_detail(_cp10_missing, _cp10_failed)])
}

# CP-11 Alternate Communications Protocols: the capability to employ the organization-defined alternative
# communications protocols to maintain continuity of operations. Organizational capability with no
# machine-checkable evidence.
# Facts: input.cp_controls.alternate_communications_protocols.attestation.
violation contains msg if {
	msg := sprintf("NIST CP-11: %s", [_att_detail("alternate_communications_protocols")])
}

# CP-12 Safe Mode: when the organization-defined conditions are detected, the system enters a safe mode of
# operation with the organization-defined restrictions.
# Facts (input.cp_controls.safe_mode): enters_on_defined_conditions, defined_restrictions_applied (booleans).
_cp12_bools := [
	["enters_on_defined_conditions", "system does not enter safe mode when the organization-defined conditions are detected"],
	["defined_restrictions_applied", "safe mode does not apply the organization-defined restrictions"],
]

_cp12_missing := _bool_missing(["safe_mode"], _cp12_bools)

_cp12_failed := _bool_failed(["safe_mode"], _cp12_bools)

violation contains msg if {
	count(_cp12_missing | _cp12_failed) > 0
	msg := sprintf("NIST CP-12: %s", [_detail(_cp12_missing, _cp12_failed)])
}

# CP-13 Alternative Security Mechanisms: the organization-defined alternative or supplemental mechanisms satisfy
# the organization-defined security functions when the primary means is unavailable or compromised.
# Organizational arrangement with no machine-checkable evidence.
# Facts: input.cp_controls.alternative_security_mechanisms.attestation.
violation contains msg if {
	msg := sprintf("NIST CP-13: %s", [_att_detail("alternative_security_mechanisms")])
}

compliant if count(violation) == 0

# The base control ids this family evaluates; each has exactly one finding when it fails.
evaluated_controls := {"CP-1", "CP-2", "CP-3", "CP-4", "CP-6", "CP-7", "CP-8", "CP-9", "CP-10", "CP-11", "CP-12", "CP-13"}

compliance_report := {
	"family": "CP",
	"name": "Contingency Planning",
	"controls_evaluated": count(evaluated_controls),
	"violations": violation,
	"violation_count": count(violation),
	"compliant": compliant,
}
