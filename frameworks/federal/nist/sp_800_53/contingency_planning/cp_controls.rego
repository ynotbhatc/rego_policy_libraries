# METADATA
# title: "NIST SP 800-53 Rev 5 — Contingency Planning (CP) Family"
# custom:
#   class: compliance
#   framework: nist_sp_800_53
#   source: nist
#   domains: [us-federal, security-controls]
#   coverage:
#     checks: 26
#     cited: 26
#     density: sized
#     basis: size
#     tested: true
#     entrypoint: compliance_report
#     guard: self
#     as_of: v2.5.0
package nist.sp800_53.contingency_planning

import rego.v1

# NIST SP 800-53 Rev 5 — Contingency Planning (CP) Family. Every active base control (CP-1 to CP-4, CP-6 to
# CP-13; CP-5 is withdrawn) and the enhancements the SP 800-53B Moderate baseline selects. Each enhancement is its
# own requirement with its own finding, read from keys nested under its base control's object; a base control
# never fails for an enhancement.

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

# ---------------------------------------------------------------------------------------------------------------
# Enhancements (SP 800-53B Moderate baseline). Each reads only its own keys, nested under its base control's
# object, and has its own single finding.
# ---------------------------------------------------------------------------------------------------------------

_nonempty_array(x) if {
	is_array(x)
	count(x) > 0
}

# Coordination registers (CP-2(1), CP-4(1)): <path>.related_plans lists every related plan as
# {"name": <string>, "coordinated": <boolean>}. Absent, not a list, or empty is missing evidence (a system always
# has related plans: business continuity, incident response, COOP, crisis communications ...).
_coord_missing(path) := {concat(".", [_path_str(path), "related_plans"]) |
	not _nonempty_array(object.get(_obj(path), "related_plans", null))
}

_coordinated(p) if {
	is_object(p)
	p.coordinated == true
}

_plan_name(p) := p.name if {
	is_object(p)
	is_string(p.name)
} else := sprintf("%v", [p])

_coord_failed(path, what) := {sprintf("%s not coordinated with the element responsible for related plan %s (%s.related_plans)", [what, _plan_name(p), _path_str(path)]) |
	plans := object.get(_obj(path), "related_plans", null)
	_nonempty_array(plans)
	some p in plans
	not _coordinated(p)
}

# The organization-defined scope of mission and business functions (CP-2(3), CP-2(8)): "all" or "essential".
_scope_missing(path) := {concat(".", [_path_str(path), "odp.function_scope (organization-defined: all or essential)"]) |
	not object.get(_obj(path), ["odp", "function_scope"], null) in {"all", "essential"}
}

# A count that must be zero: <path>.<key> not a number is missing evidence; above zero is a finding.
_count_missing(path, key) := {concat(".", [_path_str(path), key]) |
	not is_number(object.get(_obj(path), key, null))
}

_count_nonzero(path, key, fmt) := {sprintf(fmt, [n]) |
	n := object.get(_obj(path), key, null)
	is_number(n)
	n > 0
}

# CP-2(1) Coordinate with Related Plans: contingency plan development coordinated with the organizational
# elements responsible for related plans.
# Facts: input.cp_controls.contingency_plan.coordination.related_plans (list of {name, coordinated}).
_cp2_1_path := ["contingency_plan", "coordination"]

_cp2_1_missing := _coord_missing(_cp2_1_path)

_cp2_1_failed := _coord_failed(_cp2_1_path, "contingency plan development")

violation contains msg if {
	count(_cp2_1_missing | _cp2_1_failed) > 0
	msg := sprintf("NIST CP-2(1): %s", [_detail(_cp2_1_missing, _cp2_1_failed)])
}

# CP-2(3) Resume Mission and Business Functions: the plan provides for resuming the organization-defined (all or
# essential) mission and business functions within the organization-defined period of plan activation.
# Facts (input.cp_controls.contingency_plan.resumption): covers_all_in_scope_functions (boolean);
# planned_hours (longest planned time from activation to resumption of an in-scope function) +
# odp.resumption_hours; odp.function_scope ("all" or "essential").
_cp2_3_path := ["contingency_plan", "resumption"]

_cp2_3_bools := [["covers_all_in_scope_functions", "contingency plan does not provide for resuming every in-scope mission and business function"]]

_cp2_3_missing := (_bool_missing(_cp2_3_path, _cp2_3_bools) | _num_missing(_cp2_3_path, "planned_hours", "resumption_hours")) | _scope_missing(_cp2_3_path)

_cp2_3_failed := _bool_failed(_cp2_3_path, _cp2_3_bools) | _over(_cp2_3_path, "planned_hours", "resumption_hours", "mission and business functions planned to resume up to %v hours after plan activation; the organization-defined period is %v hours")

violation contains msg if {
	count(_cp2_3_missing | _cp2_3_failed) > 0
	msg := sprintf("NIST CP-2(3): %s", [_detail(_cp2_3_missing, _cp2_3_failed)])
}

# CP-2(8) Identify Critical Assets: critical system assets supporting the organization-defined (all or essential)
# mission and business functions are identified.
# Facts (input.cp_controls.contingency_plan.critical_assets): critical_asset_count (assets tagged critical in the
# inventory, a number); all_in_scope_functions_mapped (boolean: every in-scope function maps to its supporting
# assets); odp.function_scope ("all" or "essential").
_cp2_8_path := ["contingency_plan", "critical_assets"]

_cp2_8_bools := [["all_in_scope_functions_mapped", "not every in-scope mission and business function is mapped to the critical system assets supporting it"]]

_cp2_8_none := {"no critical system assets identified (critical_asset_count is below 1)" |
	n := object.get(_obj(_cp2_8_path), "critical_asset_count", null)
	is_number(n)
	n < 1
}

_cp2_8_missing := (_bool_missing(_cp2_8_path, _cp2_8_bools) | _count_missing(_cp2_8_path, "critical_asset_count")) | _scope_missing(_cp2_8_path)

_cp2_8_failed := _bool_failed(_cp2_8_path, _cp2_8_bools) | _cp2_8_none

violation contains msg if {
	count(_cp2_8_missing | _cp2_8_failed) > 0
	msg := sprintf("NIST CP-2(8): %s", [_detail(_cp2_8_missing, _cp2_8_failed)])
}

# CP-4(1) Coordinate with Related Plans: contingency plan testing coordinated with the organizational elements
# responsible for related plans.
# Facts: input.cp_controls.plan_testing.coordination.related_plans (list of {name, coordinated}).
_cp4_1_path := ["plan_testing", "coordination"]

_cp4_1_missing := _coord_missing(_cp4_1_path)

_cp4_1_failed := _coord_failed(_cp4_1_path, "contingency plan testing")

violation contains msg if {
	count(_cp4_1_missing | _cp4_1_failed) > 0
	msg := sprintf("NIST CP-4(1): %s", [_detail(_cp4_1_missing, _cp4_1_failed)])
}

# Separation (CP-6(1), CP-7(1)): <path>.threats_assessed (the primary and alternate sites were assessed for shared
# threats) and <path>.sufficiently_separated (the assessment found the alternate site separated enough to reduce
# susceptibility to the same threats), both booleans.
_sep_bools(site) := [
	["threats_assessed", sprintf("primary and alternate %s sites not assessed for shared threats", [site])],
	["sufficiently_separated", sprintf("alternate %s site not sufficiently separated from the primary site to reduce susceptibility to the same threats", [site])],
]

# Accessibility (CP-6(3), CP-7(2)): <path>.problems_identified (accessibility problems in an area-wide disruption
# or disaster identified) and <path>.mitigation_actions_outlined (explicit mitigation actions outlined), booleans.
_access_bools(site) := [
	["problems_identified", sprintf("potential accessibility problems to the alternate %s site in an area-wide disruption or disaster not identified", [site])],
	["mitigation_actions_outlined", sprintf("explicit mitigation actions for alternate %s site accessibility problems not outlined", [site])],
]

# CP-6(1) Separation from Primary Site. Facts: input.cp_controls.alternate_storage_site.separation.
_cp6_1_path := ["alternate_storage_site", "separation"]

_cp6_1_missing := _bool_missing(_cp6_1_path, _sep_bools("storage"))

_cp6_1_failed := _bool_failed(_cp6_1_path, _sep_bools("storage"))

violation contains msg if {
	count(_cp6_1_missing | _cp6_1_failed) > 0
	msg := sprintf("NIST CP-6(1): %s", [_detail(_cp6_1_missing, _cp6_1_failed)])
}

# CP-6(3) Accessibility. Facts: input.cp_controls.alternate_storage_site.accessibility.
_cp6_3_path := ["alternate_storage_site", "accessibility"]

_cp6_3_missing := _bool_missing(_cp6_3_path, _access_bools("storage"))

_cp6_3_failed := _bool_failed(_cp6_3_path, _access_bools("storage"))

violation contains msg if {
	count(_cp6_3_missing | _cp6_3_failed) > 0
	msg := sprintf("NIST CP-6(3): %s", [_detail(_cp6_3_missing, _cp6_3_failed)])
}

# CP-7(1) Separation from Primary Site. Facts: input.cp_controls.alternate_processing_site.separation.
_cp7_1_path := ["alternate_processing_site", "separation"]

_cp7_1_missing := _bool_missing(_cp7_1_path, _sep_bools("processing"))

_cp7_1_failed := _bool_failed(_cp7_1_path, _sep_bools("processing"))

violation contains msg if {
	count(_cp7_1_missing | _cp7_1_failed) > 0
	msg := sprintf("NIST CP-7(1): %s", [_detail(_cp7_1_missing, _cp7_1_failed)])
}

# CP-7(2) Accessibility. Facts: input.cp_controls.alternate_processing_site.accessibility.
_cp7_2_path := ["alternate_processing_site", "accessibility"]

_cp7_2_missing := _bool_missing(_cp7_2_path, _access_bools("processing"))

_cp7_2_failed := _bool_failed(_cp7_2_path, _access_bools("processing"))

violation contains msg if {
	count(_cp7_2_missing | _cp7_2_failed) > 0
	msg := sprintf("NIST CP-7(2): %s", [_detail(_cp7_2_missing, _cp7_2_failed)])
}

# CP-7(3) Priority of Service: alternate processing site agreements contain priority-of-service provisions in line
# with availability requirements, including recovery time objectives.
# Facts (input.cp_controls.alternate_processing_site.priority_of_service): provisions_in_agreements (boolean);
# restoration_hours (priority restoration time the agreements commit to) + odp.recovery_time_objective_hours.
_cp7_3_path := ["alternate_processing_site", "priority_of_service"]

_cp7_3_bools := [["provisions_in_agreements", "alternate processing site agreements contain no priority-of-service provisions"]]

_cp7_3_missing := _bool_missing(_cp7_3_path, _cp7_3_bools) | _num_missing(_cp7_3_path, "restoration_hours", "recovery_time_objective_hours")

_cp7_3_failed := _bool_failed(_cp7_3_path, _cp7_3_bools) | _over(_cp7_3_path, "restoration_hours", "recovery_time_objective_hours", "alternate processing site agreements commit to priority restoration in %v hours; the organization-defined recovery time objective is %v hours")

violation contains msg if {
	count(_cp7_3_missing | _cp7_3_failed) > 0
	msg := sprintf("NIST CP-7(3): %s", [_detail(_cp7_3_missing, _cp7_3_failed)])
}

# CP-8(1) Priority of Service Provisions: primary and alternate telecommunications agreements contain
# priority-of-service provisions in line with availability requirements (including recovery time objectives);
# Telecommunications Service Priority requested when a common carrier provides services used for national security
# emergency preparedness.
# Facts (input.cp_controls.telecommunications.priority_of_service): primary_agreement_provisions,
# alternate_agreement_provisions (booleans); restoration_hours + odp.recovery_time_objective_hours;
# common_carrier_for_nsep (boolean: a common carrier provides services used for NS/EP); tsp_requested (boolean,
# read only when common_carrier_for_nsep is true).
_cp8_1_path := ["telecommunications", "priority_of_service"]

_cp8_1_bools := [
	["primary_agreement_provisions", "primary telecommunications service agreement contains no priority-of-service provisions"],
	["alternate_agreement_provisions", "alternate telecommunications service agreement contains no priority-of-service provisions"],
]

_cp8_1_obj := _obj(_cp8_1_path)

_cp8_1_tsp_missing contains concat(".", [_path_str(_cp8_1_path), "common_carrier_for_nsep"]) if {
	not is_boolean(object.get(_cp8_1_obj, "common_carrier_for_nsep", null))
}

_cp8_1_tsp_missing contains concat(".", [_path_str(_cp8_1_path), "tsp_requested"]) if {
	_cp8_1_obj.common_carrier_for_nsep == true
	object.get(_cp8_1_obj, "tsp_requested", null) == null
}

_cp8_1_tsp_failed contains sprintf("Telecommunications Service Priority not requested for services a common carrier provides for national security emergency preparedness (%s.tsp_requested is not true)", [_path_str(_cp8_1_path)]) if {
	_cp8_1_obj.common_carrier_for_nsep == true
	v := object.get(_cp8_1_obj, "tsp_requested", null)
	v != null
	not v == true
}

_cp8_1_missing := (_bool_missing(_cp8_1_path, _cp8_1_bools) | _num_missing(_cp8_1_path, "restoration_hours", "recovery_time_objective_hours")) | _cp8_1_tsp_missing

_cp8_1_failed := (_bool_failed(_cp8_1_path, _cp8_1_bools) | _over(_cp8_1_path, "restoration_hours", "recovery_time_objective_hours", "telecommunications agreements commit to priority restoration in %v hours; the organization-defined recovery time objective is %v hours")) | _cp8_1_tsp_failed

violation contains msg if {
	count(_cp8_1_missing | _cp8_1_failed) > 0
	msg := sprintf("NIST CP-8(1): %s", [_detail(_cp8_1_missing, _cp8_1_failed)])
}

# CP-8(2) Single Points of Failure: alternate telecommunications services obtained so they do not share a single
# point of failure with the primary services.
# Facts (input.cp_controls.telecommunications.single_point_of_failure): diversity_assessed (boolean: carrier,
# route and facility diversity of primary and alternate services assessed); shared_points_of_failure (list of the
# points of failure the two share, e.g. a common central office or conduit; an empty list passes).
_cp8_2_path := ["telecommunications", "single_point_of_failure"]

_cp8_2_bools := [["diversity_assessed", "diversity of primary and alternate telecommunications services not assessed"]]

_cp8_2_shared := object.get(_obj(_cp8_2_path), "shared_points_of_failure", null)

_cp8_2_list_missing := {concat(".", [_path_str(_cp8_2_path), "shared_points_of_failure"]) | not is_array(_cp8_2_shared)}

_cp8_2_list_failed := {sprintf("primary and alternate telecommunications services share single points of failure: %s", [concat(", ", sort([sprintf("%v", [x]) | some x in _cp8_2_shared]))]) |
	is_array(_cp8_2_shared)
	count(_cp8_2_shared) > 0
}

_cp8_2_missing := _bool_missing(_cp8_2_path, _cp8_2_bools) | _cp8_2_list_missing

_cp8_2_failed := _bool_failed(_cp8_2_path, _cp8_2_bools) | _cp8_2_list_failed

violation contains msg if {
	count(_cp8_2_missing | _cp8_2_failed) > 0
	msg := sprintf("NIST CP-8(2): %s", [_detail(_cp8_2_missing, _cp8_2_failed)])
}

# CP-9(1) Testing for Reliability and Integrity: backup information tested at the organization-defined frequency to
# verify media reliability and information integrity.
# Facts (input.cp_controls.backup.testing): last_test_verified (boolean: the last test restored the backup and
# confirmed media reliability and information integrity); days_since_last + odp.frequency_days.
_cp9_1_path := ["backup", "testing"]

_cp9_1_bools := [["last_test_verified", "last backup test did not verify media reliability and information integrity"]]

_cp9_1_missing := _bool_missing(_cp9_1_path, _cp9_1_bools) | _freq_missing(_cp9_1_path)

_cp9_1_failed := _bool_failed(_cp9_1_path, _cp9_1_bools) | _freq_over(_cp9_1_path, "backup information last tested %v days ago; the organization-defined frequency is %v days")

violation contains msg if {
	count(_cp9_1_missing | _cp9_1_failed) > 0
	msg := sprintf("NIST CP-9(1): %s", [_detail(_cp9_1_missing, _cp9_1_failed)])
}

# CP-9(8) Cryptographic Protection: cryptographic mechanisms prevent unauthorized disclosure and modification of
# the organization-defined backup information.
# Facts (input.cp_controls.backup.cryptographic_protection), counts from the backup tool over the in-scope backup
# sets: unencrypted_backup_sets (sets not encrypted), sets_without_cryptographic_integrity (sets without a
# cryptographic integrity check: signature, MAC or authenticated encryption). Both must be 0.
_cp9_8_path := ["backup", "cryptographic_protection"]

_cp9_8_missing := _count_missing(_cp9_8_path, "unencrypted_backup_sets") | _count_missing(_cp9_8_path, "sets_without_cryptographic_integrity")

_cp9_8_failed := _count_nonzero(_cp9_8_path, "unencrypted_backup_sets", "%v backup sets not encrypted") | _count_nonzero(_cp9_8_path, "sets_without_cryptographic_integrity", "%v backup sets without cryptographic integrity protection")

violation contains msg if {
	count(_cp9_8_missing | _cp9_8_failed) > 0
	msg := sprintf("NIST CP-9(8): %s", [_detail(_cp9_8_missing, _cp9_8_failed)])
}

# CP-10(2) Transaction Recovery: transaction recovery implemented for transaction-based systems.
# Facts (input.cp_controls.recovery.transaction_recovery): transaction_based (boolean; false means the enhancement
# does not apply and it passes); implemented (boolean, read only when transaction_based is true: journaling,
# rollback or transaction log replay in place).
_cp10_2_obj := _obj(["recovery", "transaction_recovery"])

_cp10_2_path := _path_str(["recovery", "transaction_recovery"])

_cp10_2_missing contains concat(".", [_cp10_2_path, "transaction_based"]) if {
	not is_boolean(object.get(_cp10_2_obj, "transaction_based", null))
}

_cp10_2_missing contains concat(".", [_cp10_2_path, "implemented"]) if {
	_cp10_2_obj.transaction_based == true
	object.get(_cp10_2_obj, "implemented", null) == null
}

_cp10_2_failed contains sprintf("transaction recovery not implemented for a transaction-based system (%s.implemented is not true)", [_cp10_2_path]) if {
	_cp10_2_obj.transaction_based == true
	v := object.get(_cp10_2_obj, "implemented", null)
	v != null
	not v == true
}

violation contains msg if {
	count(_cp10_2_missing | _cp10_2_failed) > 0
	msg := sprintf("NIST CP-10(2): %s", [_detail(_cp10_2_missing, _cp10_2_failed)])
}

compliant if count(violation) == 0

# The control and enhancement ids this family evaluates; each has exactly one finding when it fails.
evaluated_controls := {
	"CP-1", "CP-2", "CP-2(1)", "CP-2(3)", "CP-2(8)", "CP-3", "CP-4", "CP-4(1)", "CP-6", "CP-6(1)", "CP-6(3)",
	"CP-7", "CP-7(1)", "CP-7(2)", "CP-7(3)", "CP-8", "CP-8(1)", "CP-8(2)", "CP-9", "CP-9(1)", "CP-9(8)", "CP-10",
	"CP-10(2)", "CP-11", "CP-12", "CP-13",
}

compliance_report := {
	"family": "CP",
	"name": "Contingency Planning",
	"controls_evaluated": count(evaluated_controls),
	"violations": violation,
	"violation_count": count(violation),
	"compliant": compliant,
}
