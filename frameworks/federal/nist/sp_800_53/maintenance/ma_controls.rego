# METADATA
# title: "NIST SP 800-53 Rev 5 — Maintenance (MA) Family"
# custom:
#   class: compliance
#   framework: nist_sp_800_53
#   source: nist
#   domains: [us-federal, security-controls]
#   coverage:
#     checks: 12
#     cited: 7
#     density: sized
#     basis: size
#     tested: true
#     entrypoint: compliance_report
#     guard: self
#     as_of: v2.5.0
package nist.sp800_53.maintenance

import rego.v1

# NIST SP 800-53 Rev 5 — Maintenance (MA) Family, base controls MA-1 to MA-7 (no enhancements).
# Facts live under input.ma_controls. Every control fails closed: a fact that is missing or of the wrong type is
# reported as missing evidence. Booleans pass only on true; numbers are checked with is_number before comparing.

default compliant := false

# ---------------------------------------------------------------------------------------------------------------
# Helpers. Paths are dotted and relative to input.ma_controls.
# ---------------------------------------------------------------------------------------------------------------

_get(path) := object.get(input, array.concat(["ma_controls"], split(path, ".")), null)

_path(p) := concat("", ["input.ma_controls.", p])

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
# MA-1 Policy and Procedures
# Facts: policy.documented, procedures.documented, policy.official_designated (booleans);
#        policy.review.days_since_last + policy.review.odp.frequency_days;
#        procedures.review.days_since_last + procedures.review.odp.frequency_days.
# One finding listing every unmet element.
# ---------------------------------------------------------------------------------------------------------------

_ma1_bools := ["policy.documented", "procedures.documented", "policy.official_designated"]

_ma1_missing := (_bool_missing(_ma1_bools) | _freq_missing("policy.review")) | _freq_missing("procedures.review")

_ma1_overdue := {m | m := _overdue("policy.review", "Policy review")} | {m | m := _overdue("procedures.review", "Procedures review")}

_ma1_unmet := ({sprintf("evidence missing: %s not collected", [p]) | some p in _ma1_missing} | _bool_false(_ma1_bools)) | _ma1_overdue

violation contains msg if {
	count(_ma1_unmet) > 0
	msg := sprintf("NIST MA-1: Maintenance policy and procedures requirements not met — %s", [concat("; ", sort(_ma1_unmet))])
}

# ---------------------------------------------------------------------------------------------------------------
# MA-2 Controlled Maintenance
# Facts (booleans) under controlled_maintenance: records_scheduled_documented_reviewed,
#   activities_approved_and_monitored, offsite_removal_approved, media_sanitized_before_offsite,
#   controls_checked_after_maintenance, records_include_required_information.
# ---------------------------------------------------------------------------------------------------------------

_ma2_bools := [
	"controlled_maintenance.records_scheduled_documented_reviewed",
	"controlled_maintenance.activities_approved_and_monitored",
	"controlled_maintenance.offsite_removal_approved",
	"controlled_maintenance.media_sanitized_before_offsite",
	"controlled_maintenance.controls_checked_after_maintenance",
	"controlled_maintenance.records_include_required_information",
]

_ma2_missing := _bool_missing(_ma2_bools)

violation contains msg if {
	count(_ma2_missing) > 0
	msg := _missing_msg("MA-2", _ma2_missing)
}

violation contains msg if {
	count(_ma2_missing) == 0
	failed := _bool_false(_ma2_bools)
	count(failed) > 0
	msg := sprintf("NIST MA-2: Controlled maintenance not in place — %s", [concat("; ", sort(failed))])
}

# ---------------------------------------------------------------------------------------------------------------
# MA-3 Maintenance Tools
# Facts: maintenance_tools.approved, maintenance_tools.controlled, maintenance_tools.monitored (booleans);
#        maintenance_tools.review.days_since_last + maintenance_tools.review.odp.frequency_days (review of
#        previously approved tools at the organization-defined frequency).
# ---------------------------------------------------------------------------------------------------------------

_ma3_bools := ["maintenance_tools.approved", "maintenance_tools.controlled", "maintenance_tools.monitored"]

_ma3_missing := _bool_missing(_ma3_bools) | _freq_missing("maintenance_tools.review")

violation contains msg if {
	count(_ma3_missing) > 0
	msg := _missing_msg("MA-3", _ma3_missing)
}

violation contains msg if {
	count(_ma3_missing) == 0
	failed := _bool_false(_ma3_bools) | {m | m := _overdue("maintenance_tools.review", "Review of approved maintenance tools")}
	count(failed) > 0
	msg := sprintf("NIST MA-3: Maintenance tools not approved, controlled, monitored and reviewed — %s", [concat("; ", sort(failed))])
}

# ---------------------------------------------------------------------------------------------------------------
# MA-4 Nonlocal Maintenance
# Facts (booleans) under nonlocal_maintenance: approved_and_monitored, tools_per_policy_and_security_plan,
#   strong_authentication, records_maintained, sessions_terminated_on_completion.
# ---------------------------------------------------------------------------------------------------------------

_ma4_bools := [
	"nonlocal_maintenance.approved_and_monitored",
	"nonlocal_maintenance.tools_per_policy_and_security_plan",
	"nonlocal_maintenance.strong_authentication",
	"nonlocal_maintenance.records_maintained",
	"nonlocal_maintenance.sessions_terminated_on_completion",
]

_ma4_missing := _bool_missing(_ma4_bools)

violation contains msg if {
	count(_ma4_missing) > 0
	msg := _missing_msg("MA-4", _ma4_missing)
}

violation contains msg if {
	count(_ma4_missing) == 0
	failed := _bool_false(_ma4_bools)
	count(failed) > 0
	msg := sprintf("NIST MA-4: Nonlocal maintenance not controlled — %s", [concat("; ", sort(failed))])
}

# ---------------------------------------------------------------------------------------------------------------
# MA-5 Maintenance Personnel
# Facts (booleans) under maintenance_personnel: authorization_process_established, authorized_list_maintained,
#   unescorted_access_verified, supervisors_designated.
# ---------------------------------------------------------------------------------------------------------------

_ma5_bools := [
	"maintenance_personnel.authorization_process_established",
	"maintenance_personnel.authorized_list_maintained",
	"maintenance_personnel.unescorted_access_verified",
	"maintenance_personnel.supervisors_designated",
]

_ma5_missing := _bool_missing(_ma5_bools)

violation contains msg if {
	count(_ma5_missing) > 0
	msg := _missing_msg("MA-5", _ma5_missing)
}

violation contains msg if {
	count(_ma5_missing) == 0
	failed := _bool_false(_ma5_bools)
	count(failed) > 0
	msg := sprintf("NIST MA-5: Maintenance personnel not authorized or supervised — %s", [concat("; ", sort(failed))])
}

# ---------------------------------------------------------------------------------------------------------------
# MA-6 Timely Maintenance
# Facts: timely_maintenance.components_covered (boolean: support or spare-part arrangements exist for the
#        organization-defined components); timely_maintenance.max_hours_to_support (longest observed time from
#        failure to support or parts) against timely_maintenance.odp.time_period_hours. Observed above the
#        organization-defined period is a finding.
# ---------------------------------------------------------------------------------------------------------------

_ma6 := {
	"covered": _get("timely_maintenance.components_covered"),
	"hours": _get("timely_maintenance.max_hours_to_support"),
	"odp": _get("timely_maintenance.odp.time_period_hours"),
}

_ma6_missing := (_bool_missing(["timely_maintenance.components_covered"]) | {_path("timely_maintenance.max_hours_to_support") | not is_number(_ma6.hours)}) | {_path("timely_maintenance.odp.time_period_hours") | not is_number(_ma6.odp)}

violation contains msg if {
	count(_ma6_missing) > 0
	msg := _missing_msg("MA-6", _ma6_missing)
}

violation contains msg if {
	count(_ma6_missing) == 0
	failed := {"components not covered by support or spare-part arrangements" | _ma6.covered == false} | {sprintf("support or parts took %v hours; the organization-defined period is %v hours", [_ma6.hours, _ma6.odp]) | _ma6.hours > _ma6.odp}
	count(failed) > 0
	msg := sprintf("NIST MA-6: Maintenance support not obtained in time — %s", [concat("; ", sort(failed))])
}

# ---------------------------------------------------------------------------------------------------------------
# MA-7 Field Maintenance — organizational control, no machine-checkable evidence.
# Facts: field_maintenance.attestation {"attested": true, "by": <name>, "date": <date>}.
# ---------------------------------------------------------------------------------------------------------------

violation contains msg if {
	not _attested("field_maintenance")
	msg := "NIST MA-7: Restriction of field maintenance to trusted facilities not attested — input.ma_controls.field_maintenance.attestation needs attested: true, by and date (organizational control, no machine-checkable evidence)"
}

compliant if count(violation) == 0

# The base control ids this family evaluates; each has exactly one finding when it fails.
evaluated_controls := {"MA-1", "MA-2", "MA-3", "MA-4", "MA-5", "MA-6", "MA-7"}

compliance_report := {
	"family": "MA",
	"name": "Maintenance",
	"controls_evaluated": count(evaluated_controls),
	"violations": violation,
	"violation_count": count(violation),
	"compliant": compliant,
}
