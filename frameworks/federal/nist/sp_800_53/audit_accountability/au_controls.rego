# METADATA
# title: "NIST SP 800-53 Rev 5 — Audit and Accountability (AU) Family"
# custom:
#   class: compliance
#   framework: nist_sp_800_53
#   source: nist
#   domains: [us-federal, security-controls]
#   coverage:
#     checks: 18
#     cited: 17
#     density: sized
#     basis: size
#     tested: true
#     entrypoint: compliance_report
#     guard: self
#     as_of: v2.5.0
package nist.sp800_53.audit_accountability

import rego.v1

# NIST SP 800-53 Rev 5 — Audit and Accountability (AU) Family
# Generation, protection, review, and analysis of audit records.
# Evaluated: AU-1..AU-12 and the NIST SP 800-53B Moderate enhancements AU-3(1), AU-6(1), AU-6(3), AU-7(1),
# AU-9(4) (17 ids). A base control never fails on an enhancement's requirement; each enhancement is its own finding.

default compliant := false

# ── Evidence helpers ─────────────────────────────────────────────────────
# A fact path is dotted below input.au_controls. A fact that is absent, null or of the wrong type is missing
# evidence, never a pass.
_au_get(p) := object.get(input, array.concat(["au_controls"], split(p, ".")), null)

_au_path(p) := concat(".", ["input.au_controls", p])

_au_bool_missing(ps) := {_au_path(p) | some p in ps; not is_boolean(_au_get(p))}

# Finding text for an existing boolean rule that fired: evidence missing when one of the facts it reads is absent
# or not a boolean, otherwise the rule's own text. The rule's pass condition is unchanged.
_au_detail(ps, text) := sprintf("evidence missing — %s not collected", [concat(", ", sort(m))]) if {
	m := _au_bool_missing(ps)
	count(m) > 0
} else := text

# Finding text for an enhancement: the missing evidence when any, otherwise the unmet elements.
_au_enh_detail(missing, failed) := sprintf("evidence missing — %s not collected", [concat(", ", sort(missing))]) if {
	count(missing) > 0
} else := concat("; ", sort(failed))

violation contains msg if {
	not input.au_controls.policy.documented
	msg := sprintf("NIST AU-1: %s", [_au_detail(["policy.documented"], "Audit and accountability policy not documented")])
}

violation contains msg if {
	not input.au_controls.event_logging.enabled
	msg := sprintf("NIST AU-2: %s", [_au_detail(["event_logging.enabled"], "Event types for logging not identified or event logging not enabled")])
}

violation contains msg if {
	not input.au_controls.content_of_records.adequate
	msg := sprintf("NIST AU-3: %s", [_au_detail(["content_of_records.adequate"], "Audit record content lacks who/what/when/where/source/outcome")])
}

violation contains msg if {
	not input.au_controls.storage_capacity.adequate
	msg := sprintf("NIST AU-4: %s", [_au_detail(["storage_capacity.adequate"], "Audit record storage capacity insufficient for required retention")])
}

violation contains msg if {
	not input.au_controls.response_to_failures.alerting
	msg := sprintf("NIST AU-5: %s", [_au_detail(["response_to_failures.alerting"], "Audit logging failure does not alert appropriate personnel")])
}

violation contains msg if {
	not input.au_controls.review_and_analysis.regular
	msg := sprintf("NIST AU-6: %s", [_au_detail(["review_and_analysis.regular"], "Audit records not regularly reviewed or analyzed")])
}

violation contains msg if {
	not input.au_controls.reduction_and_reporting.tools_available
	msg := sprintf("NIST AU-7: %s", [_au_detail(["reduction_and_reporting.tools_available"], "Audit record reduction/report-generation tooling unavailable")])
}

# AU-8 Time Stamps: internal clocks generate time stamps in UTC, with a fixed UTC offset, or with the
# offset recorded. Synchronisation to an authoritative source was AU-8(1), withdrawn in Rev 5 and moved to
# SC-45(1) (evaluated in the SC family); au_controls.time_stamps.synchronized is no longer read here.
violation contains msg if {
	not input.au_controls.time_stamps.utc_or_offset_recorded == true
	msg := sprintf("NIST AU-8: %s", [_au_detail(["time_stamps.utc_or_offset_recorded"], "Audit record time stamps not evidenced as UTC, fixed UTC offset, or recorded offset (input.au_controls.time_stamps.utc_or_offset_recorded)")])
}

violation contains msg if {
	not input.au_controls.protection_of_records.tamper_resistant
	msg := sprintf("NIST AU-9: %s", [_au_detail(["protection_of_records.tamper_resistant"], "Audit records not protected against unauthorized modification/deletion")])
}

violation contains msg if {
	not input.au_controls.non_repudiation.implemented
	msg := sprintf("NIST AU-10: %s", [_au_detail(["non_repudiation.implemented"], "Non-repudiation of actions by individuals not implemented")])
}

# AU-11 Audit Record Retention: "Retain audit records for [ODP time period] ...". NIST fixes no period;
# the organisation supplies it as input.au_controls.odp.retention_period_days. Either value missing is
# reported as missing evidence.
_au11_retained := object.get(input, ["au_controls", "retention_period_days"], null)

_au11_odp := object.get(input, ["au_controls", "odp", "retention_period_days"], null)

_au11_missing contains "input.au_controls.retention_period_days" if not is_number(_au11_retained)

_au11_missing contains "input.au_controls.odp.retention_period_days (organization-defined period)" if not is_number(_au11_odp)

violation contains msg if {
	count(_au11_missing) > 0
	msg := sprintf("NIST AU-11: evidence missing — %s not collected", [concat(", ", sort(_au11_missing))])
}

violation contains msg if {
	count(_au11_missing) == 0
	_au11_retained < _au11_odp
	msg := sprintf(
		"NIST AU-11: Audit record retention %v days is below the organization-defined %v days",
		[_au11_retained, _au11_odp],
	)
}

violation contains msg if {
	not input.au_controls.generation.required_events_captured
	msg := sprintf("NIST AU-12: %s", [_au_detail(["generation.required_events_captured"], "Audit record generation does not capture all required events")])
}

# ── Moderate-baseline enhancements (NIST SP 800-53B) ─────────────────────

_au_nonempty_array(v) if {
	is_array(v)
	count(v) > 0
}

_au_list_missing(ps) := {concat("", [_au_path(p), " (non-empty list)"]) | some p in ps; not _au_nonempty_array(_au_get(p))}

_au_array_missing(ps) := {concat("", [_au_path(p), " (list)"]) | some p in ps; not is_array(_au_get(p))}

_au_num_missing(ps) := {_au_path(p) | some p in ps; not is_number(_au_get(p))}

_au_bool_false(ps) := {sprintf("%s is not true", [_au_path(p)]) | some p in ps; _au_get(p) == false}

# Organization-defined items (odp) that the observed list (obs) lacks; `what` names the items.
_au_lacking(obs, odp, what) := {sprintf("%s not covered: %v (%s)", [what, sort(lack), _au_path(obs)]) |
	o := _au_get(obs)
	l := _au_get(odp)
	is_array(o)
	is_array(l)
	lack := {x | some x in l; not x in o}
	count(lack) > 0
}

_au_nonzero(p, what) := {sprintf("%v %s (%s)", [v, what, _au_path(p)]) |
	v := _au_get(p)
	is_number(v)
	v > 0
}

# AU-3(1) Additional Audit Information: audit records carry the organization-defined additional information.
# Facts (input.au_controls.content_of_records.additional_information): odp.fields (non-empty list of the
# organization-defined fields); fields_present (list of the fields the generated records contain).
_au3_1 := "content_of_records.additional_information"

_au3_1_missing := _au_list_missing([concat(".", [_au3_1, "odp.fields"])]) | _au_array_missing([concat(".", [_au3_1, "fields_present"])])

_au3_1_failed := _au_lacking(concat(".", [_au3_1, "fields_present"]), concat(".", [_au3_1, "odp.fields"]), "organization-defined audit record fields")

# AU-6(1) Automated Process Integration: audit review, analysis and reporting are integrated using the
# organization-defined automated mechanisms.
# Facts (input.au_controls.review_and_analysis.automated_integration): odp.mechanisms (non-empty list);
# mechanisms_integrated (list of the mechanisms the review process is observed to use, e.g. SIEM, SOAR).
_au6_1 := "review_and_analysis.automated_integration"

_au6_1_missing := _au_list_missing([concat(".", [_au6_1, "odp.mechanisms"])]) | _au_array_missing([concat(".", [_au6_1, "mechanisms_integrated"])])

_au6_1_failed := _au_lacking(concat(".", [_au6_1, "mechanisms_integrated"]), concat(".", [_au6_1, "odp.mechanisms"]), "organization-defined automated mechanisms")

# AU-6(3) Correlate Audit Record Repositories: audit records are analyzed and correlated across repositories.
# Facts (input.au_controls.review_and_analysis.correlation): correlation_enabled (boolean);
# uncorrelated_repositories (count of audit record repositories not fed into the correlation).
_au6_3 := "review_and_analysis.correlation"

_au6_3_missing := _au_bool_missing([concat(".", [_au6_3, "correlation_enabled"])]) | _au_num_missing([concat(".", [_au6_3, "uncorrelated_repositories"])])

_au6_3_failed := _au_bool_false([concat(".", [_au6_3, "correlation_enabled"])]) | _au_nonzero(concat(".", [_au6_3, "uncorrelated_repositories"]), "audit record repositories not correlated")

# AU-7(1) Automatic Processing: audit records can be processed, sorted and searched for events of interest by the
# organization-defined fields.
# Facts (input.au_controls.reduction_and_reporting.automatic_processing): odp.fields (non-empty list);
# searchable_fields (list); sort_supported (boolean).
_au7_1 := "reduction_and_reporting.automatic_processing"

_au7_1_missing := (_au_list_missing([concat(".", [_au7_1, "odp.fields"])]) | _au_array_missing([concat(".", [_au7_1, "searchable_fields"])])) | _au_bool_missing([concat(".", [_au7_1, "sort_supported"])])

_au7_1_failed := _au_lacking(concat(".", [_au7_1, "searchable_fields"]), concat(".", [_au7_1, "odp.fields"]), "organization-defined search fields") | _au_bool_false([concat(".", [_au7_1, "sort_supported"])])

# AU-9(4) Access by Subset of Privileged Users: management of audit logging is limited to the organization-defined
# subset of privileged users or roles.
# Facts (input.au_controls.protection_of_records.management_access): odp.authorized_roles (non-empty list);
# accounts_outside_authorized_roles (count of accounts able to manage audit logging that are not in those roles).
_au9_4 := "protection_of_records.management_access"

_au9_4_missing := _au_list_missing([concat(".", [_au9_4, "odp.authorized_roles"])]) | _au_num_missing([concat(".", [_au9_4, "accounts_outside_authorized_roles"])])

_au9_4_failed := _au_nonzero(concat(".", [_au9_4, "accounts_outside_authorized_roles"]), "accounts able to manage audit logging outside the organization-defined roles")

violation contains sprintf("NIST AU-3(1): %s", [_au_enh_detail(_au3_1_missing, _au3_1_failed)]) if count(_au3_1_missing | _au3_1_failed) > 0

violation contains sprintf("NIST AU-6(1): %s", [_au_enh_detail(_au6_1_missing, _au6_1_failed)]) if count(_au6_1_missing | _au6_1_failed) > 0

violation contains sprintf("NIST AU-6(3): %s", [_au_enh_detail(_au6_3_missing, _au6_3_failed)]) if count(_au6_3_missing | _au6_3_failed) > 0

violation contains sprintf("NIST AU-7(1): %s", [_au_enh_detail(_au7_1_missing, _au7_1_failed)]) if count(_au7_1_missing | _au7_1_failed) > 0

violation contains sprintf("NIST AU-9(4): %s", [_au_enh_detail(_au9_4_missing, _au9_4_failed)]) if count(_au9_4_missing | _au9_4_failed) > 0

compliant if count(violation) == 0

# The control and enhancement ids this family evaluates; each has exactly one finding when it fails.
evaluated_controls := {
	"AU-1", "AU-2", "AU-3", "AU-3(1)", "AU-4", "AU-5", "AU-6", "AU-6(1)", "AU-6(3)", "AU-7", "AU-7(1)", "AU-8", "AU-9",
	"AU-9(4)", "AU-10", "AU-11", "AU-12",
}

compliance_report := {
	"family": "AU",
	"name": "Audit and Accountability",
	"controls_evaluated": count(evaluated_controls),
	"violations": violation,
	"violation_count": count(violation),
	"compliant": compliant,
}
