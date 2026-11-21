# METADATA
# title: "NIST SP 800-53 Rev 5 — Audit and Accountability (AU) Family"
# custom:
#   class: compliance
#   framework: nist_sp_800_53
#   source: nist
#   domains: [us-federal, security-controls]
#   coverage:
#     checks: 32
#     cited: 31
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
# Evaluated: AU-1..AU-14 and AU-16, the NIST SP 800-53B Moderate enhancements AU-3(1), AU-6(1), AU-6(3), AU-7(1),
# AU-9(4), and the NIST / FedRAMP High enhancements AU-5(1), AU-5(2), AU-6(4), AU-6(5), AU-6(6), AU-6(7), AU-9(2),
# AU-9(3), AU-12(1), AU-12(3), and the Privacy-baseline enhancement AU-3(3) (31 ids). AU-15 is withdrawn (moved to AU-5(5)).
# A base control never fails on an enhancement's requirement; each enhancement is its own finding.

default compliant := false

# ── Evidence helpers ─────────────────────────────────────────────────────
# A fact path is dotted below input.au_controls. A fact that is absent, null or of the wrong type is missing
# evidence, never a pass.
_au_get(p) := object.get(input, array.concat(["au_controls"], split(p, ".")), null)

_au_path(p) := concat(".", ["input.au_controls", p])

_au_bool_missing(ps) := {_au_path(p) | some p in ps; not is_boolean(_au_get(p))}

# Finding text for an existing boolean rule that fired: evidence missing when one of the facts it reads is absent
# or not a boolean, otherwise the rule's own text. Every such rule passes only on `== true` (strict since
# 2026-11-19: "yes", 1, "false" or an object no longer pass).
_au_detail(ps, text) := sprintf("evidence missing — %s not collected", [concat(", ", sort(m))]) if {
	m := _au_bool_missing(ps)
	count(m) > 0
} else := text

# Finding text for an enhancement: the missing evidence when any, otherwise the unmet elements.
_au_enh_detail(missing, failed) := sprintf("evidence missing — %s not collected", [concat(", ", sort(missing))]) if {
	count(missing) > 0
} else := concat("; ", sort(failed))

violation contains msg if {
	not input.au_controls.policy.documented == true
	msg := sprintf("NIST AU-1: %s", [_au_detail(["policy.documented"], "Audit and accountability policy not documented")])
}

violation contains msg if {
	not input.au_controls.event_logging.enabled == true
	msg := sprintf("NIST AU-2: %s", [_au_detail(["event_logging.enabled"], "Event types for logging not identified or event logging not enabled")])
}

violation contains msg if {
	not input.au_controls.content_of_records.adequate == true
	msg := sprintf("NIST AU-3: %s", [_au_detail(["content_of_records.adequate"], "Audit record content lacks who/what/when/where/source/outcome")])
}

violation contains msg if {
	not input.au_controls.storage_capacity.adequate == true
	msg := sprintf("NIST AU-4: %s", [_au_detail(["storage_capacity.adequate"], "Audit record storage capacity insufficient for required retention")])
}

violation contains msg if {
	not input.au_controls.response_to_failures.alerting == true
	msg := sprintf("NIST AU-5: %s", [_au_detail(["response_to_failures.alerting"], "Audit logging failure does not alert appropriate personnel")])
}

violation contains msg if {
	not input.au_controls.review_and_analysis.regular == true
	msg := sprintf("NIST AU-6: %s", [_au_detail(["review_and_analysis.regular"], "Audit records not regularly reviewed or analyzed")])
}

violation contains msg if {
	not input.au_controls.reduction_and_reporting.tools_available == true
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
	not input.au_controls.protection_of_records.tamper_resistant == true
	msg := sprintf("NIST AU-9: %s", [_au_detail(["protection_of_records.tamper_resistant"], "Audit records not protected against unauthorized modification/deletion")])
}

violation contains msg if {
	not input.au_controls.non_repudiation.implemented == true
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
	not input.au_controls.generation.required_events_captured == true
	msg := sprintf("NIST AU-12: %s", [_au_detail(["generation.required_events_captured"], "Audit record generation does not capture all required events")])
}

# ── Moderate-baseline enhancements (NIST SP 800-53B) ─────────────────────

_au_nonempty_array(v) if {
	is_array(v)
	count(v) > 0
}

_au_list_missing(ps) := {concat("", [_au_path(p), " (non-empty list)"]) | some p in ps; not _au_nonempty_array(_au_get(p))}

_au_array_missing(ps) := {concat("", [_au_path(p), " (list)"]) | some p in ps; not is_array(_au_get(p))}

# A count: a non-negative whole number; anything else is evidence missing.
_au_count_ok(x) if {
	is_number(x)
	x >= 0
	floor(x) == x
}

_au_count_missing(ps) := {_au_path(p) | some p in ps; not _au_count_ok(_au_get(p))}

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
	_au_count_ok(v)
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

_au6_3_missing := (_au_bool_missing([concat(".", [_au6_3, "correlation_enabled"])]) | _au_num_missing([concat(".", [_au6_3, "uncorrelated_repositories"])])) | _au_count_missing([concat(".", [_au6_3, "uncorrelated_repositories"])])

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

_au9_4_missing := (_au_list_missing([concat(".", [_au9_4, "odp.authorized_roles"])]) | _au_num_missing([concat(".", [_au9_4, "accounts_outside_authorized_roles"])])) | _au_count_missing([concat(".", [_au9_4, "accounts_outside_authorized_roles"])])

_au9_4_failed := _au_nonzero(concat(".", [_au9_4, "accounts_outside_authorized_roles"]), "accounts able to manage audit logging outside the organization-defined roles")

violation contains sprintf("NIST AU-3(1): %s", [_au_enh_detail(_au3_1_missing, _au3_1_failed)]) if count(_au3_1_missing | _au3_1_failed) > 0

violation contains sprintf("NIST AU-6(1): %s", [_au_enh_detail(_au6_1_missing, _au6_1_failed)]) if count(_au6_1_missing | _au6_1_failed) > 0

violation contains sprintf("NIST AU-6(3): %s", [_au_enh_detail(_au6_3_missing, _au6_3_failed)]) if count(_au6_3_missing | _au6_3_failed) > 0

violation contains sprintf("NIST AU-7(1): %s", [_au_enh_detail(_au7_1_missing, _au7_1_failed)]) if count(_au7_1_missing | _au7_1_failed) > 0

violation contains sprintf("NIST AU-9(4): %s", [_au_enh_detail(_au9_4_missing, _au9_4_failed)]) if count(_au9_4_missing | _au9_4_failed) > 0

# ── NIST and FedRAMP High-baseline ids and remaining base controls ───────
# Same shape as the Moderate enhancements: a set of missing evidence and a set of unmet elements per id.

_au_f(base, f) := concat(".", [base, f])

# The observed value may not exceed the organization-defined value; both must be numbers.
_au_over(obs, odp, fmt) := {sprintf(fmt, [o, l]) |
	o := _au_get(obs)
	l := _au_get(odp)
	is_number(o)
	is_number(l)
	o > l
}

# Organizational element with no machine-checkable evidence: {attested: true, by, date} at <base>.attestation.
_au_attested(base) if {
	a := _au_get(_au_f(base, "attestation"))
	a.attested == true
	is_string(a.by)
	trim_space(a.by) != ""
	is_string(a.date)
	trim_space(a.date) != ""
}

# AU-5(1) Storage Capacity Warning: a warning reaches the organization-defined personnel, roles or locations
# within the organization-defined period when audit log storage reaches the organization-defined percentage.
# Facts (input.au_controls.response_to_failures.storage_warning): warning_threshold_percent (configured) +
# odp.threshold_percent; warning_delivery_minutes (configured or longest observed) + odp.within_minutes;
# odp.recipients (non-empty list); warning_recipients (list of the recipients the warning is configured to reach).
_au5_1 := "response_to_failures.storage_warning"

_au5_1_missing := (_au_num_missing([_au_f(_au5_1, f) | some f in ["warning_threshold_percent", "odp.threshold_percent", "warning_delivery_minutes", "odp.within_minutes"]]) | _au_list_missing([_au_f(_au5_1, "odp.recipients")])) | _au_array_missing([_au_f(_au5_1, "warning_recipients")])

_au5_1_failed := (_au_over(_au_f(_au5_1, "warning_threshold_percent"), _au_f(_au5_1, "odp.threshold_percent"), "storage warning fires at %v%% of capacity; the organization-defined percentage is %v%%") | _au_over(_au_f(_au5_1, "warning_delivery_minutes"), _au_f(_au5_1, "odp.within_minutes"), "storage warning delivered within %v minutes; the organization-defined period is %v minutes")) | _au_lacking(_au_f(_au5_1, "warning_recipients"), _au_f(_au5_1, "odp.recipients"), "organization-defined warning recipients")

# AU-5(2) Real-time Alerts: an alert reaches the organization-defined personnel, roles or locations within the
# organization-defined real-time period when the organization-defined audit failure events occur.
# Facts (input.au_controls.response_to_failures.real_time_alerts): odp.failure_events (non-empty list);
# alerted_events (list of failure events with a configured alert); alert_latency_seconds (configured or longest
# observed) + odp.within_seconds; odp.recipients (non-empty list).
_au5_2 := "response_to_failures.real_time_alerts"

_au5_2_missing := (_au_list_missing([_au_f(_au5_2, "odp.failure_events"), _au_f(_au5_2, "odp.recipients")]) | _au_array_missing([_au_f(_au5_2, "alerted_events")])) | _au_num_missing([_au_f(_au5_2, "alert_latency_seconds"), _au_f(_au5_2, "odp.within_seconds")])

_au5_2_failed := _au_lacking(_au_f(_au5_2, "alerted_events"), _au_f(_au5_2, "odp.failure_events"), "organization-defined audit failure events") | _au_over(_au_f(_au5_2, "alert_latency_seconds"), _au_f(_au5_2, "odp.within_seconds"), "audit failure alerts delivered within %v seconds; the organization-defined real-time period is %v seconds")

# AU-6(4) Central Review and Analysis: audit records from multiple components can be reviewed and analyzed
# centrally. Facts (input.au_controls.review_and_analysis.central_review): enabled (boolean: a central review
# capability such as a SIEM is in use); components_not_centralized (count of system components whose audit
# records do not reach it).
_au6_4 := "review_and_analysis.central_review"

_au6_4_missing := (_au_bool_missing([_au_f(_au6_4, "enabled")]) | _au_num_missing([_au_f(_au6_4, "components_not_centralized")])) | _au_count_missing([_au_f(_au6_4, "components_not_centralized")])

_au6_4_failed := _au_bool_false([_au_f(_au6_4, "enabled")]) | _au_nonzero(_au_f(_au6_4, "components_not_centralized"), "system components whose audit records are not centrally reviewed")

# AU-6(5) Integrated Analysis of Audit Records: analysis of audit records is integrated with analysis of the
# organization-defined sources (vulnerability scanning, performance data, system monitoring, other sources).
# Facts (input.au_controls.review_and_analysis.integrated_analysis): odp.sources (non-empty list);
# sources_integrated (list of the sources the audit analysis is observed to correlate with).
_au6_5 := "review_and_analysis.integrated_analysis"

_au6_5_missing := _au_list_missing([_au_f(_au6_5, "odp.sources")]) | _au_array_missing([_au_f(_au6_5, "sources_integrated")])

_au6_5_failed := _au_lacking(_au_f(_au6_5, "sources_integrated"), _au_f(_au6_5, "odp.sources"), "organization-defined analysis sources")

# AU-6(6) Correlation with Physical Monitoring: audit record information is correlated with physical access
# monitoring information. Facts (input.au_controls.review_and_analysis.physical_correlation): enabled (boolean:
# physical access logs are fed into and correlated with audit records); physical_access_sources_uncorrelated
# (count of physical access monitoring sources not correlated).
_au6_6 := "review_and_analysis.physical_correlation"

_au6_6_missing := (_au_bool_missing([_au_f(_au6_6, "enabled")]) | _au_num_missing([_au_f(_au6_6, "physical_access_sources_uncorrelated")])) | _au_count_missing([_au_f(_au6_6, "physical_access_sources_uncorrelated")])

_au6_6_failed := _au_bool_false([_au_f(_au6_6, "enabled")]) | _au_nonzero(_au_f(_au6_6, "physical_access_sources_uncorrelated"), "physical access monitoring sources not correlated with audit records")

# AU-6(7) Permitted Actions: the permitted review, analysis and reporting actions are specified for each
# organization-defined system process, role or user.
# Facts (input.au_controls.review_and_analysis.permitted_actions): odp.defined_for (non-empty list drawn from
# "system process", "role", "user"); entities_without_defined_actions (count of such entities with access to audit
# record information and no specified permitted actions).
_au6_7 := "review_and_analysis.permitted_actions"

_au6_7_kinds := {"system process", "role", "user"}

_au6_7_odp_ok if {
	l := _au_get(_au_f(_au6_7, "odp.defined_for"))
	_au_nonempty_array(l)
	every k in l {
		k in _au6_7_kinds
	}
}

_au6_7_missing contains concat("", [_au_path(_au_f(_au6_7, "odp.defined_for")), " (non-empty list of system process, role, user)"]) if {
	not _au6_7_odp_ok
}

_au6_7_missing contains m if {
	some m in _au_num_missing([_au_f(_au6_7, "entities_without_defined_actions")])
}

_au6_7_missing contains m if {
	some m in _au_count_missing([_au_f(_au6_7, "entities_without_defined_actions")])
}

_au6_7_failed := _au_nonzero(_au_f(_au6_7, "entities_without_defined_actions"), "processes, roles or users with access to audit information and no specified permitted actions")

# AU-9(2) Store on Separate Physical Systems or Components: audit records are stored at the organization-defined
# frequency in a repository on a physically different system or component.
# Facts (input.au_controls.protection_of_records.separate_system): stored_on_separate_system (boolean);
# hours_since_last_transfer (age of the newest record copied off the audited system) + odp.frequency_hours.
_au9_2 := "protection_of_records.separate_system"

_au9_2_missing := _au_bool_missing([_au_f(_au9_2, "stored_on_separate_system")]) | _au_num_missing([_au_f(_au9_2, "hours_since_last_transfer"), _au_f(_au9_2, "odp.frequency_hours")])

_au9_2_failed := _au_bool_false([_au_f(_au9_2, "stored_on_separate_system")]) | _au_over(_au_f(_au9_2, "hours_since_last_transfer"), _au_f(_au9_2, "odp.frequency_hours"), "audit records last stored to the separate repository %v hours ago; the organization-defined frequency is %v hours")

# AU-9(3) Cryptographic Protection: cryptographic mechanisms protect the integrity of audit information and audit
# tools. Facts (input.au_controls.protection_of_records.cryptographic): records_integrity_protected,
# tools_integrity_protected (booleans: e.g. signed or hash-chained logs; signed audit tool binaries).
_au9_3 := [_au_f("protection_of_records.cryptographic", f) | some f in ["records_integrity_protected", "tools_integrity_protected"]]

_au9_3_missing := _au_bool_missing(_au9_3)

_au9_3_failed := _au_bool_false(_au9_3)

# AU-12(1) System-wide and Time-correlated Audit Trail: audit records from the organization-defined components are
# compiled into a system-wide trail, time-correlated within the organization-defined tolerance.
# Facts (input.au_controls.generation.system_wide_trail): odp.components (non-empty list); components_in_trail
# (list); max_time_skew_ms (largest observed clock skew between contributing components) + odp.tolerance_ms.
_au12_1 := "generation.system_wide_trail"

_au12_1_missing := (_au_list_missing([_au_f(_au12_1, "odp.components")]) | _au_array_missing([_au_f(_au12_1, "components_in_trail")])) | _au_num_missing([_au_f(_au12_1, "max_time_skew_ms"), _au_f(_au12_1, "odp.tolerance_ms")])

_au12_1_failed := _au_lacking(_au_f(_au12_1, "components_in_trail"), _au_f(_au12_1, "odp.components"), "organization-defined components") | _au_over(_au_f(_au12_1, "max_time_skew_ms"), _au_f(_au12_1, "odp.tolerance_ms"), "audit trail time-correlated within %v ms; the organization-defined tolerance is %v ms")

# AU-12(3) Changes by Authorized Individuals: the organization-defined individuals or roles can change the logging
# on the organization-defined components within the organization-defined time thresholds.
# Facts (input.au_controls.generation.authorized_changes): capability_enabled (boolean); odp.roles (non-empty list);
# accounts_outside_roles (count of accounts able to change logging that are not in those roles);
# max_minutes_to_apply (longest observed time for a logging change to take effect) + odp.within_minutes.
_au12_3 := "generation.authorized_changes"

_au12_3_missing := ((_au_bool_missing([_au_f(_au12_3, "capability_enabled")]) | _au_list_missing([_au_f(_au12_3, "odp.roles")])) | _au_num_missing([_au_f(_au12_3, f) | some f in ["accounts_outside_roles", "max_minutes_to_apply", "odp.within_minutes"]])) | _au_count_missing([_au_f(_au12_3, "accounts_outside_roles")])

_au12_3_failed := (_au_bool_false([_au_f(_au12_3, "capability_enabled")]) | _au_nonzero(_au_f(_au12_3, "accounts_outside_roles"), "accounts able to change logging outside the organization-defined roles")) | _au_over(_au_f(_au12_3, "max_minutes_to_apply"), _au_f(_au12_3, "odp.within_minutes"), "logging changes took up to %v minutes to apply; the organization-defined threshold is %v minutes")

# AU-13 Monitoring for Information Disclosure: the organization-defined open-source information and sites are
# monitored at the organization-defined frequency, and a discovered disclosure is notified to the
# organization-defined personnel. Facts (input.au_controls.information_disclosure_monitoring): odp.sources
# (non-empty list); days_since_last (last monitoring run) + odp.frequency_days; disclosures_not_notified (count of
# disclosures found in the review period not notified to the organization-defined personnel or roles).
_au13 := "information_disclosure_monitoring"

_au13_missing := (_au_list_missing([_au_f(_au13, "odp.sources")]) | _au_num_missing([_au_f(_au13, f) | some f in ["days_since_last", "odp.frequency_days", "disclosures_not_notified"]])) | _au_count_missing([_au_f(_au13, "disclosures_not_notified")])

_au13_failed := _au_over(_au_f(_au13, "days_since_last"), _au_f(_au13, "odp.frequency_days"), "information disclosure monitoring last run %v days ago; the organization-defined frequency is %v days") | _au_nonzero(_au_f(_au13, "disclosures_not_notified"), "discovered information disclosures not notified")

# AU-14 Session Audit: the organization-defined users or roles can record, view, hear or log user session content,
# and session auditing is developed and used in consultation with legal counsel.
# Facts (input.au_controls.session_audit): capability_enabled (boolean); odp.roles (non-empty list);
# legal_consultation.attestation {attested: true, by, date} (organizational element, no machine-checkable evidence).
_au14 := "session_audit"

_au14_missing := (_au_bool_missing([_au_f(_au14, "capability_enabled")]) | _au_list_missing([_au_f(_au14, "odp.roles")])) | {concat("", [_au_path(_au_f(_au14, "legal_consultation.attestation")), " (legal counsel consultation not attested)"]) | not _au_attested(_au_f(_au14, "legal_consultation"))}

_au14_failed := _au_bool_false([_au_f(_au14, "capability_enabled")])

# AU-16 Cross-organizational Audit Logging: the organization-defined methods coordinate the organization-defined
# audit information among external organizations when it crosses organizational boundaries.
# Facts (input.au_controls.cross_organizational): odp.methods (non-empty list); methods_in_use (list);
# external_transfers_without_coordination (count of cross-boundary audit flows with no coordination method).
_au16 := "cross_organizational"

_au16_missing := ((_au_list_missing([_au_f(_au16, "odp.methods")]) | _au_array_missing([_au_f(_au16, "methods_in_use")])) | _au_num_missing([_au_f(_au16, "external_transfers_without_coordination")])) | _au_count_missing([_au_f(_au16, "external_transfers_without_coordination")])

_au16_failed := _au_lacking(_au_f(_au16, "methods_in_use"), _au_f(_au16, "odp.methods"), "organization-defined coordination methods") | _au_nonzero(_au_f(_au16, "external_transfers_without_coordination"), "cross-boundary audit information flows without a coordination method")

violation contains sprintf("NIST AU-5(1): %s", [_au_enh_detail(_au5_1_missing, _au5_1_failed)]) if count(_au5_1_missing | _au5_1_failed) > 0

violation contains sprintf("NIST AU-5(2): %s", [_au_enh_detail(_au5_2_missing, _au5_2_failed)]) if count(_au5_2_missing | _au5_2_failed) > 0

violation contains sprintf("NIST AU-6(4): %s", [_au_enh_detail(_au6_4_missing, _au6_4_failed)]) if count(_au6_4_missing | _au6_4_failed) > 0

violation contains sprintf("NIST AU-6(5): %s", [_au_enh_detail(_au6_5_missing, _au6_5_failed)]) if count(_au6_5_missing | _au6_5_failed) > 0

violation contains sprintf("NIST AU-6(6): %s", [_au_enh_detail(_au6_6_missing, _au6_6_failed)]) if count(_au6_6_missing | _au6_6_failed) > 0

violation contains sprintf("NIST AU-6(7): %s", [_au_enh_detail(_au6_7_missing, _au6_7_failed)]) if count(_au6_7_missing | _au6_7_failed) > 0

violation contains sprintf("NIST AU-9(2): %s", [_au_enh_detail(_au9_2_missing, _au9_2_failed)]) if count(_au9_2_missing | _au9_2_failed) > 0

violation contains sprintf("NIST AU-9(3): %s", [_au_enh_detail(_au9_3_missing, _au9_3_failed)]) if count(_au9_3_missing | _au9_3_failed) > 0

violation contains sprintf("NIST AU-12(1): %s", [_au_enh_detail(_au12_1_missing, _au12_1_failed)]) if count(_au12_1_missing | _au12_1_failed) > 0

violation contains sprintf("NIST AU-12(3): %s", [_au_enh_detail(_au12_3_missing, _au12_3_failed)]) if count(_au12_3_missing | _au12_3_failed) > 0

violation contains sprintf("NIST AU-13: %s", [_au_enh_detail(_au13_missing, _au13_failed)]) if count(_au13_missing | _au13_failed) > 0

violation contains sprintf("NIST AU-14: %s", [_au_enh_detail(_au14_missing, _au14_failed)]) if count(_au14_missing | _au14_failed) > 0

violation contains sprintf("NIST AU-16: %s", [_au_enh_detail(_au16_missing, _au16_failed)]) if count(_au16_missing | _au16_failed) > 0

compliant if count(violation) == 0

# ---------------------------------------------------------------------------------------------------------
# NIST SP 800-53B Privacy-baseline enhancements. Each is its own requirement; its base control never fails for it.
# ---------------------------------------------------------------------------------------------------------

# AU-3(3) Limit Personally Identifiable Information Elements: audit records contain only the PII elements the
# privacy risk assessment identified.
# Facts (input.au_controls.content_of_records.pii_elements): odp.permitted_elements (non-empty list of the
# organization-defined elements); elements_present (list of the PII elements the generated records contain, from
# the audit record schema or a field scan; [] when they contain none).
_au3_3 := "content_of_records.pii_elements"

_au3_3_missing := _au_list_missing([_au_f(_au3_3, "odp.permitted_elements")]) | _au_array_missing([_au_f(_au3_3, "elements_present")])

_au3_3_failed := {sprintf("audit records contain PII elements outside the organization-defined list: %v (%s)", [sort(extra), _au_path(_au_f(_au3_3, "elements_present"))]) |
	o := _au_get(_au_f(_au3_3, "elements_present"))
	l := _au_get(_au_f(_au3_3, "odp.permitted_elements"))
	is_array(o)
	is_array(l)
	extra := {x | some x in o; not x in l}
	count(extra) > 0
}

violation contains sprintf("NIST AU-3(3): %s", [_au_enh_detail(_au3_3_missing, _au3_3_failed)]) if count(_au3_3_missing | _au3_3_failed) > 0

# The control and enhancement ids this family evaluates; each has exactly one finding when it fails.
evaluated_controls := {
	"AU-1", "AU-2", "AU-3", "AU-3(1)", "AU-4", "AU-5", "AU-5(1)", "AU-5(2)", "AU-6", "AU-6(1)", "AU-6(3)", "AU-6(4)",
	"AU-6(5)", "AU-6(6)", "AU-6(7)", "AU-7", "AU-7(1)", "AU-8", "AU-9", "AU-9(2)", "AU-9(3)", "AU-9(4)", "AU-10",
	"AU-11", "AU-12", "AU-12(1)", "AU-12(3)", "AU-13", "AU-14", "AU-16",
	"AU-3(3)",
}

compliance_report := {
	"family": "AU",
	"name": "Audit and Accountability",
	"controls_evaluated": count(evaluated_controls),
	"violations": violation,
	"violation_count": count(violation),
	"compliant": compliant,
}
