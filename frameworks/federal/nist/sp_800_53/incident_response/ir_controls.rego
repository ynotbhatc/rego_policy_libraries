# METADATA
# title: "NIST SP 800-53 Rev 5 — Incident Response (IR) Family"
# custom:
#   class: compliance
#   framework: nist_sp_800_53
#   source: nist
#   domains: [us-federal, security-controls]
#   coverage:
#     checks: 33
#     cited: 24
#     density: sized
#     basis: size
#     tested: true
#     entrypoint: compliance_report
#     guard: self
#     as_of: v2.5.0
package nist.sp800_53.incident_response

import rego.v1

# NIST SP 800-53 Rev 5 — Incident Response (IR) Family
# Detect, analyze, contain, eradicate, and recover from incidents. Base controls IR-1 to IR-9 and the
# enhancements the NIST SP 800-53B Moderate and High baselines (and FedRAMP High) select. An enhancement is its own requirement with its own finding; a
# base control never fails for an enhancement.
#
# IR-1 and IR-4 to IR-9 read one boolean fact each and pass only when it is true; a fact that is absent or not a
# boolean ("true", 1, null) is reported as evidence missing, a fact that is false keeps its original message. The
# enhancements (Moderate, then High) fail closed: a fact that is absent or of the wrong type is evidence missing,
# booleans pass only on true, numbers are checked with is_number before any comparison.

default compliant := false

_get(path) := object.get(input, array.concat(["ir_controls"], split(path, ".")), null)

_path(p) := concat("", ["input.ir_controls.", p])

_missing_txt(paths) := sprintf("evidence missing — %s not collected", [concat(", ", sort(paths))])

# Required booleans that are absent or not a boolean ("true", 1 and null are not evidence).
_bool_missing(paths) := {_path(p) |
	some p in paths
	not is_boolean(_get(p))
}

# Required booleans that are present and false: `checks` is a list of [path, text when false].
_bool_false(checks) := {sprintf("%s (%s is false)", [c[1], _path(c[0])]) |
	some c in checks
	_get(c[0]) == false
}

_paths(checks) := [c[0] | some c in checks]

# Counts that must be zero. A non-number or a negative number is missing evidence.
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

# One finding per id: every unmet element, then the evidence that was not collected.
_detail(missing, unmet) := _missing_txt(missing) if {
	count(missing) > 0
	count(unmet) == 0
} else := sprintf("%s; %s", [concat("; ", sort(unmet)), _missing_txt(missing)]) if {
	count(missing) > 0
} else := concat("; ", sort(unmet))

violation contains msg if {
	not is_boolean(_get("policy.documented"))
	msg := sprintf("NIST IR-1: %s", [_missing_txt({_path("policy.documented")})])
}

violation contains msg if {
	input.ir_controls.policy.documented == false
	msg := "NIST IR-1: Incident response policy and procedures not documented"
}

# IR-2 and IR-3 frequencies are organization-defined (IR-2 "[frequency] thereafter"; IR-3 "[frequency]").
# The organisation supplies the frequency in days under .odp.frequency_days; the observed age is compared
# with it. Either value missing is reported as missing evidence. (The old *_within_year booleans are not read.)
_freq_missing(path, obs, odp) := {m |
	some pair in [[obs, "days_since_last"], [odp, "odp.frequency_days (organization-defined frequency)"]]
	not is_number(pair[0])
	m := concat("", ["input.ir_controls.", path, ".", pair[1]])
}

_ir2 := object.get(input, ["ir_controls", "training"], {})

_ir2_missing := _freq_missing("training", object.get(_ir2, "days_since_last", null), object.get(_ir2, ["odp", "frequency_days"], null))

violation contains msg if {
	count(_ir2_missing) > 0
	msg := sprintf("NIST IR-2: evidence missing — %s not collected", [concat(", ", sort(_ir2_missing))])
}

violation contains msg if {
	count(_ir2_missing) == 0
	_ir2.days_since_last > _ir2.odp.frequency_days
	msg := sprintf("NIST IR-2: Incident response training last provided %v days ago; the organization-defined frequency is %v days", [_ir2.days_since_last, _ir2.odp.frequency_days])
}

_ir3 := object.get(input, ["ir_controls", "testing"], {})

_ir3_missing := _freq_missing("testing", object.get(_ir3, "days_since_last", null), object.get(_ir3, ["odp", "frequency_days"], null))

violation contains msg if {
	count(_ir3_missing) > 0
	msg := sprintf("NIST IR-3: evidence missing — %s not collected", [concat(", ", sort(_ir3_missing))])
}

violation contains msg if {
	count(_ir3_missing) == 0
	_ir3.days_since_last > _ir3.odp.frequency_days
	msg := sprintf("NIST IR-3: Incident response capability last tested %v days ago; the organization-defined frequency is %v days", [_ir3.days_since_last, _ir3.odp.frequency_days])
}

violation contains msg if {
	not is_boolean(_get("handling.process_defined"))
	msg := sprintf("NIST IR-4: %s", [_missing_txt({_path("handling.process_defined")})])
}

violation contains msg if {
	input.ir_controls.handling.process_defined == false
	msg := "NIST IR-4: Incident handling process (preparation/detection/analysis/containment/eradication/recovery) not defined"
}

# IR-5 Incident Monitoring: "Track and document incidents." (monitoring.continuous is not read: continuous
# monitoring is SI-4, not IR-5.)
violation contains msg if {
	not input.ir_controls.incident_tracking.tracked_and_documented == true
	not input.ir_controls.incident_tracking.tracked_and_documented == false
	msg := sprintf("NIST IR-5: %s", [_missing_txt({_path("incident_tracking.tracked_and_documented")})])
}

violation contains msg if {
	input.ir_controls.incident_tracking.tracked_and_documented == false
	msg := "NIST IR-5: Incidents not evidenced as tracked and documented (input.ir_controls.incident_tracking.tracked_and_documented)"
}

violation contains msg if {
	not is_boolean(_get("reporting.timely"))
	msg := sprintf("NIST IR-6: %s", [_missing_txt({_path("reporting.timely")})])
}

violation contains msg if {
	input.ir_controls.reporting.timely == false
	msg := "NIST IR-6: Incident reporting to internal/external parties not timely"
}

violation contains msg if {
	not is_boolean(_get("assistance.available"))
	msg := sprintf("NIST IR-7: %s", [_missing_txt({_path("assistance.available")})])
}

violation contains msg if {
	input.ir_controls.assistance.available == false
	msg := "NIST IR-7: Incident response assistance/coordination resources not available"
}

violation contains msg if {
	not is_boolean(_get("plan.documented"))
	msg := sprintf("NIST IR-8: %s", [_missing_txt({_path("plan.documented")})])
}

violation contains msg if {
	input.ir_controls.plan.documented == false
	msg := "NIST IR-8: Documented incident response plan does not exist"
}

violation contains msg if {
	not is_boolean(_get("information_spillage.process_defined"))
	msg := sprintf("NIST IR-9: %s", [_missing_txt({_path("information_spillage.process_defined")})])
}

violation contains msg if {
	input.ir_controls.information_spillage.process_defined == false
	msg := "NIST IR-9: Information spillage response process not defined"
}

# IR-3(2) Coordination with Related Plans: incident response testing is coordinated with the organizational
# elements responsible for related plans (contingency, continuity, crisis communications, and so on).
# Facts: testing.coordinated_with_related_plans (boolean, from the last test's after-action record).
_ir3_2_bools := [["testing.coordinated_with_related_plans", "incident response testing not coordinated with the owners of related plans"]]

_ir3_2_missing := _bool_missing(_paths(_ir3_2_bools))

_ir3_2_unmet := _bool_false(_ir3_2_bools)

violation contains msg if {
	count(_ir3_2_missing | _ir3_2_unmet) > 0
	msg := sprintf("NIST IR-3(2): %s", [_detail(_ir3_2_missing, _ir3_2_unmet)])
}

# IR-4(1) Automated Incident Handling Processes: the incident handling process is supported by automated
# mechanisms (case management, SOAR playbooks, automated containment).
# Facts: handling.automated_support.enabled (boolean: an automated mechanism supports incident handling).
_ir4_1_bools := [["handling.automated_support.enabled", "incident handling not supported by an automated mechanism"]]

_ir4_1_missing := _bool_missing(_paths(_ir4_1_bools))

_ir4_1_unmet := _bool_false(_ir4_1_bools)

violation contains msg if {
	count(_ir4_1_missing | _ir4_1_unmet) > 0
	msg := sprintf("NIST IR-4(1): %s", [_detail(_ir4_1_missing, _ir4_1_unmet)])
}

# IR-6(1) Automated Reporting: incidents are reported through automated mechanisms.
# Facts: reporting.automated.enabled (boolean: incidents are reported by an automated mechanism);
#        reporting.automated.incidents_reported_manually_only (number of incidents in the review period that
#        reached no automated reporting channel; must be 0).
_ir6_1_bools := [["reporting.automated.enabled", "incidents not reported through an automated mechanism"]]

_ir6_1_zeros := [["reporting.automated.incidents_reported_manually_only", "%v incidents not reported through the automated mechanism"]]

_ir6_1_missing := _bool_missing(_paths(_ir6_1_bools)) | _zero_missing(_paths(_ir6_1_zeros))

_ir6_1_unmet := _bool_false(_ir6_1_bools) | _zero_unmet(_ir6_1_zeros)

violation contains msg if {
	count(_ir6_1_missing | _ir6_1_unmet) > 0
	msg := sprintf("NIST IR-6(1): %s", [_detail(_ir6_1_missing, _ir6_1_unmet)])
}

# IR-6(3) Supply Chain Coordination: incident information is provided to the product or service provider and to
# the other organizations in the supply chain for components related to the incident.
# Facts: reporting.supply_chain.incidents_not_shared (number of incidents in the review period involving a
#        supplied product or service whose provider was not given the incident information; must be 0).
_ir6_3_zeros := [["reporting.supply_chain.incidents_not_shared", "%v supply-chain-related incidents not shared with the provider or other supply chain organizations"]]

_ir6_3_missing := _zero_missing(_paths(_ir6_3_zeros))

_ir6_3_unmet := _zero_unmet(_ir6_3_zeros)

violation contains msg if {
	count(_ir6_3_missing | _ir6_3_unmet) > 0
	msg := sprintf("NIST IR-6(3): %s", [_detail(_ir6_3_missing, _ir6_3_unmet)])
}

# IR-7(1) Automation Support for Availability of Information and Support: incident response information and
# support are made more available through automated mechanisms (self-service portal, knowledge base, chat).
# Facts: assistance.automated_support.enabled (boolean).
_ir7_1_bools := [["assistance.automated_support.enabled", "incident response information and support not made available through an automated mechanism"]]

_ir7_1_missing := _bool_missing(_paths(_ir7_1_bools))

_ir7_1_unmet := _bool_false(_ir7_1_bools)

violation contains msg if {
	count(_ir7_1_missing | _ir7_1_unmet) > 0
	msg := sprintf("NIST IR-7(1): %s", [_detail(_ir7_1_missing, _ir7_1_unmet)])
}

# ---------------------------------------------------------------------------------------------------------------
# High-baseline enhancements (NIST SP 800-53B High and FedRAMP High). Each reads only its own keys, nested under
# its base control's object, and has its own single finding.
# ---------------------------------------------------------------------------------------------------------------

# Organization-defined maximum: the observed number at <path>.<obs> may not exceed <path>.odp.<odp>. Either one not
# a number is missing evidence. `fmt` takes the observed value and the organization-defined value.
_max_missing(path, obs, odp) := {_path(concat(".", [path, k[0]])) |
	some k in [[obs, _get(concat(".", [path, obs]))], [concat(".", ["odp", odp]), _get(concat(".", [path, "odp", odp]))]]
	not is_number(k[1])
}

_max_over(path, obs, odp, fmt) := {sprintf(fmt, [n, m]) |
	n := _get(concat(".", [path, obs]))
	m := _get(concat(".", [path, "odp", odp]))
	is_number(n)
	is_number(m)
	n > m
}

# Organization-defined lists: <path>.odp.<odp> is the non-empty list the organisation requires and <path>.<obs> the
# list observed. Either not a list (or the ODP list empty) is missing evidence; each required item not observed is
# a finding.
_nonempty_array(x) if {
	is_array(x)
	count(x) > 0
}

_list_missing(path, obs, odp) := {_path(concat(".", [path, obs])) |
	not is_array(_get(concat(".", [path, obs])))
} | {concat("", [_path(concat(".", [path, "odp", odp])), " (organization-defined)"]) |
	not _nonempty_array(_get(concat(".", [path, "odp", odp])))
}

_list_unmet(path, obs, odp, fmt) := {sprintf(fmt, [x]) |
	seen := _get(concat(".", [path, obs]))
	req := _get(concat(".", [path, "odp", odp]))
	is_array(seen)
	_nonempty_array(req)
	some x in req
	not x in seen
}

# Attestation: for an organizational control with no machine-checkable evidence, the only accepted evidence is
# {"attested": true, "by": <non-empty string>, "date": <non-empty string>} at input.ir_controls.<path>.attestation.
_attested(a) if {
	a.attested == true
	is_string(a.by)
	trim_space(a.by) != ""
	is_string(a.date)
	trim_space(a.date) != ""
}

_att_note := "this control has no machine-checkable evidence and is met only by an attestation {attested: true, by: <name>, date: <date>}"

_att_detail(path) := sprintf("evidence missing — %s not collected; not attested: %s", [_path(concat(".", [path, "attestation"])), _att_note]) if {
	_get(concat(".", [path, "attestation"])) == null
} else := sprintf("%s is not a complete attestation; not attested: %s", [_path(concat(".", [path, "attestation"])), _att_note]) if {
	not _attested(_get(concat(".", [path, "attestation"])))
}

# IR-2(1) Simulated Events: incident response training includes simulated events (tabletop, live-fire, red team
# scenarios) so personnel can respond in a crisis.
# Facts: training.simulated_events.included_in_last_training (boolean, from the last training record).
_ir2_1_bools := [["training.simulated_events.included_in_last_training", "incident response training does not incorporate simulated events"]]

_ir2_1_missing := _bool_missing(_paths(_ir2_1_bools))

_ir2_1_unmet := _bool_false(_ir2_1_bools)

violation contains msg if {
	count(_ir2_1_missing | _ir2_1_unmet) > 0
	msg := sprintf("NIST IR-2(1): %s", [_detail(_ir2_1_missing, _ir2_1_unmet)])
}

# IR-2(2) Automated Training Environments: an incident response training environment is provided using the
# organization-defined automated mechanisms (a cyber range, an automated exercise platform).
# Facts (input.ir_controls.training.automated_environment): odp.mechanisms (organization-defined list);
# mechanisms_in_use (mechanisms the training environment actually provides).
_ir2_2_missing := _list_missing("training.automated_environment", "mechanisms_in_use", "mechanisms")

_ir2_2_unmet := _list_unmet("training.automated_environment", "mechanisms_in_use", "mechanisms", "incident response training environment does not provide automated mechanism %v")

violation contains msg if {
	count(_ir2_2_missing | _ir2_2_unmet) > 0
	msg := sprintf("NIST IR-2(2): %s", [_detail(_ir2_2_missing, _ir2_2_unmet)])
}

# IR-4(2) Dynamic Reconfiguration: the incident response capability includes the organization-defined types of
# dynamic reconfiguration (for example firewall or router rule changes, access list changes, traffic rerouting)
# for the organization-defined system components.
# Facts (input.ir_controls.handling.dynamic_reconfiguration): odp.reconfiguration_types (organization-defined
# list); supported_reconfiguration_types (types the response tooling can apply, from the SOAR playbook catalogue).
_ir4_2_missing := _list_missing("handling.dynamic_reconfiguration", "supported_reconfiguration_types", "reconfiguration_types")

_ir4_2_unmet := _list_unmet("handling.dynamic_reconfiguration", "supported_reconfiguration_types", "reconfiguration_types", "incident response capability cannot perform dynamic reconfiguration %v")

violation contains msg if {
	count(_ir4_2_missing | _ir4_2_unmet) > 0
	msg := sprintf("NIST IR-4(2): %s", [_detail(_ir4_2_missing, _ir4_2_unmet)])
}

# IR-4(4) Information Correlation: incident information and individual responses are correlated for an
# organization-wide view.
# Facts (input.ir_controls.handling.correlation): enabled (boolean: incidents from every system feed one
# correlation platform, a SIEM or case management system); incidents_not_correlated (number of incidents in the
# review period that were never linked into the organization-wide view; must be 0).
_ir4_4_bools := [["handling.correlation.enabled", "incident information not correlated into an organization-wide view"]]

_ir4_4_zeros := [["handling.correlation.incidents_not_correlated", "%v incidents not correlated with the organization-wide incident view"]]

_ir4_4_missing := _bool_missing(_paths(_ir4_4_bools)) | _zero_missing(_paths(_ir4_4_zeros))

_ir4_4_unmet := _bool_false(_ir4_4_bools) | _zero_unmet(_ir4_4_zeros)

violation contains msg if {
	count(_ir4_4_missing | _ir4_4_unmet) > 0
	msg := sprintf("NIST IR-4(4): %s", [_detail(_ir4_4_missing, _ir4_4_unmet)])
}

# IR-4(6) Insider Threats: an incident handling capability for incidents involving insider threats.
# Facts: handling.insider_threat.playbook_in_place (boolean: the incident handling process has an insider threat
# playbook with assigned handlers).
_ir4_6_bools := [["handling.insider_threat.playbook_in_place", "no incident handling capability for incidents involving insider threats"]]

_ir4_6_missing := _bool_missing(_paths(_ir4_6_bools))

_ir4_6_unmet := _bool_false(_ir4_6_bools)

violation contains msg if {
	count(_ir4_6_missing | _ir4_6_unmet) > 0
	msg := sprintf("NIST IR-4(6): %s", [_detail(_ir4_6_missing, _ir4_6_unmet)])
}

# IR-4(11) Integrated Incident Response Team: an integrated incident response team is established and maintained
# that can deploy to any organization-identified location within the organization-defined period.
# Facts (input.ir_controls.handling.integrated_team): established (boolean); deployment_hours (longest
# demonstrated or planned deployment time to an identified location) + odp.deployment_hours.
_ir4_11_bools := [["handling.integrated_team.established", "no integrated incident response team established and maintained"]]

_ir4_11_missing := _bool_missing(_paths(_ir4_11_bools)) | _max_missing("handling.integrated_team", "deployment_hours", "deployment_hours")

_ir4_11_unmet := _bool_false(_ir4_11_bools) | _max_over("handling.integrated_team", "deployment_hours", "deployment_hours", "integrated incident response team deploys in %v hours; the organization-defined period is %v hours")

violation contains msg if {
	count(_ir4_11_missing | _ir4_11_unmet) > 0
	msg := sprintf("NIST IR-4(11): %s", [_detail(_ir4_11_missing, _ir4_11_unmet)])
}

# IR-5(1) Automated Tracking, Data Collection, and Analysis: incidents tracked and incident information collected
# and analysed with automated mechanisms.
# Facts (input.ir_controls.incident_tracking.automated): enabled (boolean: an incident tracking system collects
# and analyses incident data); incidents_tracked_manually_only (number of incidents in the review period recorded
# outside the automated mechanism; must be 0).
_ir5_1_bools := [["incident_tracking.automated.enabled", "incidents not tracked and analysed with an automated mechanism"]]

_ir5_1_zeros := [["incident_tracking.automated.incidents_tracked_manually_only", "%v incidents tracked outside the automated mechanism"]]

_ir5_1_missing := _bool_missing(_paths(_ir5_1_bools)) | _zero_missing(_paths(_ir5_1_zeros))

_ir5_1_unmet := _bool_false(_ir5_1_bools) | _zero_unmet(_ir5_1_zeros)

violation contains msg if {
	count(_ir5_1_missing | _ir5_1_unmet) > 0
	msg := sprintf("NIST IR-5(1): %s", [_detail(_ir5_1_missing, _ir5_1_unmet)])
}

# IR-9(2) Training: information spillage response training provided at the organization-defined frequency.
# Facts (input.ir_controls.information_spillage.training): days_since_last + odp.frequency_days.
_ir9_2_missing := _freq_missing("information_spillage.training", _get("information_spillage.training.days_since_last"), _get("information_spillage.training.odp.frequency_days"))

_ir9_2_unmet := _max_over("information_spillage.training", "days_since_last", "frequency_days", "information spillage response training last provided %v days ago; the organization-defined frequency is %v days")

violation contains msg if {
	count(_ir9_2_missing | _ir9_2_unmet) > 0
	msg := sprintf("NIST IR-9(2): %s", [_detail(_ir9_2_missing, _ir9_2_unmet)])
}

# IR-9(3) Post-spill Operations: the organization-defined procedures let personnel affected by a spill keep
# working while contaminated systems are corrected. An organizational arrangement with no machine-checkable
# evidence.
# Facts: input.ir_controls.information_spillage.post_spill_operations.attestation.
violation contains msg if {
	msg := sprintf("NIST IR-9(3): %s", [_att_detail("information_spillage.post_spill_operations")])
}

# IR-9(4) Exposure to Unauthorized Personnel: the organization-defined controls are applied to personnel exposed
# to information outside their access authorizations.
# Facts (input.ir_controls.information_spillage.exposure): exposures_without_controls (number of spill cases in
# the review period where an exposed person was not put through the organization-defined controls, e.g. briefing
# and non-disclosure; from the spill case records; must be 0).
_ir9_4_zeros := [["information_spillage.exposure.exposures_without_controls", "%v cases of personnel exposed to unauthorized information without the organization-defined controls applied"]]

_ir9_4_missing := _zero_missing(_paths(_ir9_4_zeros))

_ir9_4_unmet := _zero_unmet(_ir9_4_zeros)

violation contains msg if {
	count(_ir9_4_missing | _ir9_4_unmet) > 0
	msg := sprintf("NIST IR-9(4): %s", [_detail(_ir9_4_missing, _ir9_4_unmet)])
}

compliant if count(violation) == 0

# The control and enhancement ids this family evaluates; each has exactly one finding when it fails.
evaluated_controls := {
	"IR-1", "IR-2", "IR-2(1)", "IR-2(2)", "IR-3", "IR-3(2)", "IR-4", "IR-4(1)", "IR-4(2)", "IR-4(4)", "IR-4(6)",
	"IR-4(11)", "IR-5", "IR-5(1)", "IR-6", "IR-6(1)", "IR-6(3)", "IR-7", "IR-7(1)", "IR-8", "IR-9", "IR-9(2)",
	"IR-9(3)", "IR-9(4)",
}

compliance_report := {
	"family": "IR",
	"name": "Incident Response",
	"controls_evaluated": count(evaluated_controls),
	"violations": violation,
	"violation_count": count(violation),
	"compliant": compliant,
}
