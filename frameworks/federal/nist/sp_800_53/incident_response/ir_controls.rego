# METADATA
# title: "NIST SP 800-53 Rev 5 — Incident Response (IR) Family"
# custom:
#   class: compliance
#   framework: nist_sp_800_53
#   source: nist
#   domains: [us-federal, security-controls]
#   coverage:
#     checks: 23
#     cited: 14
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
# NIST SP 800-53B Moderate-baseline enhancements. An enhancement is its own requirement with its own finding; a
# base control never fails for an enhancement.
#
# IR-1 and IR-4 to IR-9 read one fact each and pass as before when it is set; an absent fact is reported as
# evidence missing, a fact that is false keeps its original message. The enhancements fail closed: a fact that
# is absent or of the wrong type is evidence missing, booleans pass only on true, counts are checked with
# is_number before any comparison.

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
	not input.ir_controls.policy.documented
	not input.ir_controls.policy.documented == false
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
	not input.ir_controls.handling.process_defined
	not input.ir_controls.handling.process_defined == false
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
	not input.ir_controls.reporting.timely
	not input.ir_controls.reporting.timely == false
	msg := sprintf("NIST IR-6: %s", [_missing_txt({_path("reporting.timely")})])
}

violation contains msg if {
	input.ir_controls.reporting.timely == false
	msg := "NIST IR-6: Incident reporting to internal/external parties not timely"
}

violation contains msg if {
	not input.ir_controls.assistance.available
	not input.ir_controls.assistance.available == false
	msg := sprintf("NIST IR-7: %s", [_missing_txt({_path("assistance.available")})])
}

violation contains msg if {
	input.ir_controls.assistance.available == false
	msg := "NIST IR-7: Incident response assistance/coordination resources not available"
}

violation contains msg if {
	not input.ir_controls.plan.documented
	not input.ir_controls.plan.documented == false
	msg := sprintf("NIST IR-8: %s", [_missing_txt({_path("plan.documented")})])
}

violation contains msg if {
	input.ir_controls.plan.documented == false
	msg := "NIST IR-8: Documented incident response plan does not exist"
}

violation contains msg if {
	not input.ir_controls.information_spillage.process_defined
	not input.ir_controls.information_spillage.process_defined == false
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

compliant if count(violation) == 0

# The control and enhancement ids this family evaluates; each has exactly one finding when it fails.
evaluated_controls := {
	"IR-1", "IR-2", "IR-3", "IR-3(2)", "IR-4", "IR-4(1)", "IR-5", "IR-6", "IR-6(1)", "IR-6(3)", "IR-7", "IR-7(1)",
	"IR-8", "IR-9",
}

compliance_report := {
	"family": "IR",
	"name": "Incident Response",
	"controls_evaluated": count(evaluated_controls),
	"violations": violation,
	"violation_count": count(violation),
	"compliant": compliant,
}
