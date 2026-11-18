# METADATA
# title: "NIST SP 800-53 Rev 5 — Assessment, Authorization, and Monitoring (CA) Family"
# custom:
#   class: compliance
#   framework: nist_sp_800_53
#   source: nist
#   domains: [us-federal, security-controls]
#   coverage:
#     checks: 8
#     cited: 8
#     density: section
#     basis: role
#     tested: true
#     entrypoint: compliance_report
#     guard: self
#     as_of: v2.5.0
package nist.sp800_53.assessment_authorization

import rego.v1

# NIST SP 800-53 Rev 5 — Assessment, Authorization, and Monitoring (CA) Family. Every active base control (CA-1,
# CA-2, CA-3, CA-5, CA-6, CA-7, CA-8, CA-9; CA-4 is withdrawn). Enhancements are not evaluated: a control never
# fails for an enhancement.

default compliant := false

# ---------------------------------------------------------------------------------------------------------------
# Evidence helpers. Every control reads its facts under input.ca_controls.<name>; `path` is the list of keys below
# that root. A fact that is absent, null or of the wrong type is missing evidence, never a pass.
# ---------------------------------------------------------------------------------------------------------------

_root := "ca_controls"

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
# Facts (input.ca_controls.policy_procedures): policy_documented, procedures_documented, official_designated
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
	msg := sprintf("NIST CA-1: %s", [_detail(_pp_missing, _pp_failed)])
}

# CA-2 Control Assessments: assessor or team selected; assessment plan developed and approved by the authorizing
# official (or designated representative) before the assessment; controls assessed at the organization-defined
# frequency; an assessment report produced; results provided to the organization-defined individuals or roles.
# Facts (input.ca_controls.control_assessment): assessor_selected, plan_developed, plan_approved_before_assessment,
# report_produced, results_provided (booleans); days_since_last + odp.frequency_days.
_ca2_bools := [
	["assessor_selected", "no assessor or assessment team selected"],
	["plan_developed", "no control assessment plan developed"],
	["plan_approved_before_assessment", "assessment plan not approved by the authorizing official or designated representative before the assessment"],
	["report_produced", "no control assessment report produced"],
	["results_provided", "assessment results not provided to the organization-defined individuals or roles"],
]

_ca2_missing := _bool_missing(["control_assessment"], _ca2_bools) | _freq_missing(["control_assessment"])

_ca2_failed := _bool_failed(["control_assessment"], _ca2_bools) | _freq_over(["control_assessment"], "controls last assessed %v days ago; the organization-defined frequency is %v days")

violation contains msg if {
	count(_ca2_missing | _ca2_failed) > 0
	msg := sprintf("NIST CA-2: %s", [_detail(_ca2_missing, _ca2_failed)])
}

# CA-3 Information Exchange: exchanges with other systems approved and managed through the organization-selected
# agreement type; each agreement documents interface characteristics, security and privacy requirements,
# controls, responsibilities and impact level; agreements reviewed and updated at the organization-defined
# frequency.
# Facts (input.ca_controls.information_exchange): exchanges_approved_under_agreements, agreements_document_requirements
# (booleans); agreement_review.days_since_last + agreement_review.odp.frequency_days.
_ca3_bools := [
	["exchanges_approved_under_agreements", "information exchanges with other systems not approved and managed under agreements"],
	["agreements_document_requirements", "exchange agreements do not document interface characteristics, security and privacy requirements, controls, responsibilities and impact level"],
]

_ca3_missing := _bool_missing(["information_exchange"], _ca3_bools) | _freq_missing(["information_exchange", "agreement_review"])

_ca3_failed := _bool_failed(["information_exchange"], _ca3_bools) | _freq_over(["information_exchange", "agreement_review"], "exchange agreements last reviewed %v days ago; the organization-defined frequency is %v days")

violation contains msg if {
	count(_ca3_missing | _ca3_failed) > 0
	msg := sprintf("NIST CA-3: %s", [_detail(_ca3_missing, _ca3_failed)])
}

# CA-5 Plan of Action and Milestones: a POA&M documents planned remediation of assessed weaknesses and known
# vulnerabilities, and is updated at the organization-defined frequency.
# Facts (input.ca_controls.poam): documented (boolean); days_since_last (last update) + odp.frequency_days.
_ca5_bools := [["documented", "no plan of action and milestones documents planned remediation of weaknesses and vulnerabilities"]]

_ca5_missing := _bool_missing(["poam"], _ca5_bools) | _freq_missing(["poam"])

_ca5_failed := _bool_failed(["poam"], _ca5_bools) | _freq_over(["poam"], "plan of action and milestones last updated %v days ago; the organization-defined frequency is %v days")

violation contains msg if {
	count(_ca5_missing | _ca5_failed) > 0
	msg := sprintf("NIST CA-5: %s", [_detail(_ca5_missing, _ca5_failed)])
}

# CA-6 Authorization: senior officials assigned as authorizing official for the system and for common controls;
# the system's authorizing official accepts inherited common controls and authorizes operation before operations
# begin; the common-control authorizing official authorizes those controls for inheritance; authorizations
# updated at the organization-defined frequency.
# Facts (input.ca_controls.authorization): system_ao_assigned, common_controls_ao_assigned,
# common_controls_accepted, authorized_to_operate, common_controls_authorized_for_inheritance (booleans);
# days_since_last (last authorization update) + odp.frequency_days.
_ca6_bools := [
	["system_ao_assigned", "no senior official assigned as authorizing official for the system"],
	["common_controls_ao_assigned", "no senior official assigned as authorizing official for common controls"],
	["common_controls_accepted", "the authorizing official has not accepted the inherited common controls"],
	["authorized_to_operate", "the system is not authorized to operate"],
	["common_controls_authorized_for_inheritance", "common controls not authorized for inheritance"],
]

_ca6_missing := _bool_missing(["authorization"], _ca6_bools) | _freq_missing(["authorization"])

_ca6_failed := _bool_failed(["authorization"], _ca6_bools) | _freq_over(["authorization"], "authorization last updated %v days ago; the organization-defined frequency is %v days")

violation contains msg if {
	count(_ca6_missing | _ca6_failed) > 0
	msg := sprintf("NIST CA-6: %s", [_detail(_ca6_missing, _ca6_failed)])
}

# CA-7 Continuous Monitoring: a system-level continuous monitoring strategy, implemented, that establishes the
# organization-defined metrics and monitoring/assessment frequencies, and includes ongoing control assessments,
# ongoing metric monitoring, correlation and analysis, response actions, and reporting of security and privacy
# status to the organization-defined personnel at the organization-defined frequency.
# Facts (input.ca_controls.continuous_monitoring): strategy_implemented, metrics_established, frequencies_established,
# ongoing_assessments, ongoing_metric_monitoring, correlation_and_analysis, response_actions (booleans);
# status_reporting.days_since_last + status_reporting.odp.frequency_days.
_ca7_bools := [
	["strategy_implemented", "no system-level continuous monitoring strategy implemented"],
	["metrics_established", "organization-defined system-level metrics not established"],
	["frequencies_established", "monitoring and control-assessment frequencies not established"],
	["ongoing_assessments", "no ongoing control assessments"],
	["ongoing_metric_monitoring", "no ongoing monitoring of the defined metrics"],
	["correlation_and_analysis", "assessment and monitoring information not correlated and analyzed"],
	["response_actions", "no response actions taken on the analysis results"],
]

_ca7_missing := _bool_missing(["continuous_monitoring"], _ca7_bools) | _freq_missing(["continuous_monitoring", "status_reporting"])

_ca7_failed := _bool_failed(["continuous_monitoring"], _ca7_bools) | _freq_over(["continuous_monitoring", "status_reporting"], "security and privacy status last reported %v days ago; the organization-defined frequency is %v days")

violation contains msg if {
	count(_ca7_missing | _ca7_failed) > 0
	msg := sprintf("NIST CA-7: %s", [_detail(_ca7_missing, _ca7_failed)])
}

# CA-8 Penetration Testing: penetration testing at the organization-defined frequency on the organization-defined
# systems or components.
# Facts (input.ca_controls.penetration_testing): defined_scope_covered (boolean: the last test covered every
# organization-defined system or component); days_since_last + odp.frequency_days.
_ca8_bools := [["defined_scope_covered", "penetration testing did not cover the organization-defined systems or components"]]

_ca8_missing := _bool_missing(["penetration_testing"], _ca8_bools) | _freq_missing(["penetration_testing"])

_ca8_failed := _bool_failed(["penetration_testing"], _ca8_bools) | _freq_over(["penetration_testing"], "penetration test last conducted %v days ago; the organization-defined frequency is %v days")

violation contains msg if {
	count(_ca8_missing | _ca8_failed) > 0
	msg := sprintf("NIST CA-8: %s", [_detail(_ca8_missing, _ca8_failed)])
}

# CA-9 Internal System Connections: internal connections of the organization-defined components authorized and
# documented (interface characteristics, requirements, nature of the information); connections terminated after
# the organization-defined conditions; continued need reviewed at the organization-defined frequency.
# Facts (input.ca_controls.internal_connections): all_authorized, all_documented, terminated_on_defined_conditions
# (booleans); review.days_since_last + review.odp.frequency_days.
_ca9_bools := [
	["all_authorized", "internal system connections not all authorized"],
	["all_documented", "internal system connections not all documented"],
	["terminated_on_defined_conditions", "internal connections not terminated after the organization-defined conditions"],
]

_ca9_missing := _bool_missing(["internal_connections"], _ca9_bools) | _freq_missing(["internal_connections", "review"])

_ca9_failed := _bool_failed(["internal_connections"], _ca9_bools) | _freq_over(["internal_connections", "review"], "continued need for internal connections last reviewed %v days ago; the organization-defined frequency is %v days")

violation contains msg if {
	count(_ca9_missing | _ca9_failed) > 0
	msg := sprintf("NIST CA-9: %s", [_detail(_ca9_missing, _ca9_failed)])
}

compliant if count(violation) == 0

# The base control ids this family evaluates; each has exactly one finding when it fails.
evaluated_controls := {"CA-1", "CA-2", "CA-3", "CA-5", "CA-6", "CA-7", "CA-8", "CA-9"}

compliance_report := {
	"family": "CA",
	"name": "Assessment, Authorization, and Monitoring",
	"controls_evaluated": count(evaluated_controls),
	"violations": violation,
	"violation_count": count(violation),
	"compliant": compliant,
}
