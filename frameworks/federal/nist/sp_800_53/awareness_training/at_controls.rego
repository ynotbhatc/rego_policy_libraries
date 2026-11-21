# METADATA
# title: "NIST SP 800-53 Rev 5 — Awareness and Training (AT) Family"
# custom:
#   class: compliance
#   framework: nist_sp_800_53
#   source: nist
#   domains: [us-federal, security-controls]
#   coverage:
#     checks: 7
#     cited: 7
#     density: section
#     basis: role
#     tested: true
#     entrypoint: compliance_report
#     guard: self
#     as_of: v2.5.0
package nist.sp800_53.awareness_training

import rego.v1

# NIST SP 800-53 Rev 5 — Awareness and Training (AT) Family. Every active base control (AT-1, AT-2, AT-3, AT-4,
# AT-6; AT-5 is withdrawn) and the NIST SP 800-53B Moderate enhancements AT-2(2) and AT-2(3) (7 ids). A base
# control never fails for an enhancement; each enhancement is its own finding.

default compliant := false

# ---------------------------------------------------------------------------------------------------------------
# Evidence helpers. Every control reads its facts under input.at_controls.<name>; `path` is the list of keys below
# that root. A fact that is absent, null or of the wrong type is missing evidence, never a pass.
# ---------------------------------------------------------------------------------------------------------------

_root := "at_controls"

_path_str(path) := concat(".", array.concat(["input", _root], path))

_obj(path) := v if {
	v := object.get(input, array.concat([_root], path), {})
	is_object(v)
} else := {}

# Boolean facts: `checks` is a list of [key, description of the unmet state]. Absent, null or not a boolean
# ("true", 1) is missing evidence; the boolean false is a finding.
_bool_missing(path, checks) := {concat(".", [_path_str(path), c[0]]) |
	some c in checks
	not is_boolean(object.get(_obj(path), c[0], null))
}

_bool_failed(path, checks) := {sprintf("%s (%s.%s is not true)", [c[1], _path_str(path), c[0]]) |
	some c in checks
	object.get(_obj(path), c[0], null) == false
}

# A count that must be zero, at <path>.<key>: not a number is missing evidence, above zero is a finding.
_zero_missing(path, key) := {concat(".", [_path_str(path), key]) | not is_number(object.get(_obj(path), key, null))}

_zero_failed(path, key, fmt) := {sprintf(fmt, [v, concat(".", [_path_str(path), key])]) |
	v := object.get(_obj(path), key, null)
	is_number(v)
	v > 0
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
# Facts (input.at_controls.policy_procedures): policy_documented, procedures_documented, official_designated
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
	msg := sprintf("NIST AT-1: %s", [_detail(_pp_missing, _pp_failed)])
}

# AT-2 Literacy Training and Awareness: literacy training for all users at initial training and at the
# organization-defined frequency thereafter, and when system changes or organization-defined events require it;
# awareness techniques employed; content updated at the organization-defined frequency; lessons learned from
# incidents and breaches incorporated.
# Facts (input.at_controls.literacy_training): initial_training_for_new_users, training_on_system_changes_and_events,
# awareness_techniques_employed, lessons_learned_incorporated (booleans); refresher.days_since_last +
# refresher.odp.frequency_days; content_update.days_since_last + content_update.odp.frequency_days.
_at2_bools := [
	["initial_training_for_new_users", "literacy training not part of initial training for new users"],
	["training_on_system_changes_and_events", "literacy training not provided when system changes or organization-defined events require it"],
	["awareness_techniques_employed", "organization-defined awareness techniques not employed"],
	["lessons_learned_incorporated", "lessons learned from incidents or breaches not incorporated into literacy training"],
]

_at2_missing := (_bool_missing(["literacy_training"], _at2_bools) | _freq_missing(["literacy_training", "refresher"])) | _freq_missing(["literacy_training", "content_update"])

_at2_failed := (_bool_failed(["literacy_training"], _at2_bools) | _freq_over(["literacy_training", "refresher"], "literacy training last provided %v days ago; the organization-defined frequency is %v days")) | _freq_over(["literacy_training", "content_update"], "literacy training content last updated %v days ago; the organization-defined frequency is %v days")

violation contains msg if {
	count(_at2_missing | _at2_failed) > 0
	msg := sprintf("NIST AT-2: %s", [_detail(_at2_missing, _at2_failed)])
}

# AT-3 Role-based Training: role-based training before access is authorized or duties are performed, at the
# organization-defined frequency thereafter and when system changes require it; content updated at the
# organization-defined frequency; lessons learned incorporated.
# Facts (input.at_controls.role_based_training): trained_before_access, training_on_system_changes,
# lessons_learned_incorporated (booleans); refresher.days_since_last + refresher.odp.frequency_days;
# content_update.days_since_last + content_update.odp.frequency_days.
_at3_bools := [
	["trained_before_access", "role-based training not provided before access is authorized or duties are performed"],
	["training_on_system_changes", "role-based training not provided when system changes require it"],
	["lessons_learned_incorporated", "lessons learned from incidents or breaches not incorporated into role-based training"],
]

_at3_missing := (_bool_missing(["role_based_training"], _at3_bools) | _freq_missing(["role_based_training", "refresher"])) | _freq_missing(["role_based_training", "content_update"])

_at3_failed := (_bool_failed(["role_based_training"], _at3_bools) | _freq_over(["role_based_training", "refresher"], "role-based training last provided %v days ago; the organization-defined frequency is %v days")) | _freq_over(["role_based_training", "content_update"], "role-based training content last updated %v days ago; the organization-defined frequency is %v days")

violation contains msg if {
	count(_at3_missing | _at3_failed) > 0
	msg := sprintf("NIST AT-3: %s", [_detail(_at3_missing, _at3_failed)])
}

# AT-4 Training Records: training activities documented and monitored; individual training records retained for
# the organization-defined time period.
# Facts (input.at_controls.training_records): documented_and_monitored (boolean); retention_days (configured
# retention) + odp.retention_days (organization-defined period).
_at4_bools := [["documented_and_monitored", "security and privacy training activities not documented and monitored"]]

_at4_missing := _bool_missing(["training_records"], _at4_bools) | _num_missing(["training_records"], "retention_days", "retention_days")

_at4_failed := _bool_failed(["training_records"], _at4_bools) | _under(["training_records"], "retention_days", "retention_days", "individual training records retained for %v days; the organization-defined period is %v days")

violation contains msg if {
	count(_at4_missing | _at4_failed) > 0
	msg := sprintf("NIST AT-4: %s", [_detail(_at4_missing, _at4_failed)])
}

# AT-6 Training Feedback: feedback on organizational training results provided to the organization-defined
# personnel at the organization-defined frequency.
# Facts (input.at_controls.training_feedback): provided_to_designated_personnel (boolean); days_since_last +
# odp.frequency_days.
_at6_bools := [["provided_to_designated_personnel", "training-results feedback not provided to the organization-defined personnel"]]

_at6_missing := _bool_missing(["training_feedback"], _at6_bools) | _freq_missing(["training_feedback"])

_at6_failed := _bool_failed(["training_feedback"], _at6_bools) | _freq_over(["training_feedback"], "training-results feedback last provided %v days ago; the organization-defined frequency is %v days")

violation contains msg if {
	count(_at6_missing | _at6_failed) > 0
	msg := sprintf("NIST AT-6: %s", [_detail(_at6_missing, _at6_failed)])
}

# AT-2(2) Insider Threat and AT-2(3) Social Engineering and Mining: literacy training covers recognising and
# reporting potential indicators of insider threat (AT-2(2)) and potential and actual social engineering and social
# mining (AT-2(3)). Evidence comes from the learning-management system.
# Facts (input.at_controls.literacy_training.insider_threat and .social_engineering): module_in_curriculum
# (boolean: the topic is a module of the literacy curriculum); users_not_completed (count of in-scope users who have
# not completed that module).
_at2_topic_missing(key) := _bool_missing(["literacy_training", key], [["module_in_curriculum", ""]]) | _zero_missing(["literacy_training", key], "users_not_completed")

_at2_topic_failed(key, topic) := _bool_failed(["literacy_training", key], [["module_in_curriculum", sprintf("%s module not in the literacy training curriculum", [topic])]]) | _zero_failed(["literacy_training", key], "users_not_completed", concat("", ["%v users have not completed the ", topic, " literacy training module (%s)"]))

_at2_2_missing := _at2_topic_missing("insider_threat")

_at2_2_failed := _at2_topic_failed("insider_threat", "insider-threat")

violation contains msg if {
	count(_at2_2_missing | _at2_2_failed) > 0
	msg := sprintf("NIST AT-2(2): %s", [_detail(_at2_2_missing, _at2_2_failed)])
}

_at2_3_missing := _at2_topic_missing("social_engineering")

_at2_3_failed := _at2_topic_failed("social_engineering", "social engineering and social mining")

violation contains msg if {
	count(_at2_3_missing | _at2_3_failed) > 0
	msg := sprintf("NIST AT-2(3): %s", [_detail(_at2_3_missing, _at2_3_failed)])
}

compliant if count(violation) == 0

# The control and enhancement ids this family evaluates; each has exactly one finding when it fails.
evaluated_controls := {"AT-1", "AT-2", "AT-2(2)", "AT-2(3)", "AT-3", "AT-4", "AT-6"}

compliance_report := {
	"family": "AT",
	"name": "Awareness and Training",
	"controls_evaluated": count(evaluated_controls),
	"violations": violation,
	"violation_count": count(violation),
	"compliant": compliant,
}
