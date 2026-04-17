package ncsc_caf.d1_response_recovery

import rego.v1

# NCSC Cyber Assessment Framework 4.0
# Objective D — Minimising the Impact of Cyber Security Incidents
# Principle D1 — Response and Recovery Planning
#
# Contributing Outcomes covered (automatable subset):
#   D1.a — Response Planning
#   D1.b — Response Capability
#   D1.c — Testing and Exercising
#
# Note: D1.d (Cyber Security Incident Communications) is non-automatable
# and handled separately.
#
# Scoring: "achieved" | "partially_achieved" | "not_achieved"

# ---------------------------------------------------------------------------
# D1.a — Response Planning
# IGPs: Documented IR/recovery plan covering NIS incidents, plan includes
#       comms and stakeholder notification procedures, roles and
#       responsibilities defined, plan reviewed at least annually
# ---------------------------------------------------------------------------

default _d1a_plan_exists := false
_d1a_plan_exists if {
    input.incident_response.plan.exists == true
}

default _d1a_plan_current := false
_d1a_plan_current if {
    input.incident_response.plan.last_review_days <= 365
}

default _d1a_plan_acceptable_age := false
_d1a_plan_acceptable_age if {
    input.incident_response.plan.last_review_days <= 730
}

default _d1a_covers_nis := false
_d1a_covers_nis if {
    input.incident_response.plan.covers_nis_incidents == true
}

default _d1a_comms_documented := false
_d1a_comms_documented if {
    input.incident_response.plan.communications_documented == true
}

default _d1a_roles_defined := false
_d1a_roles_defined if {
    input.incident_response.plan.roles_defined == true
}

default _d1a_fully_achieved := false
_d1a_fully_achieved if {
    _d1a_plan_exists
    _d1a_plan_current
    _d1a_covers_nis
    _d1a_comms_documented
    _d1a_roles_defined
}

default _d1a_partially_achieved := false
_d1a_partially_achieved if {
    _d1a_plan_exists
    _d1a_plan_acceptable_age
}

default co_d1a_achievement := "not_achieved"

co_d1a_achievement := "achieved" if { _d1a_fully_achieved }

co_d1a_achievement := "partially_achieved" if {
    not _d1a_fully_achieved
    _d1a_partially_achieved
}

co_d1a_details := {
    "plan_exists": _d1a_plan_exists,
    "last_review_days": object.get(input, ["incident_response", "plan", "last_review_days"], 9999),
    "plan_current": _d1a_plan_current,
    "covers_nis_incidents": _d1a_covers_nis,
    "communications_documented": _d1a_comms_documented,
    "roles_defined": _d1a_roles_defined,
    "achievement": co_d1a_achievement,
}

# ---------------------------------------------------------------------------
# D1.b — Response Capability
# IGPs: Dedicated IR capability (in-house or retainer) with 24/7 availability
#       for critical incidents, defined response time SLAs, clear escalation
#       paths, technical capability to investigate and contain incidents
# ---------------------------------------------------------------------------

default _d1b_soc_available := false
_d1b_soc_available if {
    input.incident_response.capability.soc_available == true
}

default _d1b_24x7_coverage := false
_d1b_24x7_coverage if {
    input.incident_response.capability.soc_hours == "24x7"
}

default _d1b_ir_retainer := false
_d1b_ir_retainer if {
    input.incident_response.capability.ir_retainer_exists == true
}

default _d1b_sla_tight := false
_d1b_sla_tight if {
    input.incident_response.capability.response_time_sla_hours <= 4
}

default _d1b_sla_acceptable := false
_d1b_sla_acceptable if {
    input.incident_response.capability.response_time_sla_hours <= 24
}

default _d1b_escalation_defined := false
_d1b_escalation_defined if {
    input.incident_response.capability.escalation_paths_defined == true
}

default _d1b_fully_achieved := false
_d1b_fully_achieved if {
    _d1b_soc_available
    _d1b_24x7_coverage
    _d1b_ir_retainer
    _d1b_sla_tight
    _d1b_escalation_defined
}

default _d1b_partially_achieved := false
_d1b_partially_achieved if {
    _d1b_soc_available
    _d1b_ir_retainer
    _d1b_sla_acceptable
}

default co_d1b_achievement := "not_achieved"

co_d1b_achievement := "achieved" if { _d1b_fully_achieved }

co_d1b_achievement := "partially_achieved" if {
    not _d1b_fully_achieved
    _d1b_partially_achieved
}

co_d1b_details := {
    "soc_available": _d1b_soc_available,
    "soc_hours": object.get(input, ["incident_response", "capability", "soc_hours"], "unknown"),
    "ir_retainer_exists": _d1b_ir_retainer,
    "response_time_sla_hours": object.get(input, ["incident_response", "capability", "response_time_sla_hours"], 9999),
    "sla_tight": _d1b_sla_tight,
    "escalation_paths_defined": _d1b_escalation_defined,
    "achievement": co_d1b_achievement,
}

# ---------------------------------------------------------------------------
# D1.c — Testing and Exercising
# IGPs: IR plan tested against realistic scenarios at least annually,
#       tabletop exercises conducted, functional/live exercises run,
#       lessons learned documented and post-exercise actions tracked
# ---------------------------------------------------------------------------

default _d1c_exercise_annual := false
_d1c_exercise_annual if {
    input.incident_response.exercises.last_exercise_days <= 365
}

default _d1c_tabletop_conducted := false
_d1c_tabletop_conducted if {
    input.incident_response.exercises.tabletop_conducted == true
}

default _d1c_functional_exercise := false
_d1c_functional_exercise if {
    input.incident_response.exercises.functional_exercise_days <= 365
}

default _d1c_lessons_tracked := false
_d1c_lessons_tracked if {
    input.incident_response.exercises.post_exercise_actions_tracked == true
}

default _d1c_fully_achieved := false
_d1c_fully_achieved if {
    _d1c_exercise_annual
    _d1c_tabletop_conducted
    _d1c_functional_exercise
    _d1c_lessons_tracked
}

default _d1c_partially_achieved := false
_d1c_partially_achieved if {
    _d1c_exercise_annual
    _d1c_tabletop_conducted
}

default co_d1c_achievement := "not_achieved"

co_d1c_achievement := "achieved" if { _d1c_fully_achieved }

co_d1c_achievement := "partially_achieved" if {
    not _d1c_fully_achieved
    _d1c_partially_achieved
}

co_d1c_details := {
    "last_exercise_days": object.get(input, ["incident_response", "exercises", "last_exercise_days"], 9999),
    "exercise_conducted_annually": _d1c_exercise_annual,
    "tabletop_conducted": _d1c_tabletop_conducted,
    "functional_exercise_days": object.get(input, ["incident_response", "exercises", "functional_exercise_days"], 9999),
    "functional_exercise_annual": _d1c_functional_exercise,
    "post_exercise_actions_tracked": _d1c_lessons_tracked,
    "achievement": co_d1c_achievement,
}

# ---------------------------------------------------------------------------
# Objective-level rollup
# ---------------------------------------------------------------------------

default d1_compliant := false

d1_compliant if {
    co_d1a_achievement == "achieved"
    co_d1b_achievement == "achieved"
    co_d1c_achievement == "achieved"
}

d1_achievement_counts := {
    "achieved": count([co | some co in [co_d1a_achievement, co_d1b_achievement, co_d1c_achievement]; co == "achieved"]),
    "partially_achieved": count([co | some co in [co_d1a_achievement, co_d1b_achievement, co_d1c_achievement]; co == "partially_achieved"]),
    "not_achieved": count([co | some co in [co_d1a_achievement, co_d1b_achievement, co_d1c_achievement]; co == "not_achieved"]),
}

compliance_report := {
    "principle": "D1",
    "name": "Response and Recovery Planning",
    "compliant": d1_compliant,
    "achievement_counts": d1_achievement_counts,
    "contributing_outcomes": {
        "D1.a": co_d1a_details,
        "D1.b": co_d1b_details,
        "D1.c": co_d1c_details,
    },
}
