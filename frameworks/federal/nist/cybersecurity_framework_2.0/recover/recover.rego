package nist.csf.recover

import rego.v1

# NIST Cybersecurity Framework 2.0 — RECOVER (RC) function
# Develop and implement appropriate activities to maintain plans for resilience
# and to restore any capabilities or services impaired due to an incident.

default compliant := false

# RC.RP — Recovery Planning
violation contains msg if {
    not input.recover.recovery_planning.recovery_plan_executed
    msg := "CSF RC.RP-01: Recovery plan not executed during or after a cybersecurity incident"
}

# RC.IM — Improvements
violation contains msg if {
    not input.recover.improvements.recovery_plans_incorporate_lessons
    msg := "CSF RC.IM-01: Recovery plans don't incorporate lessons learned"
}

violation contains msg if {
    not input.recover.improvements.recovery_strategies_updated
    msg := "CSF RC.IM-02: Recovery strategies not updated"
}

# RC.CO — Communications
violation contains msg if {
    not input.recover.communications.public_relations_managed
    msg := "CSF RC.CO-01: Public relations not managed during recovery"
}

violation contains msg if {
    not input.recover.communications.reputation_repaired
    msg := "CSF RC.CO-02: Reputation repair after an event not performed"
}

violation contains msg if {
    not input.recover.communications.recovery_activities_communicated
    msg := "CSF RC.CO-03: Recovery activities not communicated to internal stakeholders and leadership"
}

compliant if { count(violation) == 0 }

compliance_report := {
    "function": "RECOVER",
    "controls_evaluated": 6,
    "violations": violation,
    "violation_count": count(violation),
    "compliant": compliant,
}
