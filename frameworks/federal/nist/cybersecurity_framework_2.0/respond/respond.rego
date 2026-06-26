package nist.csf.respond

import rego.v1

# NIST Cybersecurity Framework 2.0 — RESPOND (RS) function
# Develop and implement appropriate activities to take action regarding
# a detected cybersecurity incident.

default compliant := false

# RS.RP — Response Planning
violation contains msg if {
    not input.respond.response_planning.response_plan_executed
    msg := "CSF RS.RP-01: Response plan not executed during or after an incident"
}

# RS.CO — Communications
violation contains msg if {
    not input.respond.communications.personnel_know_roles
    msg := "CSF RS.CO-01: Personnel don't know their roles when a response is needed"
}

violation contains msg if {
    not input.respond.communications.events_reported_within_criteria
    msg := "CSF RS.CO-02: Incidents not reported consistent with established criteria"
}

violation contains msg if {
    not input.respond.communications.information_shared_with_stakeholders
    msg := "CSF RS.CO-03: Response information not shared with internal stakeholders"
}

violation contains msg if {
    not input.respond.communications.coordination_with_stakeholders
    msg := "CSF RS.CO-04: Coordination with external stakeholders not aligned with plan"
}

violation contains msg if {
    not input.respond.communications.voluntary_information_sharing
    msg := "CSF RS.CO-05: Voluntary information sharing with external stakeholders not performed"
}

# RS.AN — Analysis
violation contains msg if {
    not input.respond.analysis.notifications_investigated
    msg := "CSF RS.AN-01: Notifications from detection systems not investigated"
}

violation contains msg if {
    not input.respond.analysis.incident_impact_understood
    msg := "CSF RS.AN-02: Impact of incident not understood"
}

violation contains msg if {
    not input.respond.analysis.forensics_performed
    msg := "CSF RS.AN-03: Forensics not performed during/after incident"
}

violation contains msg if {
    not input.respond.analysis.incidents_categorized
    msg := "CSF RS.AN-04: Incidents not categorized consistent with response plan"
}

violation contains msg if {
    not input.respond.analysis.vulnerability_disclosures_addressed
    msg := "CSF RS.AN-05: Vulnerability disclosures from internal/external sources not addressed"
}

# RS.MI — Mitigation
violation contains msg if {
    not input.respond.mitigation.incidents_contained
    msg := "CSF RS.MI-01: Incidents not contained"
}

violation contains msg if {
    not input.respond.mitigation.incidents_mitigated
    msg := "CSF RS.MI-02: Incidents not mitigated"
}

violation contains msg if {
    not input.respond.mitigation.newly_identified_vulnerabilities_mitigated
    msg := "CSF RS.MI-03: Newly identified vulnerabilities not mitigated or accepted as residual risk"
}

# RS.IM — Improvements
violation contains msg if {
    not input.respond.improvements.response_plans_incorporate_lessons
    msg := "CSF RS.IM-01: Response plans don't incorporate lessons learned"
}

violation contains msg if {
    not input.respond.improvements.response_strategies_updated
    msg := "CSF RS.IM-02: Response strategies not updated"
}

compliant if { count(violation) == 0 }

compliance_report := {
    "function": "RESPOND",
    "controls_evaluated": 16,
    "violations": violation,
    "violation_count": count(violation),
    "compliant": compliant,
}
