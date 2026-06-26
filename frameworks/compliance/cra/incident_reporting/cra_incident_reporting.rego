package cra.incident_reporting

import rego.v1

# EU Cyber Resilience Act (CRA) — Article 14
# Manufacturer reporting obligations for actively exploited vulnerabilities
# and severe incidents.
#
# Reporting timeline (Article 14(2)):
#   T+24h:  early warning notification to ENISA + CSIRT
#   T+72h:  vulnerability/incident notification with available information
#   T+14d:  final report (or 1 month for incidents) with root cause + mitigation
#
# Article 14(8): also obliged to inform impacted users without undue delay.

default compliant := false

# Article 14(2)(a) — 24-hour early warning
violation contains msg if {
    input.incident_reporting.actively_exploited_vuln_known == true
    input.incident_reporting.hours_since_aware_of_vuln > 24
    not input.incident_reporting.early_warning_sent
    msg := sprintf("CRA Art.14(2)(a): No early warning sent to ENISA/CSIRT within 24h (current: %dh since awareness)", [input.incident_reporting.hours_since_aware_of_vuln])
}

# Article 14(2)(b) — 72-hour vulnerability notification
violation contains msg if {
    input.incident_reporting.actively_exploited_vuln_known == true
    input.incident_reporting.hours_since_aware_of_vuln > 72
    not input.incident_reporting.vulnerability_notification_sent
    msg := sprintf("CRA Art.14(2)(b): No vulnerability notification to ENISA within 72h (current: %dh)", [input.incident_reporting.hours_since_aware_of_vuln])
}

# Article 14(2)(c) — Final report within 14 days
violation contains msg if {
    input.incident_reporting.actively_exploited_vuln_known == true
    input.incident_reporting.days_since_aware_of_vuln > 14
    not input.incident_reporting.final_vuln_report_sent
    msg := sprintf("CRA Art.14(2)(c): Final vulnerability report not submitted within 14 days (current: %dd)", [input.incident_reporting.days_since_aware_of_vuln])
}

# Severe incident reporting (also 24/72/1-month timeline per Art.14(3))
violation contains msg if {
    input.incident_reporting.severe_incident_occurred == true
    input.incident_reporting.hours_since_incident > 24
    not input.incident_reporting.incident_early_warning_sent
    msg := "CRA Art.14(3)(a): Severe incident not reported to ENISA/CSIRT within 24h"
}

violation contains msg if {
    input.incident_reporting.severe_incident_occurred == true
    input.incident_reporting.hours_since_incident > 72
    not input.incident_reporting.incident_notification_sent
    msg := "CRA Art.14(3)(b): Severe incident notification not submitted within 72h"
}

violation contains msg if {
    input.incident_reporting.severe_incident_occurred == true
    input.incident_reporting.days_since_incident > 30
    not input.incident_reporting.incident_final_report_sent
    msg := "CRA Art.14(3)(c): Final incident report not submitted within 1 month"
}

# Article 14(8) — Inform impacted users without undue delay
violation contains msg if {
    input.incident_reporting.users_impacted == true
    not input.incident_reporting.affected_users_notified
    msg := "CRA Art.14(8): Impacted users not notified without undue delay"
}

# Article 14(9) — Provide mitigation measures alongside notification
violation contains msg if {
    input.incident_reporting.users_impacted == true
    input.incident_reporting.affected_users_notified == true
    not input.incident_reporting.mitigation_guidance_provided
    msg := "CRA Art.14(9): User notification did not include corrective measures / mitigation guidance"
}

# Single reporting point (Art.14(7) — manufacturer must register with ENISA single entry point)
violation contains msg if {
    not input.incident_reporting.single_entry_point_registered
    msg := "CRA Art.14(7): Manufacturer not registered with the ENISA single reporting platform"
}

# Process maturity
violation contains msg if {
    not input.incident_reporting.process_documented
    msg := "CRA Art.14: Documented incident reporting process not in place"
}

violation contains msg if {
    not input.incident_reporting.process_tested_annually
    msg := "CRA Art.14: Incident reporting process not exercised at least annually"
}

compliant if { count(violation) == 0 }

compliance_report := {
    "family": "Article 14",
    "name":   "Reporting obligations of manufacturers",
    "controls_evaluated": 11,
    "violations": violation,
    "violation_count": count(violation),
    "compliant": compliant,
}
