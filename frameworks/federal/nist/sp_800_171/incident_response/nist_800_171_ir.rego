package nist.sp800_171.incident_response

import rego.v1

# NIST SP 800-171 Rev 3 - Incident Response (IR) Requirements
# Family: 3.6 — Protecting Controlled Unclassified Information (CUI)

# 3.6.1: Establish an operational incident-handling capability for organizational systems
#         including preparation, detection, analysis, containment, recovery, and user response
default incident_handling_capability := false

incident_handling_capability if {
    input.nist_800_171.incident_response.handling.plan_documented == true
    input.nist_800_171.incident_response.handling.preparation_phase == true
    input.nist_800_171.incident_response.handling.detection_procedures == true
    input.nist_800_171.incident_response.handling.analysis_procedures == true
    input.nist_800_171.incident_response.handling.containment_procedures == true
    input.nist_800_171.incident_response.handling.recovery_procedures == true
    input.nist_800_171.incident_response.handling.user_response_procedures == true
}

# 3.6.2: Track, document, and report incidents to appropriate officials and/or authorities
default incident_tracking_reporting := false

incident_tracking_reporting if {
    input.nist_800_171.incident_response.tracking.incident_tracking_system == true
    input.nist_800_171.incident_response.tracking.documentation_required == true
    input.nist_800_171.incident_response.tracking.designated_officials_identified == true
    input.nist_800_171.incident_response.tracking.reporting_timelines_defined == true
}

# 3.6.3: Test the organizational incident response capability (tabletop exercise or live drill)
#         at least annually
default incident_response_testing := false

incident_response_testing if {
    input.nist_800_171.incident_response.testing.tested_annually == true
    input.nist_800_171.incident_response.testing.test_type_documented == true
    input.nist_800_171.incident_response.testing.results_reviewed == true
    input.nist_800_171.incident_response.testing.lessons_incorporated == true
}

# Violations set
violations contains msg if {
    not incident_handling_capability
    msg := "NIST 800-171 3.6.1: An operational incident-handling capability must be established covering preparation, detection, analysis, containment, recovery, and user response"
}

violations contains msg if {
    not incident_tracking_reporting
    msg := "NIST 800-171 3.6.2: Incidents must be tracked, documented, and reported to designated officials with defined reporting timelines"
}

violations contains msg if {
    not incident_response_testing
    msg := "NIST 800-171 3.6.3: Incident response capability must be tested at least annually with results reviewed and lessons incorporated"
}

# Compliance aggregation
default compliant := false

compliant if { count(violations) == 0 }

compliance_report := {
    "family": "3.6 Incident Response",
    "standard": "NIST SP 800-171 Rev 3",
    "total_controls": 3,
    "violations": violations,
    "compliant": compliant,
    "controls": {
        "3.6.1_incident_handling_capability": incident_handling_capability,
        "3.6.2_incident_tracking_reporting": incident_tracking_reporting,
        "3.6.3_incident_response_testing": incident_response_testing,
    },
}
