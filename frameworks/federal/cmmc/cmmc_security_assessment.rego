package cmmc.security_assessment

import rego.v1

# =============================================================================
# CMMC 2.0 — Domain 3.12: Security Assessment
# NIST SP 800-171 Rev 2 — 4 Practices
# =============================================================================

# 3.12.1 — Periodically assess the security controls in organizational systems
#           to determine if the controls are effective in their application. (L2)
default compliant_3_12_1 := false
compliant_3_12_1 if {
    input.assessment.security_controls_assessed == true
    input.assessment.assessment_frequency_days <= 365
    input.assessment.assessment_results_documented == true
}

violation_3_12_1 contains msg if {
    not input.assessment.security_controls_assessed
    msg := "3.12.1: Security controls in CUI systems have not been periodically assessed"
}
violation_3_12_1 contains msg if {
    input.assessment.assessment_frequency_days > 365
    msg := sprintf("3.12.1: Security control assessments conducted every %v days (must be at least annually)", [input.assessment.assessment_frequency_days])
}
violation_3_12_1 contains msg if {
    not input.assessment.assessment_results_documented
    msg := "3.12.1: Security control assessment results are not documented"
}

# 3.12.2 — Develop and implement plans of action designed to correct deficiencies
#           and reduce or eliminate vulnerabilities in organizational systems. (L2)
default compliant_3_12_2 := false
compliant_3_12_2 if {
    input.assessment.plan_of_action_exists == true
    input.assessment.poam_tracks_deficiencies == true
    input.assessment.poam_reviewed_regularly == true
}

violation_3_12_2 contains msg if {
    not input.assessment.plan_of_action_exists
    msg := "3.12.2: No Plan of Action and Milestones (POA&M) exists to address security deficiencies"
}
violation_3_12_2 contains msg if {
    not input.assessment.poam_tracks_deficiencies
    msg := "3.12.2: POA&M does not track all identified security deficiencies and vulnerabilities"
}
violation_3_12_2 contains msg if {
    not input.assessment.poam_reviewed_regularly
    msg := "3.12.2: POA&M is not reviewed and updated on a regular basis"
}

# 3.12.3 — Monitor security controls on an ongoing basis to ensure the continued
#           effectiveness of the controls. (L2)
default compliant_3_12_3 := false
compliant_3_12_3 if {
    input.assessment.continuous_monitoring_program == true
    input.assessment.security_metrics_collected == true
    input.assessment.control_effectiveness_reviewed == true
}

violation_3_12_3 contains msg if {
    not input.assessment.continuous_monitoring_program
    msg := "3.12.3: No continuous monitoring program for CUI system security controls"
}
violation_3_12_3 contains msg if {
    not input.assessment.security_metrics_collected
    msg := "3.12.3: Security metrics are not collected to assess ongoing control effectiveness"
}
violation_3_12_3 contains msg if {
    not input.assessment.control_effectiveness_reviewed
    msg := "3.12.3: Security control effectiveness is not reviewed on an ongoing basis"
}

# 3.12.4 — Develop, document, and periodically update system security plans
#           that describe system boundaries, system environments of operation,
#           how security requirements are implemented, and the relationships
#           with or connections to other systems. (L2)
default compliant_3_12_4 := false
compliant_3_12_4 if {
    input.assessment.system_security_plan_exists == true
    input.assessment.ssp_documents_boundaries == true
    input.assessment.ssp_documents_cui_environment == true
    input.assessment.ssp_updated_annually == true
}

violation_3_12_4 contains msg if {
    not input.assessment.system_security_plan_exists
    msg := "3.12.4: No System Security Plan (SSP) exists for CUI systems"
}
violation_3_12_4 contains msg if {
    not input.assessment.ssp_documents_boundaries
    msg := "3.12.4: SSP does not document system boundaries and connections to other systems"
}
violation_3_12_4 contains msg if {
    not input.assessment.ssp_documents_cui_environment
    msg := "3.12.4: SSP does not describe CUI operating environment and security requirement implementation"
}
violation_3_12_4 contains msg if {
    not input.assessment.ssp_updated_annually
    msg := "3.12.4: System Security Plan is not reviewed and updated at least annually"
}

# ---------------------------------------------------------------------------
# Aggregate
# ---------------------------------------------------------------------------

all_violations := array.concat(
    array.concat(
        [v | some v in violation_3_12_1],
        [v | some v in violation_3_12_2]
    ),
    array.concat(
        [v | some v in violation_3_12_3],
        [v | some v in violation_3_12_4]
    )
)

practices := [
    {"id": "3.12.1", "level": 2, "compliant": compliant_3_12_1},
    {"id": "3.12.2", "level": 2, "compliant": compliant_3_12_2},
    {"id": "3.12.3", "level": 2, "compliant": compliant_3_12_3},
    {"id": "3.12.4", "level": 2, "compliant": compliant_3_12_4},
]

passing_count := count([p | some p in practices; p.compliant == true])

default compliant := false
compliant if count(all_violations) == 0

compliance_report := {
    "domain": "Security Assessment",
    "domain_id": "3.12",
    "total_practices": 4,
    "passing": passing_count,
    "failing": 4 - passing_count,
    "compliant": compliant,
    "violations": all_violations,
}
