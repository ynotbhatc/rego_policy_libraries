package nist.sp800_171.security_assessment

import rego.v1

# NIST SP 800-171 Rev 3 - Security Assessment (CA) Requirements
# Family: 3.12 — Protecting Controlled Unclassified Information (CUI)

# 3.12.1: Periodically assess the security controls in organizational systems to determine
#          if the controls are effective in their application
default security_controls_assessed := false

security_controls_assessed if {
    input.nist_800_171.security_assessment.controls_assessment.periodic_assessments == true
    input.nist_800_171.security_assessment.controls_assessment.effectiveness_determined == true
    input.nist_800_171.security_assessment.controls_assessment.results_documented == true
    input.nist_800_171.security_assessment.controls_assessment.independent_assessor == true
}

# 3.12.2: Develop and implement plans of action designed to correct deficiencies and reduce
#          or eliminate vulnerabilities in organizational systems
default plans_of_action := false

plans_of_action if {
    input.nist_800_171.security_assessment.plans_of_action.poam_documented == true
    input.nist_800_171.security_assessment.plans_of_action.deficiencies_tracked == true
    input.nist_800_171.security_assessment.plans_of_action.milestones_defined == true
    input.nist_800_171.security_assessment.plans_of_action.progress_monitored == true
}

# 3.12.3: Monitor security controls on an ongoing basis to ensure the continued effectiveness
#          of the controls
default continuous_monitoring := false

continuous_monitoring if {
    input.nist_800_171.security_assessment.continuous_monitoring.monitoring_implemented == true
    input.nist_800_171.security_assessment.continuous_monitoring.ongoing_not_just_periodic == true
    input.nist_800_171.security_assessment.continuous_monitoring.automated_where_possible == true
}

# 3.12.4: Develop, document, and periodically update system security plans that describe
#          system boundaries, system environments, how security requirements are implemented,
#          and the relationships with or connections to other systems
default system_security_plan := false

system_security_plan if {
    input.nist_800_171.security_assessment.ssp.plan_documented == true
    input.nist_800_171.security_assessment.ssp.system_boundary_defined == true
    input.nist_800_171.security_assessment.ssp.environment_described == true
    input.nist_800_171.security_assessment.ssp.requirements_implementation_described == true
    input.nist_800_171.security_assessment.ssp.interconnections_documented == true
    input.nist_800_171.security_assessment.ssp.updated_periodically == true
}

# Violations set
violations contains msg if {
    not security_controls_assessed
    msg := "NIST 800-171 3.12.1: Security controls must be periodically assessed by an independent assessor to determine effectiveness"
}

violations contains msg if {
    not plans_of_action
    msg := "NIST 800-171 3.12.2: Plans of action (POA&M) must be developed and implemented to correct deficiencies with tracked milestones"
}

violations contains msg if {
    not continuous_monitoring
    msg := "NIST 800-171 3.12.3: Security controls must be continuously monitored on an ongoing basis with automated mechanisms where possible"
}

violations contains msg if {
    not system_security_plan
    msg := "NIST 800-171 3.12.4: System security plans must be documented, describing boundaries, environments, implementation, and interconnections, and updated periodically"
}

# Compliance aggregation
default compliant := false

compliant if { count(violations) == 0 }

compliance_report := {
    "family": "3.12 Security Assessment",
    "standard": "NIST SP 800-171 Rev 3",
    "total_controls": 4,
    "violations": violations,
    "compliant": compliant,
    "controls": {
        "3.12.1_security_controls_assessed": security_controls_assessed,
        "3.12.2_plans_of_action": plans_of_action,
        "3.12.3_continuous_monitoring": continuous_monitoring,
        "3.12.4_system_security_plan": system_security_plan,
    },
}
