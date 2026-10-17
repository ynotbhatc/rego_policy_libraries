# METADATA
# title: "SOX (Sarbanes-Oxley Act) Compliance Framework"
# custom:
#   class: compliance
#   framework: sox
#   source: us-federal
#   domains: [financial, public-company]
#   coverage:
#     checks: 23
#     cited: 23
#     density: orchestrator
#     basis: role
#     tested: true
#     entrypoint: none
#     guard: n/a
#     as_of: v2.4.1
package sox.main

import rego.v1

# SOX (Sarbanes-Oxley Act) Compliance Framework
# Main aggregation policy for SOX compliance assessment

# Overall SOX compliance evaluation
default sox_compliant := false

sox_compliant if {
    section_302_compliant
    section_404_compliant
    section_409_compliant
    management_assessment_compliant
    itgc_controls_compliant
    application_controls_all_compliant
}

# ITGC and application controls are scored (it_general_controls_score,
# application_controls_score) so a failed area must also fail the verdict.
default itgc_controls_compliant := false

itgc_controls_compliant if {
    data.sox.itgc.access_controls.implemented
    data.sox.itgc.change_management.controlled
    data.sox.itgc.computer_operations.monitored
    data.sox.itgc.system_development.secure
    data.sox.itgc.data_center_operations.controlled
    data.sox.itgc.backup_recovery.tested
}

default application_controls_all_compliant := false

application_controls_all_compliant if {
    data.sox.application_controls.input_validation.comprehensive
    data.sox.application_controls.processing_controls.accurate
    data.sox.application_controls.output_controls.complete
    data.sox.application_controls.data_integrity.maintained
    data.sox.application_controls.error_handling.robust
    data.sox.application_controls.transaction_logging.complete
}

# Section 302: Corporate Responsibility for Financial Reports
default section_302_compliant := false

section_302_compliant if {
    data.sox.section_302.ceo_certification.provided
    data.sox.section_302.cfo_certification.provided
    data.sox.section_302.disclosure_controls.effective
    data.sox.section_302.material_weaknesses.none_identified
}

# Section 404: Management Assessment of Internal Controls
default section_404_compliant := false

section_404_compliant if {
    data.sox.section_404.management_assessment.completed
    data.sox.section_404.internal_controls.designed_effectively
    data.sox.section_404.internal_controls.operating_effectively
    data.sox.section_404.external_auditor_attestation.unqualified
}

# Section 409: Real-time Issuer Disclosures
default section_409_compliant := false

section_409_compliant if {
    data.sox.section_409.material_events.disclosed_timely
    data.sox.section_409.disclosure_process.automated
    data.sox.section_409.disclosure_controls.reviewed_quarterly
}

# Management Assessment Framework
default management_assessment_compliant := false

management_assessment_compliant if {
    data.sox.management.assessment_framework.documented
    data.sox.management.testing_procedures.comprehensive
    data.sox.management.deficiency_remediation.timely
    data.sox.management.continuous_monitoring.implemented
}

# SOX Compliance Score Calculation
default sox_compliance_score := 0

sox_compliance_score := score if {
    components := [
        section_302_score,
        section_404_score,
        section_409_score,
        management_assessment_score,
        it_general_controls_score,
        application_controls_score
    ]
    score := (sum(components) / count(components)) * 100
}

# Section 302 Score
default section_302_score := 0

section_302_score := score if {
    checks := [
        _d_section_302_ceo_certification_provided,
        _d_section_302_cfo_certification_provided,
        _d_section_302_disclosure_controls_effective,
        _d_section_302_material_weaknesses_none_identified,
        _d_section_302_quarterly_review_completed,
        _d_section_302_annual_assessment_completed
    ]
    passed := count([check | check := checks[_]; check == true])
    score := passed / count(checks)
}

# Section 404 Score
default section_404_score := 0

section_404_score := score if {
    checks := [
        _d_section_404_management_assessment_completed,
        _d_section_404_internal_controls_designed_effectively,
        _d_section_404_internal_controls_operating_effectively,
        _d_section_404_external_auditor_attestation_unqualified,
        _d_section_404_remediation_plan_implemented,
        _d_section_404_continuous_monitoring_active
    ]
    passed := count([check | check := checks[_]; check == true])
    score := passed / count(checks)
}

# Section 409 Score
default section_409_score := 0

section_409_score := score if {
    checks := [
        _d_section_409_material_events_disclosed_timely,
        _d_section_409_disclosure_process_automated,
        _d_section_409_disclosure_controls_reviewed_quarterly,
        _d_section_409_event_detection_real_time,
        _d_section_409_filing_deadlines_met
    ]
    passed := count([check | check := checks[_]; check == true])
    score := passed / count(checks)
}

# Management Assessment Score
default management_assessment_score := 0

management_assessment_score := score if {
    checks := [
        _d_management_assessment_framework_documented,
        _d_management_testing_procedures_comprehensive,
        _d_management_deficiency_remediation_timely,
        _d_management_continuous_monitoring_implemented,
        _d_management_risk_assessment_annual,
        _d_management_control_documentation_current
    ]
    passed := count([check | check := checks[_]; check == true])
    score := passed / count(checks)
}

# IT General Controls Score
default it_general_controls_score := 0

it_general_controls_score := score if {
    checks := [
        _d_itgc_access_controls_implemented,
        _d_itgc_change_management_controlled,
        _d_itgc_computer_operations_monitored,
        _d_itgc_system_development_secure,
        _d_itgc_data_center_operations_controlled,
        _d_itgc_backup_recovery_tested
    ]
    passed := count([check | check := checks[_]; check == true])
    score := passed / count(checks)
}

# Application Controls Score
default application_controls_score := 0

application_controls_score := score if {
    checks := [
        _d_application_controls_input_validation_comprehensive,
        _d_application_controls_processing_controls_accurate,
        _d_application_controls_output_controls_complete,
        _d_application_controls_data_integrity_maintained,
        _d_application_controls_error_handling_robust,
        _d_application_controls_transaction_logging_complete
    ]
    passed := count([check | check := checks[_]; check == true])
    score := passed / count(checks)
}

# SOX Detailed Findings
sox_detailed_findings := findings if {
    findings := {
        "section_302_findings": section_302_findings,
        "section_404_findings": section_404_findings,
        "section_409_findings": section_409_findings,
        "itgc_findings": itgc_findings,
        "application_control_findings": application_control_findings,
        "management_findings": management_findings
    }
}

# Section 302 Findings
section_302_findings := findings if {
    findings := [finding |
        controls := [
            {"control": "CEO Certification", "status": _d_section_302_ceo_certification_provided},
            {"control": "CFO Certification", "status": _d_section_302_cfo_certification_provided},
            {"control": "Disclosure Controls", "status": _d_section_302_disclosure_controls_effective},
            {"control": "Material Weaknesses", "status": _d_section_302_material_weaknesses_none_identified}
        ]
        control := controls[_]
        not control.status
        finding := {
            "control_name": control.control,
            "status": "NON_COMPLIANT",
            "section": "302",
            "risk_level": _determine_302_risk_level(control.control),
            "remediation": _get_302_remediation(control.control)
        }
    ]
}

# Section 404 Findings
section_404_findings := findings if {
    findings := [finding |
        controls := [
            {"control": "Management Assessment", "status": _d_section_404_management_assessment_completed},
            {"control": "Control Design", "status": _d_section_404_internal_controls_designed_effectively},
            {"control": "Control Operation", "status": _d_section_404_internal_controls_operating_effectively},
            {"control": "Auditor Attestation", "status": _d_section_404_external_auditor_attestation_unqualified}
        ]
        control := controls[_]
        not control.status
        finding := {
            "control_name": control.control,
            "status": "NON_COMPLIANT",
            "section": "404",
            "risk_level": _determine_404_risk_level(control.control),
            "remediation": _get_404_remediation(control.control)
        }
    ]
}

# Section 409 Findings
section_409_findings := findings if {
    findings := [finding |
        controls := [
            {"control": "Timely Disclosure", "status": _d_section_409_material_events_disclosed_timely},
            {"control": "Automated Process", "status": _d_section_409_disclosure_process_automated},
            {"control": "Quarterly Review", "status": _d_section_409_disclosure_controls_reviewed_quarterly}
        ]
        control := controls[_]
        not control.status
        finding := {
            "control_name": control.control,
            "status": "NON_COMPLIANT",
            "section": "409",
            "risk_level": _determine_409_risk_level(control.control),
            "remediation": _get_409_remediation(control.control)
        }
    ]
}

# IT General Controls Findings
itgc_findings := findings if {
    findings := [finding |
        controls := [
            {"control": "Access Controls", "status": _d_itgc_access_controls_implemented},
            {"control": "Change Management", "status": _d_itgc_change_management_controlled},
            {"control": "Computer Operations", "status": _d_itgc_computer_operations_monitored},
            {"control": "System Development", "status": _d_itgc_system_development_secure}
        ]
        control := controls[_]
        not control.status
        finding := {
            "control_name": control.control,
            "status": "NON_COMPLIANT",
            "section": "ITGC",
            "risk_level": _determine_itgc_risk_level(control.control),
            "remediation": _get_itgc_remediation(control.control)
        }
    ]
}

# Application Control Findings
application_control_findings := findings if {
    findings := [finding |
        controls := [
            {"control": "Input Validation", "status": _d_application_controls_input_validation_comprehensive},
            {"control": "Processing Controls", "status": _d_application_controls_processing_controls_accurate},
            {"control": "Output Controls", "status": _d_application_controls_output_controls_complete},
            {"control": "Data Integrity", "status": _d_application_controls_data_integrity_maintained}
        ]
        control := controls[_]
        not control.status
        finding := {
            "control_name": control.control,
            "status": "NON_COMPLIANT",
            "section": "Application Controls",
            "risk_level": _determine_app_risk_level(control.control),
            "remediation": _get_app_remediation(control.control)
        }
    ]
}

# Management Findings
management_findings := findings if {
    findings := [finding |
        controls := [
            {"control": "Assessment Framework", "status": _d_management_assessment_framework_documented},
            {"control": "Testing Procedures", "status": _d_management_testing_procedures_comprehensive},
            {"control": "Deficiency Remediation", "status": _d_management_deficiency_remediation_timely},
            {"control": "Continuous Monitoring", "status": _d_management_continuous_monitoring_implemented}
        ]
        control := controls[_]
        not control.status
        finding := {
            "control_name": control.control,
            "status": "NON_COMPLIANT",
            "section": "Management",
            "risk_level": _determine_mgmt_risk_level(control.control),
            "remediation": _get_mgmt_remediation(control.control)
        }
    ]
}

# Risk Level Determination Functions
_determine_302_risk_level(control) := "CRITICAL" if {
    control in ["CEO Certification", "CFO Certification"]
}

_determine_302_risk_level(control) := "HIGH" if {
    control in ["Disclosure Controls", "Material Weaknesses"]
}

_determine_404_risk_level(control) := "CRITICAL" if {
    control in ["Management Assessment", "Auditor Attestation"]
}

_determine_404_risk_level(control) := "HIGH" if {
    control in ["Control Design", "Control Operation"]
}

_determine_409_risk_level(control) := "HIGH" if {
    control == "Timely Disclosure"
}

_determine_409_risk_level(control) := "MEDIUM" if {
    control in ["Automated Process", "Quarterly Review"]
}

_determine_itgc_risk_level(control) := "HIGH" if {
    control in ["Access Controls", "Change Management"]
}

_determine_itgc_risk_level(control) := "MEDIUM" if {
    control in ["Computer Operations", "System Development"]
}

_determine_app_risk_level(control) := "HIGH" if {
    control in ["Input Validation", "Data Integrity"]
}

_determine_app_risk_level(control) := "MEDIUM" if {
    control in ["Processing Controls", "Output Controls"]
}

_determine_mgmt_risk_level(control) := "HIGH" if {
    control in ["Assessment Framework", "Deficiency Remediation"]
}

_determine_mgmt_risk_level(control) := "MEDIUM" if {
    control in ["Testing Procedures", "Continuous Monitoring"]
}

# Remediation Recommendations
_get_302_remediation(control) := "Implement executive certification process with legal review" if {
    control in ["CEO Certification", "CFO Certification"]
}

_get_302_remediation(control) := "Establish disclosure controls and procedures framework" if {
    control == "Disclosure Controls"
}

_get_302_remediation(control) := "Conduct comprehensive control testing and remediate identified weaknesses" if {
    control == "Material Weaknesses"
}

_get_404_remediation(control) := "Develop management assessment methodology and documentation" if {
    control == "Management Assessment"
}

_get_404_remediation(control) := "Design comprehensive internal control framework" if {
    control == "Control Design"
}

_get_404_remediation(control) := "Implement control monitoring and testing procedures" if {
    control == "Control Operation"
}

_get_404_remediation(control) := "Engage qualified external auditor for Section 404 attestation" if {
    control == "Auditor Attestation"
}

_get_409_remediation(control) := "Implement real-time event detection and disclosure procedures" if {
    control == "Timely Disclosure"
}

_get_409_remediation(control) := "Deploy automated disclosure management system" if {
    control == "Automated Process"
}

_get_409_remediation(control) := "Establish quarterly disclosure control review process" if {
    control == "Quarterly Review"
}

_get_itgc_remediation(control) := "Implement role-based access controls with segregation of duties" if {
    control == "Access Controls"
}

_get_itgc_remediation(control) := "Establish formal change management process with approvals" if {
    control == "Change Management"
}

_get_itgc_remediation(control) := "Deploy comprehensive system monitoring and alerting" if {
    control == "Computer Operations"
}

_get_itgc_remediation(control) := "Implement secure development lifecycle (SDLC) practices" if {
    control == "System Development"
}

_get_app_remediation(control) := "Implement comprehensive input validation and sanitization" if {
    control == "Input Validation"
}

_get_app_remediation(control) := "Deploy automated processing controls and reconciliation" if {
    control == "Processing Controls"
}

_get_app_remediation(control) := "Implement output validation and completeness checks" if {
    control == "Output Controls"
}

_get_app_remediation(control) := "Deploy data integrity monitoring and verification" if {
    control == "Data Integrity"
}

_get_mgmt_remediation(control) := "Document comprehensive control assessment framework" if {
    control == "Assessment Framework"
}

_get_mgmt_remediation(control) := "Develop detailed testing procedures and documentation" if {
    control == "Testing Procedures"
}

_get_mgmt_remediation(control) := "Implement deficiency tracking and remediation workflow" if {
    control == "Deficiency Remediation"
}

_get_mgmt_remediation(control) := "Deploy continuous monitoring and automated testing" if {
    control == "Continuous Monitoring"
}

# SOX Compliance Level Determination
# FULLY_COMPLIANT additionally requires the gated verdict: a high average score
# must not mask a failed ITGC / application-control area.
default _fully_compliant := false

_fully_compliant if {
    sox_compliance_score >= 95
    sox_compliant
}

sox_compliance_level := "FULLY_COMPLIANT" if _fully_compliant

sox_compliance_level := "SUBSTANTIALLY_COMPLIANT" if {
    sox_compliance_score >= 85
    not _fully_compliant
}

sox_compliance_level := "PARTIALLY_COMPLIANT" if {
    sox_compliance_score >= 70
    sox_compliance_score < 85
}

sox_compliance_level := "NON_COMPLIANT" if {
    sox_compliance_score < 70
}

# Overall SOX Assessment Summary
overall_sox_assessment := assessment if {
    assessment := {
        "compliance_status": sox_compliant,
        "compliance_score": sox_compliance_score,
        "compliance_level": sox_compliance_level,
        "section_scores": {
            "section_302": section_302_score * 100,
            "section_404": section_404_score * 100,
            "section_409": section_409_score * 100,
            "management": management_assessment_score * 100,
            "itgc": it_general_controls_score * 100,
            "application_controls": application_controls_score * 100
        },
        "total_findings": count(sox_detailed_findings.section_302_findings) + 
                         count(sox_detailed_findings.section_404_findings) + 
                         count(sox_detailed_findings.section_409_findings) + 
                         count(sox_detailed_findings.itgc_findings) + 
                         count(sox_detailed_findings.application_control_findings) + 
                         count(sox_detailed_findings.management_findings),
        "critical_findings": _count_critical_findings,
        "high_findings": _count_high_findings,
        "medium_findings": _count_medium_findings
    }
}

# Count findings by risk level
_count_critical_findings := count([finding |
    some section_key
    section := sox_detailed_findings[section_key]
    finding := section[_]
    finding.risk_level == "CRITICAL"
])

_count_high_findings := count([finding |
    some section_key
    section := sox_detailed_findings[section_key]
    finding := section[_]
    finding.risk_level == "HIGH"
])

_count_medium_findings := count([finding |
    some section_key
    section := sox_detailed_findings[section_key]
    finding := section[_]
    finding.risk_level == "MEDIUM"
])

# ---------------------------------------------------------------------------
# Fact accessors. A missing data field must read as false, not make the whole
# checks/controls array undefined (which silently dropped that control's
# finding and zeroed the section score).
# ---------------------------------------------------------------------------

default _d_section_302_ceo_certification_provided := false

_d_section_302_ceo_certification_provided := data.sox.section_302.ceo_certification.provided

default _d_section_302_cfo_certification_provided := false

_d_section_302_cfo_certification_provided := data.sox.section_302.cfo_certification.provided

default _d_section_302_disclosure_controls_effective := false

_d_section_302_disclosure_controls_effective := data.sox.section_302.disclosure_controls.effective

default _d_section_302_material_weaknesses_none_identified := false

_d_section_302_material_weaknesses_none_identified := data.sox.section_302.material_weaknesses.none_identified

default _d_section_302_quarterly_review_completed := false

_d_section_302_quarterly_review_completed := data.sox.section_302.quarterly_review.completed

default _d_section_302_annual_assessment_completed := false

_d_section_302_annual_assessment_completed := data.sox.section_302.annual_assessment.completed

default _d_section_404_management_assessment_completed := false

_d_section_404_management_assessment_completed := data.sox.section_404.management_assessment.completed

default _d_section_404_internal_controls_designed_effectively := false

_d_section_404_internal_controls_designed_effectively := data.sox.section_404.internal_controls.designed_effectively

default _d_section_404_internal_controls_operating_effectively := false

_d_section_404_internal_controls_operating_effectively := data.sox.section_404.internal_controls.operating_effectively

default _d_section_404_external_auditor_attestation_unqualified := false

_d_section_404_external_auditor_attestation_unqualified := data.sox.section_404.external_auditor_attestation.unqualified

default _d_section_404_remediation_plan_implemented := false

_d_section_404_remediation_plan_implemented := data.sox.section_404.remediation_plan.implemented

default _d_section_404_continuous_monitoring_active := false

_d_section_404_continuous_monitoring_active := data.sox.section_404.continuous_monitoring.active

default _d_section_409_material_events_disclosed_timely := false

_d_section_409_material_events_disclosed_timely := data.sox.section_409.material_events.disclosed_timely

default _d_section_409_disclosure_process_automated := false

_d_section_409_disclosure_process_automated := data.sox.section_409.disclosure_process.automated

default _d_section_409_disclosure_controls_reviewed_quarterly := false

_d_section_409_disclosure_controls_reviewed_quarterly := data.sox.section_409.disclosure_controls.reviewed_quarterly

default _d_section_409_event_detection_real_time := false

_d_section_409_event_detection_real_time := data.sox.section_409.event_detection.real_time

default _d_section_409_filing_deadlines_met := false

_d_section_409_filing_deadlines_met := data.sox.section_409.filing_deadlines.met

default _d_management_assessment_framework_documented := false

_d_management_assessment_framework_documented := data.sox.management.assessment_framework.documented

default _d_management_testing_procedures_comprehensive := false

_d_management_testing_procedures_comprehensive := data.sox.management.testing_procedures.comprehensive

default _d_management_deficiency_remediation_timely := false

_d_management_deficiency_remediation_timely := data.sox.management.deficiency_remediation.timely

default _d_management_continuous_monitoring_implemented := false

_d_management_continuous_monitoring_implemented := data.sox.management.continuous_monitoring.implemented

default _d_management_risk_assessment_annual := false

_d_management_risk_assessment_annual := data.sox.management.risk_assessment.annual

default _d_management_control_documentation_current := false

_d_management_control_documentation_current := data.sox.management.control_documentation.current

default _d_itgc_access_controls_implemented := false

_d_itgc_access_controls_implemented := data.sox.itgc.access_controls.implemented

default _d_itgc_change_management_controlled := false

_d_itgc_change_management_controlled := data.sox.itgc.change_management.controlled

default _d_itgc_computer_operations_monitored := false

_d_itgc_computer_operations_monitored := data.sox.itgc.computer_operations.monitored

default _d_itgc_system_development_secure := false

_d_itgc_system_development_secure := data.sox.itgc.system_development.secure

default _d_itgc_data_center_operations_controlled := false

_d_itgc_data_center_operations_controlled := data.sox.itgc.data_center_operations.controlled

default _d_itgc_backup_recovery_tested := false

_d_itgc_backup_recovery_tested := data.sox.itgc.backup_recovery.tested

default _d_application_controls_input_validation_comprehensive := false

_d_application_controls_input_validation_comprehensive := data.sox.application_controls.input_validation.comprehensive

default _d_application_controls_processing_controls_accurate := false

_d_application_controls_processing_controls_accurate := data.sox.application_controls.processing_controls.accurate

default _d_application_controls_output_controls_complete := false

_d_application_controls_output_controls_complete := data.sox.application_controls.output_controls.complete

default _d_application_controls_data_integrity_maintained := false

_d_application_controls_data_integrity_maintained := data.sox.application_controls.data_integrity.maintained

default _d_application_controls_error_handling_robust := false

_d_application_controls_error_handling_robust := data.sox.application_controls.error_handling.robust

default _d_application_controls_transaction_logging_complete := false

_d_application_controls_transaction_logging_complete := data.sox.application_controls.transaction_logging.complete
