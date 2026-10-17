# METADATA
# title: "Simplified SOX (Sarbanes-Oxley Act) Compliance Framework"
# custom:
#   class: compliance
#   framework: sox
#   source: us-federal
#   domains: [financial, public-company]
#   coverage:
#     checks: 15
#     cited: 15
#     density: orchestrator
#     basis: role
#     tested: true
#     entrypoint: none
#     guard: n/a
#     as_of: v2.4.1
package sox.simplified

import rego.v1

# Simplified SOX (Sarbanes-Oxley Act) Compliance Framework
# Main policy for SOX compliance assessment

# Overall SOX compliance evaluation
default sox_compliant := false

sox_compliant if {
    section_302_compliant
    section_404_compliant
    section_409_compliant
    itgc_compliant
}

# Section 302: Corporate Responsibility for Financial Reports
default section_302_compliant := false

section_302_compliant if {
    input.sox.section_302.ceo_certification.provided
    input.sox.section_302.cfo_certification.provided
    input.sox.section_302.disclosure_controls.effective
    input.sox.section_302.material_weaknesses.none_identified
}

# Section 404: Management Assessment of Internal Controls
default section_404_compliant := false

section_404_compliant if {
    input.sox.section_404.management_assessment.completed
    input.sox.section_404.internal_controls.designed_effectively
    input.sox.section_404.internal_controls.operating_effectively
    input.sox.section_404.external_auditor_attestation.unqualified
}

# Section 409: Real-time Issuer Disclosures
default section_409_compliant := false

section_409_compliant if {
    input.sox.section_409.material_events.disclosed_timely
    input.sox.section_409.disclosure_process.automated
    input.sox.section_409.disclosure_controls.reviewed_quarterly
}

# IT General Controls (ITGC) Compliance
default itgc_compliant := false

itgc_compliant if {
    input.sox.itgc.access_controls.implemented
    input.sox.itgc.change_management.controlled
    input.sox.itgc.computer_operations.monitored
    input.sox.itgc.system_development.secure
    input.sox.itgc.data_center_operations.controlled
    input.sox.itgc.backup_recovery.tested
}

# SOX Compliance Score Calculation
default sox_compliance_score := 0

sox_compliance_score := score if {
    components := [
        section_302_score,
        section_404_score,
        section_409_score,
        itgc_score
    ]
    score := (sum(components) / count(components))
}

# Section 302 Score
section_302_score := score if {
    checks := [
        _i_section_302_ceo_certification_provided,
        _i_section_302_cfo_certification_provided,
        _i_section_302_disclosure_controls_effective,
        _i_section_302_material_weaknesses_none_identified,
        _i_section_302_quarterly_review_completed,
        _i_section_302_annual_assessment_completed
    ]
    passed := count([check | check := checks[_]; check == true])
    score := passed / count(checks)
}

# Section 404 Score
section_404_score := score if {
    checks := [
        _i_section_404_management_assessment_completed,
        _i_section_404_internal_controls_designed_effectively,
        _i_section_404_internal_controls_operating_effectively,
        _i_section_404_external_auditor_attestation_unqualified,
        _i_section_404_remediation_plan_implemented,
        _i_section_404_continuous_monitoring_active
    ]
    passed := count([check | check := checks[_]; check == true])
    score := passed / count(checks)
}

# Section 409 Score
section_409_score := score if {
    checks := [
        _i_section_409_material_events_disclosed_timely,
        _i_section_409_disclosure_process_automated,
        _i_section_409_disclosure_controls_reviewed_quarterly,
        _i_section_409_event_detection_real_time,
        _i_section_409_filing_deadlines_met
    ]
    passed := count([check | check := checks[_]; check == true])
    score := passed / count(checks)
}

# ITGC Score
itgc_score := score if {
    checks := [
        _i_itgc_access_controls_implemented,
        _i_itgc_change_management_controlled,
        _i_itgc_computer_operations_monitored,
        _i_itgc_system_development_secure,
        _i_itgc_data_center_operations_controlled,
        _i_itgc_backup_recovery_tested
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
        "itgc_findings": itgc_findings
    }
}

# Section 302 Findings
section_302_findings := findings if {
    findings := [finding |
        controls := [
            {"control": "CEO Certification", "status": _i_section_302_ceo_certification_provided, "risk": "CRITICAL"},
            {"control": "CFO Certification", "status": _i_section_302_cfo_certification_provided, "risk": "CRITICAL"},
            {"control": "Disclosure Controls", "status": _i_section_302_disclosure_controls_effective, "risk": "HIGH"},
            {"control": "Material Weaknesses", "status": _i_section_302_material_weaknesses_none_identified, "risk": "HIGH"}
        ]
        control := controls[_]
        not control.status
        finding := {
            "control_name": control.control,
            "status": "NON_COMPLIANT",
            "section": "302",
            "risk_level": control.risk,
            "remediation": _get_302_remediation(control.control)
        }
    ]
}

# Section 404 Findings
section_404_findings := findings if {
    findings := [finding |
        controls := [
            {"control": "Management Assessment", "status": _i_section_404_management_assessment_completed, "risk": "CRITICAL"},
            {"control": "Control Design", "status": _i_section_404_internal_controls_designed_effectively, "risk": "HIGH"},
            {"control": "Control Operation", "status": _i_section_404_internal_controls_operating_effectively, "risk": "HIGH"},
            {"control": "Auditor Attestation", "status": _i_section_404_external_auditor_attestation_unqualified, "risk": "CRITICAL"}
        ]
        control := controls[_]
        not control.status
        finding := {
            "control_name": control.control,
            "status": "NON_COMPLIANT",
            "section": "404",
            "risk_level": control.risk,
            "remediation": _get_404_remediation(control.control)
        }
    ]
}

# Section 409 Findings
section_409_findings := findings if {
    findings := [finding |
        controls := [
            {"control": "Timely Disclosure", "status": _i_section_409_material_events_disclosed_timely, "risk": "HIGH"},
            {"control": "Automated Process", "status": _i_section_409_disclosure_process_automated, "risk": "MEDIUM"},
            {"control": "Quarterly Review", "status": _i_section_409_disclosure_controls_reviewed_quarterly, "risk": "MEDIUM"}
        ]
        control := controls[_]
        not control.status
        finding := {
            "control_name": control.control,
            "status": "NON_COMPLIANT",
            "section": "409",
            "risk_level": control.risk,
            "remediation": _get_409_remediation(control.control)
        }
    ]
}

# ITGC Findings
itgc_findings := findings if {
    findings := [finding |
        controls := [
            {"control": "Access Controls", "status": _i_itgc_access_controls_implemented, "risk": "HIGH"},
            {"control": "Change Management", "status": _i_itgc_change_management_controlled, "risk": "HIGH"},
            {"control": "Computer Operations", "status": _i_itgc_computer_operations_monitored, "risk": "MEDIUM"},
            {"control": "System Development", "status": _i_itgc_system_development_secure, "risk": "MEDIUM"}
        ]
        control := controls[_]
        not control.status
        finding := {
            "control_name": control.control,
            "status": "NON_COMPLIANT",
            "section": "ITGC",
            "risk_level": control.risk,
            "remediation": _get_itgc_remediation(control.control)
        }
    ]
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

# SOX Compliance Level Determination
sox_compliance_level := "FULLY_COMPLIANT" if {
    sox_compliance_score >= 0.95
}

sox_compliance_level := "SUBSTANTIALLY_COMPLIANT" if {
    sox_compliance_score >= 0.85
    sox_compliance_score < 0.95
}

sox_compliance_level := "PARTIALLY_COMPLIANT" if {
    sox_compliance_score >= 0.70
    sox_compliance_score < 0.85
}

sox_compliance_level := "NON_COMPLIANT" if {
    sox_compliance_score < 0.70
}

# Overall SOX Assessment Summary
overall_sox_assessment := assessment if {
    assessment := {
        "compliance_status": sox_compliant,
        "compliance_score": sox_compliance_score * 100,
        "compliance_level": sox_compliance_level,
        "section_scores": {
            "section_302": section_302_score * 100,
            "section_404": section_404_score * 100,
            "section_409": section_409_score * 100,
            "itgc": itgc_score * 100
        },
        "total_findings": count(sox_detailed_findings.section_302_findings) + 
                         count(sox_detailed_findings.section_404_findings) + 
                         count(sox_detailed_findings.section_409_findings) + 
                         count(sox_detailed_findings.itgc_findings),
        "critical_findings": count_critical_findings,
        "high_findings": count_high_findings,
        "medium_findings": count_medium_findings
    }
}

# Count findings by risk level
count_critical_findings := count([finding |
    some section_key
    section := sox_detailed_findings[section_key]
    finding := section[_]
    finding.risk_level == "CRITICAL"
])

count_high_findings := count([finding |
    some section_key
    section := sox_detailed_findings[section_key]
    finding := section[_]
    finding.risk_level == "HIGH"
])

count_medium_findings := count([finding |
    some section_key
    section := sox_detailed_findings[section_key]
    finding := section[_]
    finding.risk_level == "MEDIUM"
])

# ---------------------------------------------------------------------------
# Fact accessors. A missing input field must read as false, not make the whole
# checks/controls array undefined (which silently dropped that control's
# finding and left the score and assessment undefined).
# ---------------------------------------------------------------------------

default _i_section_302_ceo_certification_provided := false

_i_section_302_ceo_certification_provided := input.sox.section_302.ceo_certification.provided

default _i_section_302_cfo_certification_provided := false

_i_section_302_cfo_certification_provided := input.sox.section_302.cfo_certification.provided

default _i_section_302_disclosure_controls_effective := false

_i_section_302_disclosure_controls_effective := input.sox.section_302.disclosure_controls.effective

default _i_section_302_material_weaknesses_none_identified := false

_i_section_302_material_weaknesses_none_identified := input.sox.section_302.material_weaknesses.none_identified

default _i_section_302_quarterly_review_completed := false

_i_section_302_quarterly_review_completed := input.sox.section_302.quarterly_review.completed

default _i_section_302_annual_assessment_completed := false

_i_section_302_annual_assessment_completed := input.sox.section_302.annual_assessment.completed

default _i_section_404_management_assessment_completed := false

_i_section_404_management_assessment_completed := input.sox.section_404.management_assessment.completed

default _i_section_404_internal_controls_designed_effectively := false

_i_section_404_internal_controls_designed_effectively := input.sox.section_404.internal_controls.designed_effectively

default _i_section_404_internal_controls_operating_effectively := false

_i_section_404_internal_controls_operating_effectively := input.sox.section_404.internal_controls.operating_effectively

default _i_section_404_external_auditor_attestation_unqualified := false

_i_section_404_external_auditor_attestation_unqualified := input.sox.section_404.external_auditor_attestation.unqualified

default _i_section_404_remediation_plan_implemented := false

_i_section_404_remediation_plan_implemented := input.sox.section_404.remediation_plan.implemented

default _i_section_404_continuous_monitoring_active := false

_i_section_404_continuous_monitoring_active := input.sox.section_404.continuous_monitoring.active

default _i_section_409_material_events_disclosed_timely := false

_i_section_409_material_events_disclosed_timely := input.sox.section_409.material_events.disclosed_timely

default _i_section_409_disclosure_process_automated := false

_i_section_409_disclosure_process_automated := input.sox.section_409.disclosure_process.automated

default _i_section_409_disclosure_controls_reviewed_quarterly := false

_i_section_409_disclosure_controls_reviewed_quarterly := input.sox.section_409.disclosure_controls.reviewed_quarterly

default _i_section_409_event_detection_real_time := false

_i_section_409_event_detection_real_time := input.sox.section_409.event_detection.real_time

default _i_section_409_filing_deadlines_met := false

_i_section_409_filing_deadlines_met := input.sox.section_409.filing_deadlines.met

default _i_itgc_access_controls_implemented := false

_i_itgc_access_controls_implemented := input.sox.itgc.access_controls.implemented

default _i_itgc_change_management_controlled := false

_i_itgc_change_management_controlled := input.sox.itgc.change_management.controlled

default _i_itgc_computer_operations_monitored := false

_i_itgc_computer_operations_monitored := input.sox.itgc.computer_operations.monitored

default _i_itgc_system_development_secure := false

_i_itgc_system_development_secure := input.sox.itgc.system_development.secure

default _i_itgc_data_center_operations_controlled := false

_i_itgc_data_center_operations_controlled := input.sox.itgc.data_center_operations.controlled

default _i_itgc_backup_recovery_tested := false

_i_itgc_backup_recovery_tested := input.sox.itgc.backup_recovery.tested
