# METADATA
# title: "SOX (Sarbanes-Oxley Act) Compliance Framework"
# custom:
#   class: compliance
#   framework: sox
#   source: us-federal
#   domains: [financial, public-company]
#   coverage:
#     checks: 32
#     cited: 32
#     density: orchestrator
#     basis: role
#     tested: true
#     entrypoint: compliance_report
#     guard: self
#     as_of: v2.5.0
package sox.main

import rego.v1

# SOX (Sarbanes-Oxley Act) Compliance Framework — main aggregation policy.
# Facts are read from data.sox.<area>.<control>.<field> (loaded by the caller), not from input.
#
# Sources (fetched 2026-11-23):
#   SOX 302  15 U.S.C. 7241    https://www.govinfo.gov/content/pkg/USCODE-2024-title15/html/USCODE-2024-title15-chap98-subchapIII-sec7241.htm
#   SOX 404  15 U.S.C. 7262    https://www.govinfo.gov/content/pkg/USCODE-2024-title15/html/USCODE-2024-title15-chap98-subchapIV-sec7262.htm
#   SOX 409  15 U.S.C. 78m(l)  https://www.govinfo.gov/content/pkg/USCODE-2024-title15/html/USCODE-2024-title15-chap2B-sec78m.htm
#   17 CFR 240.13a-11, 240.13a-14, 240.13a-15 and 229.308 (Item 308): https://www.ecfr.gov/current/title-17
#   Form 8-K General Instruction B.1, read in the adopting release, 69 FR 15594 (25 March 2004):
#     https://www.federalregister.gov/citation/69-FR-15594 (the current form is published at sec.gov)
#
# What the statute and rules require, and what this module therefore scores:
#   302  the principal executive and financial officers certify each annual and quarterly report; disclosure
#        controls are maintained and evaluated each fiscal quarter (13a-15(a), (b)); ICFR is evaluated as of
#        fiscal year end (13a-15(c)); material weaknesses are disclosed (7241(a)(5), Item 308(a)(3)).
#   404  management's annual internal control report (7262(a)) and, unless the issuer is exempt, the auditor's
#        attestation (7262(b)). Emerging growth companies (7262(b)) and issuers that are neither large accelerated
#        nor accelerated filers (7262(c)) are exempt from the attestation.
#   409  disclosure "on a rapid and current basis" (78m(l)), which the SEC implemented through Form 8-K: a report
#        is due within four business days after the event (General Instruction B.1).
#
# Not implemented here: Section 802 (record retention, 18 U.S.C. 1519 and 1520) and Section 906 (criminal
# certification, 18 U.S.C. 1350). No check in this module speaks for them.
#
# Advisories are reported and never scored: the statute and rules do not require an automated disclosure
# process, real-time event detection or continuous monitoring. Checks marked "Library criterion" in their basis
# are this library's operationalisation (IT general controls, application controls and management practices
# that support ICFR); they are scored, and the basis says they are not statutory text.
#
# Every scored check has one of four states:
#   PASS              the fact is the boolean true
#   NON_COMPLIANT     the fact is the boolean false
#   EVIDENCE_MISSING  the fact is absent, null or not a boolean (never a pass)
#   NOT_APPLICABLE    only the auditor attestation, and only on an explicit statement:
#                     external_auditor_attestation.required = false together with
#                     external_auditor_attestation.exemption = "emerging_growth_company" or "non_accelerated_filer"
# The score, the findings, the verdict and the counts all come from the same list of checks, so
# passed + failed + not applicable = total on every input (evidence-missing checks are part of failed).

# Overall SOX compliance evaluation: every scored check passes or is not applicable.
default sox_compliant := false

sox_compliant if {
	section_302_compliant
	section_404_compliant
	section_409_compliant
	management_assessment_compliant
	itgc_controls_compliant
	application_controls_all_compliant
}

# Section 302: Corporate Responsibility for Financial Reports
default section_302_compliant := false

section_302_compliant if _area_compliant("section_302")

# Section 404: Management Assessment of Internal Controls
default section_404_compliant := false

section_404_compliant if _area_compliant("section_404")

# Section 409: Real Time Issuer Disclosures
default section_409_compliant := false

section_409_compliant if _area_compliant("section_409")

# Management Assessment Framework
default management_assessment_compliant := false

management_assessment_compliant if _area_compliant("management")

# ITGC and application controls are scored, so a failed area must also fail the verdict.
default itgc_controls_compliant := false

itgc_controls_compliant if _area_compliant("itgc")

default application_controls_all_compliant := false

application_controls_all_compliant if _area_compliant("application_controls")

# ---------------------------------------------------------------------------
# The checks. This one list feeds the scores, the findings, the verdict and the counts.
# ---------------------------------------------------------------------------

_checks := [
	{
		"area": "section_302",
		"section": "302",
		"control": "CEO Certification",
		"state": _state(_d_section_302_ceo_certification_provided),
		"risk_level": "CRITICAL",
		"remediation": "Implement executive certification process with legal review",
		"basis": "15 U.S.C. 7241(a); 17 CFR 240.13a-14(a)",
		"evidence": "data.sox.section_302.ceo_certification.provided",
	},
	{
		"area": "section_302",
		"section": "302",
		"control": "CFO Certification",
		"state": _state(_d_section_302_cfo_certification_provided),
		"risk_level": "CRITICAL",
		"remediation": "Implement executive certification process with legal review",
		"basis": "15 U.S.C. 7241(a); 17 CFR 240.13a-14(a)",
		"evidence": "data.sox.section_302.cfo_certification.provided",
	},
	{
		"area": "section_302",
		"section": "302",
		"control": "Disclosure Controls",
		"state": _state(_d_section_302_disclosure_controls_effective),
		"risk_level": "HIGH",
		"remediation": "Establish disclosure controls and procedures framework",
		"basis": "15 U.S.C. 7241(a)(4); 17 CFR 240.13a-15(a)",
		"evidence": "data.sox.section_302.disclosure_controls.effective",
	},
	{
		"area": "section_302",
		"section": "302",
		"control": "Material Weaknesses",
		"state": _state(_d_section_302_material_weaknesses_none_identified),
		"risk_level": "HIGH",
		"remediation": "Conduct comprehensive control testing and remediate identified weaknesses",
		"basis": "15 U.S.C. 7241(a)(5) (disclosure to the auditors and audit committee); 17 CFR 229.308(a)(3) (no effective-ICFR conclusion with a material weakness)",
		"evidence": "data.sox.section_302.material_weaknesses.none_identified",
	},
	{
		"area": "section_302",
		"section": "302",
		"control": "Quarterly Evaluation",
		"state": _state(_d_section_302_quarterly_review_completed),
		"risk_level": "HIGH",
		"remediation": "Evaluate disclosure controls and procedures as of the end of each fiscal quarter",
		"basis": "17 CFR 240.13a-15(b)",
		"evidence": "data.sox.section_302.quarterly_review.completed",
	},
	{
		"area": "section_302",
		"section": "302",
		"control": "Annual Assessment",
		"state": _state(_d_section_302_annual_assessment_completed),
		"risk_level": "HIGH",
		"remediation": "Complete management's evaluation of internal control over financial reporting as of fiscal year end",
		"basis": "17 CFR 240.13a-15(c)",
		"evidence": "data.sox.section_302.annual_assessment.completed",
	},
	{
		"area": "section_404",
		"section": "404",
		"control": "Management Assessment",
		"state": _state(_d_section_404_management_assessment_completed),
		"risk_level": "CRITICAL",
		"remediation": "Develop management assessment methodology and documentation",
		"basis": "15 U.S.C. 7262(a); 17 CFR 229.308(a)",
		"evidence": "data.sox.section_404.management_assessment.completed",
	},
	{
		"area": "section_404",
		"section": "404",
		"control": "Control Design",
		"state": _state(_d_section_404_internal_controls_designed_effectively),
		"risk_level": "HIGH",
		"remediation": "Design comprehensive internal control framework",
		"basis": "15 U.S.C. 7262(a)(2)",
		"evidence": "data.sox.section_404.internal_controls.designed_effectively",
	},
	{
		"area": "section_404",
		"section": "404",
		"control": "Control Operation",
		"state": _state(_d_section_404_internal_controls_operating_effectively),
		"risk_level": "HIGH",
		"remediation": "Implement control monitoring and testing procedures",
		"basis": "15 U.S.C. 7262(a)(2)",
		"evidence": "data.sox.section_404.internal_controls.operating_effectively",
	},
	{
		"area": "section_404",
		"section": "404",
		"control": "Auditor Attestation",
		"state": _attestation_state,
		"risk_level": "CRITICAL",
		"remediation": "Engage qualified external auditor for Section 404 attestation",
		"basis": "15 U.S.C. 7262(b); not required of issuers exempt under 7262(b) or (c)",
		"evidence": "data.sox.section_404.external_auditor_attestation.unqualified",
	},
	{
		"area": "section_404",
		"section": "404",
		"control": "Remediation Plan",
		"state": _state(_d_section_404_remediation_plan_implemented),
		"risk_level": "MEDIUM",
		"remediation": "Implement the remediation plan for identified control deficiencies",
		"basis": "Library criterion (the statute requires the assessment and its disclosure, not a plan)",
		"evidence": "data.sox.section_404.remediation_plan.implemented",
	},
	{
		"area": "section_409",
		"section": "409",
		"control": "Timely Disclosure",
		"state": _state(_d_section_409_material_events_disclosed_timely),
		"risk_level": "HIGH",
		"remediation": "Implement event identification and disclosure procedures that meet the Form 8-K deadline",
		"basis": "15 U.S.C. 78m(l)",
		"evidence": "data.sox.section_409.material_events.disclosed_timely",
	},
	{
		"area": "section_409",
		"section": "409",
		"control": "Filing Deadlines",
		"state": _state(_d_section_409_filing_deadlines_met),
		"risk_level": "HIGH",
		"remediation": "File current reports on Form 8-K within four business days of the triggering event",
		"basis": "Form 8-K General Instruction B.1 (four business days); 17 CFR 240.13a-11(a)",
		"evidence": "data.sox.section_409.filing_deadlines.met",
	},
	{
		"area": "section_409",
		"section": "409",
		"control": "Quarterly Review",
		"state": _state(_d_section_409_disclosure_controls_reviewed_quarterly),
		"risk_level": "MEDIUM",
		"remediation": "Establish quarterly disclosure control review process",
		"basis": "17 CFR 240.13a-15(b)",
		"evidence": "data.sox.section_409.disclosure_controls.reviewed_quarterly",
	},
	{
		"area": "management",
		"section": "Management",
		"control": "Assessment Framework",
		"state": _state(_d_management_assessment_framework_documented),
		"risk_level": "HIGH",
		"remediation": "Document comprehensive control assessment framework",
		"basis": "17 CFR 240.13a-15(c) (suitable, recognized control framework)",
		"evidence": "data.sox.management.assessment_framework.documented",
	},
	{
		"area": "management",
		"section": "Management",
		"control": "Testing Procedures",
		"state": _state(_d_management_testing_procedures_comprehensive),
		"risk_level": "MEDIUM",
		"remediation": "Develop detailed testing procedures and documentation",
		"basis": "17 CFR 229.308, Instruction 2 (evidential matter supporting the assessment)",
		"evidence": "data.sox.management.testing_procedures.comprehensive",
	},
	{
		"area": "management",
		"section": "Management",
		"control": "Deficiency Remediation",
		"state": _state(_d_management_deficiency_remediation_timely),
		"risk_level": "HIGH",
		"remediation": "Implement deficiency tracking and remediation workflow",
		"basis": "Library criterion",
		"evidence": "data.sox.management.deficiency_remediation.timely",
	},
	{
		"area": "management",
		"section": "Management",
		"control": "Risk Assessment",
		"state": _state(_d_management_risk_assessment_annual),
		"risk_level": "MEDIUM",
		"remediation": "Perform the financial reporting risk assessment each fiscal year",
		"basis": "Library criterion supporting the annual evaluation (17 CFR 240.13a-15(c))",
		"evidence": "data.sox.management.risk_assessment.annual",
	},
	{
		"area": "management",
		"section": "Management",
		"control": "Control Documentation",
		"state": _state(_d_management_control_documentation_current),
		"risk_level": "MEDIUM",
		"remediation": "Bring control documentation up to date",
		"basis": "17 CFR 229.308, Instruction 2 (documentation supporting the assessment)",
		"evidence": "data.sox.management.control_documentation.current",
	},
	{
		"area": "itgc",
		"section": "ITGC",
		"control": "Access Controls",
		"state": _state(_d_itgc_access_controls_implemented),
		"risk_level": "HIGH",
		"remediation": "Implement role-based access controls with segregation of duties",
		"basis": "Library criterion (IT general control)",
		"evidence": "data.sox.itgc.access_controls.implemented",
	},
	{
		"area": "itgc",
		"section": "ITGC",
		"control": "Change Management",
		"state": _state(_d_itgc_change_management_controlled),
		"risk_level": "HIGH",
		"remediation": "Establish formal change management process with approvals",
		"basis": "Library criterion (IT general control)",
		"evidence": "data.sox.itgc.change_management.controlled",
	},
	{
		"area": "itgc",
		"section": "ITGC",
		"control": "Computer Operations",
		"state": _state(_d_itgc_computer_operations_monitored),
		"risk_level": "MEDIUM",
		"remediation": "Deploy comprehensive system monitoring and alerting",
		"basis": "Library criterion (IT general control)",
		"evidence": "data.sox.itgc.computer_operations.monitored",
	},
	{
		"area": "itgc",
		"section": "ITGC",
		"control": "System Development",
		"state": _state(_d_itgc_system_development_secure),
		"risk_level": "MEDIUM",
		"remediation": "Implement secure development lifecycle (SDLC) practices",
		"basis": "Library criterion (IT general control)",
		"evidence": "data.sox.itgc.system_development.secure",
	},
	{
		"area": "itgc",
		"section": "ITGC",
		"control": "Data Center Operations",
		"state": _state(_d_itgc_data_center_operations_controlled),
		"risk_level": "MEDIUM",
		"remediation": "Establish controlled data center operations",
		"basis": "Library criterion (IT general control)",
		"evidence": "data.sox.itgc.data_center_operations.controlled",
	},
	{
		"area": "itgc",
		"section": "ITGC",
		"control": "Backup and Recovery",
		"state": _state(_d_itgc_backup_recovery_tested),
		"risk_level": "MEDIUM",
		"remediation": "Test backup and recovery procedures",
		"basis": "Library criterion (IT general control)",
		"evidence": "data.sox.itgc.backup_recovery.tested",
	},
	{
		"area": "application_controls",
		"section": "Application Controls",
		"control": "Input Validation",
		"state": _state(_d_application_controls_input_validation_comprehensive),
		"risk_level": "HIGH",
		"remediation": "Implement comprehensive input validation and sanitization",
		"basis": "Library criterion (application control)",
		"evidence": "data.sox.application_controls.input_validation.comprehensive",
	},
	{
		"area": "application_controls",
		"section": "Application Controls",
		"control": "Processing Controls",
		"state": _state(_d_application_controls_processing_controls_accurate),
		"risk_level": "MEDIUM",
		"remediation": "Deploy automated processing controls and reconciliation",
		"basis": "Library criterion (application control)",
		"evidence": "data.sox.application_controls.processing_controls.accurate",
	},
	{
		"area": "application_controls",
		"section": "Application Controls",
		"control": "Output Controls",
		"state": _state(_d_application_controls_output_controls_complete),
		"risk_level": "MEDIUM",
		"remediation": "Implement output validation and completeness checks",
		"basis": "Library criterion (application control)",
		"evidence": "data.sox.application_controls.output_controls.complete",
	},
	{
		"area": "application_controls",
		"section": "Application Controls",
		"control": "Data Integrity",
		"state": _state(_d_application_controls_data_integrity_maintained),
		"risk_level": "HIGH",
		"remediation": "Deploy data integrity monitoring and verification",
		"basis": "Library criterion (application control)",
		"evidence": "data.sox.application_controls.data_integrity.maintained",
	},
	{
		"area": "application_controls",
		"section": "Application Controls",
		"control": "Error Handling",
		"state": _state(_d_application_controls_error_handling_robust),
		"risk_level": "MEDIUM",
		"remediation": "Implement error detection, reporting and correction controls",
		"basis": "Library criterion (application control)",
		"evidence": "data.sox.application_controls.error_handling.robust",
	},
	{
		"area": "application_controls",
		"section": "Application Controls",
		"control": "Transaction Logging",
		"state": _state(_d_application_controls_transaction_logging_complete),
		"risk_level": "MEDIUM",
		"remediation": "Implement complete transaction logging and audit trails",
		"basis": "Library criterion (application control)",
		"evidence": "data.sox.application_controls.transaction_logging.complete",
	},
]

# Reported, never scored (see the header).
advisories := [
	{
		"advisory": "Automated Disclosure Process",
		"sox_section": "409",
		"status": _advisory_state(_d_section_409_disclosure_process_automated),
		"scored": false,
		"note": "15 U.S.C. 78m(l) requires disclosure on a rapid and current basis; neither it nor Form 8-K requires an automated process",
		"evidence": "data.sox.section_409.disclosure_process.automated",
	},
	{
		"advisory": "Real-Time Event Detection",
		"sox_section": "409",
		"status": _advisory_state(_d_section_409_event_detection_real_time),
		"scored": false,
		"note": "Form 8-K General Instruction B.1 allows four business days after the event; real-time detection is not required",
		"evidence": "data.sox.section_409.event_detection.real_time",
	},
	{
		"advisory": "Continuous Monitoring",
		"sox_section": "404",
		"status": _advisory_state(_d_section_404_continuous_monitoring_active),
		"scored": false,
		"note": "15 U.S.C. 7262(a) and 17 CFR 240.13a-15(c) require an assessment as of fiscal year end; continuous monitoring is not required",
		"evidence": "data.sox.section_404.continuous_monitoring.active",
	},
	{
		"advisory": "Continuous Monitoring",
		"sox_section": "Management",
		"status": _advisory_state(_d_management_continuous_monitoring_implemented),
		"scored": false,
		"note": "17 CFR 240.13a-15(c) and (d) require annual and quarterly evaluations; continuous monitoring is not required",
		"evidence": "data.sox.management.continuous_monitoring.implemented",
	},
]

_state(true) := "PASS"

_state(false) := "NON_COMPLIANT"

_state(value) := "EVIDENCE_MISSING" if not is_boolean(value)

_advisory_state(true) := "MET"

_advisory_state(false) := "NOT_MET"

_advisory_state(value) := "NOT_REPORTED" if not is_boolean(value)

# Section 404(b) attestation: exempt only on an explicit statement naming the exemption.
default _attestation_exempt := false

_attestation_exempt if {
	data.sox.section_404.external_auditor_attestation.required == false
	data.sox.section_404.external_auditor_attestation.exemption in {"emerging_growth_company", "non_accelerated_filer"}
}

_attestation_state := "NOT_APPLICABLE" if {
	_attestation_exempt
} else := _state(_d_section_404_external_auditor_attestation_unqualified)

_area_checks(area) := [check | some check in _checks; check.area == area]

_with_state(checks, states) := [check | some check in checks; check.state in states]

_open_states := {"NON_COMPLIANT", "EVIDENCE_MISSING"}

_area_compliant(area) if count(_with_state(_area_checks(area), _open_states)) == 0

# Share of the applicable checks that pass.
_area_score(area) := count(_with_state(checks, {"PASS"})) / applicable if {
	checks := _area_checks(area)
	applicable := count(checks) - count(_with_state(checks, {"NOT_APPLICABLE"}))
	applicable > 0
}

_area_findings(area) := [finding |
	some check in _with_state(_area_checks(area), _open_states)
	finding := {
		"control_name": check.control,
		"status": check.state,
		"section": check.section,
		"risk_level": check.risk_level,
		"remediation": check.remediation,
		"basis": check.basis,
		"evidence": check.evidence,
	}
]

# The counts every consumer reads. Evidence-missing checks are part of failed.
total_controls := count(_checks)

_count_in(states) := count(_with_state(_checks, states))

# SOX Compliance Score Calculation: the mean of the six area scores, as a percentage.
default sox_compliance_score := 0

sox_compliance_score := (sum(components) / count(components)) * 100 if {
	components := [
		section_302_score,
		section_404_score,
		section_409_score,
		management_assessment_score,
		it_general_controls_score,
		application_controls_score,
	]
}

default section_302_score := 0

section_302_score := _area_score("section_302")

default section_404_score := 0

section_404_score := _area_score("section_404")

default section_409_score := 0

section_409_score := _area_score("section_409")

default management_assessment_score := 0

management_assessment_score := _area_score("management")

default it_general_controls_score := 0

it_general_controls_score := _area_score("itgc")

default application_controls_score := 0

application_controls_score := _area_score("application_controls")

# SOX Detailed Findings: every scored check that is not passing and not exempt.
section_302_findings := _area_findings("section_302")

section_404_findings := _area_findings("section_404")

section_409_findings := _area_findings("section_409")

itgc_findings := _area_findings("itgc")

application_control_findings := _area_findings("application_controls")

management_findings := _area_findings("management")

sox_detailed_findings := {
	"section_302_findings": section_302_findings,
	"section_404_findings": section_404_findings,
	"section_409_findings": section_409_findings,
	"itgc_findings": itgc_findings,
	"application_control_findings": application_control_findings,
	"management_findings": management_findings,
}

# SOX Compliance Level Determination
# FULLY_COMPLIANT additionally requires the gated verdict: a high average score
# must not mask a failed area.
default _fully_compliant := false

_fully_compliant if {
	is_number(sox_compliance_score)
	sox_compliance_score >= 95
	sox_compliant
}

sox_compliance_level := "FULLY_COMPLIANT" if _fully_compliant

sox_compliance_level := "SUBSTANTIALLY_COMPLIANT" if {
	is_number(sox_compliance_score)
	sox_compliance_score >= 85
	not _fully_compliant
}

sox_compliance_level := "PARTIALLY_COMPLIANT" if {
	is_number(sox_compliance_score)
	sox_compliance_score >= 70
	sox_compliance_score < 85
}

sox_compliance_level := "NON_COMPLIANT" if {
	is_number(sox_compliance_score)
	sox_compliance_score < 70
}

_violations := [finding |
	some area in ["section_302", "section_404", "section_409", "itgc", "application_controls", "management"]
	some finding in _area_findings(area)
]

_findings_at(risk_level) := count([finding | some finding in _violations; finding.risk_level == risk_level])

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
			"application_controls": application_controls_score * 100,
		},
		"total_findings": count(_violations),
		"critical_findings": _findings_at("CRITICAL"),
		"high_findings": _findings_at("HIGH"),
		"medium_findings": _findings_at("MEDIUM"),
		"advisories": [advisory | some advisory in advisories],
	}
}

# ---------------------------------------------------------------------------
# Fact accessors. A missing data field reads as null (evidence missing); it must not make the
# checks list undefined.
# ---------------------------------------------------------------------------

default _d_section_302_ceo_certification_provided := null

_d_section_302_ceo_certification_provided := data.sox.section_302.ceo_certification.provided

default _d_section_302_cfo_certification_provided := null

_d_section_302_cfo_certification_provided := data.sox.section_302.cfo_certification.provided

default _d_section_302_disclosure_controls_effective := null

_d_section_302_disclosure_controls_effective := data.sox.section_302.disclosure_controls.effective

default _d_section_302_material_weaknesses_none_identified := null

_d_section_302_material_weaknesses_none_identified := data.sox.section_302.material_weaknesses.none_identified

default _d_section_302_quarterly_review_completed := null

_d_section_302_quarterly_review_completed := data.sox.section_302.quarterly_review.completed

default _d_section_302_annual_assessment_completed := null

_d_section_302_annual_assessment_completed := data.sox.section_302.annual_assessment.completed

default _d_section_404_management_assessment_completed := null

_d_section_404_management_assessment_completed := data.sox.section_404.management_assessment.completed

default _d_section_404_internal_controls_designed_effectively := null

_d_section_404_internal_controls_designed_effectively := data.sox.section_404.internal_controls.designed_effectively

default _d_section_404_internal_controls_operating_effectively := null

_d_section_404_internal_controls_operating_effectively := data.sox.section_404.internal_controls.operating_effectively

default _d_section_404_external_auditor_attestation_unqualified := null

_d_section_404_external_auditor_attestation_unqualified := data.sox.section_404.external_auditor_attestation.unqualified

default _d_section_404_remediation_plan_implemented := null

_d_section_404_remediation_plan_implemented := data.sox.section_404.remediation_plan.implemented

default _d_section_409_material_events_disclosed_timely := null

_d_section_409_material_events_disclosed_timely := data.sox.section_409.material_events.disclosed_timely

default _d_section_409_filing_deadlines_met := null

_d_section_409_filing_deadlines_met := data.sox.section_409.filing_deadlines.met

default _d_section_409_disclosure_controls_reviewed_quarterly := null

_d_section_409_disclosure_controls_reviewed_quarterly := data.sox.section_409.disclosure_controls.reviewed_quarterly

default _d_management_assessment_framework_documented := null

_d_management_assessment_framework_documented := data.sox.management.assessment_framework.documented

default _d_management_testing_procedures_comprehensive := null

_d_management_testing_procedures_comprehensive := data.sox.management.testing_procedures.comprehensive

default _d_management_deficiency_remediation_timely := null

_d_management_deficiency_remediation_timely := data.sox.management.deficiency_remediation.timely

default _d_management_risk_assessment_annual := null

_d_management_risk_assessment_annual := data.sox.management.risk_assessment.annual

default _d_management_control_documentation_current := null

_d_management_control_documentation_current := data.sox.management.control_documentation.current

default _d_itgc_access_controls_implemented := null

_d_itgc_access_controls_implemented := data.sox.itgc.access_controls.implemented

default _d_itgc_change_management_controlled := null

_d_itgc_change_management_controlled := data.sox.itgc.change_management.controlled

default _d_itgc_computer_operations_monitored := null

_d_itgc_computer_operations_monitored := data.sox.itgc.computer_operations.monitored

default _d_itgc_system_development_secure := null

_d_itgc_system_development_secure := data.sox.itgc.system_development.secure

default _d_itgc_data_center_operations_controlled := null

_d_itgc_data_center_operations_controlled := data.sox.itgc.data_center_operations.controlled

default _d_itgc_backup_recovery_tested := null

_d_itgc_backup_recovery_tested := data.sox.itgc.backup_recovery.tested

default _d_application_controls_input_validation_comprehensive := null

_d_application_controls_input_validation_comprehensive := data.sox.application_controls.input_validation.comprehensive

default _d_application_controls_processing_controls_accurate := null

_d_application_controls_processing_controls_accurate := data.sox.application_controls.processing_controls.accurate

default _d_application_controls_output_controls_complete := null

_d_application_controls_output_controls_complete := data.sox.application_controls.output_controls.complete

default _d_application_controls_data_integrity_maintained := null

_d_application_controls_data_integrity_maintained := data.sox.application_controls.data_integrity.maintained

default _d_application_controls_error_handling_robust := null

_d_application_controls_error_handling_robust := data.sox.application_controls.error_handling.robust

default _d_application_controls_transaction_logging_complete := null

_d_application_controls_transaction_logging_complete := data.sox.application_controls.transaction_logging.complete

default _d_section_409_disclosure_process_automated := null

_d_section_409_disclosure_process_automated := data.sox.section_409.disclosure_process.automated

default _d_section_409_event_detection_real_time := null

_d_section_409_event_detection_real_time := data.sox.section_409.event_detection.real_time

default _d_section_404_continuous_monitoring_active := null

_d_section_404_continuous_monitoring_active := data.sox.section_404.continuous_monitoring.active

default _d_management_continuous_monitoring_implemented := null

_d_management_continuous_monitoring_implemented := data.sox.management.continuous_monitoring.implemented

# Framework-key entrypoint: the product reads /v1/data/sox/main/compliance_report. This package
# names its report `overall_sox_assessment`; expose it under the shared name with an explicit `compliant` and a
# fail-closed default so the entrypoint is never undefined.
default compliance_report := {
	"framework_key": "sox",
	"compliant": false,
	"fail_closed": true,
	"violations": [{"control": "FAIL-CLOSED", "title": "no report produced for sox; this is not a passing result"}],
	"violation_count": 1,
	"failed_controls": 1,
	"total_controls": 1,
}

# violations, violation_count, failed_controls and total_controls all come from _checks.
compliance_report := object.union(overall_sox_assessment, {
	"framework_key": "sox",
	"compliant": _entrypoint_compliant,
	"violations": _violations,
	"violation_count": count(_violations),
	"total_controls": count(_checks),
	"passed_controls": _count_in({"PASS"}),
	"failed_controls": _count_in(_open_states),
	"evidence_missing_controls": _count_in({"EVIDENCE_MISSING"}),
	"not_applicable_controls": _count_in({"NOT_APPLICABLE"}),
})

default _entrypoint_compliant := false

_entrypoint_compliant if overall_sox_assessment.compliance_status == true
