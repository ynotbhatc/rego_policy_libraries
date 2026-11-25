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
# Facts are read from input.sox.<area>.<control>.<field>, the input document the caller posts. When the input
# has no "sox" key, facts loaded as data.sox.<area>.<control>.<field> are read instead (the older way to feed
# this module). The two are never merged and input.sox always wins; the report states which one was read in
# evidence_source ("input", "data" or "none") and sets data_sox_ignored when both were present.
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
		"state": _state(_fact("section_302.ceo_certification.provided")),
		"risk_level": "CRITICAL",
		"remediation": "Implement executive certification process with legal review",
		"basis": "15 U.S.C. 7241(a); 17 CFR 240.13a-14(a)",
		"evidence": _ref("section_302.ceo_certification.provided"),
		"path": "section_302.ceo_certification.provided",
	},
	{
		"area": "section_302",
		"section": "302",
		"control": "CFO Certification",
		"state": _state(_fact("section_302.cfo_certification.provided")),
		"risk_level": "CRITICAL",
		"remediation": "Implement executive certification process with legal review",
		"basis": "15 U.S.C. 7241(a); 17 CFR 240.13a-14(a)",
		"evidence": _ref("section_302.cfo_certification.provided"),
		"path": "section_302.cfo_certification.provided",
	},
	{
		"area": "section_302",
		"section": "302",
		"control": "Disclosure Controls",
		"state": _state(_fact("section_302.disclosure_controls.effective")),
		"risk_level": "HIGH",
		"remediation": "Establish disclosure controls and procedures framework",
		"basis": "15 U.S.C. 7241(a)(4); 17 CFR 240.13a-15(a)",
		"evidence": _ref("section_302.disclosure_controls.effective"),
		"path": "section_302.disclosure_controls.effective",
	},
	{
		"area": "section_302",
		"section": "302",
		"control": "Material Weaknesses",
		"state": _state(_fact("section_302.material_weaknesses.none_identified")),
		"risk_level": "HIGH",
		"remediation": "Conduct comprehensive control testing and remediate identified weaknesses",
		"basis": "15 U.S.C. 7241(a)(5) (disclosure to the auditors and audit committee); 17 CFR 229.308(a)(3) (no effective-ICFR conclusion with a material weakness)",
		"evidence": _ref("section_302.material_weaknesses.none_identified"),
		"path": "section_302.material_weaknesses.none_identified",
	},
	{
		"area": "section_302",
		"section": "302",
		"control": "Quarterly Evaluation",
		"state": _state(_fact("section_302.quarterly_review.completed")),
		"risk_level": "HIGH",
		"remediation": "Evaluate disclosure controls and procedures as of the end of each fiscal quarter",
		"basis": "17 CFR 240.13a-15(b)",
		"evidence": _ref("section_302.quarterly_review.completed"),
		"path": "section_302.quarterly_review.completed",
	},
	{
		"area": "section_302",
		"section": "302",
		"control": "Annual Assessment",
		"state": _state(_fact("section_302.annual_assessment.completed")),
		"risk_level": "HIGH",
		"remediation": "Complete management's evaluation of internal control over financial reporting as of fiscal year end",
		"basis": "17 CFR 240.13a-15(c)",
		"evidence": _ref("section_302.annual_assessment.completed"),
		"path": "section_302.annual_assessment.completed",
	},
	{
		"area": "section_404",
		"section": "404",
		"control": "Management Assessment",
		"state": _state(_fact("section_404.management_assessment.completed")),
		"risk_level": "CRITICAL",
		"remediation": "Develop management assessment methodology and documentation",
		"basis": "15 U.S.C. 7262(a); 17 CFR 229.308(a)",
		"evidence": _ref("section_404.management_assessment.completed"),
		"path": "section_404.management_assessment.completed",
	},
	{
		"area": "section_404",
		"section": "404",
		"control": "Control Design",
		"state": _state(_fact("section_404.internal_controls.designed_effectively")),
		"risk_level": "HIGH",
		"remediation": "Design comprehensive internal control framework",
		"basis": "15 U.S.C. 7262(a)(2)",
		"evidence": _ref("section_404.internal_controls.designed_effectively"),
		"path": "section_404.internal_controls.designed_effectively",
	},
	{
		"area": "section_404",
		"section": "404",
		"control": "Control Operation",
		"state": _state(_fact("section_404.internal_controls.operating_effectively")),
		"risk_level": "HIGH",
		"remediation": "Implement control monitoring and testing procedures",
		"basis": "15 U.S.C. 7262(a)(2)",
		"evidence": _ref("section_404.internal_controls.operating_effectively"),
		"path": "section_404.internal_controls.operating_effectively",
	},
	{
		"area": "section_404",
		"section": "404",
		"control": "Auditor Attestation",
		"state": _attestation_state,
		"risk_level": "CRITICAL",
		"remediation": "Engage qualified external auditor for Section 404 attestation",
		"basis": "15 U.S.C. 7262(b); not required of issuers exempt under 7262(b) or (c)",
		"evidence": _ref("section_404.external_auditor_attestation.unqualified"),
		"path": "section_404.external_auditor_attestation.unqualified",
	},
	{
		"area": "section_404",
		"section": "404",
		"control": "Remediation Plan",
		"state": _state(_fact("section_404.remediation_plan.implemented")),
		"risk_level": "MEDIUM",
		"remediation": "Implement the remediation plan for identified control deficiencies",
		"basis": "Library criterion (the statute requires the assessment and its disclosure, not a plan)",
		"evidence": _ref("section_404.remediation_plan.implemented"),
		"path": "section_404.remediation_plan.implemented",
	},
	{
		"area": "section_409",
		"section": "409",
		"control": "Timely Disclosure",
		"state": _state(_fact("section_409.material_events.disclosed_timely")),
		"risk_level": "HIGH",
		"remediation": "Implement event identification and disclosure procedures that meet the Form 8-K deadline",
		"basis": "15 U.S.C. 78m(l)",
		"evidence": _ref("section_409.material_events.disclosed_timely"),
		"path": "section_409.material_events.disclosed_timely",
	},
	{
		"area": "section_409",
		"section": "409",
		"control": "Filing Deadlines",
		"state": _state(_fact("section_409.filing_deadlines.met")),
		"risk_level": "HIGH",
		"remediation": "File current reports on Form 8-K within four business days of the triggering event",
		"basis": "Form 8-K General Instruction B.1 (four business days); 17 CFR 240.13a-11(a)",
		"evidence": _ref("section_409.filing_deadlines.met"),
		"path": "section_409.filing_deadlines.met",
	},
	{
		"area": "section_409",
		"section": "409",
		"control": "Quarterly Review",
		"state": _state(_fact("section_409.disclosure_controls.reviewed_quarterly")),
		"risk_level": "MEDIUM",
		"remediation": "Establish quarterly disclosure control review process",
		"basis": "17 CFR 240.13a-15(b)",
		"evidence": _ref("section_409.disclosure_controls.reviewed_quarterly"),
		"path": "section_409.disclosure_controls.reviewed_quarterly",
	},
	{
		"area": "management",
		"section": "Management",
		"control": "Assessment Framework",
		"state": _state(_fact("management.assessment_framework.documented")),
		"risk_level": "HIGH",
		"remediation": "Document comprehensive control assessment framework",
		"basis": "17 CFR 240.13a-15(c) (suitable, recognized control framework)",
		"evidence": _ref("management.assessment_framework.documented"),
		"path": "management.assessment_framework.documented",
	},
	{
		"area": "management",
		"section": "Management",
		"control": "Testing Procedures",
		"state": _state(_fact("management.testing_procedures.comprehensive")),
		"risk_level": "MEDIUM",
		"remediation": "Develop detailed testing procedures and documentation",
		"basis": "17 CFR 229.308, Instruction 2 (evidential matter supporting the assessment)",
		"evidence": _ref("management.testing_procedures.comprehensive"),
		"path": "management.testing_procedures.comprehensive",
	},
	{
		"area": "management",
		"section": "Management",
		"control": "Deficiency Remediation",
		"state": _state(_fact("management.deficiency_remediation.timely")),
		"risk_level": "HIGH",
		"remediation": "Implement deficiency tracking and remediation workflow",
		"basis": "Library criterion",
		"evidence": _ref("management.deficiency_remediation.timely"),
		"path": "management.deficiency_remediation.timely",
	},
	{
		"area": "management",
		"section": "Management",
		"control": "Risk Assessment",
		"state": _state(_fact("management.risk_assessment.annual")),
		"risk_level": "MEDIUM",
		"remediation": "Perform the financial reporting risk assessment each fiscal year",
		"basis": "Library criterion supporting the annual evaluation (17 CFR 240.13a-15(c))",
		"evidence": _ref("management.risk_assessment.annual"),
		"path": "management.risk_assessment.annual",
	},
	{
		"area": "management",
		"section": "Management",
		"control": "Control Documentation",
		"state": _state(_fact("management.control_documentation.current")),
		"risk_level": "MEDIUM",
		"remediation": "Bring control documentation up to date",
		"basis": "17 CFR 229.308, Instruction 2 (documentation supporting the assessment)",
		"evidence": _ref("management.control_documentation.current"),
		"path": "management.control_documentation.current",
	},
	{
		"area": "itgc",
		"section": "ITGC",
		"control": "Access Controls",
		"state": _state(_fact("itgc.access_controls.implemented")),
		"risk_level": "HIGH",
		"remediation": "Implement role-based access controls with segregation of duties",
		"basis": "Library criterion (IT general control)",
		"evidence": _ref("itgc.access_controls.implemented"),
		"path": "itgc.access_controls.implemented",
	},
	{
		"area": "itgc",
		"section": "ITGC",
		"control": "Change Management",
		"state": _state(_fact("itgc.change_management.controlled")),
		"risk_level": "HIGH",
		"remediation": "Establish formal change management process with approvals",
		"basis": "Library criterion (IT general control)",
		"evidence": _ref("itgc.change_management.controlled"),
		"path": "itgc.change_management.controlled",
	},
	{
		"area": "itgc",
		"section": "ITGC",
		"control": "Computer Operations",
		"state": _state(_fact("itgc.computer_operations.monitored")),
		"risk_level": "MEDIUM",
		"remediation": "Deploy comprehensive system monitoring and alerting",
		"basis": "Library criterion (IT general control)",
		"evidence": _ref("itgc.computer_operations.monitored"),
		"path": "itgc.computer_operations.monitored",
	},
	{
		"area": "itgc",
		"section": "ITGC",
		"control": "System Development",
		"state": _state(_fact("itgc.system_development.secure")),
		"risk_level": "MEDIUM",
		"remediation": "Implement secure development lifecycle (SDLC) practices",
		"basis": "Library criterion (IT general control)",
		"evidence": _ref("itgc.system_development.secure"),
		"path": "itgc.system_development.secure",
	},
	{
		"area": "itgc",
		"section": "ITGC",
		"control": "Data Center Operations",
		"state": _state(_fact("itgc.data_center_operations.controlled")),
		"risk_level": "MEDIUM",
		"remediation": "Establish controlled data center operations",
		"basis": "Library criterion (IT general control)",
		"evidence": _ref("itgc.data_center_operations.controlled"),
		"path": "itgc.data_center_operations.controlled",
	},
	{
		"area": "itgc",
		"section": "ITGC",
		"control": "Backup and Recovery",
		"state": _state(_fact("itgc.backup_recovery.tested")),
		"risk_level": "MEDIUM",
		"remediation": "Test backup and recovery procedures",
		"basis": "Library criterion (IT general control)",
		"evidence": _ref("itgc.backup_recovery.tested"),
		"path": "itgc.backup_recovery.tested",
	},
	{
		"area": "application_controls",
		"section": "Application Controls",
		"control": "Input Validation",
		"state": _state(_fact("application_controls.input_validation.comprehensive")),
		"risk_level": "HIGH",
		"remediation": "Implement comprehensive input validation and sanitization",
		"basis": "Library criterion (application control)",
		"evidence": _ref("application_controls.input_validation.comprehensive"),
		"path": "application_controls.input_validation.comprehensive",
	},
	{
		"area": "application_controls",
		"section": "Application Controls",
		"control": "Processing Controls",
		"state": _state(_fact("application_controls.processing_controls.accurate")),
		"risk_level": "MEDIUM",
		"remediation": "Deploy automated processing controls and reconciliation",
		"basis": "Library criterion (application control)",
		"evidence": _ref("application_controls.processing_controls.accurate"),
		"path": "application_controls.processing_controls.accurate",
	},
	{
		"area": "application_controls",
		"section": "Application Controls",
		"control": "Output Controls",
		"state": _state(_fact("application_controls.output_controls.complete")),
		"risk_level": "MEDIUM",
		"remediation": "Implement output validation and completeness checks",
		"basis": "Library criterion (application control)",
		"evidence": _ref("application_controls.output_controls.complete"),
		"path": "application_controls.output_controls.complete",
	},
	{
		"area": "application_controls",
		"section": "Application Controls",
		"control": "Data Integrity",
		"state": _state(_fact("application_controls.data_integrity.maintained")),
		"risk_level": "HIGH",
		"remediation": "Deploy data integrity monitoring and verification",
		"basis": "Library criterion (application control)",
		"evidence": _ref("application_controls.data_integrity.maintained"),
		"path": "application_controls.data_integrity.maintained",
	},
	{
		"area": "application_controls",
		"section": "Application Controls",
		"control": "Error Handling",
		"state": _state(_fact("application_controls.error_handling.robust")),
		"risk_level": "MEDIUM",
		"remediation": "Implement error detection, reporting and correction controls",
		"basis": "Library criterion (application control)",
		"evidence": _ref("application_controls.error_handling.robust"),
		"path": "application_controls.error_handling.robust",
	},
	{
		"area": "application_controls",
		"section": "Application Controls",
		"control": "Transaction Logging",
		"state": _state(_fact("application_controls.transaction_logging.complete")),
		"risk_level": "MEDIUM",
		"remediation": "Implement complete transaction logging and audit trails",
		"basis": "Library criterion (application control)",
		"evidence": _ref("application_controls.transaction_logging.complete"),
		"path": "application_controls.transaction_logging.complete",
	},
]

# Reported, never scored (see the header).
advisories := [
	{
		"advisory": "Automated Disclosure Process",
		"sox_section": "409",
		"status": _advisory_state(_fact("section_409.disclosure_process.automated")),
		"scored": false,
		"note": "15 U.S.C. 78m(l) requires disclosure on a rapid and current basis; neither it nor Form 8-K requires an automated process",
		"evidence": _ref("section_409.disclosure_process.automated"),
	},
	{
		"advisory": "Real-Time Event Detection",
		"sox_section": "409",
		"status": _advisory_state(_fact("section_409.event_detection.real_time")),
		"scored": false,
		"note": "Form 8-K General Instruction B.1 allows four business days after the event; real-time detection is not required",
		"evidence": _ref("section_409.event_detection.real_time"),
	},
	{
		"advisory": "Continuous Monitoring",
		"sox_section": "404",
		"status": _advisory_state(_fact("section_404.continuous_monitoring.active")),
		"scored": false,
		"note": "15 U.S.C. 7262(a) and 17 CFR 240.13a-15(c) require an assessment as of fiscal year end; continuous monitoring is not required",
		"evidence": _ref("section_404.continuous_monitoring.active"),
	},
	{
		"advisory": "Continuous Monitoring",
		"sox_section": "Management",
		"status": _advisory_state(_fact("management.continuous_monitoring.implemented")),
		"scored": false,
		"note": "17 CFR 240.13a-15(c) and (d) require annual and quarterly evaluations; continuous monitoring is not required",
		"evidence": _ref("management.continuous_monitoring.implemented"),
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
	_fact("section_404.external_auditor_attestation.required") == false
	_fact("section_404.external_auditor_attestation.exemption") in {"emerging_growth_company", "non_accelerated_filer"}
}

_attestation_state := "NOT_APPLICABLE" if {
	_attestation_exempt
} else := _state(_fact("section_404.external_auditor_attestation.unqualified"))

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
		"detail": _detail(check),
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
# Evidence source. Facts are posted as the input document, under input.sox, like every other module in
# this library. A caller that still loads them as the data document data.sox is served only when the
# input has no "sox" key at all. The two are never merged: once input.sox is posted (even as null, or
# with one fact), nothing is read from data.sox, so loaded data cannot override or fill in posted input.
# ---------------------------------------------------------------------------

default _input_has_sox := false

_input_has_sox if {
	is_object(input)
	"sox" in object.keys(input)
}

# The data.sox areas this module reads, each by a ground reference (data.sox also holds the sox packages,
# so it is never read whole). An area that is not loaded has no entry.
_data_area["section_302"] := data.sox.section_302

_data_area["section_404"] := data.sox.section_404

_data_area["section_409"] := data.sox.section_409

_data_area["management"] := data.sox.management

_data_area["itgc.access_controls"] := data.sox.itgc.access_controls

_data_area["itgc.change_management"] := data.sox.itgc.change_management

_data_area["itgc.computer_operations"] := data.sox.itgc.computer_operations

_data_area["itgc.system_development"] := data.sox.itgc.system_development

_data_area["itgc.data_center_operations"] := data.sox.itgc.data_center_operations

_data_area["itgc.backup_recovery"] := data.sox.itgc.backup_recovery

_data_area["application_controls.input_validation"] := data.sox.application_controls.input_validation

_data_area["application_controls.processing_controls"] := data.sox.application_controls.processing_controls

_data_area["application_controls.output_controls"] := data.sox.application_controls.output_controls

_data_area["application_controls.data_integrity"] := data.sox.application_controls.data_integrity

_data_area["application_controls.error_handling"] := data.sox.application_controls.error_handling

_data_area["application_controls.transaction_logging"] := data.sox.application_controls.transaction_logging

default _data_sox_loaded := false

_data_sox_loaded if count(_data_area) > 0

_nest([area], value) := {area: value}

_nest([package_name, area], value) := {package_name: {area: value}}

_data_sox := object.union_n([_nest(split(key, "."), value) | some key, value in _data_area])

# "input", "data" or "none" (nothing posted and nothing loaded).
evidence_source := "input" if {
	_input_has_sox
} else := "data" if {
	_data_sox_loaded
} else := "none"

# True when data.sox is loaded and was not read because input.sox was posted.
default data_sox_ignored := false

data_sox_ignored if {
	_input_has_sox
	_data_sox_loaded
}

# An input.sox that is not an object (null, a string) reads as empty: every fact is missing evidence.
_sox := input.sox if {
	_input_has_sox
	is_object(input.sox)
} else := {} if {
	_input_has_sox
} else := _data_sox

_source_document := "data" if {
	evidence_source == "data"
} else := "input"

# A fact by its dotted path below sox; null when it is absent or its parent is not an object.
_fact(path) := object.get(_sox, split(path, "."), null)

# The fact's full name in the document it was read from, for findings.
_ref(path) := sprintf("%s.sox.%s", [_source_document, path])

# Only the booleans are evidence. Anything else is named as an evidence problem.
_problem(path) := sprintf("evidence missing: %s not collected", [_ref(path)]) if {
	_fact(path) == null
}

_problem(path) := sprintf("%s is not a boolean (got %s)", [_ref(path), type_name(_fact(path))]) if {
	_fact(path) != null
	not is_boolean(_fact(path))
}

# What a finding says about its fact.
_detail(check) := sprintf("%s is false", [check.evidence]) if {
	check.state == "NON_COMPLIANT"
} else := _problem(check.path)

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
	"evidence_source": evidence_source,
	"data_sox_ignored": data_sox_ignored,
})

default _entrypoint_compliant := false

_entrypoint_compliant if overall_sox_assessment.compliance_status == true
