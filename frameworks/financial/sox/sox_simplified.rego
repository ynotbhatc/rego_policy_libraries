# METADATA
# title: "Simplified SOX (Sarbanes-Oxley Act) Compliance Framework"
# custom:
#   class: compliance
#   framework: sox
#   source: us-federal
#   domains: [financial, public-company]
#   coverage:
#     checks: 20
#     cited: 20
#     density: orchestrator
#     basis: role
#     tested: true
#     entrypoint: none
#     guard: n/a
#     as_of: v2.5.0
package sox.simplified

import rego.v1

# Simplified SOX (Sarbanes-Oxley Act) Compliance Framework.
# Facts are read from input.sox.<area>.<control>.<field>, the input document the caller posts. This module
# never reads data.sox; evidence_source is "input", or "none" when the input has no "sox" key.
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
	itgc_compliant
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

# IT General Controls (ITGC) Compliance
default itgc_compliant := false

itgc_compliant if _area_compliant("itgc")

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

# SOX Compliance Score Calculation: the mean of the four area scores (0 to 1).
default sox_compliance_score := 0

sox_compliance_score := sum(components) / count(components) if {
	components := [
		section_302_score,
		section_404_score,
		section_409_score,
		itgc_score,
	]
}

default section_302_score := 0

section_302_score := _area_score("section_302")

default section_404_score := 0

section_404_score := _area_score("section_404")

default section_409_score := 0

section_409_score := _area_score("section_409")

default itgc_score := 0

itgc_score := _area_score("itgc")

# SOX Detailed Findings: every scored check that is not passing and not exempt.
section_302_findings := _area_findings("section_302")

section_404_findings := _area_findings("section_404")

section_409_findings := _area_findings("section_409")

itgc_findings := _area_findings("itgc")

sox_detailed_findings := {
	"section_302_findings": section_302_findings,
	"section_404_findings": section_404_findings,
	"section_409_findings": section_409_findings,
	"itgc_findings": itgc_findings,
}

# SOX Compliance Level Determination
# FULLY_COMPLIANT additionally requires the gated verdict.
default _fully_compliant := false

_fully_compliant if {
	is_number(sox_compliance_score)
	sox_compliance_score >= 0.95
	sox_compliant
}

sox_compliance_level := "FULLY_COMPLIANT" if _fully_compliant

sox_compliance_level := "SUBSTANTIALLY_COMPLIANT" if {
	is_number(sox_compliance_score)
	sox_compliance_score >= 0.85
	not _fully_compliant
}

sox_compliance_level := "PARTIALLY_COMPLIANT" if {
	is_number(sox_compliance_score)
	sox_compliance_score >= 0.70
	sox_compliance_score < 0.85
}

sox_compliance_level := "NON_COMPLIANT" if {
	is_number(sox_compliance_score)
	sox_compliance_score < 0.70
}

_all_findings := [finding |
	some area in ["section_302", "section_404", "section_409", "itgc"]
	some finding in _area_findings(area)
]

_findings_at(risk_level) := count([finding | some finding in _all_findings; finding.risk_level == risk_level])

count_critical_findings := _findings_at("CRITICAL")

count_high_findings := _findings_at("HIGH")

count_medium_findings := _findings_at("MEDIUM")

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
			"itgc": itgc_score * 100,
		},
		"total_findings": count(_all_findings),
		"critical_findings": count_critical_findings,
		"high_findings": count_high_findings,
		"medium_findings": count_medium_findings,
		"total_controls": count(_checks),
		"passed_controls": _count_in({"PASS"}),
		"failed_controls": _count_in(_open_states),
		"evidence_missing_controls": _count_in({"EVIDENCE_MISSING"}),
		"not_applicable_controls": _count_in({"NOT_APPLICABLE"}),
		"advisories": [advisory | some advisory in advisories],
		"evidence_source": evidence_source,
	}
}

# ---------------------------------------------------------------------------
# Evidence source. Facts are posted as the input document, under input.sox, like every other module in
# this library. This module never reads data.sox.
# ---------------------------------------------------------------------------

default _input_has_sox := false

_input_has_sox if {
	is_object(input)
	"sox" in object.keys(input)
}

# "input" or "none" (nothing posted).
evidence_source := "input" if {
	_input_has_sox
} else := "none"

# An input.sox that is absent or not an object (null, a string) reads as empty: every fact is missing evidence.
_sox := input.sox if {
	_input_has_sox
	is_object(input.sox)
} else := {}

_source_document := "input"

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
