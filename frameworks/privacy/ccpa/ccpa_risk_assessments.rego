# METADATA
# title: "CCPA — Risk Assessments (11 CCR Article 10, §§7150–7157)"
# custom:
#   class: compliance
#   framework: ccpa
#   source: us-state
#   domains: [privacy, us-state]
#   coverage:
#     checks: 32
#     cited: 26
#     density: sized
#     basis: size
#     tested: true
#     entrypoint: compliance_report
#     guard: self
#     as_of: v2.3.7
package ccpa.risk_assessments

import rego.v1

# ---------------------------------------------------------------------------
# CCPA Regulations, Article 10 — Risk Assessments (11 CCR §§7150–7157)
# Approved 2025-09-22, effective 2026-01-01. Reference:
# cppa.ca.gov/regulations/ccpa_updates.html (approved text PDF).
#
# §7150(b): six processing activities present significant risk to privacy and
# require a risk assessment BEFORE the processing starts. §7152: what the
# assessment must document. §7155: review every three years, update within
# 45 days of a material change, legacy processing assessed by 2027-12-31,
# retain five years. §7157: submit summary information to the Agency by
# 2028-04-01 (for 2026–2027 assessments) and by April 1 each year after.
#
# Fail-closed: every activity must be declared in_use true/false (undeclared
# is a violation); an activity in use is then evaluated and every required
# fact must be boolean true. Report-content facts are
# evaluated once for the business's risk-assessment practice (not per
# assessment); feed the weakest assessment's facts.
#
# Input contract — input.ccpa.risk_assessments.*
#   activities.<id>.in_use / .assessment_completed_before_processing   bool
#   stakeholders.*   §7151    report.*   §7152(a)(1)–(9)   admt_provider.*  §7153
#   timing.*         §7155    submission.* §7157
# ---------------------------------------------------------------------------

default compliant := false

compliant if {
	count(violations) == 0
}

default _in := {}

_in := input.ccpa.risk_assessments

# ── §7150(b) — activities that require a risk assessment before processing ─

activities := {
	"selling_or_sharing": "§7150(b)(1): selling or sharing personal information",
	"sensitive_personal_information": "§7150(b)(2): processing sensitive personal information (beyond the HR-administration carve-out)",
	"admt_significant_decision": "§7150(b)(3): using ADMT for a significant decision concerning a consumer",
	"inference_from_observation_work_or_education": "§7150(b)(4): automated inference about a consumer from systematic observation as applicant, student, employee or contractor",
	"inference_in_sensitive_location": "§7150(b)(5): automated inference about a consumer based on presence in a sensitive location",
	"training_admt_or_biometric_technology": "§7150(b)(6): processing personal information to train ADMT for significant decisions, or facial/emotion-recognition or other identification/profiling technology",
}

_in_use(id) if _in.activities[id].in_use == true

# Fail-closed: every §7150(b) activity must be declared in_use true or false.
# An undeclared activity cannot be assumed absent (that is how a privacy
# assessment regime fails open), so it is a violation until classified.
violations contains msg if {
	some id, text in activities
	not _in.activities[id].in_use == true
	not _in.activities[id].in_use == false
	msg := sprintf("CCPA %v — activity not declared (activities.%v.in_use must be true or false)", [text, id])
}

violations contains msg if {
	some id, text in activities
	_in_use(id)
	not _in.activities[id].assessment_completed_before_processing == true
	msg := sprintf("CCPA %v — no risk assessment conducted and documented before initiating this processing (§7150(a), §7155(a)(1))", [text])
}

_any_in_use if {
	some id, _ in activities
	_in_use(id)
}

# ── §7151 — stakeholder involvement ───────────────────────────────────────

violations contains msg if {
	_any_in_use
	not _in.stakeholders.processing_employees_included == true
	msg := "CCPA §7151(a): employees whose duties include the assessed processing were not included in the risk assessment process"
}

# ── §7152(a) — contents of the risk assessment report ─────────────────────

_report_checks := {
	"purpose_specific_not_generic": "CCPA §7152(a)(1): purpose of processing not identified specifically (generic purposes such as 'to improve our services' are not permitted)",
	"categories_and_minimum_pi_identified": "CCPA §7152(a)(2): categories of personal information (including sensitive PI) and the minimum PI necessary for the purpose not documented",
	"operational_elements_documented": "CCPA §7152(a)(3): operational elements not documented — collection/use/disclosure/retention method and sources, retention periods or criteria, consumer interaction method and purpose, approximate consumer count, disclosures made, and recipients with purposes",
	"benefits_specific": "CCPA §7152(a)(4): benefits to the business, consumer, stakeholders and public not identified specifically",
	"negative_impacts_with_sources": "CCPA §7152(a)(5): negative impacts to consumers' privacy, with their sources and causes, not identified (security, discrimination, loss of control, coercion, economic, physical, reputational, psychological harms)",
	"safeguards_documented": "CCPA §7152(a)(6): safeguards planned for the processing (and for each identified negative impact) not documented",
	"decision_to_initiate_documented": "CCPA §7152(a)(7): whether the business will initiate the processing not documented",
	"contributors_identified": "CCPA §7152(a)(8): individuals who provided information for the assessment not identified (legal counsel excepted)",
	"reviewed_and_approved_by_decision_authority": "CCPA §7152(a)(9): review/approval date and the names and positions of reviewers not documented, or the approver lacks authority to decide whether the processing proceeds",
}

violations contains msg if {
	_any_in_use
	some key, msg in _report_checks
	not _in.report[key] == true
}

# ADMT for significant decisions: the assessment must describe the logic and the output (§7152(a)(3)(G)).
violations contains msg if {
	_in_use("admt_significant_decision")
	not _in.report.admt_logic_and_output_documented == true
	msg := "CCPA §7152(a)(3)(G): for ADMT used in significant decisions, the assessment does not document the logic (assumptions, limitations) and the output and how it drives the decision"
}

# ── §7153 — ADMT made available to other businesses ───────────────────────

violations contains msg if {
	_in.admt_provider.provides_admt_to_recipient_businesses == true
	not _in.admt_provider.facts_provided_for_recipient_assessments == true
	msg := "CCPA §7153(a): business makes ADMT trained on personal information available to other businesses for significant decisions but does not provide them the facts needed for their own risk assessments"
}

# ── §7155 — timing and retention ──────────────────────────────────────────

_timing_checks := {
	"reviewed_at_least_every_three_years": "CCPA §7155(a)(2): risk assessments not reviewed and updated at least once every three years",
	"updated_within_45_days_of_material_change": "CCPA §7155(a)(3): risk assessments not updated within 45 calendar days of a material change (new or larger negative impacts, weakened safeguards)",
	"retained_five_years_or_duration_of_processing": "CCPA §7155(c): risk assessments (original and updated) not retained for the duration of processing or five years after completion, whichever is later",
}

violations contains msg if {
	_any_in_use
	some key, msg in _timing_checks
	not _in.timing[key] == true
}

legacy_assessment_deadline := "2027-12-31T23:59:59Z"

# Processing that began before 2026-01-01 and continues: assessed by 2027-12-31.
violations contains msg if {
	_in.timing.legacy_processing_continuing == true
	not _in.timing.legacy_processing_assessed == true
	time.now_ns() > time.parse_rfc3339_ns(legacy_assessment_deadline)
	msg := "CCPA §7155(b): processing that began before the regulations' effective date and continues was not risk-assessed by 2027-12-31"
}

violations contains msg if {
	_in.timing.legacy_processing_continuing == true
	not _in.timing.legacy_processing_assessed == true
	time.now_ns() <= time.parse_rfc3339_ns(legacy_assessment_deadline)
	not _in.timing.legacy_assessment_scheduled == true
	msg := "CCPA §7155(b): pre-existing processing continues without a risk assessment and none is scheduled before the 2027-12-31 deadline"
}

# ── §7157 — submission to the Agency ──────────────────────────────────────

first_submission_deadline := "2028-04-01T00:00:00Z"

_submission_checks := {
	"submitted_by_april_1": "CCPA §7157(a): risk assessment information not submitted to the Agency by April 1 following the assessment year (2028-04-01 for 2026–2027 assessments)",
	"includes_required_contents": "CCPA §7157(b): submission lacks required contents — business name and contact, period covered, count of assessments per §7150(b) activity, categories of PI/sensitive PI involved, penalty-of-perjury attestation, submitter name/title/date",
	"submitted_by_responsible_executive": "CCPA §7157(c): submission not made by an executive directly responsible for risk-assessment compliance with sufficient knowledge and authority",
	"reports_available_within_30_days_of_request": "CCPA §7157(e): business cannot produce full risk assessment reports within 30 calendar days of an Agency or Attorney General request",
}

violations contains msg if {
	_any_in_use
	some key, msg in _submission_checks
	not _in.submission[key] == true
}

# ── Report ────────────────────────────────────────────────────────────────

compliance_report := {
	"standard": "CCPA Regulations — Article 10 Risk Assessments (11 CCR §§7150–7157, effective 2026-01-01)",
	"domain": "Risk Assessments",
	"activities_in_use": [id | some id, _ in activities; _in_use(id)],
	"activities_assessed_before_processing": [id | some id, _ in activities; _in_use(id); _in.activities[id].assessment_completed_before_processing == true],
	"legacy_assessment_deadline": substring(legacy_assessment_deadline, 0, 10),
	"first_submission_deadline": substring(first_submission_deadline, 0, 10),
	"compliant": compliant,
	"violation_count": count(violations),
	"violations": violations,
}
