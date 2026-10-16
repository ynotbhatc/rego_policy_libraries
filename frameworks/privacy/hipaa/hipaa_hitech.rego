# HITECH Act and the HIPAA Breach Notification Rule.
#
# Part 1 - 45 CFR Part 164 Subpart D (§§ 164.400-164.414), keyed to the regulation's own paragraph citations.
#   Source: https://www.govinfo.gov/bulkdata/CFR/2025/title-45/CFR-2025-title45-vol2.xml
#   sha256 5fb58263c7533af259dacbc0d72e097158b995551a0fb241c4f997d4ef856b52, retrieved 2026-10-13
#   (2025 annual edition, GovInfo bulk XML; public domain).
#   This module already carried the breach-notification checks (as HITECH topic booleans); they are re-keyed
#   here to the paragraphs they implement rather than duplicated in a new module.
#   Measured in the XML: Subpart D has 13 paragraphs labelled Standard / Implementation specification(s)
#   (§§ 164.404-164.410) plus the unlabelled duties of § 164.412(a)-(b) and § 164.414(a)-(b); all 17 are rows:
#   4 standards, 9 implementation specifications, 4 other obligations. § 164.400 (applicability) and
#   § 164.402 (definitions) are not controls (out_of_scope).
#   facts        9 rows decided by this module's original input.hitech.* checks (see fact_basis).
#   attestation  8 rows: input.hipaa.subpart_d["<id>"] == true.
#   Applicability: §§ 164.404-164.408 and 164.414(a) bind covered entities, § 164.410 business associates,
#   §§ 164.412 and 164.414(b) both; input.hipaa.scope flags must each be declared true or false.
#
# Part 2 - HITECH Act statutory provisions with no Subchapter C paragraph (42 U.S.C. §§ 17921-17954), kept as
#   this module always evaluated them: business associate direct liability and HITECH business associate
#   agreements (42 U.S.C. §17934), corrective-action readiness (42 U.S.C. §17939 enforcement), electronic access
#   and the out-of-pocket restriction (42 U.S.C. §17935), and the EHR security / meaningful-use checks (HITECH
#   EHR incentive provisions, administered by CMS, not part of 45 CFR Subchapter C). Each failing check is a
#   violation, as before. penalty_awareness, accounting_ehr_expansion and hitech_minimum_necessary never gated the
#   verdict and are dropped, with the old report sub-objects (no reader exists).
#
# Fail-closed: missing or non-object input.hipaa.subpart_d is a FAIL-CLOSED violation; a failed fact, a non-true
# attestation, an unknown id, an undeclared scope flag or a failing HITECH statutory check is a violation.
#
# OPA endpoint: POST /v1/data/hipaa/hitech/report

# METADATA
# title: "HIPAA Breach Notification Rule (45 CFR 164.400-164.414, CFR citations) and HITECH Act statutory checks"
# custom:
#   class: compliance
#   framework: hipaa
#   source: hhs
#   domains: [privacy, healthcare]
#   coverage:
#     checks: 29
#     cited: 20
#     expected: 17
#     found: 20
#     scope: module
#     density: full
#     basis: declared-total
#     tested: true
#     entrypoint: report
#     guard: self
#     as_of: v2.4.2
package hipaa.hitech

import rego.v1

source := {
	"regulation": "45 CFR Subtitle A, Subchapter C — Administrative Data Standards and Related Requirements (Parts 160, 162, 164)",
	"edition": "Code of Federal Regulations, Title 45, Volume 2, 2025 annual edition (GovInfo bulk XML)",
	"url": "https://www.govinfo.gov/bulkdata/CFR/2025/title-45/CFR-2025-title45-vol2.xml",
	"sha256": "5fb58263c7533af259dacbc0d72e097158b995551a0fb241c4f997d4ef856b52",
	"retrieved": "2026-10-13",
}

sections := {
	"164.404": "§ 164.404 Notification to individuals",
	"164.406": "§ 164.406 Notification to the media",
	"164.408": "§ 164.408 Notification to the Secretary",
	"164.410": "§ 164.410 Notification by a business associate",
	"164.412": "§ 164.412 Law enforcement delay",
	"164.414": "§ 164.414 Administrative requirements and burden of proof",
}

scope_roles := {
	"health_plan": "45 CFR 160.103 - whether the entity is a health plan must be declared true or false",
	"health_care_provider": "45 CFR 160.103 - whether the entity is a covered health care provider must be declared true or false",
	"health_care_clearinghouse": "45 CFR 160.103 - whether the entity is a health care clearinghouse must be declared true or false",
	"business_associate": "45 CFR 160.103 - whether the entity acts as a business associate must be declared true or false",
}

# One row per Subpart D obligation paragraph, keyed by CFR citation.
breach_notification_table := [
	{"id": "164.404(a)", "section": "164.404", "status": "standard", "gate": "covered_entity", "title": "Notification to individuals following discovery of a breach of unsecured protected health information (breaches treated as discovered, (a)(2))"},
	{"id": "164.404(b)", "section": "164.404", "status": "implementation specification", "gate": "covered_entity", "title": "Timeliness of notification to individuals: without unreasonable delay and no later than 60 calendar days after discovery"},
	{"id": "164.404(c)", "section": "164.404", "status": "implementation specification", "gate": "covered_entity", "title": "Content of notification to individuals (elements (A)-(E); plain language)"},
	{"id": "164.404(d)", "section": "164.404", "status": "implementation specification", "gate": "covered_entity", "title": "Methods of individual notification (written notice; substitute notice; urgent situations)"},
	{"id": "164.406(a)", "section": "164.406", "status": "standard", "gate": "covered_entity", "title": "Notification to prominent media outlets for a breach involving more than 500 residents of a State or jurisdiction"},
	{"id": "164.406(b)", "section": "164.406", "status": "implementation specification", "gate": "covered_entity", "title": "Timeliness of media notification: no later than 60 calendar days after discovery"},
	{"id": "164.406(c)", "section": "164.406", "status": "implementation specification", "gate": "covered_entity", "title": "Content of media notification meets § 164.404(c)"},
	{"id": "164.408(a)", "section": "164.408", "status": "standard", "gate": "covered_entity", "title": "Notification to the Secretary following discovery of a breach"},
	{"id": "164.408(b)", "section": "164.408", "status": "implementation specification", "gate": "covered_entity", "title": "Breaches involving 500 or more individuals: notify the Secretary contemporaneously with the individual notice"},
	{"id": "164.408(c)", "section": "164.408", "status": "implementation specification", "gate": "covered_entity", "title": "Breaches involving less than 500 individuals: maintain a log and notify the Secretary within 60 days after the end of each calendar year"},
	{"id": "164.410(a)", "section": "164.410", "status": "standard", "gate": "business_associate", "title": "Notification by a business associate to the covered entity following discovery of a breach"},
	{"id": "164.410(b)", "section": "164.410", "status": "implementation specification", "gate": "business_associate", "title": "Timeliness of business associate notification: no later than 60 calendar days after discovery"},
	{"id": "164.410(c)", "section": "164.410", "status": "implementation specification", "gate": "business_associate", "title": "Content of business associate notification (identification of each individual; other information the covered entity needs under § 164.404(c))"},
	{"id": "164.412(a)", "section": "164.412", "status": "obligation", "gate": "", "title": "Law enforcement delay - written statement: delay notification, notice or posting for the period the official specifies"},
	{"id": "164.412(b)", "section": "164.412", "status": "obligation", "gate": "", "title": "Law enforcement delay - oral statement: document it (including the official's identity) and delay no longer than 30 days unless a written statement is submitted"},
	{"id": "164.414(a)", "section": "164.414", "status": "obligation", "gate": "covered_entity", "title": "Administrative requirements of § 164.530(b), (d), (e), (g), (h), (i) and (j) apply to this subpart"},
	{"id": "164.414(b)", "section": "164.414", "status": "obligation", "gate": "", "title": "Burden of proof: demonstrate that all notifications were made, or that the use or disclosure did not constitute a breach (§ 164.402)"},
]

breach_notification_rule := {r.id: r | some r in breach_notification_table}

out_of_scope := {
	"164.400": "Applicability (breaches occurring on or after September 23, 2009) - scoping",
	"164.402": "Definitions (breach, unsecured PHI); the four-factor assessment of 164.402(2) is evaluated under 164.414(b)",
}

fact_basis := {
	"164.404(b)": "input.hitech.breach_notification.individuals.within_60_days",
	"164.404(c)": "input.hitech.breach_notification.individuals.{includes_description,includes_types_of_phi,includes_steps_to_protect,includes_investigation_steps,includes_contact_info}",
	"164.404(d)": "input.hitech.breach_notification.individuals.written_notice",
	"164.406(a)": "input.hitech.breach_notification.media.{required_threshold_500,state_or_jurisdiction.prominent_media_outlets} and hhs.large_breaches_500_plus.media_notice",
	"164.406(b)": "input.hitech.breach_notification.media.within_60_days",
	"164.408(b)": "input.hitech.breach_notification.hhs.large_breaches.within_60_days",
	"164.408(c)": "input.hitech.breach_notification.hhs.small_breaches.annual_log.submitted and input.hitech.breach_log.{maintained,all_breaches.documented,sub_500_breaches.included}",
	"164.414(a)": "input.hitech.breach_log.retention_years >= 6 (§ 164.530(j) retention)",
	"164.414(b)": "input.hitech.breach_assessment - the four-factor risk assessment of § 164.402(2) evaluated and documented, including when the low-probability exception is applied",
}

# -----------------------------------------------------------------------------
# Fact checks, one per CFR paragraph (re-keyed from the HITECH breach booleans below)
# -----------------------------------------------------------------------------

_bn := object.get(input, ["hitech", "breach_notification"], {})

_log := object.get(input, ["hitech", "breach_log"], {})

_fact_pass contains "164.404(b)" if _bn.individuals.within_60_days == true

_fact_pass contains "164.404(c)" if {
	_bn.individuals.includes_description == true
	_bn.individuals.includes_types_of_phi == true
	_bn.individuals.includes_steps_to_protect == true
	_bn.individuals.includes_investigation_steps == true
	_bn.individuals.includes_contact_info == true
}

_fact_pass contains "164.404(d)" if _bn.individuals.written_notice == true

_fact_pass contains "164.406(a)" if {
	_bn.media.required_threshold_500 == true
	_bn.media.state_or_jurisdiction.prominent_media_outlets == true
	_bn.hhs.large_breaches_500_plus.media_notice == true
}

_fact_pass contains "164.406(b)" if _bn.media.within_60_days == true

_fact_pass contains "164.408(b)" if _bn.hhs.large_breaches.within_60_days == true

_fact_pass contains "164.408(c)" if {
	_bn.hhs.small_breaches.annual_log.submitted == true
	_log.maintained == true
	_log.all_breaches.documented == true
	_log.sub_500_breaches.included == true
}

_fact_pass contains "164.414(a)" if {
	is_number(_log.retention_years)
	_log.retention_years >= 6
}

_fact_pass contains "164.414(b)" if breach_risk_assessment

# -----------------------------------------------------------------------------
# HITECH topic booleans kept from this module's original fact checks: the four-factor risk assessment
# (decides 164.414(b)) and the seven statutory checks below. The other former booleans (individual / HHS /
# media notification and breach log, now the Subpart D fact rows; penalty_awareness, accounting_ehr_expansion,
# hitech_minimum_necessary, which never gated) are dropped with their report keys: no reader exists.
# -----------------------------------------------------------------------------
default breach_risk_assessment := false

default ba_direct_liability := false

default baa_hitech_compliant := false

default cap_readiness := false

default electronic_access_to_ephi := false

default out_of_pocket_restriction := false

default ehr_security_controls := false

default meaningful_use_security := false

# Four-factor risk assessment to determine if breach must be reported
breach_risk_assessment if {
	input.hitech.breach_assessment.nature_and_extent.evaluated == true
	input.hitech.breach_assessment.who_accessed_phi.evaluated == true
	input.hitech.breach_assessment.whether_phi_acquired.evaluated == true
	input.hitech.breach_assessment.mitigation_extent.evaluated == true
	input.hitech.breach_assessment.documented == true
	input.hitech.breach_assessment.result.low_probability_exception.documented_when_applied == true
}

# BAs directly liable under HIPAA Security and Privacy Rules
ba_direct_liability if {
	input.hitech.business_associates.directly_liable == true
	input.hitech.business_associates.security_rule.applies_directly == true
	input.hitech.business_associates.privacy_rule.applies_to_use_disclosure == true
	input.hitech.business_associates.subcontractors.baa_required == true
}

# Business associate agreements updated for HITECH
baa_hitech_compliant if {
	input.hitech.baa.hitech_provisions.included == true
	input.hitech.baa.breach_notification.ba_notifies_ce_without_unreasonable_delay == true
	input.hitech.baa.breach_notification.within_60_days_max == true
	input.hitech.baa.individual_rights.access_honored == true
	input.hitech.baa.electronic_access.provided_when_requested == true
}

# Corrective action plan (CAP) readiness if investigated
cap_readiness if {
	input.hitech.enforcement.cap_template.available == true
	input.hitech.enforcement.compliance_monitoring.internal == true
	input.hitech.enforcement.audit_response.procedures_defined == true
	input.hitech.enforcement.hhs_ocr_cooperation.policy == true
}

# Covered entities must provide electronic access to ePHI
electronic_access_to_ephi if {
	input.hitech.patient_access.electronic_format.available == true
	input.hitech.patient_access.ehr.access_provided == true
	input.hitech.patient_access.third_party_directed.honored == true
	input.hitech.patient_access.fee.reasonable_cost_based == true
	input.hitech.patient_access.response_time.within_30_days == true
}

# Restriction on disclosure to health plan when patient pays out of pocket
out_of_pocket_restriction if {
	input.hitech.patient_rights.out_of_pocket.restriction_honored == true
	input.hitech.patient_rights.out_of_pocket.health_plan_disclosure.prohibited_when_restricted == true
}

ehr_security_controls if {
	input.hitech.ehr.access_controls.unique_user_id == true
	input.hitech.ehr.access_controls.emergency_access.procedure == true
	input.hitech.ehr.access_controls.automatic_logoff.configured == true
	input.hitech.ehr.encryption.at_rest == true
	input.hitech.ehr.encryption.in_transit == true
	input.hitech.ehr.audit_log.enabled == true
	input.hitech.ehr.audit_log.tamper_evident == true
	input.hitech.ehr.integrity.data_authentication == true
}

meaningful_use_security if {
	input.hitech.meaningful_use.security_risk_analysis.conducted == true
	input.hitech.meaningful_use.security_risk_analysis.annually == true
	input.hitech.meaningful_use.security_updates.implemented == true
	input.hitech.meaningful_use.security_deficiencies.corrected == true
}

# -----------------------------------------------------------------------------
# HITECH statutory checks (no 45 CFR Subchapter C paragraph) - gate the verdict as before
# -----------------------------------------------------------------------------

violations contains "HITECH 42 U.S.C. §17934: business associate direct liability under the Security and Privacy Rules (including subcontractor BAAs) is not evidenced (input.hitech.business_associates.*)" if {
	not ba_direct_liability
}

violations contains "HITECH 42 U.S.C. §17934: business associate agreements do not carry the HITECH provisions (breach notice to the covered entity within 60 days, access, electronic access) (input.hitech.baa.*)" if {
	not baa_hitech_compliant
}

violations contains "HITECH 42 U.S.C. §17939: corrective action plan readiness, internal compliance monitoring, audit response and OCR cooperation are not evidenced (input.hitech.enforcement.*)" if {
	not cap_readiness
}

violations contains "HITECH 42 U.S.C. §17935: electronic access to ePHI (electronic format, EHR access, third-party direction, cost-based fee, 30-day response) is not evidenced (input.hitech.patient_access.*)" if {
	not electronic_access_to_ephi
}

violations contains "HITECH 42 U.S.C. §17935: the out-of-pocket restriction on disclosures to a health plan is not evidenced (input.hitech.patient_rights.out_of_pocket.*)" if {
	not out_of_pocket_restriction
}

violations contains "HITECH EHR incentive provisions: EHR security controls (unique user id, emergency access, automatic logoff, encryption, tamper-evident audit log, data authentication) are not evidenced (input.hitech.ehr.*)" if {
	not ehr_security_controls
}

violations contains "HITECH EHR incentive provisions: meaningful-use security risk analysis, updates and correction of deficiencies are not evidenced (input.hitech.meaningful_use.*)" if {
	not meaningful_use_security
}

# -----------------------------------------------------------------------------
# Evaluation (fail-closed). Shared shape across the CFR-keyed HIPAA modules.
# -----------------------------------------------------------------------------

default compliant := false

compliant if count(violations) == 0

_scope := object.get(input, ["hipaa", "scope"], {})

_roles := {"health_plan", "health_care_provider", "health_care_clearinghouse", "business_associate"}

violations contains msg if {
	some k, text in scope_roles
	not _scope[k] == true
	not _scope[k] == false
	msg := sprintf("HIPAA Breach Notification Rule Input Contract: %v (input.hipaa.scope.%v undeclared)", [text, k])
}

violations contains "HIPAA Breach Notification Rule Input Contract: FAIL-CLOSED - input.hipaa.scope declares no regulated role (health_plan, health_care_provider, health_care_clearinghouse or business_associate true); applicability under 45 CFR 160.102 cannot be established" if {
	count({k | some k in _roles; _scope[k] == true}) == 0
}

_attestations := a if {
	a := object.get(input, ["hipaa", "subpart_d"], null)
	is_object(a)
}

violations contains "HIPAA Breach Notification Rule: FAIL-CLOSED - attestations 'input.hipaa.subpart_d' were not supplied (or are not an object); this module cannot be evaluated and is reported non-compliant" if {
	not _attestations
}

_attested(id) if _attestations[id] == true

_gate_open(g) if g == ""

_gate_open("covered_entity") if {
	some k in {"health_plan", "health_care_provider", "health_care_clearinghouse"}
	_scope[k] == true
}

_gate_open("provider_or_plan") if {
	some k in {"health_plan", "health_care_provider"}
	_scope[k] == true
}

_gate_open(g) if {
	not g in {"", "covered_entity", "provider_or_plan"}
	_scope[g] == true
}

applicable[id] := r if {
	some id, r in breach_notification_rule
	_gate_open(r.gate)
}

_satisfied(id) if {
	applicable[id]
	fact_basis[id]
	_fact_pass[id]
}

_satisfied(id) if {
	applicable[id]
	not fact_basis[id]
	_attested(id)
}

_unmet(id) := sprintf("fact check failed - %v", [fact_basis[id]]) if fact_basis[id]

else := sprintf("not attested - input.hipaa.subpart_d[\"%v\"] must be true", [id])

violations contains msg if {
	some id, r in applicable
	not _satisfied(id)
	msg := sprintf("HIPAA %v %v (%v): %v", [id, r.title, r.status, _unmet(id)])
}

violations contains msg if {
	some id, _ in _attestations
	not breach_notification_rule[id]
	msg := sprintf("HIPAA Breach Notification Rule Input Contract: attestation for unknown id %v - ids are the 45 CFR citations this module carries, for example 164.404(b)", [id])
}

_applicable_bool(id) if applicable[id]

else := false

_attested_bool(id) if _attested(id)

else := false

_satisfied_bool(id) if _satisfied(id)

else := false

_basis(id) := "facts" if fact_basis[id]

else := "attestation"

row_status[id] := s if {
	some id, r in breach_notification_rule
	s := {
		"title": r.title,
		"section": r.section,
		"status": r.status,
		"gate": r.gate,
		"applicable": _applicable_bool(id),
		"basis": _basis(id),
		"attested": _attested_bool(id),
		"satisfied": _satisfied_bool(id),
	}
}

section_reports[s] := rpt if {
	some s, name in sections
	ids := {id | some id; r := breach_notification_rule[id]; r.section == s}
	app := {id | some id in ids; applicable[id]}
	ok := {id | some id in app; _satisfied(id)}
	rpt := {
		"name": name,
		"rows": count(ids),
		"applicable": count(app),
		"satisfied": count(ok),
		"gaps": sort([id | some id in app; not id in ok]),
	}
}

_n_applicable := count(applicable)

_n_satisfied := count({id | some id; _ = applicable[id]; _satisfied(id)})

report := {
	"standard": "HIPAA Breach Notification Rule (45 CFR Part 164 Subpart D) and HITECH Act (42 U.S.C. §§17921-17954)",
	"source": source,
	"compliant": compliant,
	"id_scheme": "45 CFR paragraph citation for Subpart D rows, e.g. 164.404(b); HITECH statutory checks are cited to the U.S. Code section",
	"controls_total": count(breach_notification_rule),
	"standard_total": 17, # 45 CFR 164.404-164.414: 4 standards + 9 implementation specifications + 4 other obligations
	"fact_evaluated": count(fact_basis),
	"attested": count(breach_notification_rule) - count(fact_basis),
	"applicable": _n_applicable,
	"satisfied": _n_satisfied,
	"sections": section_reports,
	"requirements": row_status,
	"out_of_scope": out_of_scope,
	"violation_count": count(violations),
	"violations": violations,
}
