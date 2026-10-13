# Digital Personal Data Protection Act, 2023 (India, Act 22 of 2023) and the
# Digital Personal Data Protection Rules, 2025 (G.S.R. 846(E), notified
# 13 November 2025) — obligations of a Data Fiduciary.
#
# Sources: the Act as published in the Gazette of India (11 August 2023) and
# the Rules as published in the Gazette (egazette.gov.in, 267650.pdf).
#
# Commencement (Rule 1): Rules 1, 2, 17–21 on publication (2025-11-13);
# Rule 4 (Consent Managers) 2026-11-13; Rules 3, 5–16, 22, 23 — the
# substantive Data Fiduciary duties — 2027-05-13. This module evaluates the
# full set now so a fiduciary sees its gaps before the duties bite; the
# report carries the dates.
#
# Shape: attestation from the fiduciary's evidence, input.dpdp.*. Four scope
# flags MUST be declared true or false (children's data, Significant Data
# Fiduciary status, use of Data Processors, Third Schedule class);
# undeclared is a violation. Every other fact must be boolean true.
#
# Penalties (Schedule to the Act, s.33): up to ₹250 crore for failing
# reasonable security safeguards (s.8(5)); ₹200 crore for breach-notice
# failures (s.8(6)) and for children's-data duties (s.9); ₹150 crore for
# Significant Data Fiduciary duties (s.10); ₹50 crore for any other breach.
#
# Query: POST /v1/data/dpdp/main/compliance_report
#
# Input contract — input.dpdp.*
#   processes_childrens_data            bool (required)  s.9, Rules 10–12
#   is_significant_data_fiduciary       bool (required)  s.10, Rule 13
#   uses_data_processors                bool (required)  s.8(2), Rule 6(1)(f)
#   in_third_schedule_class             bool (required)  Rule 8(1) — e-commerce ≥2 crore users,
#                                                        gaming ≥50 lakh, social media ≥2 crore
#   lawful_basis.* notice.* consent.* obligations.* security.* breach.*
#   retention.* rights.* children.* sdf.* transfers.* government_requests.*

# METADATA
# title: "India DPDP Act 2023 + DPDP Rules 2025 — Data Fiduciary obligations"
# custom:
#   class: compliance
#   framework: dpdp_india
#   source: meity
#   domains: [privacy, india]
#   coverage:
#     checks: 79
#     cited: 65
#     density: sized
#     basis: size
#     tested: true
#     entrypoint: compliance_report
#     guard: self
#     as_of: v2.3.5
package dpdp.main

import rego.v1

default compliant := false

compliant if {
	count(violations) == 0
}

default _in := {}

_in := input.dpdp

rules_commencement := {
	"rules_1_2_17_to_21": "2025-11-13",
	"rule_4_consent_managers": "2026-11-13",
	"rules_3_5_to_16_22_23": "2027-05-13",
}

# ── Scope flags: declared or violation ───────────────────────────────────

_flags := {
	"processes_childrens_data": "s.9 / Rules 10–12 — whether the fiduciary processes personal data of children or of persons with disability with a lawful guardian must be declared true or false",
	"is_significant_data_fiduciary": "s.10 / Rule 13 — whether the fiduciary is notified as a Significant Data Fiduciary must be declared true or false",
	"uses_data_processors": "s.8(2) / Rule 6(1)(f) — whether Data Processors act on the fiduciary's behalf must be declared true or false",
	"in_third_schedule_class": "Rule 8(1) / Third Schedule — whether the fiduciary is an e-commerce entity (≥2 crore users), online gaming intermediary (≥50 lakh) or social media intermediary (≥2 crore) must be declared true or false",
}

violations contains msg if {
	some key, text in _flags
	not _in[key] == true
	not _in[key] == false
	msg := sprintf("DPDP %v (dpdp.%v undeclared)", [text, key])
}

_children if _in.processes_childrens_data == true

_sdf if _in.is_significant_data_fiduciary == true

_processors if _in.uses_data_processors == true

_third_schedule if _in.in_third_schedule_class == true

# ── A generic checker: every key in a table must be attested true ────────

_missing(section, table) := {msg |
	some key, text in table
	not _in[section][key] == true
	msg := text
}

# ── s.4 Lawful basis ─────────────────────────────────────────────────────

_lawful_basis := {
	"every_purpose_has_consent_or_legitimate_use": "DPDP Act s.4(1): not every processing purpose rests on the Data Principal's consent or on a s.7 legitimate use",
	"legitimate_uses_limited_to_section_7": "DPDP Act s.7: processing without consent is claimed on grounds outside the s.7(a)–(i) list (voluntary provision for a specified purpose, State benefits, legal functions, court orders, medical emergency, epidemic, disaster, employment)",
}

violations contains msg if {
	some msg in _missing("lawful_basis", _lawful_basis)
}

# ── s.5 + Rule 3 Notice ──────────────────────────────────────────────────

_notice := {
	"accompanies_or_precedes_consent_request": "DPDP Act s.5(1): the notice does not accompany or precede every request for consent",
	"itemised_personal_data": "DPDP Rule 3(b)(i): the notice does not give an itemised description of the personal data",
	"specified_purposes_and_goods_or_services": "DPDP Rule 3(b)(ii): the notice does not state the specified purpose(s) and a specific description of the goods, services or uses enabled",
	"manner_to_withdraw_and_exercise_rights": "DPDP Act s.5(1)(ii) / Rule 3(c): the notice does not describe how to withdraw consent (as easily as it was given) and exercise rights under the Act, with the particular link to the website or app",
	"manner_to_complain_to_board": "DPDP Act s.5(1)(iii) / Rule 3(c)(iii): the notice does not describe how to make a complaint to the Data Protection Board",
	"standalone_and_plain_language": "DPDP Rule 3(a)–(b): the notice is not presented and understandable independently of other information, in clear and plain language",
	"available_in_english_or_eighth_schedule_language": "DPDP Act s.5(3): the notice cannot be accessed in English or any language in the Eighth Schedule to the Constitution",
	"legacy_consent_notice_given": "DPDP Act s.5(2): Data Principals who consented before commencement were not given the notice as soon as reasonably practicable",
}

violations contains msg if {
	some msg in _missing("notice", _notice)
}

# ── s.6 Consent ──────────────────────────────────────────────────────────

_consent := {
	"free_specific_informed_unconditional_unambiguous_affirmative": "DPDP Act s.6(1): consent is not free, specific, informed, unconditional and unambiguous with a clear affirmative action",
	"limited_to_necessary_personal_data": "DPDP Act s.6(1): consent, and the processing under it, is not limited to the personal data necessary for the specified purpose",
	"no_bundled_or_infringing_terms": "DPDP Act s.6(2): consent terms include parts that infringe the Act or other law (e.g. waiver of the right to complain)",
	"request_plain_language_with_contact_details": "DPDP Act s.6(3): the consent request is not in clear and plain language, selectable in English or an Eighth Schedule language, with the DPO or authorised person's contact details",
	"withdrawal_as_easy_as_giving": "DPDP Act s.6(4): withdrawing consent is not as easy as giving it",
	"ceases_processing_and_causes_processors_to_cease_on_withdrawal": "DPDP Act s.6(6): on withdrawal the fiduciary does not, within a reasonable time, cease processing and cause its Data Processors to cease",
	"consent_manager_requests_honoured": "DPDP Act s.6(7)–(9): consent given, managed or withdrawn through a registered Consent Manager is not honoured",
	"can_prove_notice_and_consent": "DPDP Act s.6(10): the fiduciary cannot prove that notice was given and consent obtained in accordance with the Act and Rules",
}

violations contains msg if {
	some msg in _missing("consent", _consent)
}

# ── s.8 General obligations ──────────────────────────────────────────────

_obligations := {
	"accountable_for_processing_including_by_processors": "DPDP Act s.8(1): the fiduciary does not take responsibility for compliance in respect of processing by it or on its behalf by Data Processors",
	"accuracy_completeness_consistency_for_decisions_and_disclosures": "DPDP Act s.8(3): completeness, accuracy and consistency are not ensured for personal data used to make decisions about, or disclosed about, the Data Principal",
	"technical_and_organisational_measures": "DPDP Act s.8(4): no appropriate technical and organisational measures ensure effective observance of the Act and Rules",
	"contact_published_on_website_app_and_in_rights_responses": "DPDP Act s.8(9) / Rule 9: business contact information of the DPO or an answerable person is not prominently published on the website/app and in every response to a rights request",
	"grievance_mechanism_effective": "DPDP Act s.8(10) / s.13: no effective, readily available grievance redressal mechanism",
	"grievance_response_period_published_max_90_days": "DPDP Rule 14(3): the grievance response period (not exceeding ninety days) is not prominently published, or measures to meet it are absent",
}

violations contains msg if {
	some msg in _missing("obligations", _obligations)
}

violations contains msg if {
	_processors
	not _in.obligations.processors_under_valid_contract == true
	msg := "DPDP Act s.8(2): Data Processors are engaged without a valid contract"
}

violations contains msg if {
	_processors
	not _in.obligations.processors_erase_on_instruction == true
	msg := "DPDP Act s.8(7)(b): the fiduciary does not cause its Data Processors to erase personal data it made available to them"
}

# ── s.8(5) + Rule 6 Reasonable security safeguards (₹250 crore tier) ────

_security := {
	"encryption_obfuscation_masking_or_tokens": "DPDP Rule 6(1)(a): personal data is not secured through encryption, obfuscation, masking or virtual tokens",
	"access_control_on_computer_resources": "DPDP Rule 6(1)(b): no appropriate measures control access to the computer resources of the fiduciary and its processors",
	"access_logs_monitoring_and_review": "DPDP Rule 6(1)(c): no logs, monitoring and review give visibility of access to personal data for detecting, investigating and remediating unauthorised access",
	"continuity_measures_such_as_backups": "DPDP Rule 6(1)(d): no reasonable measures (e.g. backups) for continued processing when confidentiality, integrity or availability is compromised",
	"logs_and_personal_data_retained_one_year": "DPDP Rule 6(1)(e): logs and personal data are not retained for one year to enable detection, investigation, remediation and continuity (unless another law requires otherwise)",
	"toms_for_effective_observance_of_safeguards": "DPDP Rule 6(1)(g): no technical and organisational measures ensure effective observance of the security safeguards",
}

violations contains msg if {
	some msg in _missing("security", _security)
}

violations contains msg if {
	_processors
	not _in.security.processor_contracts_require_safeguards == true
	msg := "DPDP Rule 6(1)(f): contracts with Data Processors lack the provision requiring reasonable security safeguards"
}

# ── s.8(6) + Rule 7 Breach intimation (₹200 crore tier) ──────────────────

_breach := {
	"principals_intimated_without_delay_via_account_or_registered_mode": "DPDP Rule 7(1): affected Data Principals are not intimated without delay through their user account or a registered mode of communication",
	"principal_notice_contents": "DPDP Rule 7(1)(a)–(e): the notice to Data Principals lacks the description of the breach (nature, extent, timing), the consequences for them, mitigation implemented, safety measures they may take, and a contact who can respond",
	"board_intimated_without_delay": "DPDP Rule 7(2)(a): the Data Protection Board is not intimated without delay with a description of the breach (nature, extent, timing, location, likely impact)",
	"board_detailed_report_within_72_hours": "DPDP Rule 7(2)(b): within seventy-two hours of becoming aware, the Board does not receive the updated description, the facts and reasons, mitigation, findings on the person who caused it, remedial measures, and the report of intimations to Data Principals",
}

violations contains msg if {
	some msg in _missing("breach", _breach)
}

# ── s.8(7)–(8) + Rule 8 Retention and erasure ────────────────────────────

_retention := {
	"erase_on_withdrawal_or_purpose_served": "DPDP Act s.8(7)(a): personal data is not erased on withdrawal of consent or when the specified purpose is no longer served, whichever is earlier (unless retention is required by law)",
	"logs_and_traffic_data_retained_minimum_one_year_then_erased": "DPDP Rule 8(3): personal data, associated traffic data and processing logs are not retained for at least one year from processing and then erased (unless another law or a Government notification requires longer)",
}

violations contains msg if {
	some msg in _missing("retention", _retention)
}

violations contains msg if {
	_third_schedule
	not _in.retention.third_schedule_three_year_erasure == true
	msg := "DPDP Rule 8(1) / Third Schedule: personal data is not erased three years after the Data Principal last approached the fiduciary or exercised her rights (or Rules commencement, whichever is latest), except account-access and virtual-token purposes"
}

violations contains msg if {
	_third_schedule
	not _in.retention.forty_eight_hour_pre_erasure_notice == true
	msg := "DPDP Rule 8(2): Data Principals are not informed at least forty-eight hours before the erasure period completes that their data will be erased unless they log in or initiate contact"
}

# ── s.9 + Rules 10–12 Children (₹200 crore tier) ────────────────────────

_children_checks := {
	"verifiable_parental_consent_before_processing": "DPDP Act s.9(1) / Rule 10(1): verifiable consent of the parent (or lawful guardian) is not obtained before processing a child's personal data",
	"parent_identity_and_age_due_diligence": "DPDP Rule 10(1)(a)–(b): no due diligence confirms the person identifying as parent is an identifiable adult — reliable details held by the fiduciary, voluntarily provided details, or a virtual token from an authorised entity or Digital Locker service provider",
	"guardian_verified_for_persons_with_disability": "DPDP Rule 11: a lawful guardian of a person with disability is not verified as appointed by a court, designated authority or local level committee",
	"no_detrimental_processing": "DPDP Act s.9(2): processing likely to cause a detrimental effect on a child's well-being is not prevented",
	"no_tracking_behavioural_monitoring_or_targeted_ads": "DPDP Act s.9(3): tracking, behavioural monitoring of children or targeted advertising directed at children is not prevented",
	"exemptions_only_per_fourth_schedule": "DPDP Rule 12 / Fourth Schedule: any reliance on exemption from s.9(1) and (3) is not limited to the listed classes (healthcare, education, childcare…) and purposes, with their conditions",
}

violations contains msg if {
	_children
	some msg in _missing("children", _children_checks)
}

# ── s.10 + Rule 13 Significant Data Fiduciary (₹150 crore tier) ─────────

_sdf_checks := {
	"dpo_in_india_responsible_to_board_and_grievance_contact": "DPDP Act s.10(2)(a): no Data Protection Officer based in India, responsible to the Board of Directors or governing body, who is the grievance point of contact",
	"independent_data_auditor_appointed": "DPDP Act s.10(2)(b): no independent data auditor appointed to evaluate compliance",
	"dpia_and_audit_every_twelve_months": "DPDP Act s.10(2)(c) / Rule 13(1): a Data Protection Impact Assessment and an audit are not undertaken once in every twelve months",
	"significant_observations_reported_to_board": "DPDP Rule 13(2): the person carrying out the DPIA and audit does not furnish the Board a report of significant observations",
	"algorithmic_software_due_diligence": "DPDP Rule 13(3): no due diligence verifies that technical measures including algorithmic software do not pose a risk to Data Principals' rights",
	"restricted_data_not_transferred_outside_india": "DPDP Rule 13(4): personal data specified by the Central Government (and its traffic data) is not kept from transfer outside India",
}

violations contains msg if {
	_sdf
	some msg in _missing("sdf", _sdf_checks)
}

# ── ss.11–14 + Rule 14 Rights of Data Principals ─────────────────────────

_rights := {
	"access_summary_and_recipients": "DPDP Act s.11: on request, the Data Principal cannot obtain a summary of her personal data and processing activities, and the identities of other fiduciaries and processors it was shared with",
	"correction_completion_updating": "DPDP Act s.12(2): inaccurate, incomplete or outdated personal data is not corrected, completed or updated on request",
	"erasure_on_request_unless_retention_required": "DPDP Act s.12(3): personal data is not erased on request unless retention is necessary for the specified purpose or by law",
	"means_and_identifiers_for_requests_published": "DPDP Rule 14(1): the means to make rights requests, and the identifiers required, are not prominently published on the website/app",
	"nomination_supported": "DPDP Act s.14 / Rule 14(4): the Data Principal cannot nominate an individual to exercise her rights on death or incapacity",
}

violations contains msg if {
	some msg in _missing("rights", _rights)
}

# ── s.16 + Rule 15 Transfers; Rule 23 Government requests ───────────────

_transfers := {
	"no_transfer_to_notified_restricted_countries": "DPDP Act s.16(1): personal data is transferred to a country or territory the Central Government has notified as restricted",
	"foreign_state_access_requirements_met": "DPDP Rule 15: transfers outside India do not meet the Central Government's requirements on making personal data available to a foreign State or its agencies",
}

violations contains msg if {
	some msg in _missing("transfers", _transfers)
}

_government := {
	"process_to_furnish_information_within_specified_period": "DPDP Rule 23(1): no process to furnish information called for by the Central Government's authorised person within the specified period",
	"confidentiality_of_requests_when_directed": "DPDP Rule 23(2): no process to withhold disclosure of such a request from the Data Principal when directed in the interests of sovereignty, integrity or security of the State",
}

violations contains msg if {
	some msg in _missing("government_requests", _government)
}

# ── Report ───────────────────────────────────────────────────────────────

compliance_report := {
	"framework": "India — Digital Personal Data Protection Act, 2023 and DPDP Rules, 2025",
	"standard": "Act 22 of 2023 (Gazette 11 August 2023); Rules G.S.R. 846(E) (Gazette 13 November 2025)",
	"source": "egazette.gov.in — Act and Rules as published",
	"rules_commencement": rules_commencement,
	"scope": {
		"processes_childrens_data": object.get(_in, "processes_childrens_data", "undeclared"),
		"is_significant_data_fiduciary": object.get(_in, "is_significant_data_fiduciary", "undeclared"),
		"uses_data_processors": object.get(_in, "uses_data_processors", "undeclared"),
		"in_third_schedule_class": object.get(_in, "in_third_schedule_class", "undeclared"),
	},
	"penalty_tiers_inr_crore": {"security_safeguards_s8_5": 250, "breach_intimation_s8_6": 200, "children_s9": 200, "significant_data_fiduciary_s10": 150, "other": 50},
	"compliant": compliant,
	"violation_count": count(violations),
	"violations": violations,
}
