# UK Data Protection Act 2018 (c. 12) — the duties the Act itself places on controllers and processors beyond
# the UK GDPR. One attested row per duty subsection, keyed exactly as the Act numbers it (s.62(1),
# Sch.1 para 40(1)); the row text is the subsection's own words.
#
# Source (Crown copyright; untrusted data, parsed only):
#   https://www.legislation.gov.uk/ukpga/2018/12/data.xml — revised text as the Statute Law Database publishes it,
#   point in time 2026-09-30 (dc:modified, dct:valid and the root RestrictStartDate all 2026-09-30), extent
#   E+W+S+N.I., retrieved 2026-10-13, sha256 268f9b6ccb61cd89746ec62c25639b7079059522ea84643537261f95779ff9c2.
#   Amendments by the Data (Use and Access) Act 2025 commenced on or before 2026-09-30 are in that text (s.164A
#   complaints from 2026-06-19, s.62 logging in its version in force from 2026-09-30). Of the nine effects
#   legislation.gov.uk lists as not yet applied, none touches a row here (they affect s.26(2), s.165(1),
#   Sch.3 paras 2 and 8 and Sch.4 paras 3 and 5).
#   Contains public sector information licensed under the Open Government Licence v3.0
#   (https://www.nationalarchives.gov.uk/doc/open-government-licence/version/3/).
#   Every row was emitted by a generator that resolved its id to a P1/P2 element of that XML, refused any
#   repealed (dotted-out) text and any text inserted into another Act, and copied the subsection's text with its
#   (a)/(i) labels; commentary is dropped.
#
# Relation to frameworks/privacy/gdpr (package gdpr.main): the UK GDPR's own Article duties — principles,
# lawful bases, Articles 12–22 rights, Articles 24–39 controller/processor obligations (the Art 37 DPO and the
# Art 8 child-consent age among them), Chapter V transfers — belong to that module and are NOT repeated here.
# This module carries only what the 2018 Act adds: the Part 2 supplementary conditions and Schedule safeguards,
# the separate Part 3 law-enforcement regime (its own principles, rights, controller/processor duties, logging,
# DPO and transfers), and the s.164A complaints duty. It is not imported by gdpr.main and does not import it;
# a UK controller runs both.
#
# Scope and exclusions (the full list, with citations, is out_of_scope in the report):
#   in    Part 2 Chapter 2 (ss.6–20) and its Schedules 1–3 where the text binds the controller; Part 2 Chapter 3
#         (ss.21–28) where it does; Part 3 (ss.29–81) controller/processor duties, gated by
#         input.uk_dpa_2018.scope.competent_authority; Part 6 s.164A (complaints to controllers).
#   out   Part 4 (ss.82–113, intelligence services processing); Commission functions, codes and charges (Part 5);
#         notices, which bind only once served (ss.142–159); offences (ss.144, 148, 148C, 170–173, 184);
#         definitions, overviews, permissions, exemptions and Secretary of State powers anywhere in the Act;
#         provisions repealed in this version (s.9 child's consent among them: omitted 31.12.2020 by
#         S.I. 2019/419 Sch.2 para 12 per the XML's commentary; the rule lives in UK GDPR Art 8).
#
# Judgement calls (also data in judgement_calls in the report). The duty test: a row is a subsection whose own
# text obliges or prohibits a controller or processor (must, may not, may only, permitted only, not permitted
# if) or states a principle s.34(3) makes the controller answer for. Where that is a reading, not the words:
#   - lawfulness conditions read as duties: ss.10(2), (3), (5), 35(2), 35(3), 36(3), 41(2), Sch.1 para 5(1)
#   - s.35(4)–(5), the two permitted cases for sensitive processing, are folded into the s.35(3) row
#   - Sch.1 para 39 and s.42(2) ("has an appropriate policy document if ...") read as the document's content duty
#   - s.45(1), the data subject's entitlement, read as the controller's duty to give access
#   - ss.50A(2), 50C(5) ("a person must consider") read as binding the controller deciding
#   - s.70(5), the DPO's reporting line, read as an organisational duty of the controller
#   - s.73(6), passive voice, read as the transferring controller's duty to inform
#   - ss.78(2)–(4), (6) bind the "UK authoriser", which s.78(1) defines as the transferring controller or
#     another competent authority
#   - s.62(4), a restriction on the use of logs, carried as a duty
#   - s.164A(2)–(4) not gated: they bind every controller (UK GDPR and Part 3)
#   - excluded although phrased as duties: Sch.2 paras 4A, 4B (bind only the Secretary of State); s.17
#     (binds the Commission and the accreditation body); s.9A (a lawful-basis condition, Schedule A1 has no duty)
# Gating asymmetry: Part 2 and Schedule rows that bind only some controllers are gated by their own flags
# (s.10, s.13(3), s.24(7), s.28(3)–(4), Sch.1, Sch.2 paras 16(3), 25(3), 26(4)–(5), Sch.3 paras 5(2), 12(2),
# 20(2)); Part 3 rows are gated only by competent_authority, so a competent authority that never uses consent,
# archiving, joint controllers, processors, automated decisions or transfers attests those rows true (nothing to
# do). Every flag in _gates MUST be declared true or false (bnm_rmit pattern).
#
# Input:  input.uk_dpa_2018.scope.<flag> := true | false        (every flag in _gates)
#         input.uk_dpa_2018.duties["s.62(1)"] := true            (attestation per applicable row)
# Fail-closed: a missing or non-object input.uk_dpa_2018, scope or duties container is FAIL-CLOSED; an
# undeclared or non-boolean flag, a non-true attestation of an applicable row and an attestation for an id that
# is not a row are violations.
#
# Metadata `source`: uk-parliament (the Act's issuer; value added to scripts/metadata_vocabulary.json with this module).
#
# Query: POST /v1/data/uk_dpa_2018/main/compliance_report

# METADATA
# title: "UK Data Protection Act 2018 (revised to 2026-09-30) — controller and processor duties beyond the UK GDPR, per subsection"
# custom:
#   class: compliance
#   framework: uk_dpa_2018
#   source: uk-parliament
#   domains: [privacy, uk]
#   coverage:
#     checks: 157
#     cited: 151
#     expected: 151
#     found: 157
#     scope: directory
#     density: full
#     basis: declared-total
#     tested: true
#     entrypoint: compliance_report
#     guard: self
#     as_of: v2.4.2
package uk_dpa_2018.main

import rego.v1

default compliant := false

compliant if count(violations) == 0

source := {
	"act": "Data Protection Act 2018 (c. 12)",
	"url": "https://www.legislation.gov.uk/ukpga/2018/12/data.xml",
	"point_in_time": "2026-09-30",
	"retrieved": "2026-10-13",
	"sha256": "268f9b6ccb61cd89746ec62c25639b7079059522ea84643537261f95779ff9c2",
	"licence": "Contains public sector information licensed under the Open Government Licence v3.0",
}

parts := {
	"2": "Part 2 — General processing (supplementing the UK GDPR)",
	"3": "Part 3 — Law enforcement processing",
	"6": "Part 6 — Enforcement (s.164A complaints to controllers only)",
}

chapters := {
	"P2C2": {"part": "2", "heading": "Part 2 Chapter 2 — The UK GDPR (ss.6–20)"},
	"P2C2-S1": {"part": "2", "heading": "Schedule 1 — Special categories of personal data and criminal convictions etc data (via s.10)"},
	"P2C2-S2": {"part": "2", "heading": "Schedule 2 — Exemptions etc from the UK GDPR (via s.15)"},
	"P2C2-S3": {"part": "2", "heading": "Schedule 3 — Exemptions etc from the UK GDPR: health, social work, education and child abuse data (via s.15)"},
	"P2C3": {"part": "2", "heading": "Part 2 Chapter 3 — Exemptions for manual unstructured processing and for national security and defence purposes (ss.21–28)"},
	"P3C2": {"part": "3", "heading": "Part 3 Chapter 2 — Principles (ss.34–42A)"},
	"P3C3": {"part": "3", "heading": "Part 3 Chapter 3 — Rights of the data subject (ss.43–54)"},
	"P3C4": {"part": "3", "heading": "Part 3 Chapter 4 — Controller and processor (ss.55–71A)"},
	"P3C5": {"part": "3", "heading": "Part 3 Chapter 5 — Transfers of personal data to third countries etc (ss.72–78)"},
	"P3C6": {"part": "3", "heading": "Part 3 Chapter 6 — Supplementary (ss.78A–81)"},
	"P6": {"part": "6", "heading": "Part 6 — Complaints by data subjects to controllers (s.164A)"},
}

# In-force subsection-level units the XML holds in each chapter's scope (a P2, or a P1 with no P2; dotted-out
# text not counted) against the rows emitted from it. The difference is definitions, overviews, permissions,
# exemptions and powers.
xml_units := {"P2C2": 48, "P2C2-S1": 103, "P2C2-S2": 82, "P2C2-S3": 60, "P2C3": 33, "P3C2": 42, "P3C3": 84, "P3C4": 86, "P3C5": 55, "P3C6": 24, "P6": 274}

_gates := {
	"competent_authority": "Part 3 (ss.29–81) — whether the controller is a competent authority (s.30) processing for the law enforcement purposes (s.31)",
	"special_category_or_criminal_data": "s.10 — whether the controller processes special category data under Art 9(2)(b), (g), (h), (i) or (j) UK GDPR, or criminal convictions data not under the control of official authority (Art 10)",
	"schedule_1_policy_document": "Sch.1 paras 5, 39–41 — whether the controller relies on a Schedule 1 condition that requires an appropriate policy document",
	"credit_reference_agency": "s.13 — whether the controller is a credit reference agency (Consumer Credit Act 1974 s.145(8))",
	"withholds_third_party_information": "Sch.2 para 16 — whether access requests are answered where disclosure would reveal information relating to another individual",
	"exam_data": "Sch.2 para 25 — whether the controller processes exam marks or results",
	"special_purposes": "Sch.2 para 26 — whether the controller relies on the journalism, academic, artistic or literary purposes exemption",
	"health_data_serious_harm_exemption": "Sch.3 para 5 — whether a controller that is not a health professional withholds data concerning health on the serious harm test",
	"scottish_social_work_or_education_authority": "Sch.3 paras 12 and 20 — whether the controller is a Scottish social work authority or education authority",
	"foi_public_authority": "s.24 — whether the controller is an FOI public authority holding manual unstructured personal data",
	"national_security_defence_exemption": "s.28 — whether Art 32 UK GDPR is disapplied for safeguarding national security or defence purposes (s.28(2))",
}

duties_table := [
	# ── Part 2 Chapter 2 ──
	{"id": "s.10(2)", "group": "P2C2", "gate": "special_category_or_criminal_data", "title": "Special categories of personal data and criminal convictions etc data", "text": "The processing meets the requirement in point (b), (h), (i) or (j) of Article 9(2) of the UK GDPR for authorisation by, or a basis in, the law of the United Kingdom or a part of the United Kingdom only if it meets a condition in Part 1 of Schedule 1."},
	{"id": "s.10(3)", "group": "P2C2", "gate": "special_category_or_criminal_data", "title": "Special categories of personal data and criminal convictions etc data", "text": "The processing meets the requirement in point (g) of Article 9(2) of the UK GDPR for a basis in the law of the United Kingdom or a part of the United Kingdom only if it meets a condition in Part 2 of Schedule 1."},
	{"id": "s.10(5)", "group": "P2C2", "gate": "special_category_or_criminal_data", "title": "Special categories of personal data and criminal convictions etc data", "text": "The processing meets the requirement in Article 10(1) of the UK GDPR for authorisation by the law of the United Kingdom or a part of the United Kingdom only if it meets a condition in Part 1, 2 or 3 of Schedule 1."},
	{"id": "s.13(3)", "group": "P2C2", "gate": "credit_reference_agency", "title": "Obligations of credit reference agencies", "text": "Where the controller discloses personal data in pursuance of Article 15(1) to (3) of the UK GDPR, the disclosure must be accompanied by a statement informing the data subject of the data subject's rights under section 159 of the Consumer Credit Act 1974 (correction of wrong information)."},
	# ── Schedule 1 ──
	{"id": "Sch.1 para 5(1)", "group": "P2C2-S1", "gate": "schedule_1_policy_document", "title": "Special categories of personal data and criminal convictions etc data — Part 2: Substantial public interest conditions", "text": "Except as otherwise provided, a condition in this Part of this Schedule is met only if, when the processing is carried out, the controller has an appropriate policy document in place (see paragraph 39 in Part 4 of this Schedule)."},
	{"id": "Sch.1 para 39", "group": "P2C2-S1", "gate": "schedule_1_policy_document", "title": "Special categories of personal data and criminal convictions etc data — Part 4: Appropriate policy document and additional safeguards", "text": "The controller has an appropriate policy document in place in relation to the processing of personal data in reliance on a condition described in paragraph 38 if the controller has produced a document which— (a) explains the controller's procedures for securing compliance with the principles in Article 5 of the UK GDPR (principles relating to processing of personal data) in connection with the processing of personal data in reliance on the condition in question, and (b) explains the controller's policies as regards the retention and erasure of personal data processed in reliance on the condition, giving an indication of how long such personal data is likely to be retained."},
	{"id": "Sch.1 para 40(1)", "group": "P2C2-S1", "gate": "schedule_1_policy_document", "title": "Special categories of personal data and criminal convictions etc data — Part 4: Appropriate policy document and additional safeguards", "text": "Where personal data is processed in reliance on a condition described in paragraph 38, the controller must during the relevant period— (a) retain the appropriate policy document, (b) review and (if appropriate) update it from time to time, and (c) make it available to the Commission, on request, without charge."},
	{"id": "Sch.1 para 41", "group": "P2C2-S1", "gate": "schedule_1_policy_document", "title": "Special categories of personal data and criminal convictions etc data — Part 4: Appropriate policy document and additional safeguards", "text": "A record maintained by the controller, or the controller's representative, under Article 30 of the UK GDPR in respect of the processing of personal data in reliance on a condition described in paragraph 38 must include the following information— (a) which condition is relied on, (b) how the processing satisfies Article 6 of the UK GDPR (lawfulness of processing), and (c) whether the personal data is retained and erased in accordance with the policies described in paragraph 39(b) and, if it is not, the reasons for not following those policies."},
	# ── Schedule 2 ──
	{"id": "Sch.2 para 16(3)", "group": "P2C2-S2", "gate": "withholds_third_party_information", "title": "Exemptions etc from the UK GDPR — Part 3: Restriction for the protection of rights of others", "text": "In determining whether it is reasonable to disclose the information without consent, the controller must have regard to all the relevant circumstances, including— (a) the type of information that would be disclosed, (b) any duty of confidentiality owed to the other individual, (c) any steps taken by the controller with a view to seeking the consent of the other individual, (d) whether the other individual is capable of giving consent, and (e) any express refusal of consent by the other individual."},
	{"id": "Sch.2 para 25(3)", "group": "P2C2-S2", "gate": "exam_data", "title": "Exemptions etc from the UK GDPR — Part 4: Restrictions as described in Article 23(1): restrictions of rules in Articles 13 to 15", "text": "Where a question arises as to whether the controller is obliged by Article 15 of the UK GDPR to disclose personal data, and the question arises before the day on which the exam results are announced, the controller must provide the information mentioned in Article 12(3) or (4)— (a) before the end of the period of 5 months beginning when the question arises, or (b) if earlier, before the end of the period of 40 days beginning with the announcement of the results."},
	{"id": "Sch.2 para 26(4)", "group": "P2C2-S2", "gate": "special_purposes", "title": "Exemptions etc from the UK GDPR — Part 5: Exemptions etc ... for reasons of freedom of expression and information", "text": "In determining whether publication would be in the public interest the controller must take into account the special importance of the public interest in the freedom of expression and information."},
	{"id": "Sch.2 para 26(5)", "group": "P2C2-S2", "gate": "special_purposes", "title": "Exemptions etc from the UK GDPR — Part 5: Exemptions etc ... for reasons of freedom of expression and information", "text": "In determining whether it is reasonable to believe that publication would be in the public interest, the controller must have regard to any of the codes of practice or guidelines listed in sub-paragraph (6) that is relevant to the publication in question."},
	# ── Schedule 3 ──
	{"id": "Sch.3 para 5(2)", "group": "P2C2-S3", "gate": "health_data_serious_harm_exemption", "title": "Exemptions etc from the UK GDPR: health, social work, education and child abuse data — Part 2: Health data", "text": "A controller who is not a health professional may not rely on sub-paragraph (1) to withhold data concerning health unless the controller has obtained an opinion from the person who appears to the controller to be the appropriate health professional to the effect that the serious harm test is met with respect to the data."},
	{"id": "Sch.3 para 12(2)", "group": "P2C2-S3", "gate": "scottish_social_work_or_education_authority", "title": "Exemptions etc from the UK GDPR: health, social work, education and child abuse data — Part 3: Social work data", "text": "The controller must inform the Principal Reporter of the fact that the question has arisen before the end of the period of 14 days beginning when the question arises."},
	{"id": "Sch.3 para 20(2)", "group": "P2C2-S3", "gate": "scottish_social_work_or_education_authority", "title": "Exemptions etc from the UK GDPR: health, social work, education and child abuse data — Part 4: Education data", "text": "The controller must inform the Principal Reporter of the fact that the question has arisen before the end of the period of 14 days beginning when the question arises."},
	# ── Part 2 Chapter 3 ──
	{"id": "s.24(7)", "group": "P2C3", "gate": "foi_public_authority", "title": "Manual unstructured data held by FOI public authorities", "text": "An estimate for the purposes of this section must be made in accordance with regulations under section 12(5) of the Freedom of Information Act 2000."},
	{"id": "s.28(3)", "group": "P2C3", "gate": "national_security_defence_exemption", "title": "National security and defence: modifications to Articles 9 and 32 of the UK GDPR", "text": "Where Article 32 of the UK GDPR does not apply, the controller or the processor must implement security measures appropriate to the risks arising from the processing of the personal data."},
	{"id": "s.28(4)", "group": "P2C3", "gate": "national_security_defence_exemption", "title": "National security and defence: modifications to Articles 9 and 32 of the UK GDPR", "text": "For the purposes of subsection (3), where the processing of personal data is carried out wholly or partly by automated means, the controller or the processor must, following an evaluation of the risks, implement measures designed to— (a) prevent unauthorised processing or unauthorised interference with the systems used in connection with the processing, (b) ensure that it is possible to establish the precise details of any processing that takes place, (c) ensure that any systems used in connection with the processing function properly and may, in the case of interruption, be restored, and (d) ensure that stored personal data cannot be corrupted if a system used in connection with the processing malfunctions."},
	# ── Part 3 Chapter 2 ──
	{"id": "s.34(3)", "group": "P3C2", "gate": "competent_authority", "title": "Overview and general duty of controller", "text": "The controller in relation to personal data is responsible for, and must be able to demonstrate, compliance with this Chapter."},
	{"id": "s.35(1)", "group": "P3C2", "gate": "competent_authority", "title": "The first data protection principle", "text": "The first data protection principle is that the processing of personal data for any of the law enforcement purposes must be lawful and fair."},
	{"id": "s.35(2)", "group": "P3C2", "gate": "competent_authority", "title": "The first data protection principle", "text": "The processing of personal data for any of the law enforcement purposes is lawful only if and to the extent that it is based on law and either— (a) the data subject has given consent to the processing for that purpose, or (b) the processing is necessary for the performance of a task carried out for that purpose by a competent authority."},
	{"id": "s.35(3)", "group": "P3C2", "gate": "competent_authority", "title": "The first data protection principle", "text": "In addition, where the processing for any of the law enforcement purposes is sensitive processing, the processing is permitted only in the two cases set out in subsections (4) and (5)."},
	{"id": "s.36(1)", "group": "P3C2", "gate": "competent_authority", "title": "The second data protection principle", "text": "The second data protection principle is that— (a) the law enforcement purpose for which personal data is collected (whether from the data subject or otherwise) must be specified, explicit and legitimate, and (b) personal data so collected must not be processed by or on behalf of a controller in a manner that is incompatible with the purpose for which the controller collected it."},
	{"id": "s.36(3)", "group": "P3C2", "gate": "competent_authority", "title": "The second data protection principle", "text": "Personal data collected for a law enforcement purpose may be processed for any other law enforcement purpose (whether by the controller that collected the data or by another controller) provided that— (a) the controller is authorised by law to process the data for the other purpose, and (b) the processing is necessary and proportionate to that other purpose."},
	{"id": "s.36(4)", "group": "P3C2", "gate": "competent_authority", "title": "The second data protection principle", "text": "Personal data collected for any of the law enforcement purposes may not be processed for a purpose that is not a law enforcement purpose unless the processing is authorised by law."},
	{"id": "s.37", "group": "P3C2", "gate": "competent_authority", "title": "The third data protection principle", "text": "The third data protection principle is that personal data processed for any of the law enforcement purposes must be adequate, relevant and not excessive in relation to the purpose for which it is processed."},
	{"id": "s.38(1)", "group": "P3C2", "gate": "competent_authority", "title": "The fourth data protection principle", "text": "The fourth data protection principle is that— (a) personal data processed for any of the law enforcement purposes must be accurate and, where necessary, kept up to date, and (b) every reasonable step must be taken to ensure that personal data that is inaccurate, having regard to the law enforcement purpose for which it is processed, is erased or rectified without delay."},
	{"id": "s.38(2)", "group": "P3C2", "gate": "competent_authority", "title": "The fourth data protection principle", "text": "In processing personal data for any of the law enforcement purposes, personal data based on facts must, so far as possible, be distinguished from personal data based on personal assessments."},
	{"id": "s.38(3)", "group": "P3C2", "gate": "competent_authority", "title": "The fourth data protection principle", "text": "In processing personal data for any of the law enforcement purposes, a clear distinction must, where relevant and as far as possible, be made between personal data relating to different categories of data subject, such as— (a) persons suspected of having committed or being about to commit a criminal offence; (b) persons convicted of a criminal offence; (c) persons who are or may be victims of a criminal offence; (d) witnesses or other persons with information about offences."},
	{"id": "s.38(4)", "group": "P3C2", "gate": "competent_authority", "title": "The fourth data protection principle", "text": "All reasonable steps must be taken to ensure that personal data which is inaccurate, incomplete or no longer up to date is not transmitted or made available for any of the law enforcement purposes."},
	{"id": "s.38(5)", "group": "P3C2", "gate": "competent_authority", "title": "The fourth data protection principle", "text": "For that purpose— (a) the quality of personal data must be verified before it is transmitted or made available, (b) in all transmissions of personal data, the necessary information enabling the recipient to assess the degree of accuracy, completeness and reliability of the data and the extent to which it is up to date must be included, and (c) if, after personal data has been transmitted, it emerges that the data was incorrect or that the transmission was unlawful, the recipient must be notified without delay."},
	{"id": "s.39(1)", "group": "P3C2", "gate": "competent_authority", "title": "The fifth data protection principle", "text": "The fifth data protection principle is that personal data processed for any of the law enforcement purposes must be kept for no longer than is necessary for the purpose for which it is processed."},
	{"id": "s.39(2)", "group": "P3C2", "gate": "competent_authority", "title": "The fifth data protection principle", "text": "Appropriate time limits must be established for the periodic review of the need for the continued storage of personal data for any of the law enforcement purposes."},
	{"id": "s.40", "group": "P3C2", "gate": "competent_authority", "title": "The sixth data protection principle", "text": "The sixth data protection principle is that personal data processed for any of the law enforcement purposes must be so processed in a manner that ensures appropriate security of the personal data, using appropriate technical or organisational measures (and, in this principle, “appropriate security” includes protection against unauthorised or unlawful processing and against accidental loss, destruction or damage)."},
	{"id": "s.40A(2)", "group": "P3C2", "gate": "competent_authority", "title": "Conditions for consent", "text": "The controller must be able to demonstrate that the data subject consented to the processing."},
	{"id": "s.40A(3)", "group": "P3C2", "gate": "competent_authority", "title": "Conditions for consent", "text": "If the data subject’s consent is given in writing as part of a document which also concerns other matters, the request for consent must be made— (a) in a manner which clearly distinguishes the request from the other matters, (b) in an intelligible and easily accessible form, and (c) in clear and plain language."},
	{"id": "s.40A(6)", "group": "P3C2", "gate": "competent_authority", "title": "Conditions for consent", "text": "Processing may only be carried out in reliance on consent if— (a) before the consent is given, the controller or processor informs the data subject of the right to withdraw it, and (b) it is as easy for the data subject to withdraw the consent as to give it."},
	{"id": "s.40A(7)", "group": "P3C2", "gate": "competent_authority", "title": "Conditions for consent", "text": "When assessing whether consent is freely given, account must be taken of, among other things, whether the provision of a service is conditional on consent to the processing of personal data that is not necessary for the provision of that service."},
	{"id": "s.41(2)", "group": "P3C2", "gate": "competent_authority", "title": "Safeguards: archiving", "text": "The processing is not permitted if— (a) it is carried out for the purposes of, or in connection with, measures or decisions with respect to a particular data subject, or (b) it is likely to cause substantial damage or substantial distress to a data subject."},
	{"id": "s.42(2)", "group": "P3C2", "gate": "competent_authority", "title": "Safeguards: sensitive processing", "text": "The controller has an appropriate policy document in place in relation to the sensitive processing if the controller has produced a document which— (a) explains the controller's procedures for securing compliance with the data protection principles (see section 34(1)) in connection with sensitive processing in reliance on the consent of the data subject or (as the case may be) in reliance on the condition in question, and (b) explains the controller's policies as regards the retention and erasure of personal data processed in reliance on the consent of the data subject or (as the case may be) in reliance on the condition in question, giving an indication of how long such personal data is likely to be retained."},
	{"id": "s.42(3)", "group": "P3C2", "gate": "competent_authority", "title": "Safeguards: sensitive processing", "text": "Where personal data is processed on the basis that an appropriate policy document is in place, the controller must during the relevant period— (a) retain the appropriate policy document, (b) review and (if appropriate) update it from time to time, and (c) make it available to the Commission, on request, without charge."},
	{"id": "s.42(4)", "group": "P3C2", "gate": "competent_authority", "title": "Safeguards: sensitive processing", "text": "The record maintained by the controller under section 61(1) and, where the sensitive processing is carried out by a processor on behalf of the controller, the record maintained by the processor under section 61(3) must include the following information— (a) whether the sensitive processing is carried out in reliance on the consent of the data subject or, if not, which condition in Schedule 8 is relied on, (b) how the processing satisfies section 35 (lawfulness of processing), and (c) whether the personal data is retained and erased in accordance with the policies described in subsection (2)(b) and, if it is not, the reasons for not following those policies."},
	# ── Part 3 Chapter 3 ──
	{"id": "s.44(1)", "group": "P3C3", "gate": "competent_authority", "title": "... Controller's general duties", "text": "The controller must make available to data subjects the following information (whether by making the information generally available to the public or in any other way)— (a) the identity and the contact details of the controller; (b) where applicable, the contact details of the data protection officer (see sections 69 to 71); (c) the purposes for which the controller processes personal data; (d) the existence of the rights of data subjects to request from the controller— (i) access to personal data (see section 45), (ii) rectification of personal data (see section 46), and (iii) erasure of personal data or the restriction of its processing (see section 47); (da) the existence of the right to make a complaint to the controller (see section 164A); (e) the existence of the right to lodge a complaint with the Commission (see section 165) and the contact details of the Commission."},
	{"id": "s.44(2)", "group": "P3C3", "gate": "competent_authority", "title": "... Controller's general duties", "text": "The controller must also, in specific cases for the purpose of enabling the exercise of a data subject's rights under this Part, give the data subject the following— (a) information about the legal basis for the processing; (b) information about the period for which the personal data will be stored or, where that is not possible, about the criteria used to determine that period; (c) where applicable, information about the categories of recipients of the personal data (including recipients in third countries or international organisations); (d) such further information as is necessary to enable the exercise of the data subject's rights under this Part."},
	{"id": "s.44(5)", "group": "P3C3", "gate": "competent_authority", "title": "... Controller's general duties", "text": "Where the provision of information to a data subject under subsection (2) is restricted under subsection (4), wholly or partly, the controller must inform the data subject in writing without undue delay— (a) that the provision of information has been restricted, (b) of the reasons for the restriction, (c) of the data subject's right to make a request to the Commission under section 51, (ca) of the data subject’s right to make a complaint to the controller under section 164A, (d) of the data subject's right to lodge a complaint with the Commission under section 165, and (e) of the data subject's right to apply to a court under section 167."},
	{"id": "s.44(7)", "group": "P3C3", "gate": "competent_authority", "title": "... Controller's general duties", "text": "The controller must— (a) record the reasons for a decision to restrict (whether wholly or partly) the provision of information to a data subject under subsection (2) in reliance on subsection (4), and (b) if requested to do so by the Commission, make the record available to the Commission."},
	{"id": "s.45(1)", "group": "P3C3", "gate": "competent_authority", "title": "Right of access by the data subject", "text": "A data subject is entitled to obtain from the controller— (a) confirmation as to whether or not personal data concerning him or her is being processed, and (b) where that is the case, access to the personal data and the information set out in subsection (2)."},
	{"id": "s.45(3)", "group": "P3C3", "gate": "competent_authority", "title": "Right of access by the data subject", "text": "Where a data subject makes a request under subsection (1), the information to which the data subject is entitled must be provided in writing — (a) without undue delay, and (b) in any event, before the end of the applicable time period (as to which see section 54)."},
	{"id": "s.45(5)", "group": "P3C3", "gate": "competent_authority", "title": "Right of access by the data subject", "text": "Where the rights of a data subject under subsection (1) are restricted under subsection (4), wholly or partly, the controller must inform the data subject in writing without undue delay and in any event before the end of the applicable time period (as to which see section 54)— (a) that the rights of the data subject have been restricted, (b) of the reasons for the restriction, (c) of the data subject's right to make a request to the Commission under section 51, (ca) of the data subject’s right to make a complaint to the controller under section 164A, (d) of the data subject's right to lodge a complaint with the Commission under section 165, and (e) of the data subject's right to apply to a court under section 167."},
	{"id": "s.45(7)", "group": "P3C3", "gate": "competent_authority", "title": "Right of access by the data subject", "text": "The controller must— (a) record the reasons for a decision to restrict (whether wholly or partly) the rights of a data subject under subsection (1) in reliance on subsection (4), and (b) if requested to do so by the Commission, make the record available to the Commission."},
	{"id": "s.45A(2)", "group": "P3C3", "gate": "competent_authority", "title": "Exemption from sections 44 and 45: legal professional privilege", "text": "A controller relying on the exemption in subsection (1) must inform the data subject in writing without undue delay of— (a) the decision to rely on the exemption, (b) the reason for the decision, (c) the data subject’s right to make a request to the Commission under section 51, (ca) the data subject’s right to make a complaint to the controller under section 164A, (d) the data subject’s right to lodge a complaint with the Commission under section 165, and (e) the data subject’s right to apply to a court under section 167."},
	{"id": "s.45A(4)", "group": "P3C3", "gate": "competent_authority", "title": "Exemption from sections 44 and 45: legal professional privilege", "text": "The controller must— (a) record the reason for a decision to rely on the exemption in subsection (1), and (b) if requested to do so by the Commission, make the record available to the Commission."},
	{"id": "s.46(1)", "group": "P3C3", "gate": "competent_authority", "title": "Right to rectification", "text": "The controller must, if so requested by a data subject, rectify without undue delay inaccurate personal data relating to the data subject."},
	{"id": "s.46(2)", "group": "P3C3", "gate": "competent_authority", "title": "Right to rectification", "text": "Where personal data is inaccurate because it is incomplete, the controller must, if so requested by a data subject, complete it."},
	{"id": "s.46(4)", "group": "P3C3", "gate": "competent_authority", "title": "Right to rectification", "text": "Where the controller would be required to rectify personal data under this section but the personal data must be maintained for the purposes of evidence, the controller must (instead of rectifying the personal data) restrict its processing."},
	{"id": "s.47(1)", "group": "P3C3", "gate": "competent_authority", "title": "Right to erasure or restriction of processing", "text": "The controller must erase personal data without undue delay where— (a) the processing of the personal data would infringe section 35, 36(1) to (3), 37, 38(1), 39(1), 40, 41 or 42, or (b) the controller has a legal obligation to erase the data."},
	{"id": "s.47(2)", "group": "P3C3", "gate": "competent_authority", "title": "Right to erasure or restriction of processing", "text": "Where the controller would be required to erase personal data under subsection (1) but the personal data must be maintained for the purposes of evidence, the controller must (instead of erasing the personal data) restrict its processing."},
	{"id": "s.47(3)", "group": "P3C3", "gate": "competent_authority", "title": "Right to erasure or restriction of processing", "text": "Where a data subject contests the accuracy of personal data (whether in making a request under this section or section 46 or in any other way), but it is not possible to ascertain whether it is accurate or not, the controller must restrict its processing."},
	{"id": "s.48(1)", "group": "P3C3", "gate": "competent_authority", "title": "Rights under section 46 or 47: supplementary", "text": "Where a data subject requests the rectification or erasure of personal data or the restriction of its processing, the controller must inform the data subject in writing— (a) whether the request has been granted, and (b) if it has been refused— (i) of the reasons for the refusal, (ii) of the data subject's right to make a request to the Commission under section 51, (iia) of the data subject’s right to make a complaint to the controller under section 164A, (iii) of the data subject's right to lodge a complaint with the Commission under section 165, and (iv) of the data subject's right to apply to a court under section 167."},
	{"id": "s.48(2)", "group": "P3C3", "gate": "competent_authority", "title": "Rights under section 46 or 47: supplementary", "text": "The controller must comply with the duty under subsection (1)— (a) without undue delay, and (b) in any event, before the end of the applicable time period (see section 54)."},
	{"id": "s.48(4)", "group": "P3C3", "gate": "competent_authority", "title": "Rights under section 46 or 47: supplementary", "text": "Where the rights of a data subject under subsection (1)(b)(i) are restricted under subsection (3), wholly or partly, the controller must inform the data subject in writing without undue delay— (a) that the rights of the data subject have been restricted, (b) of the reasons for the restriction, (ba) of the data subject’s right to make a complaint to the controller under section 164A, (c) of the data subject's right to lodge a complaint with the Commission under section 165, and (d) of the data subject's right to apply to a court under section 167."},
	{"id": "s.48(6)", "group": "P3C3", "gate": "competent_authority", "title": "Rights under section 46 or 47: supplementary", "text": "The controller must— (a) record the reasons for a decision to restrict (whether wholly or partly) the provision of information to a data subject under subsection (1)(b)(i) in reliance on subsection (3), and (b) if requested to do so by the Commission, make the record available to the Commission."},
	{"id": "s.48(7)", "group": "P3C3", "gate": "competent_authority", "title": "Rights under section 46 or 47: supplementary", "text": "Where the controller rectifies personal data, it must notify the competent authority (if any) from which the inaccurate personal data originated."},
	{"id": "s.48(9)", "group": "P3C3", "gate": "competent_authority", "title": "Rights under section 46 or 47: supplementary", "text": "Where the controller rectifies, erases or restricts the processing of personal data which has been disclosed by the controller— (a) the controller must notify the recipients, and (b) the recipients must similarly rectify, erase or restrict the processing of the personal data (so far as they retain responsibility for it)."},
	{"id": "s.48(10)", "group": "P3C3", "gate": "competent_authority", "title": "Rights under section 46 or 47: supplementary", "text": "Where processing is restricted in accordance with section 47(3), the controller must inform the data subject before lifting the restriction."},
	{"id": "s.50A(2)", "group": "P3C3", "gate": "competent_authority", "title": "Automated processing and significant decisions", "text": "When considering whether there is meaningful human involvement in the taking of a decision, a person must consider, among other things, the extent to which the decision is reached by means of profiling."},
	{"id": "s.50B(1)", "group": "P3C3", "gate": "competent_authority", "title": "Restrictions on automated decision-making based on sensitive processing", "text": "A significant decision based entirely or partly on sensitive processing may not be taken based solely on automated processing, unless one of the following conditions is met."},
	{"id": "s.50C(1)", "group": "P3C3", "gate": "competent_authority", "title": "Safeguards for automated decision-making", "text": "Subject to subsection (3), where a significant decision taken by or on behalf of a controller in relation to a data subject is— (a) based entirely or partly on personal data, and (b) based solely on automated processing,the controller must ensure that safeguards for the data subject’s rights, freedoms and legitimate interests are in place which comply with subsection (2) and any regulations under section 50D(4)."},
	{"id": "s.50C(2)", "group": "P3C3", "gate": "competent_authority", "title": "Safeguards for automated decision-making", "text": "The safeguards must consist of or include measures which— (a) provide the data subject with information about decisions described in subsection (1) taken in relation to the data subject; (b) enable the data subject to make representations about such decisions; (c) enable the data subject to obtain human intervention on the part of the controller in relation to such decisions; (d) enable the data subject to contest such decisions."},
	{"id": "s.50C(5)", "group": "P3C3", "gate": "competent_authority", "title": "Safeguards for automated decision-making", "text": "When considering whether there is meaningful human involvement in the reconsideration of a decision, a person must consider, among other things, the extent to which the conclusion reached on reconsideration is reached by means of profiling."},
	{"id": "s.52(1)", "group": "P3C3", "gate": "competent_authority", "title": "Form of provision of information etc", "text": "The controller must take reasonable steps to ensure that any information that is required by or under this Chapter to be provided to the data subject is provided in a concise, intelligible and easily accessible form, using clear and plain language."},
	{"id": "s.52(3)", "group": "P3C3", "gate": "competent_authority", "title": "Form of provision of information etc", "text": "Where information is provided in response to a request made by the data subject under or by virtue of any of sections 45, 46, 47, 50C or 50D, the controller must provide the information in the same form as the request where it is practicable to do so."},
	{"id": "s.52(5)", "group": "P3C3", "gate": "competent_authority", "title": "Form of provision of information etc", "text": "Subject to section 53, any information that is required by or under this Chapter to be provided to the data subject must be provided free of charge."},
	{"id": "s.52(6)", "group": "P3C3", "gate": "competent_authority", "title": "Form of provision of information etc", "text": "The controller must facilitate the exercise of the rights of the data subject arising under or by virtue of sections 45 to 50D."},
	{"id": "s.53(6)", "group": "P3C3", "gate": "competent_authority", "title": "Manifestly unfounded or excessive requests by the data subject", "text": "If, in reliance on subsection (1)(b), the controller does not take action on the request, the controller must inform the data subject of— (a) the reasons for not doing so, and (b) the data subject’s right to lodge a complaint with the Commission."},
	{"id": "s.53(7)", "group": "P3C3", "gate": "competent_authority", "title": "Manifestly unfounded or excessive requests by the data subject", "text": "The controller must comply with subsection (6)— (a) without undue delay, and (b) in any event, before the end of the applicable time period (as to which see section 54)."},
	{"id": "s.54(3B)", "group": "P3C3", "gate": "competent_authority", "title": "Meaning of “applicable time period”", "text": "A notice under subsection (3A) must— (a) be given before the end of the period of one month beginning with the relevant time, and (b) state the reasons for the delay."},
	# ── Part 3 Chapter 4 ──
	{"id": "s.55(3)", "group": "P3C4", "gate": "competent_authority", "title": "Overview and scope", "text": "Where a controller is required by any provision of this Chapter to implement appropriate technical and organisational measures, the controller must (in deciding what measures are appropriate) take into account— (a) the latest developments in technology, (b) the cost of implementation, (c) the nature, scope, context and purposes of processing, and (d) the risks for the rights and freedoms of individuals arising from the processing."},
	{"id": "s.56(1)", "group": "P3C4", "gate": "competent_authority", "title": "General obligations of the controller", "text": "Each controller must implement appropriate technical and organisational measures to ensure, and to be able to demonstrate, that the processing of personal data complies with the requirements of this Part."},
	{"id": "s.56(2)", "group": "P3C4", "gate": "competent_authority", "title": "General obligations of the controller", "text": "Where proportionate in relation to the processing, the measures implemented to comply with the duty under subsection (1) must include appropriate data protection policies."},
	{"id": "s.56(3)", "group": "P3C4", "gate": "competent_authority", "title": "General obligations of the controller", "text": "The technical and organisational measures implemented under subsection (1) must be reviewed and updated where necessary."},
	{"id": "s.57(1)", "group": "P3C4", "gate": "competent_authority", "title": "Data protection by design and default", "text": "Each controller must implement appropriate technical and organisational measures which are designed— (a) to implement the data protection principles in an effective manner, and (b) to integrate into the processing itself the safeguards necessary for that purpose."},
	{"id": "s.57(3)", "group": "P3C4", "gate": "competent_authority", "title": "Data protection by design and default", "text": "Each controller must implement appropriate technical and organisational measures for ensuring that, by default, only personal data which is necessary for each specific purpose of the processing is processed."},
	{"id": "s.57(5)", "group": "P3C4", "gate": "competent_authority", "title": "Data protection by design and default", "text": "In particular, the measures implemented to comply with the duty under subsection (3) must ensure that, by default, personal data is not made accessible to an indefinite number of people without an individual's intervention."},
	{"id": "s.58(2)", "group": "P3C4", "gate": "competent_authority", "title": "Joint controllers", "text": "Joint controllers must, in a transparent manner, determine their respective responsibilities for compliance with this Part by means of an arrangement between them, except to the extent that those responsibilities are determined under or by virtue of an enactment."},
	{"id": "s.58(3)", "group": "P3C4", "gate": "competent_authority", "title": "Joint controllers", "text": "The arrangement must designate the controller which is to be the contact point for data subjects."},
	{"id": "s.59(2)", "group": "P3C4", "gate": "competent_authority", "title": "Processors", "text": "The controller may use only a processor who provides guarantees to implement appropriate technical and organisational measures that are sufficient to secure that the processing will— (a) meet the requirements of this Part, and (b) ensure the protection of the rights of the data subject."},
	{"id": "s.59(3)", "group": "P3C4", "gate": "competent_authority", "title": "Processors", "text": "The processor used by the controller may not engage another processor (“a sub-processor”) without the prior written authorisation of the controller, which may be specific or general."},
	{"id": "s.59(4)", "group": "P3C4", "gate": "competent_authority", "title": "Processors", "text": "Where the controller gives a general written authorisation to a processor, the processor must inform the controller if the processor proposes to add to the number of sub-processors engaged by it or to replace any of them (so that the controller has the opportunity to object to the proposal)."},
	{"id": "s.59(5)", "group": "P3C4", "gate": "competent_authority", "title": "Processors", "text": "The processing by the processor must be governed by a contract in writing between the controller and the processor setting out the following— (a) the subject-matter and duration of the processing; (b) the nature and purpose of the processing; (c) the type of personal data and categories of data subjects involved; (d) the obligations and rights of the controller and processor."},
	{"id": "s.59(6)", "group": "P3C4", "gate": "competent_authority", "title": "Processors", "text": "The contract must, in particular, provide that the processor must— (a) act only on instructions from the controller, (b) ensure that the persons authorised to process personal data are subject to an appropriate duty of confidentiality, (c) assist the controller by any appropriate means to ensure compliance with the rights of the data subject under this Part, (d) at the end of the provision of services by the processor to the controller— (i) either delete or return to the controller (at the choice of the controller) the personal data to which the services relate, and (ii) delete copies of the personal data unless subject to a legal obligation to store the copies, (e) make available to the controller all information necessary to demonstrate compliance with this section, and (f) comply with the requirements of this section for engaging sub-processors."},
	{"id": "s.59(7)", "group": "P3C4", "gate": "competent_authority", "title": "Processors", "text": "The terms included in the contract in accordance with subsection (6)(a) must provide that the processor may transfer personal data to a third country or international organisation only if instructed by the controller to make the particular transfer."},
	{"id": "s.60", "group": "P3C4", "gate": "competent_authority", "title": "Processing under the authority of the controller or processor", "text": "A processor, and any person acting under the authority of a controller or processor, who has access to personal data may not process the data except— (a) on instructions from the controller, or (b) to comply with a legal obligation."},
	{"id": "s.61(1)", "group": "P3C4", "gate": "competent_authority", "title": "Records of processing activities", "text": "Each controller must maintain a record of all categories of processing activities for which the controller is responsible."},
	{"id": "s.61(2)", "group": "P3C4", "gate": "competent_authority", "title": "Records of processing activities", "text": "The controller's record must contain the following information— (a) the name and contact details of the controller; (b) where applicable, the name and contact details of the joint controller; (c) where applicable, the name and contact details of the data protection officer; (d) the purposes of the processing; (e) the categories of recipients to whom personal data has been or will be disclosed (including recipients in third countries or international organisations); (f) a description of the categories of— (i) data subject, and (ii) personal data; (g) where applicable, details of the use of profiling; (h) where applicable, the categories of transfers of personal data to a third country or an international organisation; (i) an indication of the legal basis for the processing operations, including transfers, for which the personal data is intended; (j) where possible, the envisaged time limits for erasure of the different categories of personal data; (k) where possible, a general description of the technical and organisational security measures referred to in section 66."},
	{"id": "s.61(3)", "group": "P3C4", "gate": "competent_authority", "title": "Records of processing activities", "text": "Each processor must maintain a record of all categories of processing activities carried out on behalf of a controller."},
	{"id": "s.61(4)", "group": "P3C4", "gate": "competent_authority", "title": "Records of processing activities", "text": "The processor's record must contain the following information— (a) the name and contact details of the processor and of any other processors engaged by the processor in accordance with section 59(3); (b) the name and contact details of the controller on behalf of which the processor is acting; (c) where applicable, the name and contact details of the data protection officer; (d) the categories of processing carried out on behalf of the controller; (e) where applicable, details of transfers of personal data to a third country or an international organisation where explicitly instructed to do so by the controller, including the identification of that third country or international organisation; (f) where possible, a general description of the technical and organisational security measures referred to in section 66."},
	{"id": "s.61(5)", "group": "P3C4", "gate": "competent_authority", "title": "Records of processing activities", "text": "The controller and the processor must make the records kept under this section available to the Commission on request."},
	{"id": "s.62(1)", "group": "P3C4", "gate": "competent_authority", "title": "Logging", "text": "A controller (or, where personal data is processed on behalf of the controller by a processor, the processor) must keep logs for at least the following processing operations in automated processing systems— (a) collection; (b) alteration; (c) consultation; (d) disclosure (including transfers); (e) combination; (f) erasure."},
	{"id": "s.62(2)", "group": "P3C4", "gate": "competent_authority", "title": "Logging", "text": "The logs of consultation must make it possible to establish— (a) the... date and time of, the consultation, and (b) so far as possible, the identity of the person who consulted the data."},
	{"id": "s.62(3)", "group": "P3C4", "gate": "competent_authority", "title": "Logging", "text": "The logs of disclosure must make it possible to establish— (a) the... date and time of, the disclosure, and (b) so far as possible— (i) the identity of the person who disclosed the data, and (ii) the identity of the recipients of the data."},
	{"id": "s.62(4)", "group": "P3C4", "gate": "competent_authority", "title": "Logging", "text": "The logs kept under subsection (1) may be used only for one or more of the following purposes— (a) to verify the lawfulness of processing; (b) to assist with self-monitoring by the controller or (as the case may be) the processor, including the conduct of internal disciplinary proceedings; (c) to ensure the integrity and security of personal data; (d) the purposes of criminal proceedings."},
	{"id": "s.62(5)", "group": "P3C4", "gate": "competent_authority", "title": "Logging", "text": "The controller or (as the case may be) the processor must make the logs available to the Commission on request."},
	{"id": "s.63", "group": "P3C4", "gate": "competent_authority", "title": "Co-operation with the Commission", "text": "Each controller and each processor must co-operate, on request, with the Commission in the performance of the Commission's tasks."},
	{"id": "s.64(1)", "group": "P3C4", "gate": "competent_authority", "title": "Data protection impact assessment", "text": "Where a type of processing is likely to result in a high risk to the rights and freedoms of individuals, the controller must, prior to the processing, carry out a data protection impact assessment."},
	{"id": "s.64(3)", "group": "P3C4", "gate": "competent_authority", "title": "Data protection impact assessment", "text": "A data protection impact assessment must include the following— (a) a general description of the envisaged processing operations; (b) an assessment of the risks to the rights and freedoms of data subjects; (c) the measures envisaged to address those risks; (d) safeguards, security measures and mechanisms to ensure the protection of personal data and to demonstrate compliance with this Part, taking into account the rights and legitimate interests of the data subjects and other persons concerned."},
	{"id": "s.64(4)", "group": "P3C4", "gate": "competent_authority", "title": "Data protection impact assessment", "text": "In deciding whether a type of processing is likely to result in a high risk to the rights and freedoms of individuals, the controller must take into account the nature, scope, context and purposes of the processing."},
	{"id": "s.65(2)", "group": "P3C4", "gate": "competent_authority", "title": "Prior consultation with the Commission", "text": "The controller must consult the Commission prior to the processing if a data protection impact assessment prepared under section 64 indicates that the processing of the data would result in a high risk to the rights and freedoms of individuals (in the absence of measures to mitigate the risk)."},
	{"id": "s.65(3)", "group": "P3C4", "gate": "competent_authority", "title": "Prior consultation with the Commission", "text": "Where the controller is required to consult the Commission under subsection (2), the controller must give the Commission— (a) the data protection impact assessment prepared under section 64, and (b) any other information requested by the Commission to enable the Commission to make an assessment of the compliance of the processing with the requirements of this Part."},
	{"id": "s.66(1)", "group": "P3C4", "gate": "competent_authority", "title": "Security of processing", "text": "Each controller and each processor must implement appropriate technical and organisational measures to ensure a level of security appropriate to the risks arising from the processing of personal data."},
	{"id": "s.66(2)", "group": "P3C4", "gate": "competent_authority", "title": "Security of processing", "text": "In the case of automated processing, each controller and each processor must, following an evaluation of the risks, implement measures designed to— (a) prevent unauthorised processing or unauthorised interference with the systems used in connection with it, (b) ensure that it is possible to establish the precise details of any processing that takes place, (c) ensure that any systems used in connection with the processing function properly and may, in the case of interruption, be restored, and (d) ensure that stored personal data cannot be corrupted if a system used in connection with the processing malfunctions."},
	{"id": "s.67(1)", "group": "P3C4", "gate": "competent_authority", "title": "Notification of a personal data breach to the Commission", "text": "If a controller becomes aware of a personal data breach in relation to personal data for which the controller is responsible, the controller must notify the breach to the Commission— (a) without undue delay, and (b) where feasible, not later than 72 hours after becoming aware of it."},
	{"id": "s.67(3)", "group": "P3C4", "gate": "competent_authority", "title": "Notification of a personal data breach to the Commission", "text": "Where the notification to the Commission is not made within 72 hours, the notification must be accompanied by reasons for the delay."},
	{"id": "s.67(4)", "group": "P3C4", "gate": "competent_authority", "title": "Notification of a personal data breach to the Commission", "text": "Subject to subsection (5), the notification must include— (a) a description of the nature of the personal data breach including, where possible, the categories and approximate number of data subjects concerned and the categories and approximate number of personal data records concerned; (b) the name and contact details of the data protection officer or other contact point from whom more information can be obtained; (c) a description of the likely consequences of the personal data breach; (d) a description of the measures taken or proposed to be taken by the controller to address the personal data breach, including, where appropriate, measures to mitigate its possible adverse effects."},
	{"id": "s.67(6)", "group": "P3C4", "gate": "competent_authority", "title": "Notification of a personal data breach to the Commission", "text": "The controller must record the following information in relation to a personal data breach— (a) the facts relating to the breach, (b) its effects, and (c) the remedial action taken."},
	{"id": "s.67(7)", "group": "P3C4", "gate": "competent_authority", "title": "Notification of a personal data breach to the Commission", "text": "The information mentioned in subsection (6) must be recorded in such a way as to enable the Commission to verify compliance with this section."},
	{"id": "s.67(9)", "group": "P3C4", "gate": "competent_authority", "title": "Notification of a personal data breach to the Commission", "text": "If a processor becomes aware of a personal data breach (in relation to personal data processed by the processor), the processor must notify the controller without undue delay."},
	{"id": "s.68(1)", "group": "P3C4", "gate": "competent_authority", "title": "Communication of a personal data breach to the data subject", "text": "Where a personal data breach is likely to result in a high risk to the rights and freedoms of individuals, the controller must inform the data subject of the breach without undue delay."},
	{"id": "s.68(2)", "group": "P3C4", "gate": "competent_authority", "title": "Communication of a personal data breach to the data subject", "text": "The information given to the data subject must include the following— (a) a description of the nature of the breach; (b) the name and contact details of the data protection officer or other contact point from whom more information can be obtained; (c) a description of the likely consequences of the personal data breach; (d) a description of the measures taken or proposed to be taken by the controller to address the personal data breach, including, where appropriate, measures to mitigate its possible adverse effects."},
	{"id": "s.68(5)", "group": "P3C4", "gate": "competent_authority", "title": "Communication of a personal data breach to the data subject", "text": "In a case falling within subsection (3)(c) (but not within subsection (3)(a) or (b)), the information mentioned in subsection (2) must be made available to the data subject in another equally effective way, for example, by means of a public communication."},
	{"id": "s.69(1)", "group": "P3C4", "gate": "competent_authority", "title": "Designation of a data protection officer", "text": "The controller must designate a data protection officer, unless the controller is a court, or other judicial authority, acting in its judicial capacity."},
	{"id": "s.69(2)", "group": "P3C4", "gate": "competent_authority", "title": "Designation of a data protection officer", "text": "When designating a data protection officer, the controller must have regard to the professional qualities of the proposed officer, in particular— (a) the proposed officer's expert knowledge of data protection law and practice, and (b) the ability of the proposed officer to perform the tasks mentioned in section 71."},
	{"id": "s.69(4)", "group": "P3C4", "gate": "competent_authority", "title": "Designation of a data protection officer", "text": "The controller must publish the contact details of the data protection officer and communicate these to the Commission."},
	{"id": "s.70(1)", "group": "P3C4", "gate": "competent_authority", "title": "Position of data protection officer", "text": "The controller must ensure that the data protection officer is involved, properly and in a timely manner, in all issues which relate to the protection of personal data."},
	{"id": "s.70(2)", "group": "P3C4", "gate": "competent_authority", "title": "Position of data protection officer", "text": "The controller must provide the data protection officer with the necessary resources and access to personal data and processing operations to enable the data protection officer to—"},
	{"id": "s.70(3)", "group": "P3C4", "gate": "competent_authority", "title": "Position of data protection officer", "text": "The controller— (a) must ensure that the data protection officer does not receive any instructions regarding the performance of the tasks mentioned in section 71; (b) must ensure that the data protection officer does not perform a task or fulfil a duty other than those mentioned in this Part where such task or duty would result in a conflict of interests; (c) must not dismiss or penalise the data protection officer for performing the tasks mentioned in section 71."},
	{"id": "s.70(5)", "group": "P3C4", "gate": "competent_authority", "title": "Position of data protection officer", "text": "The data protection officer, in the performance of this role, must report to the highest management level of the controller."},
	{"id": "s.71(1)", "group": "P3C4", "gate": "competent_authority", "title": "Tasks of data protection officer", "text": "The controller must entrust the data protection officer with at least the following tasks— (a) informing and advising the controller, any processor engaged by the controller, and any employee of the controller who carries out processing of personal data, of that person's obligations under this Part, (b) providing advice on the carrying out of a data protection impact assessment under section 64 and monitoring compliance with that section, (c) co-operating with the Commission, (d) acting as the contact point for the Commission on issues relating to processing, including in relation to the consultation mentioned in section 65, and consulting with the Commission, where appropriate, in relation to any other matter, (e) monitoring compliance with policies of the controller in relation to the protection of personal data, and (f) monitoring compliance by the controller with this Part."},
	{"id": "s.71(3)", "group": "P3C4", "gate": "competent_authority", "title": "Tasks of data protection officer", "text": "In performing the tasks set out in subsections (1) and (2), the data protection officer must have regard to the risks associated with processing operations, taking into account the nature, scope, context and purposes of processing."},
	# ── Part 3 Chapter 5 ──
	{"id": "s.73(1)", "group": "P3C5", "gate": "competent_authority", "title": "General principles for transfers of personal data", "text": "The controller in relation to the transfer must secure that the transfer takes place only if— (a) the three conditions set out in subsections (2) to (4) are met,... (b) in a case where the personal data was originally transmitted or otherwise made available to the controller or another competent authority by a member State..., that member State, or any person based in that member State which is a competent authority for the purposes of the Law Enforcement Directive, has authorised the transfer in accordance with the law of the member State, and— (c) the transfer is carried out in accordance with the other provisions of this Part."},
	{"id": "s.73(6)", "group": "P3C5", "gate": "competent_authority", "title": "General principles for transfers of personal data", "text": "Where a transfer is made without the authorisation mentioned in subsection (1)(b), the authority in the member State which would have been responsible for deciding whether to authorise the transfer must be informed without delay."},
	{"id": "s.75(2)", "group": "P3C5", "gate": "competent_authority", "title": "Transfers subject to appropriate safeguards", "text": "The controller must inform the Commission about the categories of data transfers that take place in reliance on subsection (1A)(b) but not in reliance on section 73(4)(aa) (transfer to processor)."},
	{"id": "s.75(3)", "group": "P3C5", "gate": "competent_authority", "title": "Transfers subject to appropriate safeguards", "text": "Where a transfer of data takes place in reliance on this section but not in reliance on section 73(4)(aa) (transfer to processor)— (a) the transfer must be documented, (b) the documentation must be provided to the Commission on request, and (c) the documentation must include, in particular— (i) the date and time of the transfer, (ii) the name of and any other pertinent information about the recipient, (iii) the justification for the transfer, and (iv) a description of the personal data transferred."},
	{"id": "s.76(2A)", "group": "P3C5", "gate": "competent_authority", "title": "Transfers based on special circumstances", "text": "In accordance with the third data protection principle, the amount of personal data transferred in reliance on this section must not be excessive in relation to the special purpose relied on."},
	{"id": "s.76(3)", "group": "P3C5", "gate": "competent_authority", "title": "Transfers based on special circumstances", "text": "Where a transfer of data takes place in reliance on this section— (a) the transfer must be documented, (b) the documentation must be provided to the Commission on request, and (c) the documentation must include, in particular— (i) the date and time of the transfer, (ii) the name of and any other pertinent information about the recipient, (iii) the justification for the transfer, and (iv) a description of the personal data transferred."},
	{"id": "s.77(6)", "group": "P3C5", "gate": "competent_authority", "title": "Additional conditions for transfers in reliance on section 73(4)(b)", "text": "Where personal data is transferred to a person in a third country in reliance on section 73(4)(b), the transferring controller must inform a relevant authority in that third country without undue delay of the transfer, unless this would be ineffective or inappropriate."},
	{"id": "s.77(7)", "group": "P3C5", "gate": "competent_authority", "title": "Additional conditions for transfers in reliance on section 73(4)(b)", "text": "The transferring controller must— (a) document any transfer to a recipient in a third country that takes place in reliance on section 73(4)(b), and (b) inform the Commission about the transfer."},
	{"id": "s.78(1)", "group": "P3C5", "gate": "competent_authority", "title": "Subsequent transfers", "text": "... The transferring controller must make it a condition of the transfer — (a) that the personal data is not to be further transferred to a third country or international organisation without the authorisation of the transferring controller or another competent authority (the “UK authoriser”), or (b) that— (i) the personal data is not to be so transferred without such authorisation except where subsection (1A) applies, and (ii) where a transfer is made without such authorisation, the UK authoriser must be informed without delay."},
	{"id": "s.78(2)", "group": "P3C5", "gate": "competent_authority", "title": "Subsequent transfers", "text": "The UK authoriser may give an authorisation for the purposes of a condition described in subsection (1) only where the further transfer is necessary for a law enforcement purpose."},
	{"id": "s.78(3)", "group": "P3C5", "gate": "competent_authority", "title": "Subsequent transfers", "text": "In deciding whether to give the authorisation, the UK authoriser must take into account (among any other relevant factors)— (a) the seriousness of the circumstances leading to the request for authorisation, (b) the purpose for which the personal data was originally transferred, and (c) the standards for the protection of personal data that apply in the third country or international organisation to which the personal data would be transferred."},
	{"id": "s.78(4)", "group": "P3C5", "gate": "competent_authority", "title": "Subsequent transfers", "text": "In a case where the personal data was originally transmitted or otherwise made available to the transferring controller or another competent authority by a member State..., the UK authoriser may not give an authorisation for the purposes of a condition described in subsection (1) unless that member State, or any person based in that member State which is a competent authority for the purposes of the Law Enforcement Directive, has authorised the transfer in accordance with the law of the member State."},
	{"id": "s.78(6)", "group": "P3C5", "gate": "competent_authority", "title": "Subsequent transfers", "text": "Where a transfer is made in a case described in subsection (4) without the authorisation mentioned in that subsection (whether made with or without authorisation from the UK authoriser), the UK authoriser must, without delay, inform, the authority in the member State which would have been responsible for deciding whether to authorise the transfer...."},
	{"id": "s.78(7)", "group": "P3C5", "gate": "competent_authority", "title": "Subsequent transfers", "text": "Where a transfer takes place in reliance on section 73(4)(aa) (transfer to processor), the transferring controller must make it a condition of the transfer that the data is only to be further transferred to a third country or international organisation where— (a) the terms of any relevant contract entered into, or authorisation given, by the transferring controller in accordance with section 59 are complied with, and (b) the further transfer satisfies the requirements in section 73(1)."},
	# ── Part 3 Chapter 6 ──
	{"id": "s.80(3)", "group": "P3C6", "gate": "competent_authority", "title": "Special processing restrictions", "text": "The controller must consider whether, if the personal data had instead been transmitted or otherwise made available within the United Kingdom to another competent authority, processing of the data by the other competent authority would have been subject to any restrictions by virtue of any enactment or rule of law."},
	{"id": "s.80(4)", "group": "P3C6", "gate": "competent_authority", "title": "Special processing restrictions", "text": "Where that would be the case, the controller must inform the non-UK recipient that the data is transmitted or otherwise made available subject to compliance by that person with the same restrictions (which must be set out in the information given to that person)."},
	{"id": "s.81(1)", "group": "P3C6", "gate": "competent_authority", "title": "Reporting of infringements", "text": "Each controller must implement effective mechanisms to encourage the reporting of an infringement of this Part."},
	{"id": "s.81(2)", "group": "P3C6", "gate": "competent_authority", "title": "Reporting of infringements", "text": "The mechanisms implemented under subsection (1) must provide that an infringement may be reported to any of the following persons— (a) the controller; (b) the Commission."},
	{"id": "s.81(3)", "group": "P3C6", "gate": "competent_authority", "title": "Reporting of infringements", "text": "The mechanisms implemented under subsection (1) must include— (a) raising awareness of the protections provided by Part 4A of the Employment Rights Act 1996 and Part 5A of the Employment Rights (Northern Ireland) Order 1996 (S.I. 1996/1919 (N.I. 16)), and (b) such other protections for a person who reports an infringement of this Part as the controller considers appropriate."},
	# ── Part 6 ──
	{"id": "s.164A(2)", "group": "P6", "gate": "", "title": "Complaints by data subjects to controllers", "text": "A controller must facilitate the making of complaints under this section by taking steps such as providing a complaint form which can be completed electronically and by other means."},
	{"id": "s.164A(3)", "group": "P6", "gate": "", "title": "Complaints by data subjects to controllers", "text": "If a controller receives a complaint under this section, the controller must acknowledge receipt of the complaint within the period of 30 days beginning when the complaint is received."},
	{"id": "s.164A(4)", "group": "P6", "gate": "", "title": "Complaints by data subjects to controllers", "text": "If a controller receives a complaint under this section, the controller must without undue delay— (a) take appropriate steps to respond to the complaint, and (b) inform the complainant of the outcome of the complaint."},
]

duties := {r.id: r | some r in duties_table}

out_of_scope := {
	"Part 1 (ss.1–3)": "preliminary: overview and definitions",
	"Part 2 Chapter 1 (ss.4–5)": "scope and definitions",
	"Part 2 Chapter 2 ss.6, 7, 8, 11, 12, 13(1)–(2), 13A, 15, 16": "definitions, interpretation, exemption signposts and Secretary of State powers; s.13(2) limits the Art 15 duty rather than adding one",
	"s.9A and Schedule A1": "a lawful-basis condition (processing for requests under the UK–US agreement on access to electronic data); Schedule A1 holds no controller duty",
	"s.17 (accreditation of certification providers)": "binds the Commission and the UK national accreditation body, not controllers; the only provision on credentials",
	"s.10(1), (4), (6)–(7)": "scope statements and Secretary of State powers",
	"repealed in this version": "ss.9, 14, 17A–17C, 18, 19, 20, 22, 23, 49, 50, 74, 74A and ss.21(1)–(4), 48(8), 54(4)–(6), 67(8), 74B(1)–(2), 75(1), 79(1)–(3) and (13), 80(5)–(7) and Sch.2 para 4(1A), (1B), (3), (4) are dotted out in the 2026-09-30 text",
	"Schedule 1 Parts 1–3 (paras 1–37), para 38, para 40(2)": "conditions a controller may rely on, a scope statement and a definition; the policy-document duty they trigger is carried by para 5(1) and paras 39–41",
	"Schedule 2 other than paras 16(3), 25(3), 26(4)–(5)": "exemptions and restrictions; paras 4A and 4B bind only the Secretary of State (immigration exemption)",
	"Schedule 3 other than paras 5(2), 12(2), 20(2); Schedule 4": "exemptions and restrictions",
	"Part 2 Chapter 3 ss.21, 24 (other than (7)), 25, 26, 27, 28(1)–(2) and (5)": "definitions, exemptions and national security certificates",
	"Part 3 Chapter 1 (ss.29–33)": "scope and definitions",
	"Part 3 ss.34(1)–(2), 35(4)–(8), 36(2), 40A(1), (4)–(5), 41(1), 42(1), (5), 42A, 43, 44(3)–(4), (6), 45(2)–(2A), (4), (6), 45A(1), (3), (5), 46(3), 47(4), 48(3), (5), 50A(1), 50B(2)–(3), 50C(3)–(4), 50D, 51, 52(2), (4), 53(1)–(5), 54(1)–(3A), (3C)–(3D)": "overviews, definitions, permissions, exceptions, Commission functions and Secretary of State powers; ss.35(4)–(5) are the two permitted cases folded into the s.35(3) row",
	"Part 3 ss.55(1)–(2), 56(4), 57(2), (4), 58(1), 59(1), (7A), (8), 64(2), 65(1), (4)–(7), 66(3), 67(2), (5), 68(3)–(4), (6)–(9), 69(3), 70(4), 71(2), 71A": "scope statements, definitions, exceptions, code-of-conduct options and Commission duties",
	"Part 3 ss.72, 73(A1), (2)–(5), (7), 74AA, 74AB, 74B, 75(1A), (4)–(8), 76(A1), (1)–(2), (4), 77(1)–(5), (8), 78(A1), (1A), (5)": "definitions of the transfer conditions, Secretary of State approval and monitoring duties, and exceptions",
	"Part 3 ss.78A, 79, 80(1)–(2), 81(4)–(6)": "national security exemption and certificates, scope and whistleblower protection",
	"Part 4 (ss.82–113)": "intelligence services processing — out of scope",
	"Part 5 (ss.114–141A)": "the Information Commission: its functions, codes of practice (ss.121–128), fees and guidance; s.137 charges: the duty to pay is imposed by regulations made under s.137, not by the Act's text",
	"Part 6 notices (ss.142–143, 145–147, 148A–148B, 149–154, 155–159)": "information, assessment, interview, enforcement and penalty notices bind a controller only once served — conditional, not attested here",
	"Part 6 offences (ss.144, 148, 148C, 170–173)": "offences are not controls",
	"Part 6 other (ss.160–164, 164B, 165–169, 174–181)": "Commission guidance, appeals, regulation-making powers, complaints to the Commission, court orders, compensation, special purposes proceedings, jurisdiction",
	"Part 7 (ss.182–215)": "supplementary: s.184 is an offence, s.185 voids contract terms, ss.209–210 apply the Act to the Crown and Parliament; no controller duty",
	"Schedules 5–21": "procedure, the Commission, amendments, transitional provision",
}

judgement_calls := {
	"duty test": "a row is a subsection whose own text obliges or prohibits a controller or processor (must, may not, may only, permitted only, not permitted if) or states a principle s.34(3) makes the controller responsible for; definitions, overviews, permissions (may restrict, may charge), carve-outs (does not apply) and powers are not rows",
	"lawfulness conditions as duties": "ss.10(2), (3), (5), 35(2), 35(3), 36(3), 41(2) and Sch.1 para 5(1) are conditions processing must meet; read as duties of the controller doing the processing",
	"s.35(4)–(5)": "the two cases in which sensitive processing is permitted are alternatives; folded into the s.35(3) row rather than each attested",
	"Sch.1 para 39 and s.42(2)": "phrased as when a controller has an appropriate policy document; read as the content duty for that document",
	"s.45(1)": "the data subject's entitlement to access is read as the controller's duty to give it",
	"ss.50A(2), 50C(5)": "a person must consider ... read as binding the controller that takes or reconsiders the decision",
	"s.70(5)": "the DPO's reporting line is an organisational duty the controller must provide for",
	"s.73(6)": "passive (the member State authority must be informed); read as the transferring controller's duty",
	"s.78(2)–(4), (6)": "bind the UK authoriser, which s.78(1) defines as the transferring controller or another competent authority",
	"s.62(4)": "a restriction on the use of logs, carried as a duty",
	"s.164A": "applies to every controller under the UK GDPR and Part 3; not gated",
	"gated rows": "conditional duties (s.10, s.13(3), s.24(7), s.28(3)–(4), Sch.1, Sch.2, Sch.3 rows and all of Part 3) are attested only when the controller declares the flag in _gates true",
	"Sch.2 para 16(3)": "a duty only when an access request would disclose information about another individual; gated rather than required of every controller",
	"Part 3 sub-cases": "rows for consent (s.40A), archiving (s.41(2)), joint controllers (s.58), processors (s.59), automated decisions (ss.50A–50C) and transfers (Chapter 5) are gated only by competent_authority: a competent authority that never does the thing attests the row as true (nothing to do)",
}

_in := object.get(input, "uk_dpa_2018", null)

_scope := object.get(input, ["uk_dpa_2018", "scope"], null)

_duties := object.get(input, ["uk_dpa_2018", "duties"], null)

_flag(k) := object.get(input, ["uk_dpa_2018", "scope", k], "undeclared")

violations contains "Data Protection Act input contract: FAIL-CLOSED — input.uk_dpa_2018 is missing or not an object; no duty can be evaluated and the controller is reported non-compliant" if {
	not is_object(_in)
}

violations contains "Data Protection Act input contract: FAIL-CLOSED — input.uk_dpa_2018.duties is missing or not an object of {\"<subsection id>\": true}" if {
	is_object(_in)
	not is_object(_duties)
}

violations contains "Data Protection Act input contract: FAIL-CLOSED — input.uk_dpa_2018.scope is missing or not an object of declared flags" if {
	is_object(_in)
	not is_object(_scope)
}

violations contains msg if {
	some flag, why in _gates
	not is_boolean(_flag(flag))
	msg := sprintf("Data Protection Act input contract: scope flag %v undeclared — %v must be declared true or false", [flag, why])
}

_gate_open("") := true

_gate_open(g) if _scope[g] == true

applicable[id] := r if {
	some id, r in duties
	_gate_open(r.gate)
}

_attested(id) if _duties[id] == true

violations contains msg if {
	some id, r in applicable
	not _attested(id)
	msg := sprintf("DPA %v (%v): %v — not attested", [id, r.title, r.text])
}

violations contains msg if {
	is_object(_duties)
	some id, _ in _duties
	not duties[id]
	msg := sprintf("Data Protection Act input contract: attestation for unknown id %v — not a duty row of this module (ids are as the Act numbers them, e.g. s.62(1), Sch.1 para 40(1))", [id])
}

chapter_reports[c] := rpt if {
	some c, ch in chapters
	ids := {id | some id, r in duties; r.group == c}
	app := {id | some id in ids; applicable[id]}
	rpt := {
		"part": ch.part,
		"heading": ch.heading,
		"duties": count(ids),
		"applicable": count(app),
		"attested": count({id | some id in app; _attested(id)}),
		"gaps": sort([id | some id in app; not _attested(id)]),
		"xml_units": xml_units[c],
	}
}

part_reports[p] := rpt if {
	some p, heading in parts
	ids := {id | some id, r in duties; chapters[r.group].part == p}
	app := {id | some id in ids; applicable[id]}
	rpt := {
		"heading": heading,
		"duties": count(ids),
		"applicable": count(app),
		"attested": count({id | some id in app; _attested(id)}),
		"gaps": count({id | some id in app; not _attested(id)}),
	}
}

compliance_report := {
	"framework": "UK Data Protection Act 2018 (c. 12) — controller and processor duties beyond the UK GDPR",
	"standard": "Data Protection Act 2018 as revised to 2026-09-30 (legislation.gov.uk), Parts 2, 3 and s.164A",
	"source": source,
	"companion_module": "frameworks/privacy/gdpr (gdpr.main) — UK GDPR Article duties; run both for a UK controller",
	"id_scheme": "the Act's own numbering: s.<section>(<subsection>), s.<section> for a section without subsections, Sch.<n> para <p>(<sub-paragraph>)",
	"scope_flags": {k: _flag(k) | some k, _ in _gates},
	"total_controls": 151,
	"duties_evaluated": count(applicable),
	"duties_attested": count({id | some id, _ in applicable; _attested(id)}),
	"parts": part_reports,
	"chapters": chapter_reports,
	"out_of_scope": out_of_scope,
	"judgement_calls": judgement_calls,
	"compliant": compliant,
	"violation_count": count(violations),
	"violations": violations,
}
