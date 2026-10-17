# 45 CFR 155.260 — Privacy and security of personally identifiable information (ACA Exchanges and non-Exchange
# entities). One attested row per obligation paragraph.
#
# Source of truth: GovInfo bulk CFR XML, annual edition, Title 45 Parts 140 to 199, "Revised as of October 1,
# 2025" (latest annual edition published for Title 45 on 2026-10-14; no 2026 Title 45 volume yet),
#   https://www.govinfo.gov/bulkdata/CFR/2025/title-45/CFR-2025-title45-vol2.xml
#   sha256 5fb58263c7533af259dacbc0d72e097158b995551a0fb241c4f997d4ef856b52, retrieved 2026-10-14.
# CFR text is public domain. Every row id is the paragraph designation and every `text`/`lead` string is copied
# verbatim from that edition (checked by substring match against the whitespace-normalised source).
#
# Rows (35): (a)(1), (a)(1)(iii)(B), (a)(2); (a)(3)(i)–(viii) principles; (a)(4)(i)–(vi) safeguards; (a)(5);
# (a)(6); (b)(2)(i)–(v) non-Exchange entity contract or agreement contents; (b)(3)(i)–(iii) standards binding
# non-Exchange entities; (c); (d)(1)–(2); (e)(1)–(4); (f).
# Note on paragraph numbering: in this edition the non-Exchange entity agreement requirements are (b)(2)(i)–(v)
# and (a)(5) is the duty to monitor, periodically assess and update security controls; both are rows as numbered.
# Folded: (a)(1)(i)–(iii) (the permitted purposes) are part of the (a)(1) row text. Not rows (out of scope):
# (a)(1)(iii)(A) (a determination by the Secretary/HHS, not a duty of the entity); (b)(1) (definition of a
# non-Exchange entity); (g) (civil money penalty — carried as data in `penalty`).
# Judgement calls:
#   - Role. (a), (b)(2)(i), (b)(3), (c), (d), (e) bind the Exchange. A non-Exchange entity is bound through its
#     contract or agreement, so (b)(2)(ii)–(v) apply to both roles (Exchange: the provision is in the executed
#     agreement; non-Exchange entity: it complies with the provision), and (f) applies to both roles.
#   - (a)(1)(iii)(B) is a precondition: attesting it means no use or disclosure outside (a)(1)(i)–(ii) was made
#     without first submitting the (1)–(4) information to HHS.
#
# Gate: input.aca_155_260.exchange_or_non_exchange_entity must be declared "exchange" or "non_exchange_entity";
# anything else is a violation. Attestation: input.aca_155_260.obligations["155.260(a)(3)(i)"] == true.
# Fail-closed: a missing or non-object obligations container is a FAIL-CLOSED violation; an undeclared role, a
# non-true attestation of an applicable row, and an unknown id are violations. Rollup per paragraph (a)–(f).
#
# Query: POST /v1/data/aca_155_260/main/compliance_report

# METADATA
# title: "45 CFR 155.260 — ACA Exchange privacy and security of PII, obligations attested"
# custom:
#   class: compliance
#   framework: aca_155_260
#   source: hhs
#   domains: [privacy, healthcare, us-federal]
#   coverage:
#     checks: 39
#     cited: 35
#     expected: 35
#     found: 35
#     scope: directory
#     density: full
#     basis: declared-total
#     tested: true
#     entrypoint: compliance_report
#     guard: self
#     as_of: v2.4.2
package aca_155_260.main

import rego.v1

default compliant := false

compliant if {
	count(violations) == 0
}

source := {
	"cfr_edition": "Title 45 Parts 140 to 199, revised as of October 1, 2025",
	"cfr_url": "https://www.govinfo.gov/bulkdata/CFR/2025/title-45/CFR-2025-title45-vol2.xml",
	"cfr_sha256": "5fb58263c7533af259dacbc0d72e097158b995551a0fb241c4f997d4ef856b52",
	"retrieved": "2026-10-14",
}

sections := {
	"(a)": "Creation, collection, use and disclosure",
	"(b)": "Application to non-Exchange entities",
	"(c)": "Workforce compliance",
	"(d)": "Written policies and procedures",
	"(e)": "Data sharing",
	"(f)": "Compliance with the Code",
}

penalty := {"155.260(g)": "Any person who knowingly and willfully uses or discloses information in violation of section 1411(g) of the Affordable Care Act will be subject to a CMP of not more than $25,000 as adjusted annually under 45 CFR part 102 per person or entity, per use or disclosure, consistent with the bases and process for imposing civil penalties specified at § 155.285, in addition to other penalties that may be prescribed by law."}

roles := {"exchange", "non_exchange_entity"}

_x := ["exchange"]

_both := ["exchange", "non_exchange_entity"]

_lead_a3 := "The Exchange must establish and implement privacy and security standards that are consistent with the following principles:"

_lead_a4 := "For the purposes of implementing the principle described in paragraph (a)(3)(vii) of this section, the Exchange must establish and implement operational, technical, administrative and physical safeguards that are consistent with any applicable laws (including this section) to ensure—"

_lead_b2 := "Prior to any person or entity becoming a non-Exchange entity, Exchanges must execute with the person or entity a contract or agreement that includes:"

_lead_b3 := "When collection, use or disclosure is not otherwise required by law, the privacy and security standards to which an Exchange binds non-Exchange entities must:"

_lead_d := "Policies and procedures regarding the creation collection, use, and disclosure of personally identifiable information must, at minimum:"

_lead_e := "Data matching and sharing arrangements that facilitate the sharing of personally identifiable information between the Exchange and agencies administering Medicaid, CHIP or the BHP for the exchange of eligibility information must:"

obligations_list := [
	# ── (a) Creation, collection, use and disclosure ─────────────────────────
	{"id": "155.260(a)(1)", "section": "(a)", "applies_to": _x, "lead": "Creation, collection, use and disclosure.", "text": "Where the Exchange creates or collects personally identifiable information for the purposes of determining eligibility for enrollment in a qualified health plan; determining eligibility for other insurance affordability programs, as defined in § 155.300; or determining eligibility for exemptions from the individual shared responsibility provisions in section 5000A of the Code, the Exchange may only use or disclose such personally identifiable information to the extent such information is necessary: (i) For the Exchange to carry out the functions described in § 155.200; (ii) For the Exchange to carry out other functions not described in paragraph (a)(1)(i) of this section, which the Secretary determines to be in compliance with section 1411(g)(2)(A) of the Affordable Care Act and for which an individual provides consent for his or her information to be used or disclosed; or (iii) For the Exchange to carry out other functions not described in paragraphs (a)(1)(i) and (ii) of this section, for which an individual provides consent for his or her information to be used or disclosed, and which the Secretary determines are in compliance with section 1411(g)(2)(A) of the Affordable Care Act under the following substantive and procedural requirements:"},
	{"id": "155.260(a)(1)(iii)(B)", "section": "(a)", "applies_to": _x, "lead": "Procedural requirements for approval of a use or disclosure of personally identifiable information.", "text": "To seek approval for a use or disclosure of personally identifiable information created or collected as described in paragraph (a)(1) of this section that is not described in paragraphs (a)(1)(i) or (ii) of this section, the Exchange must submit the following information to HHS: (1) Identity of the Exchange and appropriate contact persons; (2) Detailed description of the proposed use or disclosure, which must include, but not necessarily be limited to, a listing or description of the specific information to be used or disclosed and an identification of the persons or entities that may access or receive the information; (3) Description of how the use or disclosure will ensure the efficient operation of the Exchange consistent with section 1411(g)(2)(A) of the Affordable Care Act; and (4) Description of how the information to be used or disclosed will be protected in compliance with privacy and security standards that meet the requirements of this section or other relevant law, as applicable."},
	{"id": "155.260(a)(2)", "section": "(a)", "applies_to": _x, "lead": "Creation, collection, use and disclosure.", "text": "The Exchange may not create, collect, use, or disclose personally identifiable information unless the creation, collection, use, or disclosure is consistent with this section."},
	{"id": "155.260(a)(3)(i)", "section": "(a)", "applies_to": _x, "lead": _lead_a3, "title": "Individual access.", "text": "Individuals should be provided with a simple and timely means to access and obtain their personally identifiable information in a readable form and format;"},
	{"id": "155.260(a)(3)(ii)", "section": "(a)", "applies_to": _x, "lead": _lead_a3, "title": "Correction.", "text": "Individuals should be provided with a timely means to dispute the accuracy or integrity of their personally identifiable information and to have erroneous information corrected or to have a dispute documented if their requests are denied;"},
	{"id": "155.260(a)(3)(iii)", "section": "(a)", "applies_to": _x, "lead": _lead_a3, "title": "Openness and transparency.", "text": "There should be openness and transparency about policies, procedures, and technologies that directly affect individuals and/or their personally identifiable information;"},
	{"id": "155.260(a)(3)(iv)", "section": "(a)", "applies_to": _x, "lead": _lead_a3, "title": "Individual choice.", "text": "Individuals should be provided a reasonable opportunity and capability to make informed decisions about the collection, use, and disclosure of their personally identifiable information;"},
	{"id": "155.260(a)(3)(v)", "section": "(a)", "applies_to": _x, "lead": _lead_a3, "title": "Collection, use, and disclosure limitations.", "text": "Personally identifiable information should be created, collected, used, and/or disclosed only to the extent necessary to accomplish a specified purpose(s) and never to discriminate inappropriately;"},
	{"id": "155.260(a)(3)(vi)", "section": "(a)", "applies_to": _x, "lead": _lead_a3, "title": "Data quality and integrity.", "text": "Persons and entities should take reasonable steps to ensure that personally identifiable information is complete, accurate, and up-to-date to the extent necessary for the person's or entity's intended purposes and has not been altered or destroyed in an unauthorized manner;"},
	{"id": "155.260(a)(3)(vii)", "section": "(a)", "applies_to": _x, "lead": _lead_a3, "title": "Safeguards.", "text": "Personally identifiable information should be protected with reasonable operational, administrative, technical, and physical safeguards to ensure its confidentiality, integrity, and availability and to prevent unauthorized or inappropriate access, use, or disclosure; and,"},
	{"id": "155.260(a)(3)(viii)", "section": "(a)", "applies_to": _x, "lead": _lead_a3, "title": "Accountability.", "text": "These principles should be implemented, and adherence assured, through appropriate monitoring and other means and methods should be in place to report and mitigate non-adherence and breaches."},
	{"id": "155.260(a)(4)(i)", "section": "(a)", "applies_to": _x, "lead": _lead_a4, "text": "The confidentiality, integrity, and availability of personally identifiable information created, collected, used, and/or disclosed by the Exchange;"},
	{"id": "155.260(a)(4)(ii)", "section": "(a)", "applies_to": _x, "lead": _lead_a4, "text": "Personally identifiable information is only used by or disclosed to those authorized to receive or view it;"},
	{"id": "155.260(a)(4)(iii)", "section": "(a)", "applies_to": _x, "lead": _lead_a4, "text": "Return information, as such term is defined by section 6103(b)(2) of the Code, is kept confidential under section 6103 of the Code;"},
	{"id": "155.260(a)(4)(iv)", "section": "(a)", "applies_to": _x, "lead": _lead_a4, "text": "Personally identifiable information is protected against any reasonably anticipated threats or hazards to the confidentiality, integrity, and availability of such information;"},
	{"id": "155.260(a)(4)(v)", "section": "(a)", "applies_to": _x, "lead": _lead_a4, "text": "Personally identifiable information is protected against any reasonably anticipated uses or disclosures of such information that are not permitted or required by law; and"},
	{"id": "155.260(a)(4)(vi)", "section": "(a)", "applies_to": _x, "lead": _lead_a4, "text": "Personally identifiable information is securely destroyed or disposed of in an appropriate and reasonable manner and in accordance with retention schedules;"},
	{"id": "155.260(a)(5)", "section": "(a)", "applies_to": _x, "lead": "Creation, collection, use and disclosure.", "text": "The Exchange must monitor, periodically assess, and update the security controls and related system risks to ensure the continued effectiveness of those controls."},
	{"id": "155.260(a)(6)", "section": "(a)", "applies_to": _x, "lead": "Creation, collection, use and disclosure.", "text": "The Exchange must develop and utilize secure electronic interfaces when sharing personally identifiable information electronically."},
	# ── (b) Application to non-Exchange entities ─────────────────────────────
	{"id": "155.260(b)(2)(i)", "section": "(b)", "applies_to": _x, "lead": _lead_b2, "text": "A description of the functions to be performed by the non-Exchange entity;"},
	{"id": "155.260(b)(2)(ii)", "section": "(b)", "applies_to": _both, "lead": _lead_b2, "text": "A provision(s) binding the non-Exchange entity to comply with the privacy and security standards and obligations adopted in accordance with paragraph (b)(3) of this section, and specifically listing or incorporating those privacy and security standards and obligations;"},
	{"id": "155.260(b)(2)(iii)", "section": "(b)", "applies_to": _both, "lead": _lead_b2, "text": "A provision requiring the non-Exchange entity to monitor, periodically assess, and update its security controls and related system risks to ensure the continued effectiveness of those controls in accordance with paragraph (a)(5) of this section;"},
	{"id": "155.260(b)(2)(iv)", "section": "(b)", "applies_to": _both, "lead": _lead_b2, "text": "A provision requiring the non-Exchange entity to inform the Exchange of any change in its administrative, technical, or operational environments defined as material within the contract; and"},
	{"id": "155.260(b)(2)(v)", "section": "(b)", "applies_to": _both, "lead": _lead_b2, "text": "A provision that requires the non-Exchange entity to bind any downstream entities to the same privacy and security standards and obligations to which the non-Exchange entity has agreed in its contract or agreement with the Exchange."},
	{"id": "155.260(b)(3)(i)", "section": "(b)", "applies_to": _x, "lead": _lead_b3, "text": "Be consistent with the principles and requirements listed in paragraphs (a)(1) through (6) of this section, including being at least as protective as the standards the Exchange has established and implemented for itself in compliance with paragraph (a)(3) of this section;"},
	{"id": "155.260(b)(3)(ii)", "section": "(b)", "applies_to": _x, "lead": _lead_b3, "text": "Comply with the requirements of paragraphs (c), (d), (f), and (g) of this section; and"},
	{"id": "155.260(b)(3)(iii)", "section": "(b)", "applies_to": _x, "lead": _lead_b3, "text": "Take into specific consideration: (A) The environment in which the non-Exchange entity is operating; (B) Whether the standards are relevant and applicable to the non-Exchange entity's duties and activities in connection with the Exchange; and (C) Any existing legal requirements to which the non-Exchange entity is bound in relation to its administrative, technical, and operational controls and practices, including but not limited to, its existing data handling and information technology processes and protocols."},
	# ── (c) Workforce compliance ─────────────────────────────────────────────
	{"id": "155.260(c)", "section": "(c)", "applies_to": _x, "lead": "Workforce compliance.", "text": "The Exchange must ensure its workforce complies with the policies and procedures developed and implemented by the Exchange to comply with this section."},
	# ── (d) Written policies and procedures ──────────────────────────────────
	{"id": "155.260(d)(1)", "section": "(d)", "applies_to": _x, "lead": _lead_d, "text": "Be in writing, and available to the Secretary of HHS upon request; and"},
	{"id": "155.260(d)(2)", "section": "(d)", "applies_to": _x, "lead": _lead_d, "text": "Identify applicable law governing collection, use, and disclosure of personally identifiable information."},
	# ── (e) Data sharing ─────────────────────────────────────────────────────
	{"id": "155.260(e)(1)", "section": "(e)", "applies_to": _x, "lead": _lead_e, "text": "Meet any applicable requirements described in this section;"},
	{"id": "155.260(e)(2)", "section": "(e)", "applies_to": _x, "lead": _lead_e, "text": "Meet any applicable requirements described in section 1413(c)(1) and (c)(2) of the Affordable Care Act;"},
	{"id": "155.260(e)(3)", "section": "(e)", "applies_to": _x, "lead": _lead_e, "text": "Be equal to or more stringent than the requirements for Medicaid programs under section 1942 of the Act; and"},
	{"id": "155.260(e)(4)", "section": "(e)", "applies_to": _x, "lead": _lead_e, "text": "For those matching agreements that meet the definition of “matching program” under 5 U.S.C. 552a(a)(8), comply with 5 U.S.C. 552a(o)."},
	# ── (f) Compliance with the Code ─────────────────────────────────────────
	{"id": "155.260(f)", "section": "(f)", "applies_to": _both, "lead": "Compliance with the Code.", "text": "Return information, as defined in section 6103(b)(2) of the Code, must be kept confidential and disclosed, used, and maintained only in accordance with section 6103 of the Code."},
]

obligations := {r.id: r | some r in obligations_list}

_in := object.get(input, "aca_155_260", {})

_role := r if {
	r := _in.exchange_or_non_exchange_entity
	r in roles
}

_given := g if {
	g := _in.obligations
	is_object(g)
}

_supplied if _given

_true(id) if _given[id] == true

violations contains "ACA Exchange PII rule: FAIL-CLOSED - 45 CFR 155.260 attestations 'input.aca_155_260.obligations' were not supplied (or are not an object); this module cannot be evaluated and is reported non-compliant" if {
	not _supplied
}

violations contains "ACA Exchange PII rule Input Contract: input.aca_155_260.exchange_or_non_exchange_entity must be declared \"exchange\" or \"non_exchange_entity\"" if {
	not _role
}

applicable[id] := r if {
	some id, r in obligations
	_role in r.applies_to
}

violations contains msg if {
	some id, r in applicable
	not _true(id)
	msg := sprintf("45 CFR %v (%v, %v): not attested — %v", [id, sections[r.section], _role, r.text])
}

violations contains msg if {
	some id, _ in _given
	not obligations[id]
	msg := sprintf("ACA Exchange PII rule Input Contract: attestation for unknown id %v — ids are paragraphs such as 155.260(a)(3)(i)", [id])
}

paragraph_rollup[s] := r if {
	some s, name in sections
	ids := {id | some id; q := obligations[id]; q.section == s}
	app := {id | some id in ids; applicable[id]}
	ok := {id | some id in app; _true(id)}
	r := {
		"name": name,
		"rows_total": count(ids),
		"rows_evaluated": count(app),
		"rows_attested": count(ok),
		"gaps": sort([id | some id in app; not id in ok]),
	}
}

compliance_report := {
	"framework": "45 CFR 155.260 — Privacy and security of personally identifiable information",
	"standard": "45 CFR 155.260 (Title 45 revised as of October 1, 2025) — Exchange and non-Exchange entity obligations",
	"source": source,
	"role": object.get(_in, "exchange_or_non_exchange_entity", "undeclared"),
	"standard_total": 35,
	"rows_evaluated": count(applicable),
	"rows_attested": count([id | some id; _ = applicable[id]; _true(id)]),
	"paragraphs": paragraph_rollup,
	"penalty": penalty,
	"compliant": compliant,
	"violation_count": count(violations),
	"violations": violations,
}
