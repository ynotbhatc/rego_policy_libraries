# HIPAA Administrative Simplification - 45 CFR Part 160: the obligations it places on covered entities and
# business associates, one row per obligation paragraph, keyed to the CFR citation. Attested, fail-closed.
#
# Source: https://www.govinfo.gov/bulkdata/CFR/2025/title-45/CFR-2025-title45-vol2.xml
#   sha256 5fb58263c7533af259dacbc0d72e097158b995551a0fb241c4f997d4ef856b52, retrieved 2026-10-13
#   (2025 annual edition, GovInfo bulk XML; public domain).
#   Every id was checked by a generator to begin a paragraph of that XML. Titles summarise the paragraph; the
#   regulation's text governs.
#   Measured: Part 160 has Subparts A-E and 61 section entries (§§ 160.101-160.552; § 160.302 [Reserved]).
#   The duties on covered entities and business associates are § 160.105 (Subpart A) and § 160.310(a)-(c)(2)
#   and § 160.316(a)-(c) (Subpart C). Subparts B (preemption), D (civil money penalties) and E (hearings)
#   contain no standing duty of a regulated entity and contribute no rows.
# Rows (8) by subpart:
#   Subpart A - General Provisions                                                     1 rows
#   Subpart B - Preemption of State Law                                                0 rows
#   Subpart C - Compliance and Investigations                                          7 rows
#   Subpart D - Imposition of Civil Money Penalties                                    0 rows
#   Subpart E - Procedures for Hearings                                                0 rows
#   gates: any 8
# Paragraphs that bind HHS / the Secretary, define terms, state permissions or have lapsed are not controls; each
# is listed with its citation in out_of_scope.
#
# Evaluation: every row is attested - input.hipaa.part_160["<id>"] == true (no fact checks exist for these
# paragraphs). Applicability: input.hipaa.scope flags health_plan, health_care_provider, health_care_clearinghouse
# and business_associate must each be declared true or false; a row whose gate is closed is not evaluated.
# Fail-closed: missing or non-object input.hipaa.part_160 is a FAIL-CLOSED violation; a non-true attestation, an
# unknown id or an undeclared scope flag is a violation.
#
# OPA endpoint: POST /v1/data/hipaa/part160/compliance_report

# METADATA
# title: "HIPAA Administrative Simplification - 45 CFR Part 160, covered entity and business associate obligations (CFR citations, attested)"
# custom:
#   class: compliance
#   framework: hipaa
#   source: hhs
#   domains: [privacy, healthcare]
#   coverage:
#     checks: 13
#     cited: 10
#     expected: 8
#     found: 10
#     scope: module
#     density: full
#     basis: declared-total
#     tested: true
#     entrypoint: compliance_report
#     guard: self
#     as_of: v2.4.2
package hipaa.part160

import rego.v1

source := {
	"regulation": "45 CFR Subtitle A, Subchapter C — Administrative Data Standards and Related Requirements (Parts 160, 162, 164)",
	"edition": "Code of Federal Regulations, Title 45, Volume 2, 2025 annual edition (GovInfo bulk XML)",
	"url": "https://www.govinfo.gov/bulkdata/CFR/2025/title-45/CFR-2025-title45-vol2.xml",
	"sha256": "5fb58263c7533af259dacbc0d72e097158b995551a0fb241c4f997d4ef856b52",
	"retrieved": "2026-10-13",
}

sections := {
	"A": "Subpart A - General Provisions",
	"B": "Subpart B - Preemption of State Law",
	"C": "Subpart C - Compliance and Investigations",
	"D": "Subpart D - Imposition of Civil Money Penalties",
	"E": "Subpart E - Procedures for Hearings",
}

scope_roles := {
	"health_plan": "45 CFR 160.103 - whether the entity is a health plan must be declared true or false",
	"health_care_provider": "45 CFR 160.103 - whether the entity is a covered health care provider must be declared true or false",
	"health_care_clearinghouse": "45 CFR 160.103 - whether the entity is a health care clearinghouse must be declared true or false",
	"business_associate": "45 CFR 160.103 - whether the entity acts as a business associate must be declared true or false",
}

# One row per obligation paragraph, keyed by CFR citation.
obligations_table := [
	{"id": "160.105", "section": "A", "status": "obligation", "gate": "", "title": "Comply with new or modified standards and implementation specifications no later than 180 days from their effective date (rules effective after January 25, 2013)"},
	{"id": "160.310(a)", "section": "C", "status": "obligation", "gate": "", "title": "Provide records and compliance reports: keep the records and submit the compliance reports the Secretary determines necessary to ascertain compliance"},
	{"id": "160.310(b)", "section": "C", "status": "obligation", "gate": "", "title": "Cooperate with complaint investigations and compliance reviews undertaken by the Secretary"},
	{"id": "160.310(c)(1)", "section": "C", "status": "obligation", "gate": "", "title": "Permit access by the Secretary to facilities, books, records, accounts and other sources of information, including PHI (at any time without notice in exigent circumstances)"},
	{"id": "160.310(c)(2)", "section": "C", "status": "obligation", "gate": "", "title": "Where required information is in the exclusive possession of another who refuses to furnish it, so certify and set forth the efforts made to obtain it"},
	{"id": "160.316(a)", "section": "C", "status": "obligation", "gate": "", "title": "No threat, intimidation, coercion, harassment, discrimination or other retaliation against any person for filing a complaint under § 160.306"},
	{"id": "160.316(b)", "section": "C", "status": "obligation", "gate": "", "title": "No retaliation for testifying, assisting or participating in an investigation, compliance review, proceeding or hearing under Part 160"},
	{"id": "160.316(c)", "section": "C", "status": "obligation", "gate": "", "title": "No retaliation for opposing, in good faith and reasonably, an act or practice made unlawful by this subchapter (without a disclosure of PHI in violation of Subpart E of Part 164)"},
]

obligations := {r.id: r | some r in obligations_table}

# Paragraphs of Part 160 that are not controls, with the reason.
out_of_scope := {
	"160.101": "Subpart A - statutory basis and purpose",
	"160.102": "Subpart A - applicability; used as the input.hipaa.scope role declaration, not a control",
	"160.103": "Subpart A - definitions",
	"160.104": "Subpart A - modifications adopted by the Secretary (HHS procedure)",
	"160.201-160.205": "Subpart B - preemption of State law: the general rule and exceptions are a legal analysis, and exception determinations are requested by a State (§ 160.204) and made by the Secretary; not an obligation of a covered entity or business associate",
	"160.300": "Subpart C - applicability",
	"160.304": "Subpart C - principles for achieving compliance (the Secretary seeks cooperation, may give technical assistance)",
	"160.306": "Subpart C - complaints to the Secretary (a right of any person; investigation by the Secretary). The covered entity's duty not to retaliate is § 160.316",
	"160.308": "Subpart C - compliance reviews conducted by the Secretary; the duty to cooperate is § 160.310(b)",
	"160.310(c)(3)": "Subpart C - the Secretary's limits on disclosing PHI obtained in an investigation",
	"160.312": "Subpart C - Secretarial action regarding complaints and compliance reviews",
	"160.314": "Subpart C - investigational subpoenas and inquiries issued and conducted by the Secretary (an entity named in a subpoena must designate persons to testify, § 160.314(a)(1)(v) - a duty arising only under a subpoena, not a standing control)",
	"160.400-160.426": "Subpart D - imposition of civil money penalties by the Secretary: basis, amounts, factors, affirmative defenses, waiver, limitations, settlement, notice, collection, public notification",
	"160.500-160.552": "Subpart E - procedures for hearings before an ALJ (respondent's procedural rights and the conduct of hearings)",
}

# No fact checks exist for these paragraphs: every row is attested.
fact_basis := {}

_fact_pass := set()

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
	msg := sprintf("HIPAA Part 160 Input Contract: %v (input.hipaa.scope.%v undeclared)", [text, k])
}

violations contains "HIPAA Part 160 Input Contract: FAIL-CLOSED - input.hipaa.scope declares no regulated role (health_plan, health_care_provider, health_care_clearinghouse or business_associate true); applicability under 45 CFR 160.102 cannot be established" if {
	count({k | some k in _roles; _scope[k] == true}) == 0
}

_attestations := a if {
	a := object.get(input, ["hipaa", "part_160"], null)
	is_object(a)
}

violations contains "HIPAA Part 160: FAIL-CLOSED - attestations 'input.hipaa.part_160' were not supplied (or are not an object); this module cannot be evaluated and is reported non-compliant" if {
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
	some id, r in obligations
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

else := sprintf("not attested - input.hipaa.part_160[\"%v\"] must be true", [id])

violations contains msg if {
	some id, r in applicable
	not _satisfied(id)
	msg := sprintf("HIPAA %v %v (%v): %v", [id, r.title, r.status, _unmet(id)])
}

violations contains msg if {
	some id, _ in _attestations
	not obligations[id]
	msg := sprintf("HIPAA Part 160 Input Contract: attestation for unknown id %v - ids are the 45 CFR citations this module carries, for example 160.310(b)", [id])
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
	some id, r in obligations
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
	ids := {id | some id; r := obligations[id]; r.section == s}
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

compliance_report := {
	"framework": "HIPAA Administrative Simplification",
	"standard": "45 CFR Part 160",
	"source": source,
	"compliant": compliant,
	"id_scheme": "45 CFR paragraph citation, e.g. 160.310(b)",
	"controls_total": count(obligations),
	"standard_total": 8, # 45 CFR Part 160: obligation paragraphs binding covered entities / business associates
	"attested": count(obligations),
	"applicable": _n_applicable,
	"satisfied": _n_satisfied,
	"subparts": section_reports,
	"obligations": row_status,
	"out_of_scope": out_of_scope,
	"violation_count": count(violations),
	"violations": violations,
}
