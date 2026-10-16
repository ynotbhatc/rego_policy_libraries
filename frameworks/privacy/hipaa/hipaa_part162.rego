# HIPAA Administrative Simplification - 45 CFR Part 162: the obligations it places on covered entities and
# business associates, one row per obligation paragraph, keyed to the CFR citation. Attested, fail-closed.
#
# Source: https://www.govinfo.gov/bulkdata/CFR/2025/title-45/CFR-2025-title45-vol2.xml
#   sha256 5fb58263c7533af259dacbc0d72e097158b995551a0fb241c4f997d4ef856b52, retrieved 2026-10-13
#   (2025 annual edition, GovInfo bulk XML; public domain).
#   Every id was checked by a generator to begin a paragraph of that XML. Titles summarise the paragraph; the
#   regulation's text governs.
#   Measured: the 2025 edition prints Subparts A, D, F, I, J and K-S (44 section entries; §§ 162.402 and
#   162.900 [Reserved]); Subparts B-C, E and G-H are [Reserved]. Subpart E (health plan identifier, HPID) is
#   reserved in this edition, so there are no HPID rows. For the transaction standards (Subparts K-S) the row is
#   the paragraph in force on 2026-10-13 (the Secretary adopts the standard there; § 162.923(a) obliges its
#   use); later-dated paragraphs are in dated_obligations.
# Rows (43) by subpart:
#   Subpart D - Standard Unique Health Identifier for Health Care Providers           10 rows
#   Subpart F - Standard Unique Employer Identifier                                    1 rows
#   Subpart I - General Provisions for Transactions                                   15 rows
#   Subpart J - Code Sets                                                              2 rows
#   Subpart K - Health Care Claims or Equivalent Encounter Information                 2 rows
#   Subpart L - Eligibility for a Health Plan                                          2 rows
#   Subpart M - Referral Certification and Authorization                               2 rows
#   Subpart N - Health Care Claim Status                                               2 rows
#   Subpart O - Enrollment and Disenrollment in a Health Plan                          1 rows
#   Subpart P - Health Care Electronic Funds Transfers (EFT) and Remittance Advice     2 rows
#   Subpart Q - Health Plan Premium Payments                                           1 rows
#   Subpart R - Coordination of Benefits                                               2 rows
#   Subpart S - Medicaid Pharmacy Subrogation                                          1 rows
#   gates: covered_entity 24, health_care_clearinghouse 1, health_care_provider 8, health_plan 10
# Paragraphs that bind HHS / the Secretary, define terms, state permissions or have lapsed are not controls; each
# is listed with its citation in out_of_scope.
#
# Evaluation: every row is attested - input.hipaa.part_162["<id>"] == true (no fact checks exist for these
# paragraphs). Applicability: input.hipaa.scope flags health_plan, health_care_provider, health_care_clearinghouse
# and business_associate must each be declared true or false; a row whose gate is closed is not evaluated.
# Fail-closed: missing or non-object input.hipaa.part_162 is a FAIL-CLOSED violation; a non-true attestation, an
# unknown id or an undeclared scope flag is a violation.
#
# OPA endpoint: POST /v1/data/hipaa/part162/compliance_report

# METADATA
# title: "HIPAA Administrative Simplification - 45 CFR Part 162, covered entity and business associate obligations (CFR citations, attested)"
# custom:
#   class: compliance
#   framework: hipaa
#   source: hhs
#   domains: [privacy, healthcare]
#   coverage:
#     checks: 48
#     cited: 45
#     expected: 43
#     found: 45
#     scope: module
#     density: full
#     basis: declared-total
#     tested: true
#     entrypoint: compliance_report
#     guard: self
#     as_of: v2.4.2
package hipaa.part162

import rego.v1

source := {
	"regulation": "45 CFR Subtitle A, Subchapter C — Administrative Data Standards and Related Requirements (Parts 160, 162, 164)",
	"edition": "Code of Federal Regulations, Title 45, Volume 2, 2025 annual edition (GovInfo bulk XML)",
	"url": "https://www.govinfo.gov/bulkdata/CFR/2025/title-45/CFR-2025-title45-vol2.xml",
	"sha256": "5fb58263c7533af259dacbc0d72e097158b995551a0fb241c4f997d4ef856b52",
	"retrieved": "2026-10-13",
}

sections := {
	"D": "Subpart D - Standard Unique Health Identifier for Health Care Providers",
	"F": "Subpart F - Standard Unique Employer Identifier",
	"I": "Subpart I - General Provisions for Transactions",
	"J": "Subpart J - Code Sets",
	"K": "Subpart K - Health Care Claims or Equivalent Encounter Information",
	"L": "Subpart L - Eligibility for a Health Plan",
	"M": "Subpart M - Referral Certification and Authorization",
	"N": "Subpart N - Health Care Claim Status",
	"O": "Subpart O - Enrollment and Disenrollment in a Health Plan",
	"P": "Subpart P - Health Care Electronic Funds Transfers (EFT) and Remittance Advice",
	"Q": "Subpart Q - Health Plan Premium Payments",
	"R": "Subpart R - Coordination of Benefits",
	"S": "Subpart S - Medicaid Pharmacy Subrogation",
}

scope_roles := {
	"health_plan": "45 CFR 160.103 - whether the entity is a health plan must be declared true or false",
	"health_care_provider": "45 CFR 160.103 - whether the entity is a covered health care provider must be declared true or false",
	"health_care_clearinghouse": "45 CFR 160.103 - whether the entity is a health care clearinghouse must be declared true or false",
	"business_associate": "45 CFR 160.103 - whether the entity acts as a business associate must be declared true or false",
}

# One row per obligation paragraph, keyed by CFR citation.
obligations_table := [
	{"id": "162.410(a)(1)", "section": "D", "status": "obligation", "gate": "health_care_provider", "title": "Obtain an NPI from the National Provider System for itself and for any subpart that would be a covered health care provider if it were a separate legal entity"},
	{"id": "162.410(a)(2)", "section": "D", "status": "obligation", "gate": "health_care_provider", "title": "Use its NPI to identify itself on all standard transactions where its health care provider identifier is required"},
	{"id": "162.410(a)(3)", "section": "D", "status": "obligation", "gate": "health_care_provider", "title": "Disclose its NPI, when requested, to any entity that needs it to identify the provider in a standard transaction"},
	{"id": "162.410(a)(4)", "section": "D", "status": "obligation", "gate": "health_care_provider", "title": "Communicate to the NPS any changes in its required data elements within 30 days of the change"},
	{"id": "162.410(a)(5)", "section": "D", "status": "obligation", "gate": "health_care_provider", "title": "Require business associates that conduct standard transactions on its behalf to use its NPI and other NPIs appropriately"},
	{"id": "162.410(a)(6)", "section": "D", "status": "obligation", "gate": "health_care_provider", "title": "Comply with (a)(2)-(a)(5) for each NPI assigned to its subparts"},
	{"id": "162.410(b)", "section": "D", "status": "obligation", "gate": "health_care_provider", "title": "Organization provider: require member, employed or contracted non-covered prescribers to obtain an NPI from NPPES and disclose it on request"},
	{"id": "162.412(a)", "section": "D", "status": "obligation", "gate": "health_plan", "title": "Use the NPI of any health care provider that has one to identify that provider on all standard transactions where the identifier is required"},
	{"id": "162.412(b)", "section": "D", "status": "obligation", "gate": "health_plan", "title": "Not require a health care provider that has an NPI to obtain an additional NPI"},
	{"id": "162.414", "section": "D", "status": "obligation", "gate": "health_care_clearinghouse", "title": "Use the NPI of any health care provider that has one to identify that provider on all standard transactions where the identifier is required"},
	{"id": "162.610(b)", "section": "F", "status": "obligation", "gate": "covered_entity", "title": "Use the EIN of the appropriate employer in standard transactions that require an employer identifier, including where situationally required"},
	{"id": "162.915(a)", "section": "I", "status": "obligation", "gate": "covered_entity", "title": "No trading partner agreement that changes the definition, data condition or use of a data element or segment in a standard or operating rule (except for State or Federal law or fraud and abuse)"},
	{"id": "162.915(b)", "section": "I", "status": "obligation", "gate": "covered_entity", "title": "No trading partner agreement that adds data elements or segments to the maximum defined data set"},
	{"id": "162.915(c)", "section": "I", "status": "obligation", "gate": "covered_entity", "title": "No trading partner agreement that uses codes or data elements marked \"not used\" or absent from the implementation specification"},
	{"id": "162.915(d)", "section": "I", "status": "obligation", "gate": "covered_entity", "title": "No trading partner agreement that changes the meaning or intent of the standard's implementation specification"},
	{"id": "162.923(a)", "section": "I", "status": "obligation", "gate": "covered_entity", "title": "Conduct as a standard transaction any transaction for which a standard is adopted, when conducted electronically with another covered entity (or within the same covered entity)"},
	{"id": "162.923(b)", "section": "I", "status": "obligation", "gate": "health_care_provider", "title": "Direct data entry offered by a health plan: use the applicable data content and data condition requirements of the standard"},
	{"id": "162.923(c)", "section": "I", "status": "obligation", "gate": "covered_entity", "title": "When a business associate (including a clearinghouse) conducts a transaction on its behalf, require it to comply with Part 162 and to require the same of its agents and subcontractors"},
	{"id": "162.925(a)(1)", "section": "I", "status": "obligation", "gate": "health_plan", "title": "Conduct a transaction as a standard transaction when an entity requests it"},
	{"id": "162.925(a)(2)", "section": "I", "status": "obligation", "gate": "health_plan", "title": "Not delay or reject a transaction, or attempt to adversely affect the other entity or the transaction, because it is a standard transaction"},
	{"id": "162.925(a)(3)", "section": "I", "status": "obligation", "gate": "health_plan", "title": "Not reject a standard transaction because it contains data elements the plan does not need or use"},
	{"id": "162.925(a)(4)", "section": "I", "status": "obligation", "gate": "health_plan", "title": "Not offer a provider an incentive to conduct a transaction by direct data entry under § 162.923(b)"},
	{"id": "162.925(a)(5)", "section": "I", "status": "obligation", "gate": "health_plan", "title": "When operating as or requiring use of a clearinghouse, not charge fees or costs above normal telecommunications costs"},
	{"id": "162.925(b)", "section": "I", "status": "obligation", "gate": "health_plan", "title": "Coordination of benefits: store the COB data needed to forward the standard transaction to the other health plan or payer"},
	{"id": "162.925(c)(1)", "section": "I", "status": "obligation", "gate": "health_plan", "title": "Accept and promptly process any standard transaction that contains codes valid under Subpart J"},
	{"id": "162.925(c)(2)", "section": "I", "status": "obligation", "gate": "health_plan", "title": "Keep code sets for the current billing period and appeals periods still open to processing"},
	{"id": "162.1000(a)", "section": "J", "status": "obligation", "gate": "covered_entity", "title": "Use the medical data code sets of § 162.1002 valid at the time the health care is furnished"},
	{"id": "162.1000(b)", "section": "J", "status": "obligation", "gate": "covered_entity", "title": "Use the nonmedical data code sets of the implementation specifications valid at the time the transaction is initiated"},
	{"id": "162.1102(c)", "section": "K", "status": "obligation", "gate": "covered_entity", "title": "Health care claims or equivalent encounter information: the § 162.1102(b)(2) standards except (b)(2)(v)(A) (NCPDP D.0 / Batch 1.2; ASC X12 837 005010 dental, professional, institutional) - January 1, 2012 through August 14, 2027"},
	{"id": "162.1102(d)", "section": "K", "status": "obligation", "gate": "covered_entity", "title": "Health care claims: Quantity Prescribed (460-ET) field of NCPDP D.0 for Schedule II drug transmissions - September 21, 2020 through August 14, 2027"},
	{"id": "162.1202(c)", "section": "L", "status": "obligation", "gate": "covered_entity", "title": "Eligibility for a health plan: the § 162.1202(b)(2) standards (NCPDP D.0; ASC X12 270/271 005010) - January 1, 2012 through August 14, 2027"},
	{"id": "162.1203", "section": "L", "status": "obligation", "gate": "covered_entity", "title": "Eligibility for a health plan: CAQH CORE Phase I and II operating rules (CORE 152-157, 258-260, 270), on and after January 1, 2013, excluding acknowledgements and CORE certification"},
	{"id": "162.1302(c)", "section": "M", "status": "obligation", "gate": "covered_entity", "title": "Referral certification and authorization: the § 162.1302(b)(2) standards (NCPDP D.0; ASC X12 278 005010) - January 1, 2012 through August 14, 2027"},
	{"id": "162.1302(d)", "section": "M", "status": "obligation", "gate": "covered_entity", "title": "Referral certification and authorization: Quantity Prescribed (460-ET) field for Schedule II drug transmissions - September 21, 2020 through August 14, 2027"},
	{"id": "162.1402(c)", "section": "N", "status": "obligation", "gate": "covered_entity", "title": "Health care claim status: ASC X12 276/277 005010, on and after January 1, 2012"},
	{"id": "162.1403", "section": "N", "status": "obligation", "gate": "covered_entity", "title": "Health care claim status: CAQH CORE Phase II operating rules (CORE 250, 270), on and after January 1, 2013, excluding acknowledgements and CORE certification"},
	{"id": "162.1502(c)", "section": "O", "status": "obligation", "gate": "covered_entity", "title": "Enrollment and disenrollment in a health plan: ASC X12 834 005010, on and after January 1, 2012"},
	{"id": "162.1602(d)", "section": "P", "status": "obligation", "gate": "covered_entity", "title": "Health care EFT and remittance advice: NACHA CCD+ with the X12 835 TRN segment for Stage 1 payment initiation, and ASC X12 835 005010 for remittance advice, on and after January 1, 2014"},
	{"id": "162.1603", "section": "P", "status": "obligation", "gate": "covered_entity", "title": "Health care EFT and remittance advice: CAQH CORE Phase III EFT & ERA operating rule set, on and after January 1, 2014"},
	{"id": "162.1702(c)", "section": "Q", "status": "obligation", "gate": "covered_entity", "title": "Health plan premium payments: ASC X12 820 005010, on and after January 1, 2012"},
	{"id": "162.1802(c)", "section": "R", "status": "obligation", "gate": "covered_entity", "title": "Coordination of benefits: the § 162.1802(b)(2) standards (NCPDP D.0; ASC X12 837 005010) - January 1, 2012 through August 14, 2027"},
	{"id": "162.1802(d)", "section": "R", "status": "obligation", "gate": "covered_entity", "title": "Coordination of benefits: Quantity Prescribed (460-ET) field for Schedule II drug transmissions - September 21, 2020 through August 14, 2027"},
	{"id": "162.1902(a)", "section": "S", "status": "obligation", "gate": "covered_entity", "title": "Medicaid pharmacy subrogation: NCPDP Batch Standard Medicaid Subrogation Implementation Guide 3.0 - January 1, 2012 through August 14, 2027"},
]

obligations := {r.id: r | some r in obligations_table}

# Paragraphs of Part 162 that are not controls, with the reason.
out_of_scope := {
	"162.100": "Subpart A - applicability (covered entities must comply with the applicable requirements of this part); restated by every row",
	"162.103": "Subpart A - definitions",
	"Subparts B-C, E, G-H": "[Reserved] in the 2025 edition. Subpart E (standard unique health identifier for health plans, HPID) is reserved - no health plan identifier rows",
	"162.402": "[Reserved]",
	"162.404": "Subpart D - NPI compliance dates (May 23, 2007; small health plans May 23, 2008), all past; the obligations are the §§ 162.410-162.414 rows",
	"162.406": "Subpart D - the Secretary's adoption of the NPI; (b)(1) restates §§ 162.410-162.414",
	"162.408": "Subpart D - duties of the National Provider System (HHS)",
	"162.410(c)": "Subpart D - a provider that is not a covered entity may obtain an NPI (permission)",
	"162.600": "Subpart F - employer identifier compliance dates (2004/2005), all past",
	"162.605": "Subpart F - the Secretary's adoption of the EIN",
	"162.610(a)": "Subpart F - definition of the employer identifier (the EIN on the employee's Form W-2)",
	"162.610(c)": "Subpart F - required (restates (b)) and permitted uses",
	"162.900": "[Reserved]",
	"162.910": "Subpart I - maintenance of standards and designation of DSMOs (HHS procedure)",
	"162.920": "Subpart I - availability of implementation specifications and operating rules (incorporation by reference)",
	"162.925(a)(6)": "Subpart I - March 17, 2009 through December 31, 2011 transition rule, expired",
	"162.930": "Subpart I - functions a clearinghouse may perform as a business associate (permission)",
	"162.940": "Subpart I - exceptions requested from the Secretary to test proposed modifications; (d) binds only an organization granted an exception",
	"162.1002": "Subpart J - the medical data code sets adopted by the Secretary; their use is the § 162.1000 rows",
	"162.1011": "Subpart J - code set validity dates (definition)",
	"162.1101, 162.1201, 162.1301, 162.1401, 162.1501, 162.1601, 162.1701, 162.1801, 162.1901": "Subparts K-S - definitions of each transaction",
	"162.1102(a)-(b), 162.1202(a)-(b), 162.1302(a)-(b), 162.1402(a)-(b), 162.1502(a)-(b), 162.1602(a)-(c), 162.1702(a)-(b), 162.1802(a)-(b)": "Subparts K-R - standards for periods that ended on or before December 31, 2013",
}

# Dated obligations printed in the 2025 edition that are not yet in force on 2026-10-13 (reported, not evaluated).
dated_obligations := {
	"162.1102(e)": "2027-08-14 - claims: NCPDP F6 / Batch 15 added alongside the (c)-(d) standards (dual use until 2028-04-14)",
	"162.1102(f)": "2028-04-14 - claims: the (e)(2) standards only",
	"162.1202(d)": "2027-08-14 - eligibility: NCPDP F6 / Batch 15 added alongside (c)",
	"162.1202(e)": "2028-04-14 - eligibility: the (d)(2) standards only",
	"162.1302(e)": "2027-08-14 - referral certification and authorization: NCPDP F6 / Batch 15 added alongside (c)-(d)",
	"162.1302(f)": "2028-04-14 - referral certification and authorization: the (e)(2) standards only",
	"162.1802(e)": "2027-08-14 - coordination of benefits: NCPDP F6 / Batch 15 added alongside (c)-(d)",
	"162.1802(f)": "2028-04-14 - coordination of benefits: the (e)(2) standards only",
	"162.1902(b)": "2027-08-14 - Medicaid pharmacy subrogation: NCPDP Subrogation Batch Standard v10 added alongside (a)",
	"162.1902(c)": "2028-04-14 - Medicaid pharmacy subrogation: the paragraph (b) standard (the 2025 text says \"paragraph (b)\", which includes (b)(1))",
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
	msg := sprintf("HIPAA Part 162 Input Contract: %v (input.hipaa.scope.%v undeclared)", [text, k])
}

violations contains "HIPAA Part 162 Input Contract: FAIL-CLOSED - input.hipaa.scope declares no regulated role (health_plan, health_care_provider, health_care_clearinghouse or business_associate true); applicability under 45 CFR 160.102 cannot be established" if {
	count({k | some k in _roles; _scope[k] == true}) == 0
}

_attestations := a if {
	a := object.get(input, ["hipaa", "part_162"], null)
	is_object(a)
}

violations contains "HIPAA Part 162: FAIL-CLOSED - attestations 'input.hipaa.part_162' were not supplied (or are not an object); this module cannot be evaluated and is reported non-compliant" if {
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

else := sprintf("not attested - input.hipaa.part_162[\"%v\"] must be true", [id])

violations contains msg if {
	some id, r in applicable
	not _satisfied(id)
	msg := sprintf("HIPAA %v %v (%v): %v", [id, r.title, r.status, _unmet(id)])
}

violations contains msg if {
	some id, _ in _attestations
	not obligations[id]
	msg := sprintf("HIPAA Part 162 Input Contract: attestation for unknown id %v - ids are the 45 CFR citations this module carries, for example 162.923(a)", [id])
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
	"standard": "45 CFR Part 162",
	"source": source,
	"compliant": compliant,
	"id_scheme": "45 CFR paragraph citation, e.g. 162.923(a)",
	"controls_total": count(obligations),
	"standard_total": 43, # 45 CFR Part 162: obligation paragraphs binding covered entities / business associates
	"attested": count(obligations),
	"applicable": _n_applicable,
	"satisfied": _n_satisfied,
	"subparts": section_reports,
	"obligations": row_status,
	"out_of_scope": out_of_scope,
	"dated_obligations": dated_obligations,
	"violation_count": count(violations),
	"violations": violations,
}
