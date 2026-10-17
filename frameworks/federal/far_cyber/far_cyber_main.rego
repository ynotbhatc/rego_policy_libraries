# FAR cybersecurity contract clauses — contractor obligations of three FAR Part 52 clauses:
#   52.204-21 Basic Safeguarding of Covered Contractor Information Systems (NOV 2021)
#   52.204-25 Prohibition on Contracting for Certain Telecommunications and Video Surveillance Services
#             or Equipment (NOV 2021)
#   52.204-27 Prohibition on a ByteDance Covered Application (JUN 2023)
#
# Source of truth: GovInfo bulk CFR XML, annual edition, Title 48 Chapter 1 (Parts 52 to 99), "Revised as of
# October 1, 2025" (latest annual edition published for Title 48 on 2026-10-14; no 2026 Title 48 volume yet),
#   https://www.govinfo.gov/bulkdata/CFR/2025/title-48/CFR-2025-title48-vol2.xml
#   sha256 ffc15d12857409141954ac983f4a17f385aac3852c4affebc5394a285b92d49e, retrieved 2026-10-14.
# Currency check against acquisition.gov (FAC 2026-01, effective 2026-03-13), retrieved 2026-10-14: the clause
# dates are unchanged (NOV 2021, NOV 2021, JUN 2023) and the obligation paragraphs are substantively identical
# (differences only in capitalisation, punctuation and typography: e.g. "The contract number" vs "the contract
# number" in (d)(2)(i), a missing colon after "(d)(1) of this clause", "Web sites" vs "websites", straight vs
# curly apostrophes), so the CFR annual edition is the source and acquisition.gov was not used for row text:
#   https://www.acquisition.gov/far/52.204-21  sha256 3ec3ee8f9f053ebde3afa97f1b0680ff29ebf72f849da335f43b703b1e7a52bb
#   https://www.acquisition.gov/far/52.204-25  sha256 ef683bab724b7fb17b11ef5defbe6fc0db91d0a8bad581b86b3593201aca3d7e
#   https://www.acquisition.gov/far/52.204-27  sha256 342371ef1ffbe7583e4ef4e5e657eb9ccbf4de9f0d3604fb4fb5a977e8d7d3d4
# FAR text is public domain. Every row id is the clause paragraph designation and every `text`/`lead` string is
# copied verbatim from the CFR edition (checked by substring match against the whitespace-normalised source).
#
# Rows (24): 52.204-21 (b)(1)(i)–(xv) and (c) = 16; 52.204-25 (b)(1), (b)(2), (d)(1), (d)(2)(i), (d)(2)(ii), (e)
# = 6; 52.204-27 (b), (c) = 2.
# Not rows (out of scope): definitions (a) of each clause; 52.204-21(b)(2) (states that the clause does not relieve
# other safeguarding requirements, e.g. CUI under EO 13556 — no duty of its own); 52.204-25(c) (exceptions, not a
# duty); 52.204-25 "representation" — the clause has no representation paragraph: the offeror representations
# are in the provisions 52.204-24(d) and 52.204-26(c), which are solicitation provisions and not modelled here.
# Judgement calls: 52.204-25(b)(2) is worded as a prohibition on the agency (section 889(a)(1)(B)); it is carried
# as a contractor row because it is what the contractor must not do (use covered telecommunications equipment or
# services, whether or not in performance of the contract) and it is the basis of the 52.204-24/-26
# representations. 52.204-25(e) flow-down excludes (b)(2), per the clause text.
#
# Gates: input.far_cyber.contract_includes_52_204_21 / _25 / _27 must each be declared true or false; a clause
# whose gate is false is not evaluated. Attestation: input.far_cyber.requirements["52.204-21(b)(1)(i)"] == true.
# Fail-closed: a missing or non-object requirements container is a FAIL-CLOSED violation; an undeclared gate, a
# non-true attestation of an applicable row, and an unknown id are violations. Rollup per clause.
#
# Query: POST /v1/data/far_cyber/main/compliance_report

# METADATA
# title: "FAR cyber clauses 52.204-21, 52.204-25, 52.204-27 — contractor obligations, attested"
# custom:
#   class: compliance
#   framework: far_cyber
#   source: us-federal
#   domains: [us-federal, supply-chain]
#   coverage:
#     checks: 28
#     cited: 24
#     expected: 24
#     found: 24
#     scope: directory
#     density: full
#     basis: declared-total
#     tested: true
#     entrypoint: compliance_report
#     guard: self
#     as_of: v2.4.2
package far_cyber.main

import rego.v1

default compliant := false

compliant if {
	count(violations) == 0
}

source := {
	"cfr_edition": "Title 48 Chapter 1 (Parts 52 to 99), revised as of October 1, 2025",
	"cfr_url": "https://www.govinfo.gov/bulkdata/CFR/2025/title-48/CFR-2025-title48-vol2.xml",
	"cfr_sha256": "ffc15d12857409141954ac983f4a17f385aac3852c4affebc5394a285b92d49e",
	"currency_check": "acquisition.gov FAC 2026-01 (effective 2026-03-13): clause dates unchanged",
	"retrieved": "2026-10-14",
}

sections := {
	"52.204-21": {"title": "Basic Safeguarding of Covered Contractor Information Systems", "clause_date": "NOV 2021", "gate": "contract_includes_52_204_21"},
	"52.204-25": {"title": "Prohibition on Contracting for Certain Telecommunications and Video Surveillance Services or Equipment", "clause_date": "NOV 2021", "gate": "contract_includes_52_204_25"},
	"52.204-27": {"title": "Prohibition on a ByteDance Covered Application", "clause_date": "JUN 2023", "gate": "contract_includes_52_204_27"},
}

_gates := {
	"contract_includes_52_204_21": "FAR 52.204-21 — whether the contract includes clause 52.204-21 must be declared true or false",
	"contract_includes_52_204_25": "FAR 52.204-25 — whether the contract includes clause 52.204-25 must be declared true or false",
	"contract_includes_52_204_27": "FAR 52.204-27 — whether the contract includes clause 52.204-27 must be declared true or false",
}

notification_clocks := {
	"52.204-25(d)(2)(i)": "Within one business day from the date of such identification or notification",
	"52.204-25(d)(2)(ii)": "Within 10 business days of submitting the information in paragraph (d)(2)(i) of this clause",
}

_lead_21 := "The Contractor shall apply the following basic safeguarding requirements and procedures to protect covered contractor information systems."

requirements_list := [
	# ── 52.204-21 (b)(1) Safeguarding requirements and procedures ───────────
	{"id": "52.204-21(b)(1)(i)", "section": "52.204-21", "lead": _lead_21, "text": "Limit information system access to authorized users, processes acting on behalf of authorized users, or devices (including other information systems)."},
	{"id": "52.204-21(b)(1)(ii)", "section": "52.204-21", "lead": _lead_21, "text": "Limit information system access to the types of transactions and functions that authorized users are permitted to execute."},
	{"id": "52.204-21(b)(1)(iii)", "section": "52.204-21", "lead": _lead_21, "text": "Verify and control/limit connections to and use of external information systems."},
	{"id": "52.204-21(b)(1)(iv)", "section": "52.204-21", "lead": _lead_21, "text": "Control information posted or processed on publicly accessible information systems."},
	{"id": "52.204-21(b)(1)(v)", "section": "52.204-21", "lead": _lead_21, "text": "Identify information system users, processes acting on behalf of users, or devices."},
	{"id": "52.204-21(b)(1)(vi)", "section": "52.204-21", "lead": _lead_21, "text": "Authenticate (or verify) the identities of those users, processes, or devices, as a prerequisite to allowing access to organizational information systems."},
	{"id": "52.204-21(b)(1)(vii)", "section": "52.204-21", "lead": _lead_21, "text": "Sanitize or destroy information system media containing Federal Contract Information before disposal or release for reuse."},
	{"id": "52.204-21(b)(1)(viii)", "section": "52.204-21", "lead": _lead_21, "text": "Limit physical access to organizational information systems, equipment, and the respective operating environments to authorized individuals."},
	{"id": "52.204-21(b)(1)(ix)", "section": "52.204-21", "lead": _lead_21, "text": "Escort visitors and monitor visitor activity; maintain audit logs of physical access; and control and manage physical access devices."},
	{"id": "52.204-21(b)(1)(x)", "section": "52.204-21", "lead": _lead_21, "text": "Monitor, control, and protect organizational communications (i.e., information transmitted or received by organizational information systems) at the external boundaries and key internal boundaries of the information systems."},
	{"id": "52.204-21(b)(1)(xi)", "section": "52.204-21", "lead": _lead_21, "text": "Implement subnetworks for publicly accessible system components that are physically or logically separated from internal networks."},
	{"id": "52.204-21(b)(1)(xii)", "section": "52.204-21", "lead": _lead_21, "text": "Identify, report, and correct information and information system flaws in a timely manner."},
	{"id": "52.204-21(b)(1)(xiii)", "section": "52.204-21", "lead": _lead_21, "text": "Provide protection from malicious code at appropriate locations within organizational information systems."},
	{"id": "52.204-21(b)(1)(xiv)", "section": "52.204-21", "lead": _lead_21, "text": "Update malicious code protection mechanisms when new releases are available."},
	{"id": "52.204-21(b)(1)(xv)", "section": "52.204-21", "lead": _lead_21, "text": "Perform periodic scans of the information system and real-time scans of files from external sources as files are downloaded, opened, or executed."},
	# ── 52.204-21 (c) Subcontracts ──────────────────────────────────────────
	{"id": "52.204-21(c)", "section": "52.204-21", "lead": "Subcontracts.", "text": "The Contractor shall include the substance of this clause, including this paragraph (c), in subcontracts under this contract (including subcontracts for the acquisition of commercial products or commercial services, other than commercially available off-the-shelf items), in which the subcontractor may have Federal contract information residing in or transiting through its information system."},
	# ── 52.204-25 ───────────────────────────────────────────────────────────
	{"id": "52.204-25(b)(1)", "section": "52.204-25", "lead": "Prohibition.", "text": "The Contractor is prohibited from providing to the Government any equipment, system, or service that uses covered telecommunications equipment or services as a substantial or essential component of any system, or as critical technology as part of any system, unless an exception at paragraph (c) of this clause applies or the covered telecommunication equipment or services are covered by a waiver described in FAR 4.2104."},
	{"id": "52.204-25(b)(2)", "section": "52.204-25", "lead": "Section 889(a)(1)(B) of the John S. McCain National Defense Authorization Act for Fiscal Year 2019 (Pub. L. 115-232) prohibits the head of an executive agency on or after August 13, 2020, from entering into a contract, or extending or renewing a contract, with an entity that uses any equipment, system, or service that uses covered telecommunications equipment or services as a substantial or essential component of any system, or as critical technology as part of any system, unless an exception at paragraph (c) of this clause applies or the covered telecommunication equipment or services are covered by a waiver described in FAR 4.2104.", "text": "This prohibition applies to the use of covered telecommunications equipment or services, regardless of whether that use is in performance of work under a Federal contract."},
	{"id": "52.204-25(d)(1)", "section": "52.204-25", "lead": "Reporting requirement.", "text": "In the event the Contractor identifies covered telecommunications equipment or services used as a substantial or essential component of any system, or as critical technology as part of any system, during contract performance, or the Contractor is notified of such by a subcontractor at any tier or by any other source, the Contractor shall report the information in paragraph (d)(2) of this clause to the Contracting Officer, unless elsewhere in this contract are established procedures for reporting the information; in the case of the Department of Defense, the Contractor shall report to the website at https://dibnet.dod.mil. For indefinite delivery contracts, the Contractor shall report to the Contracting Officer for the indefinite delivery contract and the Contracting Officer(s) for any affected order or, in the case of the Department of Defense, identify both the indefinite delivery contract and any affected orders in the report provided at https://dibnet.dod.mil."},
	{"id": "52.204-25(d)(2)(i)", "section": "52.204-25", "lead": "The Contractor shall report the following information pursuant to paragraph (d)(1) of this clause:", "text": "Within one business day from the date of such identification or notification: The contract number; the order number(s), if applicable; supplier name; supplier unique entity identifier (if known); supplier Commercial and Government Entity (CAGE) code (if known); brand; model number (original equipment manufacturer number, manufacturer part number, or wholesaler number); item description; and any readily available information about mitigation actions undertaken or recommended."},
	{"id": "52.204-25(d)(2)(ii)", "section": "52.204-25", "lead": "The Contractor shall report the following information pursuant to paragraph (d)(1) of this clause:", "text": "Within 10 business days of submitting the information in paragraph (d)(2)(i) of this clause: Any further available information about mitigation actions undertaken or recommended. In addition, the Contractor shall describe the efforts it undertook to prevent use or submission of covered telecommunications equipment or services, and any additional efforts that will be incorporated to prevent future use or submission of covered telecommunications equipment or services."},
	{"id": "52.204-25(e)", "section": "52.204-25", "lead": "Subcontracts.", "text": "The Contractor shall insert the substance of this clause, including this paragraph (e) and excluding paragraph (b)(2), in all subcontracts and other contractual instruments, including subcontracts for the acquisition of commercial products or commercial services."},
	# ── 52.204-27 ───────────────────────────────────────────────────────────
	{"id": "52.204-27(b)", "section": "52.204-27", "lead": "Prohibition.", "text": "The Contractor is prohibited from having or using a covered application on any information technology owned or managed by the Government, or on any information technology used or provided by the Contractor under this contract, including equipment provided by the Contractor's employees; however, this prohibition does not apply if the Contracting Officer provides written notification to the Contractor that an exception has been granted in accordance with OMB Memorandum M-23-13."},
	{"id": "52.204-27(c)", "section": "52.204-27", "lead": "Subcontracts.", "text": "The Contractor shall insert the substance of this clause, including this paragraph (c), in all subcontracts, including subcontracts for the acquisition of commercial products or commercial services."},
]

requirements := {r.id: r | some r in requirements_list}

_in := object.get(input, "far_cyber", {})

_given := g if {
	g := _in.requirements
	is_object(g)
}

_supplied if _given

_true(id) if _given[id] == true

_gate_on(s) if _in[sections[s].gate] == true

violations contains "FAR cyber clauses: FAIL-CLOSED - attestations 'input.far_cyber.requirements' were not supplied (or are not an object); this module cannot be evaluated and is reported non-compliant" if {
	not _supplied
}

violations contains msg if {
	some key, text in _gates
	not _in[key] == true
	not _in[key] == false
	msg := sprintf("%v (far_cyber.%v undeclared)", [text, key])
}

applicable[id] := r if {
	some id, r in requirements
	_gate_on(r.section)
}

violations contains msg if {
	some id, r in applicable
	not _true(id)
	msg := sprintf("FAR %v (%v): not attested — %v", [id, sections[r.section].title, r.text])
}

violations contains msg if {
	some id, _ in _given
	not requirements[id]
	msg := sprintf("FAR cyber Input Contract: attestation for unknown id %v — ids are clause paragraphs such as 52.204-21(b)(1)(i)", [id])
}

clause_rollup[s] := r if {
	some s, c in sections
	ids := {id | some id; q := requirements[id]; q.section == s}
	app := {id | some id in ids; applicable[id]}
	ok := {id | some id in app; _true(id)}
	r := {
		"title": c.title,
		"clause_date": c.clause_date,
		"included": object.get(_in, c.gate, "undeclared"),
		"rows_total": count(ids),
		"rows_evaluated": count(app),
		"rows_attested": count(ok),
		"gaps": sort([id | some id in app; not id in ok]),
	}
}

compliance_report := {
	"framework": "FAR cybersecurity clauses (52.204-21, 52.204-25, 52.204-27)",
	"standard": "48 CFR 52.204-21 (NOV 2021), 52.204-25 (NOV 2021), 52.204-27 (JUN 2023) — contractor obligations",
	"source": source,
	"gates": {k: object.get(_in, k, "undeclared") | some k, _ in _gates},
	"notification_clocks": notification_clocks,
	"standard_total": 24,
	"rows_evaluated": count(applicable),
	"rows_attested": count([id | some id; _ = applicable[id]; _true(id)]),
	"clauses": clause_rollup,
	"compliant": compliant,
	"violation_count": count(violations),
	"violations": violations,
}
