# FTC Identity Theft Red Flags Rule (16 CFR Part 681, § 681.1) and FACTA Disposal Rule (16 CFR Part 682, § 682.3).
# One attested row per obligation paragraph.
#
# Source of truth: GovInfo bulk CFR XML, annual edition, Title 16 Parts 0 to 999, "Revised as of January 1, 2026"
# (the latest annual edition for Title 16),
#   https://www.govinfo.gov/bulkdata/CFR/2026/title-16/CFR-2026-title16-vol1.xml
#   sha256 3a5809bc55a3be5a4ef5adafc778d09323ba2a601f8008f367982c86a10e98ed, retrieved 2026-10-14.
# Cross-checked against the previous edition (revised as of January 1, 2025,
#   https://www.govinfo.gov/bulkdata/CFR/2025/title-16/CFR-2025-title16-vol1.xml
#   sha256 fbaf04e9bb41f1a8598a9f8f93091f68b5f468b50e4bf481a52abfc64982b3a9): Parts 681 and 682 are identical.
# CFR text is public domain. Every row id is the paragraph designation and every `text`/`lead` string, and every
# string in the guideline/example data tables, is copied verbatim from that edition (checked by substring match
# against the whitespace-normalised source).
#
# Rows (12): § 681.1 (c), (d)(1), (d)(2)(i)–(iv), (e)(1)–(4), (f) = 11; § 682.3(a) = 1.
# Data, not rows: Appendix A to Part 681 (Interagency Guidelines, sections I–VII — "should"/"may" guidance that
# § 681.1(f) requires the institution to consider; carried as the lead sentence of each section/paragraph in
# `appendix_a_guidelines`), Supplement A to Appendix A (26 illustrative Red Flag examples, lead sentence of each, in
# `appendix_a_supplement_a_examples`), and § 682.3(b)(1)–(5) (stated by the rule to be "illustrative only and ...
# not exclusive or exhaustive", in `disposal_examples`).
# Not rows (out of scope): § 681.1(a)–(b) (scope, definitions); § 681.2 (duties of card issuers regarding changes
# of address — outside the § 681.1 program duties named for this module); §§ 682.1, 682.2, 682.4, 682.5
# (definitions, purpose and scope, relation to other laws, effective date).
# Judgement calls:
#   - § 681.1(c) (periodic determination whether covered accounts are offered or maintained, with a risk
#     assessment) applies by its text to every financial institution or creditor in scope, including one that
#     concludes it has no covered accounts. With the single gate
#     is_financial_institution_or_creditor_with_covered_accounts, a false gate also turns off (c); an institution
#     declaring false is expected to have reached that conclusion by performing (c).
#   - § 681.1(e)(4) (oversight of service provider arrangements) is not gated on having service providers.
#
# Gates: input.ftc_red_flags.is_financial_institution_or_creditor_with_covered_accounts (§ 681.1 rows) and
# input.ftc_red_flags.possesses_consumer_report_information (§ 682.3 row) must each be declared true or false.
# Attestation: input.ftc_red_flags.obligations["681.1(d)(2)(i)"] == true.
# Fail-closed: a missing or non-object obligations container is a FAIL-CLOSED violation; an undeclared gate, a
# non-true attestation of an applicable row, and an unknown id are violations. Rollup per section.
#
# Query: POST /v1/data/ftc_red_flags/main/compliance_report

# METADATA
# title: "FTC Identity Theft Red Flags Rule (16 CFR 681.1) and Disposal Rule (16 CFR 682.3) — obligations attested"
# custom:
#   class: compliance
#   framework: ftc_red_flags
#   source: ftc
#   domains: [financial, privacy, us-federal]
#   coverage:
#     checks: 16
#     cited: 12
#     expected: 12
#     found: 12
#     scope: directory
#     density: full
#     basis: declared-total
#     tested: true
#     entrypoint: compliance_report
#     guard: self
#     as_of: v2.4.2
package ftc_red_flags.main

import rego.v1

default compliant := false

compliant if {
	count(violations) == 0
}

source := {
	"cfr_edition": "Title 16 Parts 0 to 999, revised as of January 1, 2026",
	"cfr_url": "https://www.govinfo.gov/bulkdata/CFR/2026/title-16/CFR-2026-title16-vol1.xml",
	"cfr_sha256": "3a5809bc55a3be5a4ef5adafc778d09323ba2a601f8008f367982c86a10e98ed",
	"previous_edition_sha256": "fbaf04e9bb41f1a8598a9f8f93091f68b5f468b50e4bf481a52abfc64982b3a9",
	"retrieved": "2026-10-14",
}

sections := {
	"681.1": {"title": "Duties regarding the detection, prevention, and mitigation of identity theft", "gate": "is_financial_institution_or_creditor_with_covered_accounts"},
	"682.3": {"title": "Proper disposal of consumer information", "gate": "possesses_consumer_report_information"},
}

_gates := {
	"is_financial_institution_or_creditor_with_covered_accounts": "16 CFR 681.1 — whether the entity is a financial institution or creditor (subject to FTC FCRA enforcement) that offers or maintains covered accounts must be declared true or false",
	"possesses_consumer_report_information": "16 CFR 682.3 — whether the entity maintains or otherwise possesses consumer information (consumer reports or information derived from them) for a business purpose must be declared true or false",
}

_lead_d2 := "The Program must include reasonable policies and procedures to:"

_lead_e := "Each financial institution or creditor that is required to implement a Program must provide for the continued administration of the Program and must:"

obligations_list := [
	# ── § 681.1 Identity Theft Prevention Program ────────────────────────────
	{"id": "681.1(c)", "section": "681.1", "lead": "Periodic Identification of Covered Accounts.", "text": "Each financial institution or creditor must periodically determine whether it offers or maintains covered accounts. As a part of this determination, a financial institution or creditor must conduct a risk assessment to determine whether it offers or maintains covered accounts described in paragraph (b)(3)(ii) of this section, taking into consideration: (1) The methods it provides to open its accounts; (2) The methods it provides to access its accounts; and (3) Its previous experiences with identity theft."},
	{"id": "681.1(d)(1)", "section": "681.1", "lead": "Program requirement.", "text": "Each financial institution or creditor that offers or maintains one or more covered accounts must develop and implement a written Identity Theft Prevention Program (Program) that is designed to detect, prevent, and mitigate identity theft in connection with the opening of a covered account or any existing covered account. The Program must be appropriate to the size and complexity of the financial institution or creditor and the nature and scope of its activities."},
	{"id": "681.1(d)(2)(i)", "section": "681.1", "lead": _lead_d2, "text": "Identify relevant Red Flags for the covered accounts that the financial institution or creditor offers or maintains, and incorporate those Red Flags into its Program;"},
	{"id": "681.1(d)(2)(ii)", "section": "681.1", "lead": _lead_d2, "text": "Detect Red Flags that have been incorporated into the Program of the financial institution or creditor;"},
	{"id": "681.1(d)(2)(iii)", "section": "681.1", "lead": _lead_d2, "text": "Respond appropriately to any Red Flags that are detected pursuant to paragraph (d)(2)(ii) of this section to prevent and mitigate identity theft; and"},
	{"id": "681.1(d)(2)(iv)", "section": "681.1", "lead": _lead_d2, "text": "Ensure the Program (including the Red Flags determined to be relevant) is updated periodically, to reflect changes in risks to customers and to the safety and soundness of the financial institution or creditor from identity theft."},
	{"id": "681.1(e)(1)", "section": "681.1", "lead": _lead_e, "text": "Obtain approval of the initial written Program from either its board of directors or an appropriate committee of the board of directors;"},
	{"id": "681.1(e)(2)", "section": "681.1", "lead": _lead_e, "text": "Involve the board of directors, an appropriate committee thereof, or a designated employee at the level of senior management in the oversight, development, implementation and administration of the Program;"},
	{"id": "681.1(e)(3)", "section": "681.1", "lead": _lead_e, "text": "Train staff, as necessary, to effectively implement the Program; and"},
	{"id": "681.1(e)(4)", "section": "681.1", "lead": _lead_e, "text": "Exercise appropriate and effective oversight of service provider arrangements."},
	{"id": "681.1(f)", "section": "681.1", "lead": "Guidelines.", "text": "Each financial institution or creditor that is required to implement a Program must consider the guidelines in appendix A of this part and include in its Program those guidelines that are appropriate."},
	# ── § 682.3 Proper disposal of consumer information ──────────────────────
	{"id": "682.3(a)", "section": "682.3", "lead": "Standard.", "text": "Any person who maintains or otherwise possesses consumer information for a business purpose must properly dispose of such information by taking reasonable measures to protect against unauthorized access to or use of the information in connection with its disposal."},
]

obligations := {r.id: r | some r in obligations_list}

# Appendix A to Part 681 — Interagency Guidelines (data for § 681.1(f); lead sentence of each section/paragraph)
appendix_a_guidelines := {
	"I": "In designing its Program, a financial institution or creditor may incorporate, as appropriate, its existing policies, procedures, and other arrangements that control reasonably foreseeable risks to customers or to the safety and soundness of the financial institution or creditor from identity theft.",
	"II(a)": "A financial institution or creditor should consider the following factors in identifying relevant Red Flags for covered accounts, as appropriate:",
	"II(b)": "Financial institutions and creditors should incorporate relevant Red Flags from sources such as:",
	"II(c)": "The Program should include relevant Red Flags from the following categories, as appropriate.",
	"III": "The Program's policies and procedures should address the detection of Red Flags in connection with the opening of covered accounts and existing covered accounts, such as by:",
	"IV": "The Program's policies and procedures should provide for appropriate responses to the Red Flags the financial institution or creditor has detected that are commensurate with the degree of risk posed.",
	"V": "Financial institutions and creditors should update the Program (including the Red Flags determined to be relevant) periodically, to reflect changes in risks to customers or to the safety and soundness of the financial institution or creditor from identity theft, based on factors such as:",
	"VI(a)": "Oversight by the board of directors, an appropriate committee of the board, or a designated employee at the level of senior management should include:",
	"VI(b)": "Staff of the financial institution or creditor responsible for development, implementation, and administration of its Program should report to the board of directors, an appropriate committee of the board, or a designated employee at the level of senior management, at least annually, on compliance by the financial institution or creditor with § 681.1 of this part.",
	"VI(c)": "Whenever a financial institution or creditor engages a service provider to perform an activity in connection with one or more covered accounts the financial institution or creditor should take steps to ensure that the activity of the service provider is conducted in accordance with reasonable policies and procedures designed to detect, prevent, and mitigate the risk of identity theft.",
	"VII": "Financial institutions and creditors should be mindful of other related legal requirements that may be applicable, such as:",
}

# Supplement A to Appendix A — illustrative Red Flag examples (lead sentence of each)
appendix_a_supplement_a_examples := {
	"1": "A fraud or active duty alert is included with a consumer report.",
	"2": "A consumer reporting agency provides a notice of credit freeze in response to a request for a consumer report.",
	"3": "A consumer reporting agency provides a notice of address discrepancy, as defined in § 641.1(b) of this part.",
	"4": "A consumer report indicates a pattern of activity that is inconsistent with the history and usual pattern of activity of an applicant or customer, such as:",
	"5": "Documents provided for identification appear to have been altered or forged.",
	"6": "The photograph or physical description on the identification is not consistent with the appearance of the applicant or customer presenting the identification.",
	"7": "Other information on the identification is not consistent with information provided by the person opening a new covered account or customer presenting the identification.",
	"8": "Other information on the identification is not consistent with readily accessible information that is on file with the financial institution or creditor, such as a signature card or a recent check.",
	"9": "An application appears to have been altered or forged, or gives the appearance of having been destroyed and reassembled.",
	"10": "Personal identifying information provided is inconsistent when compared against external information sources used by the financial institution or creditor.",
	"11": "Personal identifying information provided by the customer is not consistent with other personal identifying information provided by the customer.",
	"12": "Personal identifying information provided is associated with known fraudulent activity as indicated by internal or third-party sources used by the financial institution or creditor.",
	"13": "Personal identifying information provided is of a type commonly associated with fraudulent activity as indicated by internal or third-party sources used by the financial institution or creditor.",
	"14": "The SSN provided is the same as that submitted by other persons opening an account or other customers.",
	"15": "The address or telephone number provided is the same as or similar to the address or telephone number submitted by an unusually large number of other persons opening accounts or by other customers.",
	"16": "The person opening the covered account or the customer fails to provide all required personal identifying information on an application or in response to notification that the application is incomplete.",
	"17": "Personal identifying information provided is not consistent with personal identifying information that is on file with the financial institution or creditor.",
	"18": "For financial institutions and creditors that use challenge questions, the person opening the covered account or the customer cannot provide authenticating information beyond that which generally would be available from a wallet or consumer report.",
	"19": "Shortly following the notice of a change of address for a covered account, the institution or creditor receives a request for a new, additional, or replacement card or a cell phone, or for the addition of authorized users on the account.",
	"20": "A new revolving credit account is used in a manner commonly associated with known patterns of fraud.",
	"21": "A covered account is used in a manner that is not consistent with established patterns of activity on the account.",
	"22": "A covered account that has been inactive for a reasonably lengthy period of time is used (taking into consideration the type of account, the expected pattern of usage and other relevant factors).",
	"23": "Mail sent to the customer is returned repeatedly as undeliverable although transactions continue to be conducted in connection with the customer's covered account.",
	"24": "The financial institution or creditor is notified that the customer is not receiving paper account statements.",
	"25": "The financial institution or creditor is notified of unauthorized charges or transactions in connection with a customer's covered account.",
	"26": "The financial institution or creditor is notified by a customer, a victim of identity theft, a law enforcement authority, or any other person that it has opened a fraudulent account for a person engaged in identity theft.",
}

# § 682.3(b) — illustrative examples of reasonable disposal measures (not rows)
disposal_examples := {
	"682.3(b)(1)": "Implementing and monitoring compliance with policies and procedures that require the burning, pulverizing, or shredding of papers containing consumer information so that the information cannot practicably be read or reconstructed.",
	"682.3(b)(2)": "Implementing and monitoring compliance with policies and procedures that require the destruction or erasure of electronic media containing consumer information so that the information cannot practicably be read or reconstructed.",
	"682.3(b)(3)": "After due diligence, entering into and monitoring compliance with a contract with another party engaged in the business of record destruction to dispose of material, specifically identified as consumer information, in a manner consistent with this rule.",
	"682.3(b)(4)": "For persons or entities who maintain or otherwise possess consumer information through their provision of services directly to a person subject to this part, implementing and monitoring compliance with policies and procedures that protect against unauthorized or unintentional disposal of consumer information, and disposing of such information in accordance with examples (b)(1) and (2) of this section.",
	"682.3(b)(5)": "For persons subject to the Gramm-Leach-Bliley Act, 15 U.S.C. 6081 et seq., and the Federal Trade Commission's Standards for Safeguarding Customer Information, 16 CFR part 314 (“Safeguards Rule”), incorporating the proper disposal of consumer information as required by this rule into the information security program required by the Safeguards Rule.",
}

_in := object.get(input, "ftc_red_flags", {})

_given := g if {
	g := _in.obligations
	is_object(g)
}

_supplied if _given

_true(id) if _given[id] == true

_gate_on(s) if _in[sections[s].gate] == true

violations contains "FTC Red Flags/Disposal Rules: FAIL-CLOSED - attestations 'input.ftc_red_flags.obligations' were not supplied (or are not an object); this module cannot be evaluated and is reported non-compliant" if {
	not _supplied
}

violations contains msg if {
	some key, text in _gates
	not _in[key] == true
	not _in[key] == false
	msg := sprintf("%v (ftc_red_flags.%v undeclared)", [text, key])
}

applicable[id] := r if {
	some id, r in obligations
	_gate_on(r.section)
}

violations contains msg if {
	some id, r in applicable
	not _true(id)
	msg := sprintf("16 CFR %v (%v): not attested — %v", [id, sections[r.section].title, r.text])
}

violations contains msg if {
	some id, _ in _given
	not obligations[id]
	msg := sprintf("FTC Red Flags/Disposal Input Contract: attestation for unknown id %v — ids are paragraphs such as 681.1(d)(2)(i) or 682.3(a)", [id])
}

section_rollup[s] := r if {
	some s, c in sections
	ids := {id | some id, q in obligations; q.section == s}
	app := {id | some id in ids; applicable[id]}
	ok := {id | some id in app; _true(id)}
	r := {
		"title": c.title,
		"applies": object.get(_in, c.gate, "undeclared"),
		"rows_total": count(ids),
		"rows_evaluated": count(app),
		"rows_attested": count(ok),
		"gaps": sort([id | some id in app; not id in ok]),
	}
}

compliance_report := {
	"framework": "FTC Identity Theft Red Flags Rule and Disposal Rule",
	"standard": "16 CFR 681.1 and 682.3 (Title 16 revised as of January 1, 2026)",
	"source": source,
	"gates": {k: object.get(_in, k, "undeclared") | some k, _ in _gates},
	"standard_total": 12,
	"rows_evaluated": count(applicable),
	"rows_attested": count([id | some id, _ in applicable; _true(id)]),
	"sections": section_rollup,
	"compliant": compliant,
	"violation_count": count(violations),
	"violations": violations,
}
