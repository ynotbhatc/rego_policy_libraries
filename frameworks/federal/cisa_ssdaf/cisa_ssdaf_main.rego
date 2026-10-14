# CISA Secure Software Development Attestation Form (the common form under
# OMB M-22-18 as amended by M-23-16). Form "Version 1.0", OMB Control #
# 1670-0052, expiration date 03/31/2027.
#
# Sources (fetched 2026-10-13):
#   https://www.cisa.gov/secure-software-attestation-form (landing page)
#   https://www.cisa.gov/resources-tools/resources/secure-software-development-attestation-form
#     (resource page, revised May 14, 2024)
#   https://www.cisa.gov/sites/default/files/2024-04/Self_Attestation_Common_Form_FINAL_508c.pdf
#     (the form; text taken from the PDF with pdftotext, because the HTML pages
#     do not carry the form content)
#
# Practice level: this form attests against a subset of NIST SP 800-218 (SSDF
# v1.1). The practices themselves are assessed by frameworks/federal/nist_ssdf
# (nist_ssdf.main); each row below carries the SSDF tasks and the EO 14028
# §4(e) subsection the form's Appendix maps it to, as data — the SSDF is not
# restated here. EO 14028 itself: frameworks/federal/eo_14028.
#
# Shape: one control per attestation item in Section III, ids as the form
# numbers them (1a … 1f with 1b(i)/1b(ii) as 1b.i/1b.ii; 2; 3; 4 and 4a–4c),
# plus the unnumbered Section III undertaking to notify agencies (III.notify)
# and the signature requirement (III.signature: CEO or designee, OR an
# attached 3PAO assessment). Item 1 is the lead-in to 1a–1f and is not counted
# on its own. Attested as input.cisa_ssdaf.attestations["1a"] == true.
#
# Scope gates (pages 2–3 and Section I), each MUST be declared true or false:
#   attestation required if ANY of: developed after 2022-09-14; developed before
#   and modified by a major version change after 2022-09-14; continuous changes
#   delivered (SaaS, CI/CD) —
#   and NONE of the product-level exclusions: developed by a Federal agency;
#   open source freely and directly obtained by the agency; freely obtained and
#   publicly available.
# The third exclusion (third-party open source and proprietary components
# incorporated into the end product) is about components, not the product: it
# is reported, not gated, and items 2 and 3 still require the producer's steps
# for third-party components.
#
# Report data, never a pass: Section I attestation kind and type, the signatory,
# and the POA&M path (practices that cannot be attested, mitigations and a
# POA&M submitted to the agency; the agency then requests an OMB extension or
# waiver). A POA&M does not make the report compliant.
#
# Fail-closed: absent or non-object input.cisa_ssdaf is an explicit FAIL-CLOSED
# violation; non-true attestation, unknown id, malformed container or an
# undeclared scope flag are violations.
#
# Query: POST /v1/data/cisa_ssdaf/main/compliance_report

# METADATA
# title: "CISA Secure Software Development Attestation Form v1.0 (OMB 1670-0052) — Section III attestations"
# custom:
#   class: compliance
#   framework: cisa_ssdaf
#   source: cisa
#   domains: [us-federal, secure-development, supply-chain]
#   coverage:
#     checks: 26
#     cited: 21
#     density: sized
#     basis: size
#     tested: true
#     entrypoint: compliance_report
#     guard: self
#     as_of: v2.4.2
package cisa_ssdaf.main

import rego.v1

default compliant := false

compliant if {
	count(violations) == 0
}

sections := {
	"1": "1) Software developed and built in secure environments",
	"2": "2) Trusted source code supply chains",
	"3": "3) Provenance for internal code and third-party components",
	"4": "4) Automated vulnerability checking and remediation",
	"III": "Section III undertakings and signature",
}

_in_scope_flags := {
	"developed_after_2022_09_14": "CISA SSDAF scope 1 — whether the software was developed after September 14, 2022 must be declared true or false",
	"major_version_change_after_2022_09_14": "CISA SSDAF scope 2 — whether software developed before September 14, 2022 was modified by a major version change after that date must be declared true or false",
	"continuous_delivery": "CISA SSDAF scope 3 — whether the producer delivers continuous changes to the software code (SaaS, CI/CD) must be declared true or false",
}

_exclusion_flags := {
	"developed_by_federal_agency": "CISA SSDAF exclusion 1 — whether the software was developed by a Federal agency must be declared true or false",
	"open_source_obtained_directly_by_agency": "CISA SSDAF exclusion 2 — whether the software is open source freely and directly obtained by a Federal agency must be declared true or false",
	"freely_obtained_publicly_available": "CISA SSDAF exclusion 4 — whether the software is freely obtained and publicly available must be declared true or false",
}

_flags := object.union(_in_scope_flags, _exclusion_flags)

# id -> {s, eo: EO 14028 subsection per the form's Appendix, ssdf: related SSDF tasks per the Appendix, text}
attestations := {
	"1a": {"s": "1", "eo": "4e(i)(A)", "ssdf": ["PO.5.1"], "text": "Separating and protecting each environment involved in developing and building software"},
	"1b.i": {"s": "1", "eo": "4e(i)(B)", "ssdf": ["PO.5.1"], "text": "Regularly logging, monitoring, and auditing trust relationships used for authorization and access to any software development and build environments"},
	"1b.ii": {"s": "1", "eo": "4e(i)(B)", "ssdf": ["PO.5.1"], "text": "Regularly logging, monitoring, and auditing trust relationships used for authorization and access among components within each environment"},
	"1c": {"s": "1", "eo": "4e(i)(C)", "ssdf": ["PO.5.1", "PO.5.2"], "text": "Enforcing multi-factor authentication and conditional access across the environments relevant to developing and building software in a manner that minimizes security risk"},
	"1d": {"s": "1", "eo": "4e(i)(D)", "ssdf": ["PO.5.1"], "text": "Taking consistent and reasonable steps to document, as well as minimize use or inclusion of software products that create undue risk within the environments used to develop and build software"},
	"1e": {"s": "1", "eo": "4e(i)(E)", "ssdf": ["PO.5.2"], "text": "Encrypting sensitive data, such as credentials, to the extent practicable and based on risk"},
	"1f": {"s": "1", "eo": "4e(i)(F)", "ssdf": ["PO.3.2", "PO.3.3", "PO.5.1", "PO.5.2"], "text": "Implementing defensive cybersecurity practices, including continuous monitoring of operations and alerts and, as necessary, responding to suspected and confirmed cyber incidents"},
	"2": {"s": "2", "eo": "4e(iii)", "ssdf": ["PO.1.1", "PO.3.1", "PO.3.2", "PO.5.1", "PO.5.2", "PS.1.1", "PS.2.1", "PS.3.1", "PW.4.1", "PW.4.4", "PW.7.1", "PW.8.1", "RV.1.1"], "text": "The software producer makes a good-faith effort to maintain trusted source code supply chains by employing automated tools or comparable processes to address the security of internal code and third-party components and manage related vulnerabilities"},
	"3": {"s": "3", "eo": "4e(vi)", "ssdf": ["PO.1.3", "PO.3.2", "PO.5.1", "PO.5.2", "PS.3.1", "PS.3.2", "PW.4.1", "PW.4.4", "RV.1.1", "RV.1.2"], "text": "The software producer maintains provenance for internal code and third-party components incorporated into the software to the greatest extent feasible"},
	"4": {"s": "4", "eo": "4e(iv)", "ssdf": _ssdf_4, "text": "The software producer employs automated tools or comparable processes that check for security vulnerabilities"},
	"4a": {"s": "4", "eo": "4e(iv)", "ssdf": _ssdf_4, "text": "The software producer operates these processes on an ongoing basis and prior to product, version, or update releases"},
	"4b": {"s": "4", "eo": "4e(iv)", "ssdf": _ssdf_4, "text": "The software producer has a policy or process to address discovered security vulnerabilities prior to product release"},
	"4c": {"s": "4", "eo": "4e(iv)", "ssdf": _ssdf_4, "text": "The software producer operates a vulnerability disclosure program and accepts, reviews, and addresses disclosed software vulnerabilities in a timely fashion and according to any timelines specified in the vulnerability disclosure program or applicable policies"},
	"III.notify": {"s": "III", "eo": "", "ssdf": [], "text": "The software producer will notify any agency to which it has submitted this form if and when the producer ceases to make consistent use of the practices identified above in developing the software"},
	"III.signature": {"s": "III", "eo": "", "ssdf": [], "text": "The form is signed by the CEO of the software producer or a designee who is an employee with authority to bind the corporation, OR a FedRAMP-certified or agency-approved 3PAO assessment of conformance to all elements of the form is attached"},
}

# Item 4 and 4a–4c share one mapping row in the form's Appendix.
_ssdf_4 := ["PO.4.1", "PO.4.2", "PS.1.1", "PW.2.1", "PW.4.4", "PW.5.1", "PW.6.1", "PW.6.2", "PW.7.1", "PW.7.2", "PW.8.2", "PW.9.1", "PW.9.2", "RV.1.1", "RV.1.2", "RV.1.3", "RV.2.1", "RV.2.2", "RV.3.3"]

_in := object.get(input, "cisa_ssdaf", {})

_supplied if is_object(input.cisa_ssdaf)

violations contains msg if {
	not _supplied
	msg := "CISA SSDAF: FAIL-CLOSED - facts 'input.cisa_ssdaf' were not supplied (or are not an object); this module cannot be evaluated and is reported non-compliant"
}

_scope := object.get(_in, "scope", {})

violations contains msg if {
	some key, text in _flags
	not _scope[key] == true
	not _scope[key] == false
	msg := sprintf("%v (cisa_ssdaf.scope.%v undeclared)", [text, key])
}

_scope_declared if {
	every key, _ in _flags {
		is_boolean(_scope[key])
	}
}

_excluded if {
	some key, _ in _exclusion_flags
	_scope[key] == true
}

_triggered if {
	some key, _ in _in_scope_flags
	_scope[key] == true
}

default attestation_required := false

# Fail-closed: until every scope flag is declared, attestation is required.
attestation_required if not _scope_declared

attestation_required if {
	_scope_declared
	_triggered
	not _excluded
}

applicable[id] := c if {
	attestation_required
	some id, c in attestations
}

_signed if {
	_in.signatory.type in {"ceo", "designee"}
	is_string(_in.signatory.name)
	is_string(_in.signatory.date)
}

_signed if {
	_in.signatory.type == "3pao"
	_in.signatory.assessment_attached == true
}

_attested(id) if {
	id != "III.signature"
	_in.attestations[id] == true
}

_attested("III.signature") if _signed

violations contains msg if {
	some id, c in applicable
	not _attested(id)
	msg := sprintf("CISA SSDAF %v (%v): %v — not attested", [id, sections[c.s], c.text])
}

violations contains msg if {
	some id, _ in _in.attestations
	not attestations[id]
	msg := sprintf("CISA SSDAF Input Contract: attestation for unknown id %v — not an item of Section III", [id])
}

violations contains msg if {
	_in.attestations
	not is_object(_in.attestations)
	msg := "CISA SSDAF Input Contract: input.cisa_ssdaf.attestations must be an object of {\"<item>\": true}"
}

section_reports[s] := r if {
	some s, name in sections
	ids := {id | some id, c in applicable; c.s == s}
	passed := {id | some id in ids; _attested(id)}
	r := {"section": name, "items": count(ids), "attested": count(passed), "gaps": sort([id | some id in ids; not id in passed])}
}

_poam := object.get(_in, "poam", {})

compliance_report := {
	"framework": "CISA Secure Software Development Attestation Form (common form, OMB M-22-18 as amended by M-23-16)",
	"standard": "Secure Software Development Attestation Form Version 1.0 — OMB Control # 1670-0052, expires 03/31/2027",
	"source": "cisa.gov — Self_Attestation_Common_Form_FINAL_508c.pdf (resource page revised May 14, 2024; fetched 2026-10-13)",
	"practice_module": "frameworks/federal/nist_ssdf (nist_ssdf.main) — NIST SP 800-218 v1.1 practices this form attests against",
	"scope": {k: object.get(_scope, k, "undeclared") | some k, _ in _flags},
	"attestation_required": attestation_required,
	"component_exclusion_note": "Third-party open source and proprietary components incorporated into the end product are not covered by the attestation; items 2 and 3 still require the producer's steps for them",
	"section_i": {
		"attestation_kind": object.get(_in, "attestation_kind", "undeclared"),
		"attestation_type": object.get(_in, "attestation_type", "undeclared"),
		"products": object.get(_in, "products", []),
	},
	"signatory": object.get(_in, "signatory", "none"),
	"poam": {
		"submitted": object.get(_poam, "submitted", false) == true,
		"practices_not_attested": object.get(_poam, "practices_not_attested", []),
		"note": "A POA&M lets an agency continue use while it requests an OMB extension or waiver; it is not an attestation and does not make this report compliant",
	},
	"items_total": count(attestations),
	"items_evaluated": count(applicable),
	"items_attested": count([id | some id, _ in applicable; _attested(id)]),
	"sections": section_reports,
	"compliant": compliant,
	"violation_count": count(violations),
	"violations": violations,
}
