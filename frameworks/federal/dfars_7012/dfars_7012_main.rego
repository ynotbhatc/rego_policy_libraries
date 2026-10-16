# DFARS 252.204-7012 — Safeguarding Covered Defense Information and Cyber
# Incident Reporting. Clause date (MAY 2024).
#
# Source: https://www.acquisition.gov/dfars/252.204-7012-safeguarding-covered-defense-information-and-cyber-incident-reporting.
# (the URL ends in a period; the form without it returns 404). Fetched
# 2026-10-13. Page header: "DFARS Change 5/7/2026", effective date
# 05/07/2026. Prescribed at DFARS 204.7304(c).
#
# Shape: one control per contractor obligation sentence in paragraphs (b)–(m),
# cited by paragraph. Attested from the contractor's evidence as
# input.dfars_7012.obligations["c.1.ii"] == true (ids are the
# paragraph designators joined by dots: (b)(2)(ii)(D) -> "b.2.ii.D-fedramp";
# each row carries the clause citation in "cite"). Obligations that apply
# only when the contractor does the thing are gated by flags that MUST be
# declared true or false (fail-closed).
#
# Incident-triggered rows ((c)(1)–(g), (m)(2)(ii)) are attested as the
# procedure or capability being in place; a contractor with no incident to date
# attests true when it can perform them.
#
# NIST SP 800-171 is NOT restated here. (b)(2)(i) requires the security
# requirements of SP 800-171 "in effect at the time the solicitation is issued
# or as authorized by the Contracting Officer" — the clause names no revision.
# Assess the requirements themselves with the library's 800-171 modules:
#   frameworks/federal/nist/sp_800_171/     (nist_800_171.main)
#   frameworks/federal/nist/sp_800_171_r2/  (nist.sp800_171_r2.main)
# Which revision applies is a contract fact (solicitation date / Contracting
# Officer authorization), not something this module decides.
# CMMC (32 CFR Part 170 / DFARS 252.204-7021) is assessed by
# frameworks/federal/cmmc/cmmc_main.rego; this module does not duplicate it.
#
# Not contractor controls, recorded as out of scope in the report:
#   (a)    definitions (the 72-hour meaning of "rapidly report" is cited at (c)(1)(ii))
#   (h)    Government's duty to protect and minimise contractor attributional/
#          proprietary information (the one contractor sentence — identify and
#          mark it — IS a control below)
#   (i)(j) Government release authority for contractor information
#   (l)    non-abrogation of other safeguarding/reporting duties
#
# Dated windows carried in the report as data: rapidly report = within 72
# hours of discovery ((a), (c)(1)(ii)); preserve media and packet capture for
# at least 90 days from the report ((e)); NIST SP 800-171 implementation not
# later than 2017-12-31 and 30-day DoD CIO notice for contracts awarded before
# 2017-10-01 ((b)(2)(ii)(A)).
#
# Fail-closed: absent or non-object input.dfars_7012 is an explicit FAIL-CLOSED
# violation; non-true attestation, unknown id, malformed container or an
# undeclared flag are violations.
#
# Query: POST /v1/data/dfars_7012/main/compliance_report

# METADATA
# title: "DFARS 252.204-7012 (MAY 2024) — Safeguarding Covered Defense Information and Cyber Incident Reporting"
# custom:
#   class: compliance
#   framework: dfars_7012
#   source: dod
#   domains: [us-federal, defense]
#   coverage:
#     checks: 37
#     cited: 34
#     density: sized
#     basis: size
#     tested: true
#     entrypoint: compliance_report
#     guard: self
#     as_of: v2.4.2
package dfars_7012.main

import rego.v1

default compliant := false

compliant if {
	count(violations) == 0
}

sections := {
	"b": "(b) Adequate security",
	"c": "(c) Cyber incident reporting requirement",
	"d": "(d) Malicious software",
	"e": "(e) Media preservation and protection",
	"f": "(f) Access to additional information or equipment necessary for forensic analysis",
	"g": "(g) Cyber incident damage assessment activities",
	"h": "(h) DoD safeguarding and use of contractor attributional/proprietary information",
	"k": "(k) Lawful conduct of activities",
	"m": "(m) Subcontracts",
}

_flags := {
	"operates_it_on_behalf_of_government": "DFARS 252.204-7012(b)(1) — whether any covered contractor information system is part of an IT service or system operated on behalf of the Government must be declared true or false",
	"has_systems_not_operated_for_government": "DFARS 252.204-7012(b)(2) — whether any covered contractor information system is not part of an IT service or system operated on behalf of the Government must be declared true or false",
	"contract_awarded_before_2017_10_01": "DFARS 252.204-7012(b)(2)(ii)(A) — whether the contract was awarded prior to October 1, 2017 must be declared true or false",
	"requests_variance_from_800_171": "DFARS 252.204-7012(b)(2)(ii)(B) — whether the contractor varies, or requests to vary, from any NIST SP 800-171 requirement must be declared true or false",
	"relies_on_prior_dod_cio_adjudication": "DFARS 252.204-7012(b)(2)(ii)(C) — whether the contractor relies on a previous DoD CIO adjudication (nonapplicable or equally effective alternative) must be declared true or false",
	"uses_external_cloud_service_provider": "DFARS 252.204-7012(b)(2)(ii)(D) — whether an external cloud service provider stores, processes or transmits covered defense information must be declared true or false",
	"has_covered_subcontracts": "DFARS 252.204-7012(m) — whether any subcontract is for operationally critical support or involves covered defense information must be declared true or false",
}

# id -> {s: section, gates: flags that must all be true for the obligation to apply, text}
obligations := {
	# ── (b) Adequate security ────────────────────────────────────────────
	"b": {"cite": "(b)", "s": "b", "gates": [], "text": "The Contractor shall provide adequate security on all covered contractor information systems, implementing at a minimum the protections in (b)(1)–(3)"},
	"b.1.i": {"cite": "(b)(1)(i)", "s": "b", "gates": ["operates_it_on_behalf_of_government"], "text": "Cloud computing services operated on behalf of the Government are subject to the security requirements of clause 252.239-7010, Cloud Computing Services"},
	"b.1.ii": {"cite": "(b)(1)(ii)", "s": "b", "gates": ["operates_it_on_behalf_of_government"], "text": "Any other IT service or system operated on behalf of the Government (other than cloud computing) is subject to the security requirements specified elsewhere in the contract"},
	"b.2.i": {"cite": "(b)(2)(i)", "s": "b", "gates": ["has_systems_not_operated_for_government"], "text": "The covered contractor information system is subject to the security requirements in NIST SP 800-171 in effect at the time the solicitation is issued or as authorized by the Contracting Officer (assess with frameworks/federal/nist/sp_800_171)"},
	"b.2.ii.A": {"cite": "(b)(2)(ii)(A)", "s": "b", "gates": ["has_systems_not_operated_for_government"], "text": "The Contractor shall implement NIST SP 800-171 as soon as practical, but not later than December 31, 2017"},
	"b.2.ii.A-notice": {"cite": "(b)(2)(ii)(A), second sentence", "s": "b", "gates": ["has_systems_not_operated_for_government", "contract_awarded_before_2017_10_01"], "text": "For contracts awarded prior to October 1, 2017, the Contractor shall notify the DoD CIO within 30 days of contract award of any NIST SP 800-171 security requirements not implemented at the time of award"},
	"b.2.ii.B": {"cite": "(b)(2)(ii)(B)", "s": "b", "gates": ["has_systems_not_operated_for_government", "requests_variance_from_800_171"], "text": "Requests to vary from NIST SP 800-171 are submitted in writing to the Contracting Officer for consideration by the DoD CIO; only requirements adjudicated by an authorized DoD CIO representative as nonapplicable or with an equally effective alternative are not implemented"},
	"b.2.ii.C": {"cite": "(b)(2)(ii)(C)", "s": "b", "gates": ["has_systems_not_operated_for_government", "relies_on_prior_dod_cio_adjudication"], "text": "Where the DoD CIO has previously adjudicated a requirement as not applicable or an alternative as equally effective, a copy of that approval is provided to the Contracting Officer when requesting its recognition under this contract"},
	"b.2.ii.D-fedramp": {"cite": "(b)(2)(ii)(D), FedRAMP Moderate equivalence", "s": "b", "gates": ["uses_external_cloud_service_provider"], "text": "The Contractor shall require and ensure that an external cloud service provider storing, processing or transmitting covered defense information meets security requirements equivalent to those established by the Government for the FedRAMP Moderate baseline"},
	"b.2.ii.D-c-g": {"cite": "(b)(2)(ii)(D), CSP compliance with (c)–(g)", "s": "b", "gates": ["uses_external_cloud_service_provider"], "text": "The Contractor shall require and ensure that the cloud service provider complies with paragraphs (c) through (g) of the clause: cyber incident reporting, malicious software, media preservation and protection, access for forensic analysis, and cyber incident damage assessment"},
	"b.3": {"cite": "(b)(3)", "s": "b", "gates": [], "text": "Other information systems security measures are applied when the Contractor reasonably determines they may be required to provide adequate security in a dynamic environment, to accommodate special circumstances (e.g., medical devices), or for individual, isolated or temporary deficiencies based on an assessed risk or vulnerability (may be addressed in a system security plan)"},
	# ── (c) Cyber incident reporting ─────────────────────────────────────
	"c.1.i": {"cite": "(c)(1)(i)", "s": "c", "gates": [], "text": "On discovering a cyber incident affecting a covered contractor information system, the covered defense information in it, or the ability to perform operationally critical support, the Contractor conducts a review for evidence of compromise of covered defense information — compromised computers, servers, specific data and user accounts — including other systems on the Contractor's networks that may have been accessed"},
	"c.1.ii": {"cite": "(c)(1)(ii)", "s": "c", "gates": [], "text": "The Contractor rapidly reports cyber incidents to DoD at https://dibnet.dod.mil — \"rapidly report\" means within 72 hours of discovery of any cyber incident ((a))"},
	"c.2": {"cite": "(c)(2)", "s": "c", "gates": [], "text": "The cyber incident report is treated as information created by or for DoD and includes, at a minimum, the required elements at https://dibnet.dod.mil"},
	"c.3": {"cite": "(c)(3)", "s": "c", "gates": [], "text": "The Contractor or subcontractor has or acquires a DoD-approved medium assurance certificate to report cyber incidents"},
	# ── (d)–(g) ──────────────────────────────────────────────────────────
	"d": {"cite": "(d)", "s": "d", "gates": [], "text": "Malicious software discovered and isolated in connection with a reported cyber incident is submitted to the DoD Cyber Crime Center (DC3) in accordance with DC3 or Contracting Officer instructions, and not sent to the Contracting Officer"},
	"e": {"cite": "(e)", "s": "e", "gates": [], "text": "Images of all known affected information systems identified under (c)(1)(i) and all relevant monitoring/packet capture data are preserved and protected for at least 90 days from submission of the cyber incident report"},
	"f": {"cite": "(f)", "s": "f", "gates": [], "text": "Upon request by DoD, the Contractor provides DoD with access to additional information or equipment necessary to conduct a forensic analysis"},
	"g": {"cite": "(g)", "s": "g", "gates": [], "text": "If DoD elects to conduct a damage assessment, the Contractor provides, on the Contracting Officer's request, all of the damage assessment information gathered in accordance with paragraph (e)"},
	# ── (h) the contractor sentence only ─────────────────────────────────
	"h": {"cite": "(h), second sentence", "s": "h", "gates": [], "text": "To the maximum extent practicable, the Contractor identifies and marks attributional/proprietary information"},
	# ── (k) ──────────────────────────────────────────────────────────────
	"k": {"cite": "(k)", "s": "k", "gates": [], "text": "The Contractor conducts activities under the clause in accordance with applicable laws and regulations on the interception, monitoring, access, use and disclosure of electronic communications and data"},
	# ── (m) Subcontracts ─────────────────────────────────────────────────
	"m.1": {"cite": "(m)(1)", "s": "m", "gates": ["has_covered_subcontracts"], "text": "The clause, including paragraph (m), is included without alteration (except to identify the parties) in subcontracts or similar instruments for operationally critical support or whose performance involves covered defense information, including subcontracts for commercial products or commercial services"},
	"m.1-cdi": {"cite": "(m)(1), second sentence", "s": "m", "gates": ["has_covered_subcontracts"], "text": "The Contractor determines whether information required for subcontractor performance retains its identity as covered defense information requiring protection under the clause, consulting the Contracting Officer if necessary"},
	"m.2.i": {"cite": "(m)(2)(i)", "s": "m", "gates": ["has_covered_subcontracts"], "text": "Subcontractors are required to notify the prime Contractor (or next higher-tier subcontractor) when submitting a request to vary from a NIST SP 800-171 requirement to the Contracting Officer under (b)(2)(ii)(B)"},
	"m.2.ii": {"cite": "(m)(2)(ii)", "s": "m", "gates": ["has_covered_subcontracts"], "text": "Subcontractors are required to provide the DoD-assigned incident report number to the prime Contractor (or next higher-tier subcontractor) as soon as practicable when reporting a cyber incident to DoD under (c)"},
}

out_of_scope := {
	"(a)": "Definitions — not an obligation; the 72-hour meaning of \"rapidly report\" is carried at (c)(1)(ii) and in dated_windows",
	"(h)": "Government protection of contractor attributional/proprietary information and minimisation on release — a DoD duty; only the contractor's identify-and-mark sentence is a control",
	"(i)": "Government authority to release contractor information not created by or for DoD — a DoD authority, not a contractor control",
	"(j)": "Government authority to use and release contractor information created by or for DoD — a DoD authority, not a contractor control",
	"(l)": "Non-abrogation: the clause does not relieve other safeguarding or incident-reporting duties — assess those under their own clauses",
}

dated_windows := {
	"rapid_report_hours_from_discovery": 72,
	"media_preservation_days_from_report": 90,
	"sp_800_171_implementation_deadline": "2017-12-31",
	"pre_2017_10_01_award_dod_cio_notice_days": 30,
}

_in := object.get(input, "dfars_7012", {})

_supplied if is_object(input.dfars_7012)

violations contains msg if {
	not _supplied
	msg := "DFARS 252.204-7012: FAIL-CLOSED - facts 'input.dfars_7012' were not supplied (or are not an object); this module cannot be evaluated and is reported non-compliant"
}

violations contains msg if {
	some key, text in _flags
	not _in[key] == true
	not _in[key] == false
	msg := sprintf("%v (dfars_7012.%v undeclared)", [text, key])
}

_gates_open(gates) if {
	every g in gates {
		_in[g] == true
	}
}

applicable[id] := c if {
	some id, c in obligations
	_gates_open(c.gates)
}

_attested(id) if _in.obligations[id] == true

violations contains msg if {
	some id, c in applicable
	not _attested(id)
	msg := sprintf("DFARS 252.204-7012%v (%v): %v — not attested", [c.cite, sections[c.s], c.text])
}

violations contains msg if {
	some id, _ in _in.obligations
	not obligations[id]
	msg := sprintf("DFARS 252.204-7012 Input Contract: attestation for unknown id %v — not a contractor obligation of paragraphs (b)–(m)", [id])
}

violations contains msg if {
	_in.obligations
	not is_object(_in.obligations)
	msg := "DFARS 252.204-7012 Input Contract: input.dfars_7012.obligations must be an object of {\"<id>\": true}, ids as in obligations (e.g. \"c.1.ii\")"
}

section_reports[s] := r if {
	some s, name in sections
	ids := {id | some id; c := applicable[id]; c.s == s}
	passed := {id | some id in ids; _attested(id)}
	r := {"section": name, "obligations": count(ids), "attested": count(passed), "gaps": sort([id | some id in ids; not id in passed])}
}

compliance_report := {
	"framework": "DFARS 252.204-7012 — Safeguarding Covered Defense Information and Cyber Incident Reporting",
	"standard": "DFARS 252.204-7012 (MAY 2024), DFARS Change 5/7/2026, effective 05/07/2026",
	"source": "acquisition.gov/dfars/252.204-7012 (fetched 2026-10-13)",
	"related_modules": {
		"nist_sp_800_171": "frameworks/federal/nist/sp_800_171 and frameworks/federal/nist/sp_800_171_r2 — the (b)(2)(i) requirements themselves, revision per the solicitation or Contracting Officer",
		"cmmc": "frameworks/federal/cmmc — CMMC 2.0 / DFARS 252.204-7021",
	},
	"flags": {k: object.get(_in, k, "undeclared") | some k, _ in _flags},
	"dated_windows": dated_windows,
	"out_of_scope": out_of_scope,
	"obligations_total": count(obligations),
	"obligations_evaluated": count(applicable),
	"obligations_attested": count([id | some id; _ = applicable[id]; _attested(id)]),
	"sections": section_reports,
	"compliant": compliant,
	"violation_count": count(violations),
	"violations": violations,
}
