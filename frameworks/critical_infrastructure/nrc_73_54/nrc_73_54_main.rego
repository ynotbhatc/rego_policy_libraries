# 10 CFR 73.54 — Protection of digital computer and communication systems and networks
# (NRC cyber security rule for nuclear power reactor licensees). One attested row per paragraph (a)–(h) and
# per enumerated sub-paragraph: 34 rows, every designated paragraph of the section (measured 34, emitted 34).
#
# Source of truth: U.S. Government Publishing Office, Code of Federal Regulations annual edition, bulk XML
#   https://www.govinfo.gov/bulkdata/CFR/2026/title-10/CFR-2026-title10-vol2.xml
#   sha256 209de8e592382a1cff35613f846cdfc63091eeded7a50d96d9c7df563c3c5ad8, Title 10 revised as of
#   January 1, 2026, retrieved 2026-10-14. Public domain (17 U.S.C. 105).
# Cross-checked: the 2025 edition (CFR-2025-title10-vol2.xml, revised as of January 1, 2025,
#   sha256 9d41da8efcdf53f95eddf04b58818b2098229d49675fb623ade84bbd8adb2524) carries identical §73.54 text;
#   eCFR versioner (api/versioner/v1/versions/title-10.json?section=73.54, retrieved 2026-10-14) lists no
#   amendment after 2017-01-01. Section history as printed: [74 FR 13970, Mar. 27, 2009, as amended at 80 FR 67275,
#   Nov. 2, 2015].
# Every id and text string is copied verbatim from that XML by a generator (paragraph designators parsed from
# the text); nothing is paraphrased. Enumerated sub-paragraphs carry their lead-in paragraph verbatim as `stem`.
#
# Not a row (judgement call): the undesignated opening paragraph ("By November 23, 2009 each licensee ... shall
# submit ... a cyber security plan ..."); it is a one-time, dated submission obligation already past, carried as
# data in `dated_obligations` instead. Rows (b), (c), (d) are lead-in paragraphs ("To accomplish this, the
# licensee shall:"); the brief asked for a row per paragraph, so they are kept and attested as a whole.
#
# Input: input.nrc_73_54.paragraphs["73.54(b)(1)"] == true means the licensee's evidence shows that paragraph met.
# Fail-closed: a missing or non-object `paragraphs` container is a FAIL-CLOSED violation; a missing, false or
# non-true value is a violation; an unknown id is a violation. Rollup per paragraph (a)–(h).
#
# Query: POST /v1/data/nrc_73_54/main/compliance_report

# METADATA
# title: "10 CFR 73.54 — NRC cyber security rule for nuclear power reactors, 34 paragraphs attested"
# custom:
#   class: ot
#   framework: nrc_10cfr73_54
#   source: us-federal
#   domains: [ot, energy, critical-infrastructure, us-federal]
#   coverage:
#     checks: 37
#     cited: 36
#     expected: 34
#     found: 36
#     scope: directory
#     density: full
#     basis: declared-total
#     tested: true
#     entrypoint: compliance_report
#     guard: self
#     as_of: v2.4.2
package nrc_73_54.main

import rego.v1

framework := "10 CFR 73.54 — Protection of digital computer and communication systems and networks"

source := {
	"publication": "Code of Federal Regulations, Title 10, §73.54 (annual edition, revised as of January 1, 2026)",
	"url": "https://www.govinfo.gov/bulkdata/CFR/2026/title-10/CFR-2026-title10-vol2.xml",
	"sha256": "209de8e592382a1cff35613f846cdfc63091eeded7a50d96d9c7df563c3c5ad8",
	"edition": "2026-01-01",
	"retrieved": "2026-10-14",
}

sections := {
	"a": "§73.54(a)",
	"b": "§73.54(b)",
	"c": "§73.54(c)",
	"d": "§73.54(d)",
	"e": "§73.54(e)",
	"f": "§73.54(f)",
	"g": "§73.54(g)",
	"h": "§73.54(h)",
}

# the undesignated opening paragraph of §73.54 (not a row; see header)
dated_obligations := {"cyber_security_plan_submission_by_existing_part_50_licensees": "2009-11-23"}

_rows := [
	{"id": "73.54(a)", "s": "a", "gate": "", "stem": "", "text": "Each licensee subject to the requirements of this section shall provide high assurance that digital computer and communication systems and networks are adequately protected against cyber attacks, up to and including the design basis threat as described in § 73.1.", "items": []},
	{"id": "73.54(a)(1)", "s": "a", "gate": "", "stem": "", "text": "The licensee shall protect digital computer and communication systems and networks associated with:", "items": []},
	{"id": "73.54(a)(1)(i)", "s": "a", "gate": "", "stem": "The licensee shall protect digital computer and communication systems and networks associated with:", "text": "Safety-related and important-to-safety functions;", "items": []},
	{"id": "73.54(a)(1)(ii)", "s": "a", "gate": "", "stem": "The licensee shall protect digital computer and communication systems and networks associated with:", "text": "Security functions;", "items": []},
	{"id": "73.54(a)(1)(iii)", "s": "a", "gate": "", "stem": "The licensee shall protect digital computer and communication systems and networks associated with:", "text": "Emergency preparedness functions, including offsite communications; and", "items": []},
	{"id": "73.54(a)(1)(iv)", "s": "a", "gate": "", "stem": "The licensee shall protect digital computer and communication systems and networks associated with:", "text": "Support systems and equipment which, if compromised, would adversely impact safety, security, or emergency preparedness functions.", "items": []},
	{"id": "73.54(a)(2)", "s": "a", "gate": "", "stem": "", "text": "The licensee shall protect the systems and networks identified in paragraph (a)(1) of this section from cyber attacks that would:", "items": []},
	{"id": "73.54(a)(2)(i)", "s": "a", "gate": "", "stem": "The licensee shall protect the systems and networks identified in paragraph (a)(1) of this section from cyber attacks that would:", "text": "Adversely impact the integrity or confidentiality of data and/or software;", "items": []},
	{"id": "73.54(a)(2)(ii)", "s": "a", "gate": "", "stem": "The licensee shall protect the systems and networks identified in paragraph (a)(1) of this section from cyber attacks that would:", "text": "Deny access to systems, services, and/or data; and", "items": []},
	{"id": "73.54(a)(2)(iii)", "s": "a", "gate": "", "stem": "The licensee shall protect the systems and networks identified in paragraph (a)(1) of this section from cyber attacks that would:", "text": "Adversely impact the operation of systems, networks, and associated equipment.", "items": []},
	{"id": "73.54(b)", "s": "b", "gate": "", "stem": "", "text": "To accomplish this, the licensee shall:", "items": []},
	{"id": "73.54(b)(1)", "s": "b", "gate": "", "stem": "To accomplish this, the licensee shall:", "text": "Analyze digital computer and communication systems and networks and identify those assets that must be protected against cyber attacks to satisfy paragraph (a) of this section,", "items": []},
	{"id": "73.54(b)(2)", "s": "b", "gate": "", "stem": "To accomplish this, the licensee shall:", "text": "Establish, implement, and maintain a cyber security program for the protection of the assets identified in paragraph (b)(1) of this section; and", "items": []},
	{"id": "73.54(b)(3)", "s": "b", "gate": "", "stem": "To accomplish this, the licensee shall:", "text": "Incorporate the cyber security program as a component of the physical protection program.", "items": []},
	{"id": "73.54(c)", "s": "c", "gate": "", "stem": "", "text": "The cyber security program must be designed to:", "items": []},
	{"id": "73.54(c)(1)", "s": "c", "gate": "", "stem": "The cyber security program must be designed to:", "text": "Implement security controls to protect the assets identified by paragraph (b)(1) of this section from cyber attacks;", "items": []},
	{"id": "73.54(c)(2)", "s": "c", "gate": "", "stem": "The cyber security program must be designed to:", "text": "Apply and maintain defense-in-depth protective strategies to ensure the capability to detect, respond to, and recover from cyber attacks;", "items": []},
	{"id": "73.54(c)(3)", "s": "c", "gate": "", "stem": "The cyber security program must be designed to:", "text": "Mitigate the adverse affects of cyber attacks; and", "items": []},
	{"id": "73.54(c)(4)", "s": "c", "gate": "", "stem": "The cyber security program must be designed to:", "text": "Ensure that the functions of protected assets identified by paragraph (b)(1) of this section are not adversely impacted due to cyber attacks.", "items": []},
	{"id": "73.54(d)", "s": "d", "gate": "", "stem": "", "text": "As part of the cyber security program, the licensee shall:", "items": []},
	{"id": "73.54(d)(1)", "s": "d", "gate": "", "stem": "As part of the cyber security program, the licensee shall:", "text": "Ensure that appropriate facility personnel, including contractors, are aware of cyber security requirements and receive the training necessary to perform their assigned duties and responsibilities.", "items": []},
	{"id": "73.54(d)(2)", "s": "d", "gate": "", "stem": "As part of the cyber security program, the licensee shall:", "text": "Evaluate and manage cyber risks.", "items": []},
	{"id": "73.54(d)(3)", "s": "d", "gate": "", "stem": "As part of the cyber security program, the licensee shall:", "text": "Ensure that modifications to assets, identified by paragraph (b)(1) of this section, are evaluated before implementation to ensure that the cyber security performance objectives identified in paragraph (a)(1) of this section are maintained.", "items": []},
	{"id": "73.54(d)(4)", "s": "d", "gate": "", "stem": "As part of the cyber security program, the licensee shall:", "text": "Conduct cyber security event notifications in accordance with the provisions of § 73.77.", "items": []},
	{"id": "73.54(e)", "s": "e", "gate": "", "stem": "", "text": "The licensee shall establish, implement, and maintain a cyber security plan that implements the cyber security program requirements of this section.", "items": []},
	{"id": "73.54(e)(1)", "s": "e", "gate": "", "stem": "", "text": "The cyber security plan must describe how the requirements of this section will be implemented and must account for the site-specific conditions that affect implementation.", "items": []},
	{"id": "73.54(e)(2)", "s": "e", "gate": "", "stem": "", "text": "The cyber security plan must include measures for incident response and recovery for cyber attacks. The cyber security plan must describe how the licensee will:", "items": []},
	{"id": "73.54(e)(2)(i)", "s": "e", "gate": "", "stem": "The cyber security plan must include measures for incident response and recovery for cyber attacks. The cyber security plan must describe how the licensee will:", "text": "Maintain the capability for timely detection and response to cyber attacks;", "items": []},
	{"id": "73.54(e)(2)(ii)", "s": "e", "gate": "", "stem": "The cyber security plan must include measures for incident response and recovery for cyber attacks. The cyber security plan must describe how the licensee will:", "text": "Mitigate the consequences of cyber attacks;", "items": []},
	{"id": "73.54(e)(2)(iii)", "s": "e", "gate": "", "stem": "The cyber security plan must include measures for incident response and recovery for cyber attacks. The cyber security plan must describe how the licensee will:", "text": "Correct exploited vulnerabilities; and", "items": []},
	{"id": "73.54(e)(2)(iv)", "s": "e", "gate": "", "stem": "The cyber security plan must include measures for incident response and recovery for cyber attacks. The cyber security plan must describe how the licensee will:", "text": "Restore affected systems, networks, and/or equipment affected by cyber attacks.", "items": []},
	{"id": "73.54(f)", "s": "f", "gate": "", "stem": "", "text": "The licensee shall develop and maintain written policies and implementing procedures to implement the cyber security plan. Policies, implementing procedures, site-specific analysis, and other supporting technical information used by the licensee need not be submitted for Commission review and approval as part of the cyber security plan but are subject to inspection by NRC staff on a periodic basis.", "items": []},
	{"id": "73.54(g)", "s": "g", "gate": "", "stem": "", "text": "The licensee shall review the cyber security program as a component of the physical security program in accordance with the requirements of § 73.55(m), including the periodicity requirements.", "items": []},
	{"id": "73.54(h)", "s": "h", "gate": "", "stem": "", "text": "The licensee shall retain all records and supporting technical documentation required to satisfy the requirements of this section as a record until the Commission terminates the license for which the records were developed, and shall maintain superseded portions of these records for at least three (3) years after the record is superseded, unless otherwise specified by the Commission.", "items": []},
]

paragraphs := {r.id: r | some r in _rows}

default compliant := false

compliant if count(violations) == 0

_in := input.nrc_73_54 if is_object(input.nrc_73_54)

else := {}

_given := a if {
	a := _in.paragraphs
	is_object(a)
}

_supplied if _given

_attested(id) if _given[id] == true

violations contains "10 CFR 73.54: FAIL-CLOSED - attestations 'input.nrc_73_54.paragraphs' were not supplied (or are not an object); this module cannot be evaluated and is reported non-compliant" if {
	not _supplied
}

_gate_open(g) if g == ""

applicable[id] := r if {
	some r in _rows
	_gate_open(r.gate)
	id := r.id
}

violations contains msg if {
	some id, r in applicable
	not _attested(id)
	msg := sprintf("10 CFR 73.54 %v (%v): not attested — %v", [id, sections[r.s], r.text])
}

violations contains msg if {
	some id, _ in _given
	not paragraphs[id]
	msg := sprintf("10 CFR 73.54 Input Contract: unknown id %v — ids are the CFR paragraph citations carried in this module, e.g. 73.54(b)(1)", [id])
}

section_reports[s] := rep if {
	some s, title in sections
	all_ids := [r.id | some r in _rows; r.s == s]
	open_ids := [r.id | some r in _rows; r.s == s; applicable[r.id]]
	rep := {
		"title": title,
		"total": count(all_ids),
		"applicable": count(open_ids),
		"attested": count([id | some id in open_ids; _attested(id)]),
		"gaps": [id | some id in open_ids; not _attested(id)],
	}
}

compliance_report := {
	"framework": framework,
	"source": source,
	"compliant": compliant,
	"standard_total": 34, # designated paragraphs (a)–(h) and enumerated sub-paragraphs of 10 CFR 73.54
	"total_controls": count(_rows),
	"dated_obligations": dated_obligations,
	"evaluated": count(applicable),
	"attested": count([id | some id, _ in applicable; _attested(id)]),
	"sections": section_reports,
	"violation_count": count(violations),
	"violations": violations,
}
