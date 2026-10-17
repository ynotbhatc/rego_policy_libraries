# Executive Order 14028 of May 12, 2021 — Improving the Nation's Cybersecurity.
# 86 FR 26633 (FR Doc. 2021-10460), published May 17, 2021.
#
# Source (fetched 2026-10-13): Federal Register document 2021-10460.
#   https://www.federalregister.gov/documents/2021/05/17/2021-10460/improving-the-nations-cybersecurity
#   redirected to a bot-check page for both WebFetch and a direct request, and
#   the whitehouse.gov fallback returned 404. The text was taken from the same
#   publisher's record instead:
#   https://www.federalregister.gov/api/v1/documents/2021-10460.json
#   (title, EO number, signing 2021-05-12, publication 2021-05-17, citation)
#   https://www.federalregister.gov/documents/full_text/text/2021/05/17/2021-10460.txt
#   (the GPO full text, Pages 26633-26647).
#   Amendments: the Federal Register record's executive_order_notes read "See:
#   EO 14141, January 14, 2025; EO 14144, January 16, 2025". Nothing beyond that
#   note was researched; this module encodes the text as published on
#   2021-05-17. The page's "amended by" sidebar itself was not seen.
#
# What the order is: a directive to federal agencies. Most sentences task a
# named official (OMB, CISA, NIST, the FAR Council). A sentence that ONLY tasks
# an official is not a control — an agency or supplier cannot attest to it. A
# control is a sentence whose duty an agency (FCEB Agency, or "agencies") or a
# supplier (IT/OT/ICT service provider, software producer) must itself satisfy.
# Where that duty lands on the agency or provider only once an official acts
# (OMB "shall require that agencies comply", contract language "shall be
# designed to ensure that service providers ...", what the playbook or the DHS
# logging recommendations must contain), the row is kept and marked
# "derived": true — 2(c)(i)-(iv), 4(j), 4(k), 4(q), 6(b)(ii), 7(d), 8(b),
# 8(c), 8(e). Controls by section:
#   §2 service-provider sharing and incident reporting (2(c), 2(f)); agency
#      de-duplication (2(k))
#   §3 agency cloud, Zero Trust, data evaluation, MFA and encryption (3(b)–3(d))
#   §4 the supplier-facing secure-development practices of 4(e)(i)–(x) — the
#      part a vendor attests (CISA's common form: frameworks/federal/cisa_ssdaf;
#      practices: frameworks/federal/nist_ssdf); agency duties 4(j), 4(k),
#      4(p), 4(q)
#   §6 agency use of the playbook (6(b)(ii), 6(d))
#   §7 agency EDR and CDM data access (7(b), 7(d), 7(f))
#   §8 logging and log provision (8(a), 8(b), 8(c), 8(e))
# Not controls: the IoT and consumer software labeling pilots of 4(s)–4(w) task
# NIST/Commerce only; §5 (Cyber Safety Review Board) and §9 (National Security
# Systems) are out of the requested scope.
#
# Shape: attested rows, ids are the section and paragraph designators joined by
# dots (3(d)(i) -> "3.d.i"; each row carries the order's citation in "cite").
# Rows are gated by role: is_agency, is_fceb_agency and is_supplier MUST be
# declared true or false (is_fceb_agency true also opens the all-agency rows). Attested as input.eo_14028.directives["3.d"] == true.
#
# Dated windows (days from 2021-05-12) are carried as data in the report.
#
# Fail-closed: absent or non-object input.eo_14028 is an explicit FAIL-CLOSED
# violation; non-true attestation, unknown id, malformed container or an
# undeclared role are violations.
#
# Query: POST /v1/data/eo_14028/main/compliance_report

# METADATA
# title: "Executive Order 14028 (May 12, 2021) — Improving the Nation's Cybersecurity: agency and supplier directives"
# custom:
#   class: compliance
#   framework: eo_14028
#   source: us-federal
#   domains: [us-federal, supply-chain, zero-trust]
#   coverage:
#     checks: 53
#     cited: 50
#     density: sized
#     basis: size
#     tested: true
#     entrypoint: compliance_report
#     guard: self
#     as_of: v2.4.2
package eo_14028.main

import rego.v1

default compliant := false

compliant if {
	count(violations) == 0
}

sections := {
	"2": "Sec. 2 Removing Barriers to Sharing Threat Information",
	"3": "Sec. 3 Modernizing Federal Government Cybersecurity",
	"4": "Sec. 4 Enhancing Software Supply Chain Security",
	"6": "Sec. 6 Standardizing the Federal Government's Playbook for Responding to Cybersecurity Vulnerabilities and Incidents",
	"7": "Sec. 7 Improving Detection of Cybersecurity Vulnerabilities and Incidents on Federal Government Networks",
	"8": "Sec. 8 Improving the Federal Government's Investigative and Remediation Capabilities",
}

_roles := {
	"is_agency": "EO 14028 — whether the attesting organization is an agency within the meaning of 44 U.S.C. 3502 (Sec. 10(a); includes DoD and IC agencies) must be declared true or false",
	"is_fceb_agency": "EO 14028 — whether the attesting organization is a Federal Civilian Executive Branch agency (Sec. 10(d)) must be declared true or false",
	"is_supplier": "EO 14028 — whether the attesting organization is an IT/OT/ICT service provider or software producer supplying agencies must be declared true or false",
}

# id -> {cite, s, derived, role, text (quoted from the order)}
#   role: "fceb" (sentence names FCEB Agencies), "agency" (names agencies / the head
#   of each agency), "supplier", "either" (agencies and their IT service providers)
#   derived: true when the sentence tasks an official (OMB, DHS, the FAR Council)
#   or describes what a playbook/recommendation must contain, and the duty lands
#   on the agency or provider once that official acts
directives := {
	# ── Sec. 2 ───────────────────────────────────────────────────────────
	"2.c.i": {"cite": "2(c)(i)", "s": "2", "derived": true, "role": "supplier", "text": "service providers collect and preserve data, information, and reporting relevant to cybersecurity event prevention, detection, response, and investigation on all information systems over which they have control, including systems operated on behalf of agencies, consistent with agencies' requirements"},
	"2.c.ii": {"cite": "2(c)(ii)", "s": "2", "derived": true, "role": "supplier", "text": "service providers share such data, information, and reporting, as they relate to cyber incidents or potential incidents relevant to any agency with which they have contracted, directly with such agency and any other agency that the Director of OMB ... deems appropriate"},
	"2.c.iii": {"cite": "2(c)(iii)", "s": "2", "derived": true, "role": "supplier", "text": "service providers collaborate with Federal cybersecurity or investigative agencies in their investigations of and responses to incidents or potential incidents on Federal Information Systems, including by implementing technical capabilities, such as monitoring networks for threats in collaboration with agencies they support, as needed"},
	"2.c.iv": {"cite": "2(c)(iv)", "s": "2", "derived": true, "role": "supplier", "text": "service providers share cyber threat and incident information with agencies, doing so, where possible, in industry-recognized formats for incident response and remediation"},
	"2.f.i": {"cite": "2(f)(i)", "s": "2", "derived": false, "role": "supplier", "text": "information and communications technology (ICT) service providers entering into contracts with agencies must promptly report to such agencies when they discover a cyber incident involving a software product or service provided to such agencies or involving a support system for a software product or service provided to such agencies"},
	"2.f.ii": {"cite": "2(f)(ii)", "s": "2", "derived": false, "role": "supplier", "text": "ICT service providers must also directly report to CISA whenever they report under subsection (f)(i) of this section to Federal Civilian Executive Branch (FCEB) Agencies"},
	"2.k": {"cite": "2(k)", "s": "2", "derived": false, "role": "agency", "text": "Following any updates to the FAR made by the FAR Council ..., agencies shall update their agency-specific cybersecurity requirements to remove any requirements that are duplicative of such FAR updates"},
	# ── Sec. 3 ───────────────────────────────────────────────────────────
	"3.b.i": {"cite": "3(b)(i)", "s": "3", "derived": false, "role": "agency", "text": "Within 60 days of the date of this order, the head of each agency shall update existing agency plans to prioritize resources for the adoption and use of cloud technology as outlined in relevant OMB guidance"},
	"3.b.ii": {"cite": "3(b)(ii)", "s": "3", "derived": false, "role": "agency", "text": "Within 60 days of the date of this order, the head of each agency shall develop a plan to implement Zero Trust Architecture, which shall incorporate, as appropriate, the migration steps that NIST has outlined in standards and guidance, describe any such steps that have already been completed, identify activities that will have the most immediate security impact, and include a schedule to implement them"},
	"3.b.iii": {"cite": "3(b)(iii)", "s": "3", "derived": false, "role": "agency", "text": "Within 60 days of the date of this order, the head of each agency shall provide a report to the Director of OMB and the APNSA discussing the plans required pursuant to subsection (b)(i) and (ii)"},
	"3.c": {"cite": "3(c)", "s": "3", "derived": false, "role": "agency", "text": "As agencies continue to use cloud technology, they shall do so in a coordinated, deliberate way that allows the Federal Government to prevent, detect, assess, and remediate cyber incidents ... the migration to cloud technology shall adopt Zero Trust Architecture, as practicable"},
	"3.c.iv": {"cite": "3(c)(iv)", "s": "3", "derived": false, "role": "fceb", "text": "Within 90 days of the date of this order, the heads of FCEB Agencies ... shall evaluate the types and sensitivity of their respective agency's unclassified data, and shall provide to the Secretary of Homeland Security through the Director of CISA and to the Director of OMB a report based on such evaluation"},
	"3.d": {"cite": "3(d)", "s": "3", "derived": false, "role": "agency", "text": "Within 180 days of the date of this order, agencies shall adopt multi-factor authentication and encryption for data at rest and in transit, to the maximum extent consistent with Federal records laws and other applicable laws"},
	"3.d.i": {"cite": "3(d)(i)", "s": "3", "derived": false, "role": "fceb", "text": "Heads of FCEB Agencies shall provide reports to the Secretary of Homeland Security through the Director of CISA, the Director of OMB, and the APNSA on their respective agency's progress in adopting multifactor authentication and encryption of data at rest and in transit ... every 60 days after the date of this order until the agency has fully adopted, agency-wide, multi-factor authentication and data encryption"},
	"3.d.iii": {"cite": "3(d)(iii)", "s": "3", "derived": false, "role": "fceb", "text": "Heads of FCEB Agencies that are unable to fully adopt multi-factor authentication and data encryption within 180 days of the date of this order shall, at the end of the 180-day period, provide a written rationale to the Secretary of Homeland Security through the Director of CISA, the Director of OMB, and the APNSA"},
	# ── Sec. 4 — supplier practices of 4(e) ──────────────────────────────
	"4.e.i.A": {"cite": "4(e)(i)(A)", "s": "4", "derived": false, "role": "supplier", "text": "secure software development environments, including ... using administratively separate build environments"},
	"4.e.i.B": {"cite": "4(e)(i)(B)", "s": "4", "derived": false, "role": "supplier", "text": "secure software development environments, including ... auditing trust relationships"},
	"4.e.i.C": {"cite": "4(e)(i)(C)", "s": "4", "derived": false, "role": "supplier", "text": "secure software development environments, including ... establishing multi-factor, risk-based authentication and conditional access across the enterprise"},
	"4.e.i.D": {"cite": "4(e)(i)(D)", "s": "4", "derived": false, "role": "supplier", "text": "secure software development environments, including ... documenting and minimizing dependencies on enterprise products that are part of the environments used to develop, build, and edit software"},
	"4.e.i.E": {"cite": "4(e)(i)(E)", "s": "4", "derived": false, "role": "supplier", "text": "secure software development environments, including ... employing encryption for data"},
	"4.e.i.F": {"cite": "4(e)(i)(F)", "s": "4", "derived": false, "role": "supplier", "text": "secure software development environments, including ... monitoring operations and alerts and responding to attempted and actual cyber incidents"},
	"4.e.ii": {"cite": "4(e)(ii)", "s": "4", "derived": false, "role": "supplier", "text": "generating and, when requested by a purchaser, providing artifacts that demonstrate conformance to the processes set forth in subsection (e)(i)"},
	"4.e.iii": {"cite": "4(e)(iii)", "s": "4", "derived": false, "role": "supplier", "text": "employing automated tools, or comparable processes, to maintain trusted source code supply chains, thereby ensuring the integrity of the code"},
	"4.e.iv": {"cite": "4(e)(iv)", "s": "4", "derived": false, "role": "supplier", "text": "employing automated tools, or comparable processes, that check for known and potential vulnerabilities and remediate them, which shall operate regularly, or at a minimum prior to product, version, or update release"},
	"4.e.v": {"cite": "4(e)(v)", "s": "4", "derived": false, "role": "supplier", "text": "providing, when requested by a purchaser, artifacts of the execution of the tools and processes described in subsection (e)(iii) and (iv), and making publicly available summary information on completion of these actions, to include a summary description of the risks assessed and mitigated"},
	"4.e.vi": {"cite": "4(e)(vi)", "s": "4", "derived": false, "role": "supplier", "text": "maintaining accurate and up-to-date data, provenance (i.e., origin) of software code or components, and controls on internal and third-party software components, tools, and services present in software development processes, and performing audits and enforcement of these controls on a recurring basis"},
	"4.e.vii": {"cite": "4(e)(vii)", "s": "4", "derived": false, "role": "supplier", "text": "providing a purchaser a Software Bill of Materials (SBOM) for each product directly or by publishing it on a public website"},
	"4.e.viii": {"cite": "4(e)(viii)", "s": "4", "derived": false, "role": "supplier", "text": "participating in a vulnerability disclosure program that includes a reporting and disclosure process"},
	"4.e.ix": {"cite": "4(e)(ix)", "s": "4", "derived": false, "role": "supplier", "text": "attesting to conformity with secure software development practices"},
	"4.e.x": {"cite": "4(e)(x)", "s": "4", "derived": false, "role": "supplier", "text": "ensuring and attesting, to the extent practicable, to the integrity and provenance of open source software used within any portion of a product"},
	# ── Sec. 4 — agency duties ───────────────────────────────────────────
	"4.j": {"cite": "4(j)", "s": "4", "derived": true, "role": "agency", "text": "the Director of OMB ... shall take appropriate steps to require that agencies comply with such guidance [security measures for critical software under 4(i): least privilege, network segmentation, and proper configuration]"},
	"4.k": {"cite": "4(k)", "s": "4", "derived": true, "role": "agency", "text": "the Director of OMB ... shall take appropriate steps to require that agencies comply with such guidelines [4(e)] with respect to software procured after the date of this order"},
	"4.p": {"cite": "4(p)", "s": "4", "derived": false, "role": "agency", "text": "Following the issuance of any final rule amending the FAR as described in subsection (o), agencies shall, as appropriate and consistent with applicable law, remove software products that do not meet the requirements of the amended FAR from all indefinite delivery indefinite quantity contracts; Federal Supply Schedules; Federal Government-wide Acquisition Contracts; Blanket Purchase Agreements; and Multiple Award Contracts"},
	"4.q": {"cite": "4(q)", "s": "4", "derived": true, "role": "agency", "text": "agencies employing software developed and procured prior to the date of this order (legacy software) either to comply with any requirements issued pursuant to subsection (k) or to provide a plan outlining actions to remediate or meet those requirements, and ... agencies seeking renewals of software contracts, including legacy software, to comply ... unless an extension or waiver is granted in accordance with subsection (l) or (m)"},
	# ── Sec. 6 ───────────────────────────────────────────────────────────
	"6.b.ii": {"cite": "6(b)(ii)", "s": "6", "derived": true, "role": "fceb", "text": "The playbook shall ... be used by FCEB Agencies"},
	"6.d": {"cite": "6(d)", "s": "6", "derived": false, "role": "agency", "text": "Agencies with cybersecurity vulnerability or incident response procedures that deviate from the playbook may use such procedures only after consulting with the Director of OMB and the APNSA and demonstrating that these procedures meet or exceed the standards proposed in the playbook"},
	# ── Sec. 7 ───────────────────────────────────────────────────────────
	"7.b": {"cite": "7(b)", "s": "7", "derived": false, "role": "fceb", "text": "FCEB Agencies shall deploy an Endpoint Detection and Response (EDR) initiative to support proactive detection of cybersecurity incidents within Federal Government infrastructure, active cyber hunting, containment and remediation, and incident response"},
	"7.d": {"cite": "7(d)", "s": "7", "derived": true, "role": "fceb", "text": "the Director of OMB ... shall issue requirements for FCEB Agencies to adopt Federal Government-wide EDR approaches. Those requirements shall support a capability of the Secretary of Homeland Security, acting through the Director of CISA, to engage in cyber hunt, detection, and response activities"},
	"7.f": {"cite": "7(f)", "s": "7", "derived": false, "role": "agency", "text": "Within 75 days of the date of this order, agencies shall establish or update Memoranda of Agreement (MOA) with CISA for the Continuous Diagnostics and Mitigation Program to ensure object level data, as defined in the MOA, are available and accessible to CISA, consistent with applicable law"},
	# ── Sec. 8 ───────────────────────────────────────────────────────────
	"8.a": {"cite": "8(a)", "s": "8", "derived": false, "role": "either", "text": "It is essential that agencies and their IT service providers collect and maintain such data [network and system logs on Federal Information Systems] and, when necessary to address a cyber incident on FCEB Information Systems, provide them upon request to the Secretary of Homeland Security through the Director of CISA and to the FBI, consistent with applicable law"},
	"8.b": {"cite": "8(b)", "s": "8", "derived": true, "role": "agency", "text": "Logs shall be protected by cryptographic methods to ensure integrity once collected and periodically verified against the hashes throughout their retention. Data shall be retained in a manner consistent with all applicable privacy laws and regulations"},
	"8.c": {"cite": "8(c)", "s": "8", "derived": true, "role": "agency", "text": "policies for agencies to establish requirements for logging, log retention, and log management, which shall ensure centralized access and visibility for the highest level security operations center of each agency"},
	"8.e": {"cite": "8(e)", "s": "8", "derived": true, "role": "agency", "text": "requirements to ensure that, upon request, agencies provide logs to the Secretary of Homeland Security through the Director of CISA and to the FBI, consistent with applicable law"},
}

# Days counted from the order's date, 2021-05-12.
dated_obligations := {
	"3.b_cloud_and_zero_trust_plans_and_report": {"days": 60, "due": "2021-07-11"},
	"3.c.iv_unclassified_data_evaluation_report": {"days": 90, "due": "2021-08-10"},
	"3.d_mfa_and_encryption_adopted": {"days": 180, "due": "2021-11-08"},
	"3.d.i_progress_reports_every_days": {"days": 60, "until": "MFA and encryption fully adopted agency-wide"},
	"3.d.iii_written_rationale_if_not_adopted": {"days": 180, "due": "2021-11-08"},
	"7.f_cdm_moa_with_cisa": {"days": 75, "due": "2021-07-26"},
	"2.g.i.D_most_severe_incident_report_ceiling_days_after_detection": {"days": 3, "note": "recommended FAR contract language, not itself a supplier obligation"},
}

not_controls := {
	"4.s-4.w": "IoT and consumer software labeling pilots — tasked to NIST/Commerce (with the FTC); no agency or supplier obligation",
	"4.n-4.o": "FAR contract language requiring suppliers to comply with and attest to 4(g)-(k) — the attestation itself is 4(e)(ix) here and frameworks/federal/cisa_ssdaf",
	"5": "Cyber Safety Review Board — outside the requested scope",
	"9": "National Security Systems — outside the requested scope; programs under this order do not apply to NSS until the NSM issues (9(a))",
	"named-officials": "Sentences that only task OMB, CISA, NIST, DHS, DoD, NSA, GSA or the FAR Council are not attestable by an agency or supplier and are not controls; where the duty lands on agencies or providers once the official acts, the row is kept with derived: true",
}

_in := object.get(input, "eo_14028", {})

_supplied if is_object(input.eo_14028)

violations contains msg if {
	not _supplied
	msg := "EO 14028: FAIL-CLOSED - facts 'input.eo_14028' were not supplied (or are not an object); this module cannot be evaluated and is reported non-compliant"
}

violations contains msg if {
	some key, text in _roles
	not _in[key] == true
	not _in[key] == false
	msg := sprintf("%v (eo_14028.%v undeclared)", [text, key])
}

# An FCEB Agency is an agency, so is_fceb_agency also opens the all-agency rows.
_role_open("fceb") if _in.is_fceb_agency == true

_role_open("agency") if _in.is_agency == true

_role_open("agency") if _in.is_fceb_agency == true

_role_open("supplier") if _in.is_supplier == true

_role_open("either") if _in.is_agency == true

_role_open("either") if _in.is_fceb_agency == true

_role_open("either") if _in.is_supplier == true

applicable[id] := c if {
	some id, c in directives
	_role_open(c.role)
}

_attested(id) if _in.directives[id] == true

violations contains msg if {
	some id, c in applicable
	not _attested(id)
	msg := sprintf("EO 14028 %v (%v): %v — not attested", [c.cite, sections[c.s], c.text])
}

violations contains msg if {
	some id, _ in _in.directives
	not directives[id]
	msg := sprintf("EO 14028 Input Contract: attestation for unknown id %v — not an agency or supplier directive of Secs. 2, 3, 4, 6, 7, 8", [id])
}

violations contains msg if {
	_in.directives
	not is_object(_in.directives)
	msg := "EO 14028 Input Contract: input.eo_14028.directives must be an object of {\"<id>\": true}, ids as in directives (e.g. \"3.d\")"
}

section_reports[s] := r if {
	some s, name in sections
	ids := {id | some id; c := applicable[id]; c.s == s}
	passed := {id | some id in ids; _attested(id)}
	r := {"section": name, "directives": count(ids), "attested": count(passed), "gaps": sort([id | some id in ids; not id in passed])}
}

compliance_report := {
	"framework": "Executive Order 14028 — Improving the Nation's Cybersecurity",
	"standard": "EO 14028 of May 12, 2021, 86 FR 26633 (FR Doc. 2021-10460), as published; Federal Register notes: see EO 14141 (2025-01-14), EO 14144 (2025-01-16)",
	"source": "federalregister.gov — document 2021-10460 (API record and GPO full text, fetched 2026-10-13)",
	"related_modules": {
		"cisa_ssdaf": "frameworks/federal/cisa_ssdaf — the common attestation form implementing 4(e) for suppliers",
		"nist_ssdf": "frameworks/federal/nist_ssdf — NIST SP 800-218 practices issued under 4(e)",
		"zero_trust": "frameworks/federal/zero_trust — Zero Trust Architecture (3(b)(ii), 3(c))",
	},
	"roles": {k: object.get(_in, k, "undeclared") | some k, _ in _roles},
	"dated_obligations": dated_obligations,
	"not_controls": not_controls,
	"directives_total": count(directives),
	"directives_derived": sort([id | some id; c := directives[id]; c.derived]),
	"directives_evaluated": count(applicable),
	"directives_attested": count([id | some id; _ = applicable[id]; _attested(id)]),
	"sections": section_reports,
	"compliant": compliant,
	"violation_count": count(violations),
	"violations": violations,
}
