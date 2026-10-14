# BSI Cloud Computing Compliance Criteria Catalogue — C5:2026. Main entry point: one control per C5 criterion.
#
# Source of truth: BSI, "Cloud Computing Compliance Criteria Catalogue (C5:2026)", English edition,
#   https://www.bsi.bund.de/SharedDocs/Downloads/EN/BSI/CloudComputing/ComplianceControlsCatalogue/2026/C5_2026.pdf
#   sha256 b48f7ccdd6844b2a0bb5055edf5ce109dfb186b1680c49a52c5b92cb16537163, 222 pages, retrieved 2026-10-13.
# Version: the cover reads "Version 1.0.1"; the document history table (p. 2) lists only "1.0.0, 07.04.2026,
# Initial Publication". Both are recorded in `source`. License: CC BY-ND 4.0 (p. 2). Criterion ids and titles
# are BSI's, copied from the catalogue; each `summary` is AAC's one-line paraphrase of the basic subcriteria,
# not catalogue text.
#
# Id scheme (exactly as printed): criterion <AREA>-NN (OIS-01 … PSS-12); subcriterion <AREA>-NN.NN followed by
# B (basic), AS (additional, sharpening a named basic subcriterion) or AC (additional, complementing).
# The catalogue states 17 areas (§2.1 p. 19, §2.2 p. 20) but prints no criteria total; 168 is measured from the
# extracted text (pdftotext -layout), cross-checked against the table of contents and against every
# subcriterion id referenced anywhere in the text (no dangling or missing ids):
#   17 subject areas (section 5.1–5.17, Table 2 p. 20-21)          168 criteria
#   462 basic, 29 additional (sharpening), 132 additional (complementing) subcriteria = 623
#   Every criterion has basic subcriteria, so all 168 are basic criteria; 79 also carry an additional
#   criterion (`has_additional`). Per-criterion subcriterion ids are carried as data in the area modules.
#   OIS 10  SP 3  HR 8  AM 12  PS 8  OPS 35  IAM 9  CRY 19  COS 8  PI 3  DEV 15  SSO 8  SIM 6  BCM 4  COM 4
#   INQ 4  PSS 12
# The catalogue gives no per-criterion EUCS marking (EUCS appears only in the introduction and §2.3), so none
# is carried. The six General Conditions GC-01 … GC-06 (section 4) are disclosure items for the system
# description, not criteria; they are listed in `general_conditions` and are not controls.
#
# Effective date (§3.5, p. 37): C5:2026 applies to Type 1 engagements with a specified date on or after
# 2027-06-01 and to Type 2 engagements whose specified period begins on or after 2027-06-01; earlier adoption is
# permitted. A Type 2 period that begins before and ends after 2027-06-01 uses C5:2020 only (no mixing). For
# periods ending on or after 2027-02-28 the provider discloses planned control changes in its description.
#
# How a criterion is evaluated (fail-closed); `basis` in the report says which applies:
#   facts         0 criteria. The C5:2020 module had no fact checks: all 61 of its requirements were attested.
#   attestation   168 criteria: input.bsi_c5.criteria["OIS-01"] == true. An attestation asserts the basic
#                 criterion (the minimum audit scope, §2.1 p. 19); the additional subcriteria are carried as data
#                 and are not evaluated separately.
#
# C5:2020 -> C5:2026 mapping: kept 0, renumbered 0, retired 61. The C5:2020 module did not use BSI's criterion
# ids: its 61 requirements were AAC operationalizations ("OIS-1", "IDM-5"), so no row survives under a 2026 id.
# They are listed in `legacy` with their old title and the 2026 criteria whose subject they fall under
# (`candidate_2026`, AAC's judgment from the titles, not a BSI mapping; BSI publishes its own cross-reference
# table at https://www.bsi.bund.de/C5, p. 20, which was not used here). The C5:2020 area IDM (Identity and
# Access Management) is IAM in C5:2026 (the IDM code is taken from the C5:2020 module's own area codes, not from
# a 2020 catalogue). The official C5:2020 criterion list, and so the list of 2020 criteria BSI withdrew, is not
# in the 2026 catalogue and is not reproduced here. Caveat: official C5:2020 ids share the 2026 format
# (OIS-01, OPS-22, ...), so an attestation made against a C5:2020 criterion with an id that also exists in
# C5:2026 is indistinguishable here and is accepted as a C5:2026 attestation. §3.5 forbids mixing editions in
# one engagement; keeping the input C5:2026-only is the obligation of whoever supplies it.
#
# Input contract (violations): missing or non-object input.bsi_c5.criteria is FAIL-CLOSED; a non-true
# attestation, an attestation for an unknown id, a legacy AAC id, a C5:2020 IDM-NN id or a GC id, and the
# C5:2020-era per-domain input shape (input.bsi_c5.<domain>.requirements) are violations.
#
# Query: POST /v1/data/bsi_c5/main/compliance_report

# METADATA
# title: "BSI C5:2026 — 168 criteria in 17 subject areas, attested"
# custom:
#   class: compliance
#   framework: bsi_c5
#   source: bsi
#   domains: [germany, cloud]
#   coverage:
#     checks: 7
#     cited: 1
#     expected: 168
#     found: 169
#     scope: directory
#     density: full
#     basis: declared-total
#     tested: true
#     entrypoint: compliance_report
#     guard: self
#     as_of: v2.4.2
package bsi_c5.main

import rego.v1

import data.bsi_c5.asset_management
import data.bsi_c5.business_continuity
import data.bsi_c5.communication_security
import data.bsi_c5.compliance_audit
import data.bsi_c5.cryptography
import data.bsi_c5.government_inquiries
import data.bsi_c5.identity_access_management
import data.bsi_c5.incident_management
import data.bsi_c5.operations
import data.bsi_c5.organisation_information_security
import data.bsi_c5.personnel
import data.bsi_c5.physical_security
import data.bsi_c5.portability_interoperability
import data.bsi_c5.product_security
import data.bsi_c5.security_policies
import data.bsi_c5.supplier_control
import data.bsi_c5.system_development

source := {
	"publication": "BSI Cloud Computing Compliance Criteria Catalogue (C5:2026)",
	"edition": "English",
	"version_cover": "1.0.1",
	"document_history": "1.0.0, 07.04.2026, Initial Publication (the only row in Table 1, p. 2)",
	"license": "CC BY-ND 4.0",
	"url": "https://www.bsi.bund.de/SharedDocs/Downloads/EN/BSI/CloudComputing/ComplianceControlsCatalogue/2026/C5_2026.pdf",
	"sha256": "b48f7ccdd6844b2a0bb5055edf5ce109dfb186b1680c49a52c5b92cb16537163",
	"pages": 222,
	"retrieved": "2026-10-13",
}

# Subject areas in catalogue order (section 5.x), code -> name.
sections := {
	"OIS": "5.1 Organisation of Information Security",
	"SP": "5.2 Security Policies and Procedures",
	"HR": "5.3 Personnel",
	"AM": "5.4 Asset Management",
	"PS": "5.5 Physical Security",
	"OPS": "5.6 Operations",
	"IAM": "5.7 Identity and Access Management",
	"CRY": "5.8 Cryptography and Key Management",
	"COS": "5.9 Communication Security",
	"PI": "5.10 Portability and Interoperability",
	"DEV": "5.11 Procurement, Development and Modification of Information Systems",
	"SSO": "5.12 Control and Monitoring of Service Providers and Suppliers",
	"SIM": "5.13 Security Incident Management",
	"BCM": "5.14 Business Continuity Management",
	"COM": "5.15 Compliance",
	"INQ": "5.16 Dealing with Investigation Requests from Government Agencies",
	"PSS": "5.17 Product Safety and Security",
}

dated_obligations := {
	"2027-06-01": "C5:2026 applies to Type 1 engagements dated on or after, and Type 2 periods beginning on or after, this date; a Type 2 period straddling it uses C5:2020 only; earlier adoption permitted (§3.5, p. 37)",
	"2027-02-28": "For specified periods ending on or after this date the description includes planned changes to controls to meet C5:2026 (§3.5, p. 38)",
}

# Section 4 General Conditions: disclosure items, not criteria (not attestable here).
general_conditions := {
	"GC-01": "Information on applicable law, jurisdiction, countries, partitions, regions, zones and locations",
	"GC-02": "Information on availability and incident handling during regular operation",
	"GC-03": "Information on recovery parameters in emergency operation",
	"GC-04": "Information on the approach to ensuring service availability",
	"GC-05": "Information on how investigation requests from government agencies are handled",
	"GC-06": "Information on certifications or attestations",
}

# Lineage: the 61 requirement ids of the C5:2020 module (AAC operationalizations, not BSI ids). Not controls;
# attesting one is a violation. candidate_2026 is AAC's judgment from the titles, not a BSI mapping.
legacy := {
	"OIS-1": {"area_2020": "OIS", "title": "An ISMS with defined responsibilities for provision of the cloud service is established and maintained", "candidate_2026": ["OIS-01"]},
	"OIS-2": {"area_2020": "OIS", "title": "Security roles and responsibilities are assigned, with segregation of conflicting duties enforced", "candidate_2026": ["OIS-04"]},
	"OIS-3": {"area_2020": "OIS", "title": "A risk management process identifies, assesses, and treats cloud-specific risks on a defined cadence", "candidate_2026": ["OIS-07", "OIS-08", "OIS-09"]},
	"OIS-4": {"area_2020": "OIS", "title": "Contact with relevant authorities and special-interest groups is maintained", "candidate_2026": ["OIS-06"]},
	"SP-1": {"area_2020": "SP", "title": "Security policies and instructions are documented, approved by management, and communicated to all personnel", "candidate_2026": ["SP-01"]},
	"SP-2": {"area_2020": "SP", "title": "Policies are reviewed at planned intervals and after significant changes to the service or threat landscape", "candidate_2026": ["SP-02"]},
	"SP-3": {"area_2020": "SP", "title": "Exceptions to policies are documented, risk-assessed, approved, and time-limited", "candidate_2026": ["SP-03"]},
	"HR-1": {"area_2020": "HR", "title": "Background verification of employees is performed before access, proportional to the data classification handled", "candidate_2026": ["HR-01"]},
	"HR-2": {"area_2020": "HR", "title": "Employment terms include security and confidentiality obligations that survive termination", "candidate_2026": ["HR-02"]},
	"HR-3": {"area_2020": "HR", "title": "Security awareness training is completed at onboarding and refreshed regularly for all personnel", "candidate_2026": ["HR-03"]},
	"HR-4": {"area_2020": "HR", "title": "A disciplinary process addresses violations of security policies", "candidate_2026": ["HR-04"]},
	"HR-5": {"area_2020": "HR", "title": "Offboarding revokes all access and recovers assets in a defined, timely procedure", "candidate_2026": ["HR-05", "AM-08", "IAM-04"]},
	"AM-1": {"area_2020": "AM", "title": "An inventory of all assets supporting the cloud service is maintained and kept current", "candidate_2026": ["AM-02"]},
	"AM-2": {"area_2020": "AM", "title": "Every asset has a designated owner and documented acceptable-use rules", "candidate_2026": ["AM-05", "AM-08"]},
	"AM-3": {"area_2020": "AM", "title": "Information is classified and labelled according to a defined scheme", "candidate_2026": ["AM-09"]},
	"AM-4": {"area_2020": "AM", "title": "Assets and media are securely wiped or destroyed on return, reuse, or disposal", "candidate_2026": ["AM-07"]},
	"PS-1": {"area_2020": "PS", "title": "Data centre perimeters and security zones restrict physical access to authorized persons, with entries logged", "candidate_2026": ["PS-01", "PS-03", "PS-04"]},
	"PS-2": {"area_2020": "PS", "title": "Protection against environmental threats — fire, water, temperature, power disruption — is implemented and tested", "candidate_2026": ["PS-05"]},
	"PS-3": {"area_2020": "PS", "title": "Redundant power and telecommunication supplies match the availability commitments of the service", "candidate_2026": ["PS-02", "PS-06"]},
	"PS-4": {"area_2020": "PS", "title": "Equipment is securely sited and maintained per manufacturer and security requirements", "candidate_2026": ["PS-06"]},
	"OPS-1": {"area_2020": "OPS", "title": "Operating procedures are documented and changes to them are controlled", "candidate_2026": ["SP-01", "DEV-03"]},
	"OPS-2": {"area_2020": "OPS", "title": "Capacity is monitored and forecast so that agreed service levels are sustained", "candidate_2026": ["OPS-01", "OPS-02"]},
	"OPS-3": {"area_2020": "OPS", "title": "Systems supporting the cloud service run current malware protection", "candidate_2026": ["OPS-04", "OPS-05"]},
	"OPS-4": {"area_2020": "OPS", "title": "Data backups are performed, protected against unauthorized access, and restore-tested regularly", "candidate_2026": ["OPS-06", "OPS-07", "OPS-08", "OPS-09"]},
	"OPS-5": {"area_2020": "OPS", "title": "Security-relevant events are logged; logs are protected against tampering and analysed centrally", "candidate_2026": ["OPS-10", "OPS-13", "OPS-14"]},
	"OPS-6": {"area_2020": "OPS", "title": "Vulnerabilities are identified (including by penetration tests), assessed, and remediated within defined timeframes", "candidate_2026": ["OPS-18", "OPS-22", "OPS-25"]},
	"IDM-1": {"area_2020": "IDM", "title": "Access is provisioned through a formal process on least-privilege and need-to-know principles", "candidate_2026": ["IAM-01", "IAM-02"]},
	"IDM-2": {"area_2020": "IDM", "title": "Every user has a unique identifier; shared accounts are prohibited or strictly controlled and attributable", "candidate_2026": ["IAM-01", "IAM-06"]},
	"IDM-3": {"area_2020": "IDM", "title": "Privileged access is restricted, separately managed, and its use monitored", "candidate_2026": ["IAM-06"]},
	"IDM-4": {"area_2020": "IDM", "title": "Access rights are reviewed at regular intervals and revoked without undue delay on role change or departure", "candidate_2026": ["IAM-04", "IAM-05"]},
	"IDM-5": {"area_2020": "IDM", "title": "Strong (multi-factor) authentication protects administrative and remote access to the service infrastructure", "candidate_2026": ["IAM-08"]},
	"CRY-1": {"area_2020": "CRY", "title": "Cryptographic policies mandate state-of-the-art algorithms and protocols for the cloud service", "candidate_2026": ["CRY-01"]},
	"CRY-2": {"area_2020": "CRY", "title": "Customer data is encrypted in transit over public networks", "candidate_2026": ["CRY-04"]},
	"CRY-3": {"area_2020": "CRY", "title": "Customer data is encrypted at rest", "candidate_2026": ["CRY-05"]},
	"CRY-4": {"area_2020": "CRY", "title": "Key management covers the full lifecycle and protects keys from unauthorized use, including by provider personnel", "candidate_2026": ["CRY-06", "CRY-10", "CRY-17"]},
	"COS-1": {"area_2020": "COS", "title": "Networks are segmented to separate tenants from each other and management traffic from service traffic", "candidate_2026": ["COS-03", "COS-05", "COS-06"]},
	"COS-2": {"area_2020": "COS", "title": "Perimeter protections (firewalls, intrusion detection) defend the service's network boundaries", "candidate_2026": ["COS-01", "COS-04"]},
	"COS-3": {"area_2020": "COS", "title": "Network topology and data flows of the cloud service are documented and kept current", "candidate_2026": ["COS-07"]},
	"PI-1": {"area_2020": "PI", "title": "Documented interfaces and formats let customers export their data (portability)", "candidate_2026": ["PI-01", "PI-02"]},
	"PI-2": {"area_2020": "PI", "title": "Customer data is securely deleted at contract end, with the deletion confirmed to the customer", "candidate_2026": ["PI-03"]},
	"DEV-1": {"area_2020": "DEV", "title": "A secure development policy embeds security requirements throughout the lifecycle of the cloud service", "candidate_2026": ["DEV-01"]},
	"DEV-2": {"area_2020": "DEV", "title": "Development, test, and production environments are separated", "candidate_2026": ["DEV-12"]},
	"DEV-3": {"area_2020": "DEV", "title": "Changes are tested and approved before deployment to production", "candidate_2026": ["DEV-07", "DEV-10"]},
	"DEV-4": {"area_2020": "DEV", "title": "The cloud service undergoes security testing (including code analysis and penetration testing) before and after major changes", "candidate_2026": ["PSS-02", "OPS-22"]},
	"SSO-1": {"area_2020": "SSO", "title": "Security requirements for suppliers and subprocessors are contractually enforced", "candidate_2026": ["SSO-01"]},
	"SSO-2": {"area_2020": "SSO", "title": "Subprocessors involved in the service are identified, disclosed, and monitored for compliance", "candidate_2026": ["SSO-04", "SSO-05", "SSO-07"]},
	"SSO-3": {"area_2020": "SSO", "title": "Supply-chain risks are assessed at regular intervals and on changes of supplier", "candidate_2026": ["SSO-02"]},
	"SIM-1": {"area_2020": "SIM", "title": "A security incident management process defines roles, classification, and escalation", "candidate_2026": ["SIM-01"]},
	"SIM-2": {"area_2020": "SIM", "title": "Customers are informed without undue delay of incidents affecting their data or service", "candidate_2026": ["SIM-04", "OPS-24"]},
	"SIM-3": {"area_2020": "SIM", "title": "Incident evidence is preserved and lessons learned feed back into safeguards", "candidate_2026": ["SIM-06"]},
	"BCM-1": {"area_2020": "BCM", "title": "Business continuity and disaster recovery plans for the cloud service are based on a business impact analysis", "candidate_2026": ["BCM-02", "BCM-03"]},
	"BCM-2": {"area_2020": "BCM", "title": "Continuity plans are exercised at regular intervals and updated from the results", "candidate_2026": ["BCM-04"]},
	"COM-1": {"area_2020": "COM", "title": "Applicable legal, regulatory, and contractual requirements for the service are identified and kept current", "candidate_2026": ["COM-01"]},
	"COM-2": {"area_2020": "COM", "title": "Independent audits or attestations of the cloud service are performed at regular intervals", "candidate_2026": ["COM-02"]},
	"COM-3": {"area_2020": "COM", "title": "Internal audits verify the effectiveness of the ISMS for the cloud service", "candidate_2026": ["COM-03"]},
	"INQ-1": {"area_2020": "INQ", "title": "A defined process, including legal review, governs every government request for customer data", "candidate_2026": ["INQ-01"]},
	"INQ-2": {"area_2020": "INQ", "title": "Affected customers are informed of investigation requests wherever legally permitted", "candidate_2026": ["INQ-02"]},
	"INQ-3": {"area_2020": "INQ", "title": "Disclosure is limited to the legally required minimum, and applicable jurisdictions are transparent to customers", "candidate_2026": ["INQ-03"]},
	"PSS-1": {"area_2020": "PSS", "title": "Security features and configuration guidance for the service, including the shared-responsibility split, are documented for customers", "candidate_2026": ["PSS-01"]},
	"PSS-2": {"area_2020": "PSS", "title": "Customer-facing interfaces and APIs are secured and tested against known attack classes", "candidate_2026": ["PI-01", "PSS-02"]},
	"PSS-3": {"area_2020": "PSS", "title": "A vulnerability disclosure process covers the product, and errors are handled without exposing sensitive information", "candidate_2026": ["PSS-03", "PSS-04"]},
}

# Area modules in catalogue order.
_areas := [
	{"code": "OIS", "pkg": "organisation_information_security", "criteria": organisation_information_security.criteria, "report": organisation_information_security.compliance_report},
	{"code": "SP", "pkg": "security_policies", "criteria": security_policies.criteria, "report": security_policies.compliance_report},
	{"code": "HR", "pkg": "personnel", "criteria": personnel.criteria, "report": personnel.compliance_report},
	{"code": "AM", "pkg": "asset_management", "criteria": asset_management.criteria, "report": asset_management.compliance_report},
	{"code": "PS", "pkg": "physical_security", "criteria": physical_security.criteria, "report": physical_security.compliance_report},
	{"code": "OPS", "pkg": "operations", "criteria": operations.criteria, "report": operations.compliance_report},
	{"code": "IAM", "pkg": "identity_access_management", "criteria": identity_access_management.criteria, "report": identity_access_management.compliance_report},
	{"code": "CRY", "pkg": "cryptography", "criteria": cryptography.criteria, "report": cryptography.compliance_report},
	{"code": "COS", "pkg": "communication_security", "criteria": communication_security.criteria, "report": communication_security.compliance_report},
	{"code": "PI", "pkg": "portability_interoperability", "criteria": portability_interoperability.criteria, "report": portability_interoperability.compliance_report},
	{"code": "DEV", "pkg": "system_development", "criteria": system_development.criteria, "report": system_development.compliance_report},
	{"code": "SSO", "pkg": "supplier_control", "criteria": supplier_control.criteria, "report": supplier_control.compliance_report},
	{"code": "SIM", "pkg": "incident_management", "criteria": incident_management.criteria, "report": incident_management.compliance_report},
	{"code": "BCM", "pkg": "business_continuity", "criteria": business_continuity.criteria, "report": business_continuity.compliance_report},
	{"code": "COM", "pkg": "compliance_audit", "criteria": compliance_audit.criteria, "report": compliance_audit.compliance_report},
	{"code": "INQ", "pkg": "government_inquiries", "criteria": government_inquiries.criteria, "report": government_inquiries.compliance_report},
	{"code": "PSS", "pkg": "product_security", "criteria": product_security.criteria, "report": product_security.compliance_report},
]

# All 168 criteria, id -> row plus its area code (ids are unique across areas: distinct prefixes).
criteria[id] := object.union(c, {"area": a.code}) if {
	some a in _areas
	some id, c in a.criteria
}

default compliant := false

compliant if count(violations) == 0

_in := object.get(input, "bsi_c5", {})

_container := c if {
	c := _in.criteria
	is_object(c)
}

_supplied if _container

_attested(id) if _container[id] == true

violations contains "BSI C5:2026: FAIL-CLOSED - attestations 'input.bsi_c5.criteria' were not supplied (or are not an object); the 168 criteria cannot be evaluated and the service is reported non-compliant" if {
	not _supplied
}

# Per-criterion gaps, from the area modules.
violations contains v if {
	some a in _areas
	some v in a.report.violations
}

violations contains msg if {
	some id, _ in _container
	l := legacy[id]
	msg := sprintf("BSI C5 Input Contract: %v is a retired AAC C5:2020-module requirement id, not a C5:2026 criterion — attest %v instead", [id, concat(", ", l.candidate_2026)])
}

violations contains msg if {
	some id, _ in _container
	not legacy[id]
	regex.match(`^IDM-[0-9]{2}$`, id)
	msg := sprintf("BSI C5 Input Contract: %v uses the C5:2020 area code IDM; C5:2026 names Identity and Access Management IAM (IAM-01 … IAM-09) — attest the IAM criterion", [id])
}

violations contains msg if {
	some id, _ in _container
	general_conditions[id]
	msg := sprintf("BSI C5 Input Contract: %v is a General Condition (section 4, %v), a disclosure in the system description, not an attestable criterion", [id, general_conditions[id]])
}

violations contains msg if {
	some id, _ in _container
	not criteria[id]
	not legacy[id]
	not general_conditions[id]
	not regex.match(`^IDM-[0-9]{2}$`, id)
	msg := sprintf("BSI C5 Input Contract: attestation for unknown criterion id %v — ids are C5:2026 criterion ids such as OIS-01", [id])
}

violations contains msg if {
	some key, v in _in
	key != "criteria"
	is_object(v)
	v.requirements
	msg := sprintf("BSI C5 Input Contract: input.bsi_c5.%v.requirements is the retired C5:2020-module input shape; attest C5:2026 criteria under input.bsi_c5.criteria", [key])
}

criteria_status[id] := s if {
	some id, c in criteria
	s := {
		"area": c.area,
		"title": c.title,
		"basis": "attestation",
		"has_additional": c.has_additional,
		"satisfied": _satisfied_bool(id),
	}
}

_satisfied_bool(id) if _attested(id)

else := false

subject_area_reports[code] := r if {
	some a in _areas
	code := a.code
	r := {
		"name": sections[code],
		"criteria": a.report.criteria_total,
		"satisfied": a.report.criteria_satisfied,
		"with_additional": a.report.criteria_with_additional,
		"fact_evaluated": a.report.criteria_fact_evaluated,
		"attested_basis": a.report.criteria_attested_basis,
		"gaps": a.report.gaps,
		"compliant": a.report.compliant,
	}
}

_n_satisfied := count({id | some id, _ in criteria; _attested(id)})

compliance_report := {
	"framework": "BSI C5:2026",
	"standard": "BSI Cloud Computing Compliance Criteria Catalogue (C5:2026) — basic criteria, sections 5.1–5.17",
	"source": source,
	"effective": dated_obligations,
	"compliant": compliant,
	"overall_compliant": compliant,
	"total_controls": count(criteria),
	"standard_total": 168, # C5:2026 §5: 168 criteria in 17 subject areas (measured from the catalogue text)
	"criteria_total": count(criteria),
	"criteria_satisfied": _n_satisfied,
	"criteria_fact_evaluated": 0,
	"criteria_attested_basis": count(criteria),
	"criteria_with_additional": count([id | some id, c in criteria; c.has_additional]),
	"subcriteria": {
		"basic": sum([count(c.basic) | some c in criteria]),
		"additional_sharpening": sum([count(c.additional_sharpening) | some c in criteria]),
		"additional_complementing": sum([count(c.additional_complementing) | some c in criteria]),
	},
	"subject_areas_total": count(_areas),
	"subject_areas_passing": count([code | some code, r in subject_area_reports; r.compliant]),
	"subject_areas": subject_area_reports,
	"criteria": criteria_status,
	"general_conditions": general_conditions,
	"legacy_c5_2020_module": {"kept": 0, "renumbered": 0, "retired": count(legacy)},
	"edition_caveat": "C5:2020 and C5:2026 criterion ids share a format; an attestation is read as C5:2026. Do not mix editions in one engagement (C5:2026 §3.5).",
	"violation_count": count(violations),
	"violations": violations,
}
