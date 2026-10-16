# HIPAA Security Rule - 45 CFR Part 164 Subpart C (§§ 164.308-164.316), keyed to the regulation's own
# paragraph citations. One control per standard and per implementation specification.
#
# Sources (both public domain; both retrieved 2026-10-13):
#   [CFR]  https://www.govinfo.gov/bulkdata/CFR/2025/title-45/CFR-2025-title45-vol2.xml
#          sha256 5fb58263c7533af259dacbc0d72e097158b995551a0fb241c4f997d4ef856b52
#          45 CFR Parts 160/162/164 as printed in the 2025 annual edition (GovInfo bulk XML). Every id below was
#          checked by a generator to begin a paragraph of that XML; titles are the paragraph headings.
#   [800-66r2] https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-66r2.pdf
#          sha256 3910c9b29e06d978bf17258d94e851d8d3d786ceb65beb352cc93271f4d3173e
#          Section 5 tables. `nist_800_66_r2` is the 800-66r2 section (5.x.y) for a standard and the key-activity
#          number (5.x.y.n, NIST's own "Key Activity 5.1.1.7" numbering) for an implementation specification;
#          `key_activities` is the number of key activities NIST lists for a standard, and their titles are in
#          nist_800_66_r2_key_activities. No descriptions or sample questions are carried.
#   SP 800-53 Rev 5 mapping: NOT carried. 800-66r2 Appendix D says the Security Rule -> SP 800-53 crosswalk was
#   removed from the document and placed in the NIST CPRT; the PDF contains no SP 800-53 control identifiers
#   and the CPRT export for SP_800_66_2_0_0 returned no data on 2026-10-13. The field is left out rather
#   than filled from memory.
#
# Id scheme: the CFR citation exactly as the XML nests it, e.g. 164.308(a)(1)(ii)(A). Standards keep their own
# paragraph (164.308(a)(1)(i), 164.310(b)); an implementation specification is its own paragraph and carries its
# standard in `parent`. `status` is the regulation's own marking: "required" / "addressable" as printed in
# parentheses after the specification title (§ 164.306(d)(1)), "standard" for a standard.
#   68 controls = 22 standards + 24 required + 22 addressable implementation specifications
#   164.308   9 standards, 10 required, 11 addressable   Administrative safeguards
#   164.310   4 standards,  2 required,  6 addressable   Physical safeguards
#   164.312   5 standards,  2 required,  5 addressable   Technical safeguards
#   164.314   2 standards,  7 required,  0 addressable   Organizational requirements
#   164.316   2 standards,  3 required,  0 addressable   Policies and procedures and documentation requirements
# Granularity notes: § 164.308(b)(1) carries no "Standard:" label in the 2025 text; it is counted as a standard
# (§ 164.306(c) lists § 164.308 standards; 800-66r2 § 5.1.9 treats it as one) and its (b)(2) business-associate
# to subcontractor duty is folded into that row. § 164.314 prints one "(Required)" marker per group
# ((a)(2), (b)(2)); the rows follow the enumerated paragraphs (a)(2)(i)-(iii) and (b)(2)(i)-(iv), which is also
# 800-66r2's key-activity granularity (5.4.1.1-5.4.1.5, 5.4.2.1-5.4.2.4). § 164.306 (general rules,
# flexibility of approach) is the frame these rows are read under, not a control of its own.
#
# How a control is decided (`basis` in the report):
#   facts        48 controls. 36 administrative/physical rows re-key the boolean fact checks this module
#                always had (input.hipaa.administrative.*, input.hipaa.physical.*); 12 technical rows (§ 164.312)
#                are decided by the data-activity modules in this directory (hipaa.access_control, audit_controls,
#                integrity, authentication, transmission_security), each finding attributed to the paragraph its
#                message cites (a finding citing a paragraph that is not a row, such as 164.312(a) or 164.514(d),
#                is attributed to the module's standard), and every technical row requires input.phi_systems to be
#                non-empty. An attestation for a fact row is accepted but does not decide it.
#   attestation  20 controls with no fact check: input.hipaa.specifications["<id>"] == true. For an addressable
#                specification, true attests the § 164.306(d)(3) decision was made and implemented (the
#                specification, or a documented equivalent alternative).
#   164.308(a)(1)(i), 164.308(a)(3)(i), 164.308(a)(5)(ii)(A), 164.308(a)(7)(i), 164.310(a)(1), 164.310(d)(1),
#   164.314(a)(1), 164.314(a)(2)(i), 164.314(a)(2)(ii), 164.314(a)(2)(iii), 164.314(b)(1), 164.314(b)(2)(i),
#   164.314(b)(2)(ii), 164.314(b)(2)(iii), 164.314(b)(2)(iv), 164.316(a), 164.316(b)(1), 164.316(b)(2)(i),
#   164.316(b)(2)(ii), 164.316(b)(2)(iii).
# Applicability: input.hipaa.scope declares health_plan, health_care_provider, health_care_clearinghouse and
# business_associate true/false (each undeclared flag is a violation; none true is FAIL-CLOSED). § 164.314(b)
# applies only when health_plan is true.
# Fail-closed: a missing or non-object input.hipaa.specifications is a FAIL-CLOSED violation; a failed fact, a
# non-true attestation, an unknown id or an undeclared scope flag is a violation.
#
# Dropped (no reader in this library, the compliance repo or the portal): the former report keys
# breach_notification (6 conditions on input.hipaa.breach_notification.*), privacy_controls.minimum_necessary
# (3 conditions on input.hipaa.privacy.minimum_necessary.{policy.implemented,access_limited_to_job_function,
# role_based_access.implemented}) and privacy_controls.patient_rights. They are not Security Rule paragraphs;
# Subpart D is evaluated in hipaa.hitech (input.hitech.*) and minimum necessary in hipaa.privacy_rule
# (§§ 164.502(b), 164.514(d)). The safeguard booleans remain as rules and top-level report keys.
#
# OPA endpoint: POST /v1/data/hipaa/security_rule/report

# METADATA
# title: "HIPAA Security Rule - 45 CFR 164.308-164.316, one control per standard and implementation specification (CFR citations)"
# custom:
#   class: compliance
#   framework: hipaa
#   source: hhs
#   domains: [privacy, healthcare]
#   coverage:
#     checks: 73
#     cited: 68
#     expected: 68
#     found: 68
#     scope: module
#     density: full
#     basis: declared-total
#     tested: true
#     entrypoint: report
#     guard: self
#     as_of: v2.4.2
package hipaa.security_rule

import rego.v1

# Technical safeguards (§164.312) are evaluated by the data-activity modules - measured from
# input.phi_systems[] / audit_logs[] / users[], and Guardium-feedable - not by attestation booleans.
import data.hipaa.access_control as tech_access_control
import data.hipaa.audit_controls as tech_audit_controls
import data.hipaa.authentication as tech_authentication
import data.hipaa.integrity as tech_integrity
import data.hipaa.transmission_security as tech_transmission

# Sources, flattened to strings (one per field).
source := {
	"cfr_regulation": "45 CFR Subtitle A, Subchapter C — Administrative Data Standards and Related Requirements (Parts 160, 162, 164)",
	"cfr_edition": "Code of Federal Regulations, Title 45, Volume 2, 2025 annual edition (GovInfo bulk XML)",
	"cfr_url": "https://www.govinfo.gov/bulkdata/CFR/2025/title-45/CFR-2025-title45-vol2.xml",
	"cfr_sha256": "5fb58263c7533af259dacbc0d72e097158b995551a0fb241c4f997d4ef856b52",
	"cfr_retrieved": "2026-10-13",
	"nist_800_66_r2_publication": "NIST SP 800-66 Rev. 2, Implementing the HIPAA Security Rule: A Cybersecurity Resource Guide (February 2024)",
	"nist_800_66_r2_url": "https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-66r2.pdf",
	"nist_800_66_r2_sha256": "3910c9b29e06d978bf17258d94e851d8d3d786ceb65beb352cc93271f4d3173e",
	"nist_800_66_r2_retrieved": "2026-10-13",
	"nist_800_53_r5_mapping": "not carried - 800-66r2 Appendix D moved it to the NIST CPRT; not present in the PDF",
}

sections := {
	"164.308": "§ 164.308 Administrative safeguards",
	"164.310": "§ 164.310 Physical safeguards",
	"164.312": "§ 164.312 Technical safeguards",
	"164.314": "§ 164.314 Organizational requirements",
	"164.316": "§ 164.316 Policies and procedures and documentation requirements",
}

scope_roles := {
	"health_plan": "45 CFR 160.103 - whether the entity is a health plan must be declared true or false",
	"health_care_provider": "45 CFR 160.103 - whether the entity is a covered health care provider must be declared true or false",
	"health_care_clearinghouse": "45 CFR 160.103 - whether the entity is a health care clearinghouse must be declared true or false",
	"business_associate": "45 CFR 160.103 - whether the entity acts as a business associate must be declared true or false",
}

# One row per standard and implementation specification, keyed by CFR citation.
specifications_table := [
	{"id": "164.308(a)(1)(i)", "section": "164.308", "status": "standard", "parent": "", "gate": "", "title": "Security management process", "nist_800_66_r2": ["5.1.1"], "key_activities": 9},
	{"id": "164.308(a)(1)(ii)(A)", "section": "164.308", "status": "required", "parent": "164.308(a)(1)(i)", "gate": "", "title": "Risk analysis", "nist_800_66_r2": ["5.1.1.2"]},
	{"id": "164.308(a)(1)(ii)(B)", "section": "164.308", "status": "required", "parent": "164.308(a)(1)(i)", "gate": "", "title": "Risk management", "nist_800_66_r2": ["5.1.1.3"]},
	{"id": "164.308(a)(1)(ii)(C)", "section": "164.308", "status": "required", "parent": "164.308(a)(1)(i)", "gate": "", "title": "Sanction policy", "nist_800_66_r2": ["5.1.1.6"]},
	{"id": "164.308(a)(1)(ii)(D)", "section": "164.308", "status": "required", "parent": "164.308(a)(1)(i)", "gate": "", "title": "Information system activity review", "nist_800_66_r2": ["5.1.1.7"]},
	{"id": "164.308(a)(2)", "section": "164.308", "status": "standard", "parent": "", "gate": "", "title": "Assigned security responsibility", "nist_800_66_r2": ["5.1.2"], "key_activities": 2},
	{"id": "164.308(a)(3)(i)", "section": "164.308", "status": "standard", "parent": "", "gate": "", "title": "Workforce security", "nist_800_66_r2": ["5.1.3"], "key_activities": 5},
	{"id": "164.308(a)(3)(ii)(A)", "section": "164.308", "status": "addressable", "parent": "164.308(a)(3)(i)", "gate": "", "title": "Authorization and/or supervision", "nist_800_66_r2": ["5.1.3.1"]},
	{"id": "164.308(a)(3)(ii)(B)", "section": "164.308", "status": "addressable", "parent": "164.308(a)(3)(i)", "gate": "", "title": "Workforce clearance procedure", "nist_800_66_r2": ["5.1.3.4"]},
	{"id": "164.308(a)(3)(ii)(C)", "section": "164.308", "status": "addressable", "parent": "164.308(a)(3)(i)", "gate": "", "title": "Termination procedures", "nist_800_66_r2": ["5.1.3.5"]},
	{"id": "164.308(a)(4)(i)", "section": "164.308", "status": "standard", "parent": "", "gate": "", "title": "Information access management", "nist_800_66_r2": ["5.1.4"], "key_activities": 4},
	{"id": "164.308(a)(4)(ii)(A)", "section": "164.308", "status": "required", "parent": "164.308(a)(4)(i)", "gate": "", "title": "Isolating health care clearinghouse functions", "nist_800_66_r2": ["5.1.4.1"]},
	{"id": "164.308(a)(4)(ii)(B)", "section": "164.308", "status": "addressable", "parent": "164.308(a)(4)(i)", "gate": "", "title": "Access authorization", "nist_800_66_r2": ["5.1.4.2"]},
	{"id": "164.308(a)(4)(ii)(C)", "section": "164.308", "status": "addressable", "parent": "164.308(a)(4)(i)", "gate": "", "title": "Access establishment and modification", "nist_800_66_r2": ["5.1.4.3"]},
	{"id": "164.308(a)(5)(i)", "section": "164.308", "status": "standard", "parent": "", "gate": "", "title": "Security awareness and training", "nist_800_66_r2": ["5.1.5"], "key_activities": 7},
	{"id": "164.308(a)(5)(ii)(A)", "section": "164.308", "status": "addressable", "parent": "164.308(a)(5)(i)", "gate": "", "title": "Security reminders", "nist_800_66_r2": ["5.1.5.6"]},
	{"id": "164.308(a)(5)(ii)(B)", "section": "164.308", "status": "addressable", "parent": "164.308(a)(5)(i)", "gate": "", "title": "Protection from malicious software", "nist_800_66_r2": ["5.1.5.3"]},
	{"id": "164.308(a)(5)(ii)(C)", "section": "164.308", "status": "addressable", "parent": "164.308(a)(5)(i)", "gate": "", "title": "Log-in monitoring", "nist_800_66_r2": ["5.1.5.3"]},
	{"id": "164.308(a)(5)(ii)(D)", "section": "164.308", "status": "addressable", "parent": "164.308(a)(5)(i)", "gate": "", "title": "Password management", "nist_800_66_r2": ["5.1.5.3"]},
	{"id": "164.308(a)(6)(i)", "section": "164.308", "status": "standard", "parent": "", "gate": "", "title": "Security incident procedures", "nist_800_66_r2": ["5.1.6"], "key_activities": 4},
	{"id": "164.308(a)(6)(ii)", "section": "164.308", "status": "required", "parent": "164.308(a)(6)(i)", "gate": "", "title": "Response and reporting", "nist_800_66_r2": ["5.1.6.3"]},
	{"id": "164.308(a)(7)(i)", "section": "164.308", "status": "standard", "parent": "", "gate": "", "title": "Contingency plan", "nist_800_66_r2": ["5.1.7"], "key_activities": 7},
	{"id": "164.308(a)(7)(ii)(A)", "section": "164.308", "status": "required", "parent": "164.308(a)(7)(i)", "gate": "", "title": "Data backup plan", "nist_800_66_r2": ["5.1.7.5"]},
	{"id": "164.308(a)(7)(ii)(B)", "section": "164.308", "status": "required", "parent": "164.308(a)(7)(i)", "gate": "", "title": "Disaster recovery plan", "nist_800_66_r2": ["5.1.7.5"]},
	{"id": "164.308(a)(7)(ii)(C)", "section": "164.308", "status": "required", "parent": "164.308(a)(7)(i)", "gate": "", "title": "Emergency mode operation plan", "nist_800_66_r2": ["5.1.7.6"]},
	{"id": "164.308(a)(7)(ii)(D)", "section": "164.308", "status": "addressable", "parent": "164.308(a)(7)(i)", "gate": "", "title": "Testing and revision procedures", "nist_800_66_r2": ["5.1.7.7"]},
	{"id": "164.308(a)(7)(ii)(E)", "section": "164.308", "status": "addressable", "parent": "164.308(a)(7)(i)", "gate": "", "title": "Applications and data criticality analysis", "nist_800_66_r2": ["5.1.7.2"]},
	{"id": "164.308(a)(8)", "section": "164.308", "status": "standard", "parent": "", "gate": "", "title": "Evaluation", "nist_800_66_r2": ["5.1.8"], "key_activities": 5},
	{"id": "164.308(b)(1)", "section": "164.308", "status": "standard", "parent": "", "gate": "", "title": "Business associate contracts and other arrangements (with (b)(2), business associate to subcontractor)", "nist_800_66_r2": ["5.1.9"], "key_activities": 3},
	{"id": "164.308(b)(3)", "section": "164.308", "status": "required", "parent": "164.308(b)(1)", "gate": "", "title": "Written contract or other arrangement", "nist_800_66_r2": ["5.1.9.3"]},
	{"id": "164.310(a)(1)", "section": "164.310", "status": "standard", "parent": "", "gate": "", "title": "Facility access controls", "nist_800_66_r2": ["5.2.1"], "key_activities": 6},
	{"id": "164.310(a)(2)(i)", "section": "164.310", "status": "addressable", "parent": "164.310(a)(1)", "gate": "", "title": "Contingency operations", "nist_800_66_r2": ["5.2.1.5"]},
	{"id": "164.310(a)(2)(ii)", "section": "164.310", "status": "addressable", "parent": "164.310(a)(1)", "gate": "", "title": "Facility security plan", "nist_800_66_r2": ["5.2.1.3"]},
	{"id": "164.310(a)(2)(iii)", "section": "164.310", "status": "addressable", "parent": "164.310(a)(1)", "gate": "", "title": "Access control and validation procedures", "nist_800_66_r2": ["5.2.1.4"]},
	{"id": "164.310(a)(2)(iv)", "section": "164.310", "status": "addressable", "parent": "164.310(a)(1)", "gate": "", "title": "Maintenance records", "nist_800_66_r2": ["5.2.1.6"]},
	{"id": "164.310(b)", "section": "164.310", "status": "standard", "parent": "", "gate": "", "title": "Workstation use", "nist_800_66_r2": ["5.2.2"], "key_activities": 3},
	{"id": "164.310(c)", "section": "164.310", "status": "standard", "parent": "", "gate": "", "title": "Workstation security", "nist_800_66_r2": ["5.2.3"], "key_activities": 3},
	{"id": "164.310(d)(1)", "section": "164.310", "status": "standard", "parent": "", "gate": "", "title": "Device and media controls", "nist_800_66_r2": ["5.2.4"], "key_activities": 4},
	{"id": "164.310(d)(2)(i)", "section": "164.310", "status": "required", "parent": "164.310(d)(1)", "gate": "", "title": "Disposal", "nist_800_66_r2": ["5.2.4.1"]},
	{"id": "164.310(d)(2)(ii)", "section": "164.310", "status": "required", "parent": "164.310(d)(1)", "gate": "", "title": "Media re-use", "nist_800_66_r2": ["5.2.4.2"]},
	{"id": "164.310(d)(2)(iii)", "section": "164.310", "status": "addressable", "parent": "164.310(d)(1)", "gate": "", "title": "Accountability", "nist_800_66_r2": ["5.2.4.3"]},
	{"id": "164.310(d)(2)(iv)", "section": "164.310", "status": "addressable", "parent": "164.310(d)(1)", "gate": "", "title": "Data backup and storage", "nist_800_66_r2": ["5.2.4.4"]},
	{"id": "164.312(a)(1)", "section": "164.312", "status": "standard", "parent": "", "gate": "", "title": "Access control", "nist_800_66_r2": ["5.3.1"], "key_activities": 9},
	{"id": "164.312(a)(2)(i)", "section": "164.312", "status": "required", "parent": "164.312(a)(1)", "gate": "", "title": "Unique user identification", "nist_800_66_r2": ["5.3.1.3"]},
	{"id": "164.312(a)(2)(ii)", "section": "164.312", "status": "required", "parent": "164.312(a)(1)", "gate": "", "title": "Emergency access procedure", "nist_800_66_r2": ["5.3.1.7"]},
	{"id": "164.312(a)(2)(iii)", "section": "164.312", "status": "addressable", "parent": "164.312(a)(1)", "gate": "", "title": "Automatic logoff", "nist_800_66_r2": ["5.3.1.8"]},
	{"id": "164.312(a)(2)(iv)", "section": "164.312", "status": "addressable", "parent": "164.312(a)(1)", "gate": "", "title": "Encryption and decryption", "nist_800_66_r2": ["5.3.1.8"]},
	{"id": "164.312(b)", "section": "164.312", "status": "standard", "parent": "", "gate": "", "title": "Audit controls", "nist_800_66_r2": ["5.3.2"], "key_activities": 5},
	{"id": "164.312(c)(1)", "section": "164.312", "status": "standard", "parent": "", "gate": "", "title": "Integrity", "nist_800_66_r2": ["5.3.3"], "key_activities": 6},
	{"id": "164.312(c)(2)", "section": "164.312", "status": "addressable", "parent": "164.312(c)(1)", "gate": "", "title": "Mechanism to authenticate electronic protected health information", "nist_800_66_r2": ["5.3.3.5"]},
	{"id": "164.312(d)", "section": "164.312", "status": "standard", "parent": "", "gate": "", "title": "Person or entity authentication", "nist_800_66_r2": ["5.3.4"], "key_activities": 3},
	{"id": "164.312(e)(1)", "section": "164.312", "status": "standard", "parent": "", "gate": "", "title": "Transmission security", "nist_800_66_r2": ["5.3.5"], "key_activities": 4},
	{"id": "164.312(e)(2)(i)", "section": "164.312", "status": "addressable", "parent": "164.312(e)(1)", "gate": "", "title": "Integrity controls", "nist_800_66_r2": ["5.3.5.3"]},
	{"id": "164.312(e)(2)(ii)", "section": "164.312", "status": "addressable", "parent": "164.312(e)(1)", "gate": "", "title": "Encryption", "nist_800_66_r2": ["5.3.5.4"]},
	{"id": "164.314(a)(1)", "section": "164.314", "status": "standard", "parent": "", "gate": "", "title": "Business associate contracts or other arrangements", "nist_800_66_r2": ["5.4.1"], "key_activities": 5},
	{"id": "164.314(a)(2)(i)", "section": "164.314", "status": "required", "parent": "164.314(a)(1)", "gate": "", "title": "Business associate contracts (comply with Subpart C; flow down to subcontractors; report security incidents and breaches)", "nist_800_66_r2": ["5.4.1.1", "5.4.1.2", "5.4.1.3"]},
	{"id": "164.314(a)(2)(ii)", "section": "164.314", "status": "required", "parent": "164.314(a)(1)", "gate": "", "title": "Other arrangements (meets § 164.504(e)(3))", "nist_800_66_r2": ["5.4.1.4"]},
	{"id": "164.314(a)(2)(iii)", "section": "164.314", "status": "required", "parent": "164.314(a)(1)", "gate": "", "title": "Business associate contracts with subcontractors", "nist_800_66_r2": ["5.4.1.5"]},
	{"id": "164.314(b)(1)", "section": "164.314", "status": "standard", "parent": "", "gate": "health_plan", "title": "Requirements for group health plans", "nist_800_66_r2": ["5.4.2"], "key_activities": 4},
	{"id": "164.314(b)(2)(i)", "section": "164.314", "status": "required", "parent": "164.314(b)(1)", "gate": "health_plan", "title": "Plan documents require the plan sponsor to implement administrative, physical and technical safeguards for the ePHI it handles", "nist_800_66_r2": ["5.4.2.1"]},
	{"id": "164.314(b)(2)(ii)", "section": "164.314", "status": "required", "parent": "164.314(b)(1)", "gate": "health_plan", "title": "Plan documents require the adequate separation of § 164.504(f)(2)(iii) to be supported by reasonable and appropriate security measures", "nist_800_66_r2": ["5.4.2.2"]},
	{"id": "164.314(b)(2)(iii)", "section": "164.314", "status": "required", "parent": "164.314(b)(1)", "gate": "health_plan", "title": "Plan documents require any agent given the information to implement reasonable and appropriate security measures", "nist_800_66_r2": ["5.4.2.3"]},
	{"id": "164.314(b)(2)(iv)", "section": "164.314", "status": "required", "parent": "164.314(b)(1)", "gate": "health_plan", "title": "Plan documents require the plan sponsor to report any security incident to the group health plan", "nist_800_66_r2": ["5.4.2.4"]},
	{"id": "164.316(a)", "section": "164.316", "status": "standard", "parent": "", "gate": "", "title": "Policies and procedures", "nist_800_66_r2": ["5.5.1"], "key_activities": 2},
	{"id": "164.316(b)(1)", "section": "164.316", "status": "standard", "parent": "", "gate": "", "title": "Documentation", "nist_800_66_r2": ["5.5.2"], "key_activities": 4},
	{"id": "164.316(b)(2)(i)", "section": "164.316", "status": "required", "parent": "164.316(b)(1)", "gate": "", "title": "Time limit", "nist_800_66_r2": ["5.5.2.2"]},
	{"id": "164.316(b)(2)(ii)", "section": "164.316", "status": "required", "parent": "164.316(b)(1)", "gate": "", "title": "Availability", "nist_800_66_r2": ["5.5.2.3"]},
	{"id": "164.316(b)(2)(iii)", "section": "164.316", "status": "required", "parent": "164.316(b)(1)", "gate": "", "title": "Updates", "nist_800_66_r2": ["5.5.2.4"]},
]

specifications := {r.id: r | some r in specifications_table}

# NIST SP 800-66r2 Section 5 key-activity titles per standard (titles only).
nist_800_66_r2_key_activities := {
	"5.1.1": ["Identify All ePHI and Relevant Information Systems", "Conduct Risk Assessment", "Implement a Risk Management Program", "Acquire Information Technology (IT) Systems and Services", "Create and Deploy Policies and Procedures", "Develop and Implement a Sanction Policy", "Develop and Deploy the Information System Activity Review Process", "Develop Appropriate Standard Operating Procedures", "Implement the Information System Activity Review and Audit Process"],
	"5.1.2": ["Select a Security Official to be Assigned Responsibility for HIPAA Security", "Assign and Document the Individual's Responsibility"],
	"5.1.3": ["Implement Policies and Procedures for Authorization and/or Supervision", "Establish Clear Job Descriptions and Responsibilities", "Establish Criteria and Procedures for Hiring and Assigning Tasks", "Establish a Workforce Clearance Procedure", "Establish Termination Procedures"],
	"5.1.4": ["Isolate Healthcare Clearinghouse Functions", "Implement Policies and Procedures for Authorizing Access", "Implement Policies and Procedures for Access Establishment and Modification", "Evaluate Existing Security Measures Related to Access Controls"],
	"5.1.5": ["Conduct a Training Needs Assessment", "Develop and Approve a Training Strategy and a Plan", "Protection from Malicious Software, Login Monitoring, and Password Management", "Develop Appropriate Awareness and Training Content, Materials, and Methods", "Implement the Training", "Implement Security Reminders", "Monitor and Evaluate the Training Plan"],
	"5.1.6": ["Determine the Goals of an Incident Response", "Develop and Deploy an Incident Response Team or Other Reasonable and Appropriate Response Mechanism", "Develop and Implement Policy and Procedures to Respond to and Report Security Incidents", "Incorporate Post-Incident Analysis Into Updates and Revisions"],
	"5.1.7": ["Develop a Contingency Planning Policy", "Conduct an Applications and Data Criticality Analysis", "Identify Preventive Measures", "Develop Recovery Strategy", "Data Backup Plan and Disaster Recovery Plan", "Develop and Implement an Emergency Mode Operation Plan", "Testing and Revision Procedure"],
	"5.1.8": ["Determine Whether Internal or External Evaluation is Most Appropriate", "Develop Standards and Measurements for Reviewing All Standards and Implementation Specifications of the Security Rule", "Conduct Evaluation", "Document Results", "Repeat Evaluations Periodically"],
	"5.1.9": ["Identify Entities That Are Business Associates Under the HIPAA Security Rule", "Establish a Process for Measuring Contract Performance and Terminating the Contract if Security Requirements Are Not Being Met", "Written Contract or Other Arrangement"],
	"5.2.1": ["Conduct an Analysis of Existing Physical Security Vulnerabilities", "Identify Corrective Measures", "Develop a Facility Security Plan", "Develop Access Control and Validation Procedures", "Establish Contingency Operations Procedures", "Maintain Maintenance Records"],
	"5.2.2": ["Identify Workstation and Device Types and Functions or Uses", "Identify the Expected Performance of Each Type of Workstation and Device", "Analyze Physical Surroundings for Physical Attributes"],
	"5.2.3": ["Identify All Methods of Physical Access to Workstations and Devices", "Analyze the Risks Associated with Each Type of Access", "Identify and Implement Physical Safeguards for Workstations and Devices"],
	"5.2.4": ["Implement Methods for the Final Disposal of ePHI", "Develop and Implement Procedures for the Reuse of Electronic Media", "Maintain Accountability for Hardware and Electronic Media", "Develop Data Backup and Storage Procedures"],
	"5.3.1": ["Analyze Workloads and Operations to Identify the Access Needs of All Users", "Identify Technical Access Control Capabilities", "Ensure That All System Users Have Been Assigned a Unique Identifier", "Develop Access Control Policy and Procedures", "Implement Access Control Procedures Using Selected Hardware and Software", "Review and Update Access for Users and Processes", "Establish an Emergency Access Procedure", "Automatic Logoff and Encryption and Decryption", "Terminate Access if it is No Longer Required"],
	"5.3.2": ["Determine the Activities That Will Be Tracked or Audited", "Select the Tools That Will Be Deployed for Auditing and System Activity Reviews", "Develop and Deploy the Information System Activity Review/Audit Policy", "Develop Appropriate Standard Operating Procedures", "Implement the Audit/System Activity Review Process"],
	"5.3.3": ["Identify All Users Who Have Been Authorized to Access ePHI", "Identify Any Possible Unauthorized Sources That May Be Able to Intercept the Information and Modify It", "Develop the Integrity Policy and Requirements", "Implement Procedures to Address These Requirements", "Implement a Mechanism to Authenticate ePHI", "Establish a Monitoring Process to Assess How the Implemented Process is Working"],
	"5.3.4": ["Determine Authentication Applicability to Current Systems/Applications", "Evaluate Available Authentication Options", "Select and Implement Authentication Options"],
	"5.3.5": ["Identify Any Possible Unauthorized Sources That May Be Able to Intercept and/or Modify the Information", "Develop and Implement Transmission Security Policy and Procedures", "Implement Integrity Controls", "Implement Encryption"],
	"5.4.1": ["Contract Must Provide That Business Associates Will Comply With the Applicable Requirements of the Security Rule", "Contract Must Provide That the Business Associates Enter Into Contracts With Subcontractors to Ensure the Protection of ePHI", "Contract Must Provide That Business Associates Will Report Security Incidents", "Other Arrangements", "Business Associate Contracts With Subcontractors"],
	"5.4.2": ["Amend Plan Documents of the Group Health Plan to Address the Plan Sponsor's Security of ePHI", "Amend Plan Documents of the Group Health Plan to Address Adequate Separation", "Amend Plan Documents of the Group Health Plan to Address the Security of ePHI Supplied to the Plan Sponsors' Agents and Subcontractors", "Amend Plan Documents of Group Health Plans to Address the Reporting of Security Incidents"],
	"5.5.1": ["Create and Deploy Policies and Procedures", "Update the Documentation of the Policy and Procedures"],
	"5.5.2": ["Draft, Maintain, and Update Required Documentation", "Retain Documentation for at Least Six Years", "Ensure That Documentation is Available to Those Responsible for Implementation", "Update Documentation as Required"],
}

# Which rows are decided by facts, and by which facts.
fact_basis := {
	"164.308(a)(1)(ii)(A)": "input.hipaa.administrative.security_management.risk_analysis.{conducted,documented} true and frequency_months <= 12",
	"164.308(a)(1)(ii)(B)": "input.hipaa.administrative.security_management.risk_management.implemented",
	"164.308(a)(1)(ii)(C)": "input.hipaa.administrative.security_management.sanction_policy.established",
	"164.308(a)(1)(ii)(D)": "input.hipaa.administrative.security_management.activity_review.conducted",
	"164.308(a)(2)": "input.hipaa.administrative.security_officer.{designated,documented,responsibilities.defined}",
	"164.308(a)(3)(ii)(A)": "input.hipaa.administrative.workforce.authorization_supervision.implemented",
	"164.308(a)(3)(ii)(B)": "input.hipaa.administrative.workforce.clearance_procedure.implemented",
	"164.308(a)(3)(ii)(C)": "input.hipaa.administrative.workforce.{termination_procedures.implemented,access_removed_on_termination}",
	"164.308(a)(4)(i)": "input.hipaa.administrative.access_management.least_privilege.enforced",
	"164.308(a)(4)(ii)(A)": "input.hipaa.administrative.access_management.isolating_clearinghouse_functions.addressed",
	"164.308(a)(4)(ii)(B)": "input.hipaa.administrative.access_management.access_authorization.implemented",
	"164.308(a)(4)(ii)(C)": "input.hipaa.administrative.access_management.access_establishment.implemented",
	"164.308(a)(5)(i)": "input.hipaa.administrative.training.{program.implemented,new_hires.required} true and frequency_months <= 12",
	"164.308(a)(5)(ii)(B)": "input.hipaa.administrative.training.malicious_software.covered",
	"164.308(a)(5)(ii)(C)": "input.hipaa.administrative.training.log_in_monitoring.covered",
	"164.308(a)(5)(ii)(D)": "input.hipaa.administrative.training.password_management.covered",
	"164.308(a)(6)(i)": "input.hipaa.administrative.incident_response.{breach_notification.procedures_defined,forensic_capability.available}",
	"164.308(a)(6)(ii)": "input.hipaa.administrative.incident_response.{response_procedures.implemented,reporting.implemented}",
	"164.308(a)(7)(ii)(A)": "input.hipaa.administrative.contingency.data_backup.plan_implemented",
	"164.308(a)(7)(ii)(B)": "input.hipaa.administrative.contingency.disaster_recovery.plan_implemented",
	"164.308(a)(7)(ii)(C)": "input.hipaa.administrative.contingency.emergency_mode.plan_implemented",
	"164.308(a)(7)(ii)(D)": "input.hipaa.administrative.contingency.testing.performed true and testing.frequency_months <= 12",
	"164.308(a)(7)(ii)(E)": "input.hipaa.administrative.contingency.applications.criticality_analysis_performed",
	"164.308(a)(8)": "input.hipaa.administrative.evaluation.{periodic_technical.performed,environmental_operations_changes.trigger_review} true and frequency_months <= 12",
	"164.308(b)(1)": "input.hipaa.administrative.business_associates.{contracts.required,inventory.maintained,compliance.monitored}",
	"164.308(b)(3)": "input.hipaa.administrative.business_associates.contracts.phi_safeguards.required",
	"164.310(a)(2)(i)": "input.hipaa.physical.facility_access.contingency_operations.addressed",
	"164.310(a)(2)(ii)": "input.hipaa.physical.facility_access.facility_security_plan.implemented",
	"164.310(a)(2)(iii)": "input.hipaa.physical.facility_access.access_control.implemented",
	"164.310(a)(2)(iv)": "input.hipaa.physical.facility_access.maintenance_records.tracked",
	"164.310(b)": "input.hipaa.physical.workstation_use.{policies.implemented,physical_access.restricted,screen_lock.configured}",
	"164.310(c)": "input.hipaa.physical.workstation_security.{physical_safeguards.implemented,ephi_access.restricted}",
	"164.310(d)(2)(i)": "input.hipaa.physical.device_media.disposal.{procedures_implemented,ephi_wiped}",
	"164.310(d)(2)(ii)": "input.hipaa.physical.device_media.media_reuse.sanitization_implemented",
	"164.310(d)(2)(iii)": "input.hipaa.physical.device_media.accountability.tracked",
	"164.310(d)(2)(iv)": "input.hipaa.physical.device_media.data_backup.copy_made_before_movement",
	"164.312(a)(1)": "findings cited to this paragraph by data.hipaa.access_control (and input.phi_systems non-empty)",
	"164.312(a)(2)(i)": "findings cited to this paragraph by data.hipaa.access_control (and input.phi_systems non-empty)",
	"164.312(a)(2)(ii)": "findings cited to this paragraph by data.hipaa.access_control (and input.phi_systems non-empty)",
	"164.312(a)(2)(iii)": "findings cited to this paragraph by data.hipaa.access_control (and input.phi_systems non-empty)",
	"164.312(a)(2)(iv)": "findings cited to this paragraph by data.hipaa.access_control (and input.phi_systems non-empty)",
	"164.312(b)": "findings cited to this paragraph by data.hipaa.audit_controls (and input.phi_systems non-empty)",
	"164.312(c)(1)": "findings cited to this paragraph by data.hipaa.integrity (and input.phi_systems non-empty)",
	"164.312(c)(2)": "findings cited to this paragraph by data.hipaa.integrity (and input.phi_systems non-empty)",
	"164.312(d)": "findings cited to this paragraph by data.hipaa.authentication (and input.phi_systems non-empty)",
	"164.312(e)(1)": "findings cited to this paragraph by data.hipaa.transmission_security (and input.phi_systems non-empty)",
	"164.312(e)(2)(i)": "findings cited to this paragraph by data.hipaa.transmission_security (and input.phi_systems non-empty)",
	"164.312(e)(2)(ii)": "findings cited to this paragraph by data.hipaa.transmission_security (and input.phi_systems non-empty)",
}

technical_rows := {
	"164.312(a)(1)": "access_control",
	"164.312(a)(2)(i)": "access_control",
	"164.312(a)(2)(ii)": "access_control",
	"164.312(a)(2)(iii)": "access_control",
	"164.312(a)(2)(iv)": "access_control",
	"164.312(b)": "audit_controls",
	"164.312(c)(1)": "integrity",
	"164.312(c)(2)": "integrity",
	"164.312(d)": "authentication",
	"164.312(e)(1)": "transmission_security",
	"164.312(e)(2)(i)": "transmission_security",
	"164.312(e)(2)(ii)": "transmission_security",
}

# -----------------------------------------------------------------------------
# Fact checks, one per CFR paragraph (re-keyed from this module's former booleans)
# -----------------------------------------------------------------------------

_adm := object.get(input, ["hipaa", "administrative"], {})

_phy := object.get(input, ["hipaa", "physical"], {})

_le(x, n) if {
	is_number(x)
	x <= n
}

_fact_pass contains "164.308(a)(1)(ii)(A)" if {
	_adm.security_management.risk_analysis.conducted == true
	_adm.security_management.risk_analysis.documented == true
	_le(_adm.security_management.risk_analysis.frequency_months, 12)
}

_fact_pass contains "164.308(a)(1)(ii)(B)" if _adm.security_management.risk_management.implemented == true

_fact_pass contains "164.308(a)(1)(ii)(C)" if _adm.security_management.sanction_policy.established == true

_fact_pass contains "164.308(a)(1)(ii)(D)" if _adm.security_management.activity_review.conducted == true

_fact_pass contains "164.308(a)(2)" if {
	_adm.security_officer.designated == true
	_adm.security_officer.documented == true
	_adm.security_officer.responsibilities.defined == true
}

_fact_pass contains "164.308(a)(3)(ii)(A)" if _adm.workforce.authorization_supervision.implemented == true

_fact_pass contains "164.308(a)(3)(ii)(B)" if _adm.workforce.clearance_procedure.implemented == true

_fact_pass contains "164.308(a)(3)(ii)(C)" if {
	_adm.workforce.termination_procedures.implemented == true
	_adm.workforce.access_removed_on_termination == true
}

_fact_pass contains "164.308(a)(4)(i)" if _adm.access_management.least_privilege.enforced == true

_fact_pass contains "164.308(a)(4)(ii)(A)" if _adm.access_management.isolating_clearinghouse_functions.addressed == true

_fact_pass contains "164.308(a)(4)(ii)(B)" if _adm.access_management.access_authorization.implemented == true

_fact_pass contains "164.308(a)(4)(ii)(C)" if _adm.access_management.access_establishment.implemented == true

_fact_pass contains "164.308(a)(5)(i)" if {
	_adm.training.program.implemented == true
	_le(_adm.training.frequency_months, 12)
	_adm.training.new_hires.required == true
}

_fact_pass contains "164.308(a)(5)(ii)(B)" if _adm.training.malicious_software.covered == true

_fact_pass contains "164.308(a)(5)(ii)(C)" if _adm.training.log_in_monitoring.covered == true

_fact_pass contains "164.308(a)(5)(ii)(D)" if _adm.training.password_management.covered == true

_fact_pass contains "164.308(a)(6)(i)" if {
	_adm.incident_response.breach_notification.procedures_defined == true
	_adm.incident_response.forensic_capability.available == true
}

_fact_pass contains "164.308(a)(6)(ii)" if {
	_adm.incident_response.response_procedures.implemented == true
	_adm.incident_response.reporting.implemented == true
}

_fact_pass contains "164.308(a)(7)(ii)(A)" if _adm.contingency.data_backup.plan_implemented == true

_fact_pass contains "164.308(a)(7)(ii)(B)" if _adm.contingency.disaster_recovery.plan_implemented == true

_fact_pass contains "164.308(a)(7)(ii)(C)" if _adm.contingency.emergency_mode.plan_implemented == true

_fact_pass contains "164.308(a)(7)(ii)(D)" if {
	_adm.contingency.testing.performed == true
	_le(_adm.contingency.testing.frequency_months, 12)
}

_fact_pass contains "164.308(a)(7)(ii)(E)" if _adm.contingency.applications.criticality_analysis_performed == true

_fact_pass contains "164.308(a)(8)" if {
	_adm.evaluation.periodic_technical.performed == true
	_le(_adm.evaluation.frequency_months, 12)
	_adm.evaluation.environmental_operations_changes.trigger_review == true
}

_fact_pass contains "164.308(b)(1)" if {
	_adm.business_associates.contracts.required == true
	_adm.business_associates.inventory.maintained == true
	_adm.business_associates.compliance.monitored == true
}

_fact_pass contains "164.308(b)(3)" if _adm.business_associates.contracts.phi_safeguards.required == true

_fact_pass contains "164.310(a)(2)(i)" if _phy.facility_access.contingency_operations.addressed == true

_fact_pass contains "164.310(a)(2)(ii)" if _phy.facility_access.facility_security_plan.implemented == true

_fact_pass contains "164.310(a)(2)(iii)" if _phy.facility_access.access_control.implemented == true

_fact_pass contains "164.310(a)(2)(iv)" if _phy.facility_access.maintenance_records.tracked == true

_fact_pass contains "164.310(b)" if {
	_phy.workstation_use.policies.implemented == true
	_phy.workstation_use.physical_access.restricted == true
	_phy.workstation_use.screen_lock.configured == true
}

_fact_pass contains "164.310(c)" if {
	_phy.workstation_security.physical_safeguards.implemented == true
	_phy.workstation_security.ephi_access.restricted == true
}

_fact_pass contains "164.310(d)(2)(i)" if {
	_phy.device_media.disposal.procedures_implemented == true
	_phy.device_media.disposal.ephi_wiped == true
}

_fact_pass contains "164.310(d)(2)(ii)" if _phy.device_media.media_reuse.sanitization_implemented == true

_fact_pass contains "164.310(d)(2)(iii)" if _phy.device_media.accountability.tracked == true

_fact_pass contains "164.310(d)(2)(iv)" if _phy.device_media.data_backup.copy_made_before_movement == true

# Technical rows: findings of the data-activity modules, attributed by the citation in each message.
_tech_findings := {
	"access_control": tech_access_control.violations,
	"audit_controls": tech_audit_controls.violations,
	"integrity": tech_integrity.violations,
	"authentication": tech_authentication.violations,
	"transmission_security": tech_transmission.violations,
}

_cited(msg) := trim_space(split(trim_prefix(msg, "HIPAA "), ":")[0])

_owns(id, c) if c == id

_owns(id, c) if {
	specifications[id].status == "standard"
	not specifications[c]
}

technical_attribution[id] := fs if {
	some id, m in technical_rows
	fs := {msg | some msg in _tech_findings[m]; _owns(id, _cited(msg))}
}

_ephi_scope_declared if count(object.get(input, "phi_systems", [])) > 0

_fact_pass contains id if {
	some id, _ in technical_rows
	_ephi_scope_declared
	count(technical_attribution[id]) == 0
}

# -----------------------------------------------------------------------------
# Safeguard booleans (read by hipaa.main for its score), derived from the rows above
# -----------------------------------------------------------------------------

default security_management_process := false

default assigned_security_responsibility := false

default workforce_security := false

default information_access_management := false

default security_awareness_training := false

default security_incident_procedures := false

default contingency_plan := false

default periodic_technical_evaluation := false

default business_associate_contracts := false

default facility_access_controls := false

default workstation_use_controls := false

default workstation_security := false

default device_media_controls := false

default administrative_safeguards_compliant := false

default physical_safeguards_compliant := false

default technical_safeguards_compliant := false

_all_facts(ids) if every id in ids {
	_fact_pass[id]
}

security_management_process if _all_facts(["164.308(a)(1)(ii)(A)", "164.308(a)(1)(ii)(B)", "164.308(a)(1)(ii)(C)", "164.308(a)(1)(ii)(D)"])

assigned_security_responsibility if _all_facts(["164.308(a)(2)"])

workforce_security if _all_facts(["164.308(a)(3)(ii)(A)", "164.308(a)(3)(ii)(B)", "164.308(a)(3)(ii)(C)"])

information_access_management if _all_facts(["164.308(a)(4)(i)", "164.308(a)(4)(ii)(A)", "164.308(a)(4)(ii)(B)", "164.308(a)(4)(ii)(C)"])

security_awareness_training if _all_facts(["164.308(a)(5)(i)", "164.308(a)(5)(ii)(B)", "164.308(a)(5)(ii)(C)", "164.308(a)(5)(ii)(D)"])

security_incident_procedures if _all_facts(["164.308(a)(6)(i)", "164.308(a)(6)(ii)"])

contingency_plan if _all_facts(["164.308(a)(7)(ii)(A)", "164.308(a)(7)(ii)(B)", "164.308(a)(7)(ii)(C)", "164.308(a)(7)(ii)(D)", "164.308(a)(7)(ii)(E)"])

periodic_technical_evaluation if _all_facts(["164.308(a)(8)"])

business_associate_contracts if _all_facts(["164.308(b)(1)", "164.308(b)(3)"])

facility_access_controls if _all_facts(["164.310(a)(2)(i)", "164.310(a)(2)(ii)", "164.310(a)(2)(iii)", "164.310(a)(2)(iv)"])

workstation_use_controls if _all_facts(["164.310(b)"])

workstation_security if _all_facts(["164.310(c)"])

device_media_controls if _all_facts(["164.310(d)(2)(i)", "164.310(d)(2)(ii)", "164.310(d)(2)(iii)", "164.310(d)(2)(iv)"])

administrative_safeguards_compliant if {
	security_management_process
	assigned_security_responsibility
	workforce_security
	information_access_management
	security_awareness_training
	security_incident_procedures
	contingency_plan
	periodic_technical_evaluation
	business_associate_contracts
}

physical_safeguards_compliant if {
	facility_access_controls
	workstation_use_controls
	workstation_security
	device_media_controls
}

technical_safeguards_compliant if {
	_ephi_scope_declared # fail-closed: ePHI scope must be declared
	tech_access_control.compliant
	tech_audit_controls.compliant
	tech_integrity.compliant
	tech_authentication.compliant
	tech_transmission.compliant
}

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
	msg := sprintf("HIPAA Security Rule Input Contract: %v (input.hipaa.scope.%v undeclared)", [text, k])
}

violations contains "HIPAA Security Rule Input Contract: FAIL-CLOSED - input.hipaa.scope declares no regulated role (health_plan, health_care_provider, health_care_clearinghouse or business_associate true); applicability under 45 CFR 160.102 cannot be established" if {
	count({k | some k in _roles; _scope[k] == true}) == 0
}

_attestations := a if {
	a := object.get(input, ["hipaa", "specifications"], null)
	is_object(a)
}

violations contains "HIPAA Security Rule: FAIL-CLOSED - attestations 'input.hipaa.specifications' were not supplied (or are not an object); this module cannot be evaluated and is reported non-compliant" if {
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
	some id, r in specifications
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

else := sprintf("not attested - input.hipaa.specifications[\"%v\"] must be true", [id])

violations contains msg if {
	some id, r in applicable
	not _satisfied(id)
	msg := sprintf("HIPAA %v %v (%v): %v", [id, r.title, r.status, _unmet(id)])
}

violations contains msg if {
	some id, _ in _attestations
	not specifications[id]
	msg := sprintf("HIPAA Security Rule Input Contract: attestation for unknown id %v - ids are the 45 CFR citations this module carries, for example 164.308(a)(1)(ii)(A)", [id])
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
	some id, r in specifications
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
	ids := {id | some id; r := specifications[id]; r.section == s}
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

# The five data-activity modules' own reports (§ 164.312).
technical_module_reports := {
	"access_control": tech_access_control.compliance_report,
	"audit_controls": tech_audit_controls.compliance_report,
	"integrity": tech_integrity.compliance_report,
	"authentication": tech_authentication.compliance_report,
	"transmission_security": tech_transmission.compliance_report,
}

report := {
	"standard": "HIPAA Security Rule (45 CFR Part 164 Subpart C, §§ 164.308-164.316)",
	"source": source,
	"compliant": compliant,
	"id_scheme": "45 CFR paragraph citation, e.g. 164.308(a)(1)(ii)(A); status = standard | required | addressable as the regulation marks it",
	"controls_total": count(specifications),
	"standard_total": 68, # 45 CFR 164.308-164.316: 22 standards + 24 required + 22 addressable implementation specifications
	"standards": count({id | some id; r := specifications[id]; r.status == "standard"}),
	"required_specifications": count({id | some id; r := specifications[id]; r.status == "required"}),
	"addressable_specifications": count({id | some id; r := specifications[id]; r.status == "addressable"}),
	"fact_evaluated": count(fact_basis),
	"attested": count(specifications) - count(fact_basis),
	"applicable": _n_applicable,
	"satisfied": _n_satisfied,
	"sections": section_reports,
	"specifications": row_status,
	"administrative_safeguards_compliant": administrative_safeguards_compliant,
	"physical_safeguards_compliant": physical_safeguards_compliant,
	"technical_safeguards_compliant": technical_safeguards_compliant,
	"ephi_scope_declared": count(object.get(input, "phi_systems", [])) > 0,
	"technical_modules": technical_module_reports,
	"violation_count": count(violations),
	"violations": violations,
}
