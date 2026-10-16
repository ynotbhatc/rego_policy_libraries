# HIPAA Privacy Rule - 45 CFR Part 164 Subpart E (§§ 164.500-164.534), keyed to the regulation's own
# paragraph citations. One control per paragraph the regulation labels "Standard" or "Implementation
# specification(s)".
#
# Source: https://www.govinfo.gov/bulkdata/CFR/2025/title-45/CFR-2025-title45-vol2.xml
#   sha256 5fb58263c7533af259dacbc0d72e097158b995551a0fb241c4f997d4ef856b52, retrieved 2026-10-13
#   (2025 annual edition, GovInfo bulk XML; public domain).
#   Measured in the XML: 115 labelled Standard / Implementation-specification paragraphs in §§ 164.502-164.532;
#   110 are rows here and the 5 in § 164.532 (transition provisions) are out of scope (see out_of_scope).
#   Ids were checked by a generator to begin a paragraph of the XML; titles are the paragraph headings.
#
# Id scheme: the CFR citation of the labelled paragraph, e.g. 164.502(b), 164.514(d)(3), 164.530(i)(4). Where the
# label sits on a sub-item that starts its paragraph ("(3)(i) Implementation specification: Unemancipated minors",
# "(2)(i) Implementation specification: Safeguards") the row is the paragraph it opens: 164.502(g)(3),
# 164.530(c)(2). `status` is "standard" or "implementation specification" (the Privacy Rule has no
# required/addressable marking).
#   110 rows = 55 standards + 55 implementation specifications
#   164.502   15 rows   Uses and disclosures of protected health information: General rules
#   164.504    9 rows   Uses and disclosures: Organizational requirements
#   164.506    3 rows   Uses and disclosures to carry out treatment, payment, or health care operations
#   164.508    3 rows   Uses and disclosures for which an authorization is required
#   164.509    3 rows   Uses and disclosures for which an attestation is required
#   164.510    2 rows   Uses and disclosures requiring an opportunity for the individual to agree or to object
#   164.512   12 rows   Uses and disclosures for which an authorization or opportunity to agree or object is not required
#   164.514   17 rows   Other requirements relating to uses and disclosures of protected health information
#   164.520    5 rows   Notice of privacy practices for protected health information
#   164.522    5 rows   Rights to request privacy protection for protected health information
#   164.524    5 rows   Access of individuals to protected health information
#   164.526    6 rows   Amendment of protected health information
#   164.528    4 rows   Accounting of disclosures of protected health information
#   164.530   21 rows   Administrative requirements
#
# How a row is decided (`basis` in the report):
#   facts        37 rows re-key this module's former fact checks (input.hipaa.privacy.*) to the paragraph each
#                condition implements. The former topic booleans and their report keys (notice_of_privacy_practices,
#                uses_and_disclosures, individual_rights, workforce, governance, ...) are dropped: no reader exists.
#   attestation  73 rows: input.hipaa.subpart_e["<id>"] == true. For the permissive standards (§ 164.510, § 164.512,
#                § 164.514(e)-(g), § 164.506(b)) true attests that every such use or disclosure the entity makes
#                meets the paragraph's conditions, or that it makes none.
# Applicability (gate): input.hipaa.scope flags (health_plan, health_care_provider, health_care_clearinghouse,
# business_associate, de_identifies_phi, conducts_fundraising) must each be declared true or false.
#   covered_entity: any of health_plan / health_care_provider / health_care_clearinghouse; "": any regulated
#   entity, including a business associate (§§ 164.502(a),(b),(e),(j), 164.504(e), 164.509); health_plan for the
#   group-health-plan and underwriting paragraphs; provider_or_plan for confidential communications; the
#   health_care_provider gate on facility directories; de_identifies_phi and conducts_fundraising for § 164.514(a)-(c)
#   and (f).
# § 164.509 and the reproductive-health provisions are printed in the 2025 edition and are carried as printed;
# whether they remain enforceable is a legal question outside this source.
# Fail-closed: missing or non-object input.hipaa.subpart_e is a FAIL-CLOSED violation; a failed fact, a non-true
# attestation, an unknown id or an undeclared scope flag is a violation.
# Breach notification (Subpart D) lives in hipaa.hitech; the Security Rule (Subpart C) in hipaa.security_rule.
#
# OPA endpoint: POST /v1/data/hipaa/privacy_rule/report

# METADATA
# title: "HIPAA Privacy Rule - 45 CFR 164.500-164.534, one control per Standard and Implementation specification (CFR citations)"
# custom:
#   class: compliance
#   framework: hipaa
#   source: hhs
#   domains: [privacy, healthcare]
#   coverage:
#     checks: 115
#     cited: 110
#     expected: 110
#     found: 110
#     scope: module
#     density: full
#     basis: declared-total
#     tested: true
#     entrypoint: report
#     guard: self
#     as_of: v2.4.2
package hipaa.privacy_rule

import rego.v1

source := {
	"regulation": "45 CFR Subtitle A, Subchapter C — Administrative Data Standards and Related Requirements (Parts 160, 162, 164)",
	"edition": "Code of Federal Regulations, Title 45, Volume 2, 2025 annual edition (GovInfo bulk XML)",
	"url": "https://www.govinfo.gov/bulkdata/CFR/2025/title-45/CFR-2025-title45-vol2.xml",
	"sha256": "5fb58263c7533af259dacbc0d72e097158b995551a0fb241c4f997d4ef856b52",
	"retrieved": "2026-10-13",
}

sections := {
	"164.502": "§ 164.502 Uses and disclosures of protected health information: General rules",
	"164.504": "§ 164.504 Uses and disclosures: Organizational requirements",
	"164.506": "§ 164.506 Uses and disclosures to carry out treatment, payment, or health care operations",
	"164.508": "§ 164.508 Uses and disclosures for which an authorization is required",
	"164.509": "§ 164.509 Uses and disclosures for which an attestation is required",
	"164.510": "§ 164.510 Uses and disclosures requiring an opportunity for the individual to agree or to object",
	"164.512": "§ 164.512 Uses and disclosures for which an authorization or opportunity to agree or object is not required",
	"164.514": "§ 164.514 Other requirements relating to uses and disclosures of protected health information",
	"164.520": "§ 164.520 Notice of privacy practices for protected health information",
	"164.522": "§ 164.522 Rights to request privacy protection for protected health information",
	"164.524": "§ 164.524 Access of individuals to protected health information",
	"164.526": "§ 164.526 Amendment of protected health information",
	"164.528": "§ 164.528 Accounting of disclosures of protected health information",
	"164.530": "§ 164.530 Administrative requirements",
}

scope_roles := {
	"health_plan": "45 CFR 160.103 - whether the entity is a health plan must be declared true or false",
	"health_care_provider": "45 CFR 160.103 - whether the entity is a covered health care provider must be declared true or false",
	"health_care_clearinghouse": "45 CFR 160.103 - whether the entity is a health care clearinghouse must be declared true or false",
	"business_associate": "45 CFR 160.103 - whether the entity acts as a business associate must be declared true or false",
	"de_identifies_phi": "45 CFR 164.514(a)-(c) - whether the entity de-identifies protected health information must be declared true or false",
	"conducts_fundraising": "45 CFR 164.514(f) - whether the entity uses or discloses protected health information for fundraising must be declared true or false",
}

# One row per labelled Standard / Implementation specification paragraph, keyed by CFR citation.
requirements_table := [
	{"id": "164.502(a)", "section": "164.502", "status": "standard", "gate": "", "title": "No use or disclosure of protected health information except as permitted or required by this subpart or by subpart C of part 160"},
	{"id": "164.502(b)", "section": "164.502", "status": "standard", "gate": "", "title": "Minimum necessary"},
	{"id": "164.502(c)", "section": "164.502", "status": "standard", "gate": "covered_entity", "title": "Uses and disclosures of protected health information subject to an agreed upon restriction"},
	{"id": "164.502(d)", "section": "164.502", "status": "standard", "gate": "covered_entity", "title": "Uses and disclosures of de-identified protected health information"},
	{"id": "164.502(e)(1)", "section": "164.502", "status": "standard", "gate": "", "title": "Disclosures to business associates"},
	{"id": "164.502(e)(2)", "section": "164.502", "status": "implementation specification", "gate": "", "title": "Documentation"},
	{"id": "164.502(f)", "section": "164.502", "status": "standard", "gate": "covered_entity", "title": "Deceased individuals"},
	{"id": "164.502(g)(1)", "section": "164.502", "status": "standard", "gate": "covered_entity", "title": "Personal representatives"},
	{"id": "164.502(g)(2)", "section": "164.502", "status": "implementation specification", "gate": "covered_entity", "title": "Adults and emancipated minors"},
	{"id": "164.502(g)(3)", "section": "164.502", "status": "implementation specification", "gate": "covered_entity", "title": "Unemancipated minors"},
	{"id": "164.502(g)(4)", "section": "164.502", "status": "implementation specification", "gate": "covered_entity", "title": "Deceased individuals"},
	{"id": "164.502(g)(5)", "section": "164.502", "status": "implementation specification", "gate": "covered_entity", "title": "Abuse, neglect, endangerment situations"},
	{"id": "164.502(h)", "section": "164.502", "status": "standard", "gate": "provider_or_plan", "title": "Confidential communications"},
	{"id": "164.502(i)", "section": "164.502", "status": "standard", "gate": "covered_entity", "title": "Uses and disclosures consistent with notice"},
	{"id": "164.502(j)", "section": "164.502", "status": "standard", "gate": "", "title": "Disclosures by whistleblowers and workforce member crime victims"},
	{"id": "164.504(e)(1)", "section": "164.504", "status": "standard", "gate": "", "title": "Business associate contracts"},
	{"id": "164.504(e)(2)", "section": "164.504", "status": "implementation specification", "gate": "", "title": "Business associate contracts"},
	{"id": "164.504(e)(3)", "section": "164.504", "status": "implementation specification", "gate": "", "title": "Other arrangements"},
	{"id": "164.504(e)(4)", "section": "164.504", "status": "implementation specification", "gate": "", "title": "Other requirements for contracts and other arrangements"},
	{"id": "164.504(e)(5)", "section": "164.504", "status": "implementation specification", "gate": "", "title": "Business associate contracts with subcontractors"},
	{"id": "164.504(f)(1)", "section": "164.504", "status": "standard", "gate": "health_plan", "title": "Requirements for group health plans"},
	{"id": "164.504(f)(2)", "section": "164.504", "status": "implementation specification", "gate": "health_plan", "title": "Requirements for plan documents"},
	{"id": "164.504(f)(3)", "section": "164.504", "status": "implementation specification", "gate": "health_plan", "title": "Uses and disclosures"},
	{"id": "164.504(g)", "section": "164.504", "status": "standard", "gate": "covered_entity", "title": "Requirements for a covered entity with multiple covered functions"},
	{"id": "164.506(a)", "section": "164.506", "status": "standard", "gate": "covered_entity", "title": "Permitted uses and disclosures"},
	{"id": "164.506(b)", "section": "164.506", "status": "standard", "gate": "covered_entity", "title": "Consent for uses and disclosures permitted"},
	{"id": "164.506(c)", "section": "164.506", "status": "implementation specification", "gate": "covered_entity", "title": "Treatment, payment, or health care operations"},
	{"id": "164.508(a)", "section": "164.508", "status": "standard", "gate": "covered_entity", "title": "Authorizations for uses and disclosures"},
	{"id": "164.508(b)", "section": "164.508", "status": "implementation specification", "gate": "covered_entity", "title": "Authorization general requirements"},
	{"id": "164.508(c)", "section": "164.508", "status": "implementation specification", "gate": "covered_entity", "title": "Authorization core elements and requirements"},
	{"id": "164.509(a)", "section": "164.509", "status": "standard", "gate": "", "title": "Attestations for certain uses and disclosures of protected health information to persons other than covered entities or business associates"},
	{"id": "164.509(b)", "section": "164.509", "status": "implementation specification", "gate": "", "title": "Attestation general requirements"},
	{"id": "164.509(c)", "section": "164.509", "status": "implementation specification", "gate": "", "title": "Attestation content requirements and other obligations"},
	{"id": "164.510(a)", "section": "164.510", "status": "standard", "gate": "health_care_provider", "title": "Use and disclosure for facility directories"},
	{"id": "164.510(b)", "section": "164.510", "status": "standard", "gate": "covered_entity", "title": "Uses and disclosures for involvement in the individual's care and notification purposes"},
	{"id": "164.512(a)", "section": "164.512", "status": "standard", "gate": "covered_entity", "title": "Uses and disclosures required by law"},
	{"id": "164.512(b)", "section": "164.512", "status": "standard", "gate": "covered_entity", "title": "Uses and disclosures for public health activities"},
	{"id": "164.512(c)", "section": "164.512", "status": "standard", "gate": "covered_entity", "title": "Disclosures about victims of abuse, neglect, or domestic violence"},
	{"id": "164.512(d)", "section": "164.512", "status": "standard", "gate": "covered_entity", "title": "Uses and disclosures for health oversight activities"},
	{"id": "164.512(e)", "section": "164.512", "status": "standard", "gate": "covered_entity", "title": "Disclosures for judicial and administrative proceedings"},
	{"id": "164.512(f)", "section": "164.512", "status": "standard", "gate": "covered_entity", "title": "Disclosures for law enforcement purposes"},
	{"id": "164.512(g)", "section": "164.512", "status": "standard", "gate": "covered_entity", "title": "Uses and disclosures about decedents"},
	{"id": "164.512(h)", "section": "164.512", "status": "standard", "gate": "covered_entity", "title": "Uses and disclosures for cadaveric organ, eye or tissue donation purposes"},
	{"id": "164.512(i)", "section": "164.512", "status": "standard", "gate": "covered_entity", "title": "Uses and disclosures for research purposes"},
	{"id": "164.512(j)", "section": "164.512", "status": "standard", "gate": "covered_entity", "title": "Uses and disclosures to avert a serious threat to health or safety"},
	{"id": "164.512(k)", "section": "164.512", "status": "standard", "gate": "covered_entity", "title": "Uses and disclosures for specialized government functions"},
	{"id": "164.512(l)", "section": "164.512", "status": "standard", "gate": "covered_entity", "title": "Disclosures for workers' compensation"},
	{"id": "164.514(a)", "section": "164.514", "status": "standard", "gate": "de_identifies_phi", "title": "De-identification of protected health information"},
	{"id": "164.514(b)", "section": "164.514", "status": "implementation specification", "gate": "de_identifies_phi", "title": "Requirements for de-identification of protected health information"},
	{"id": "164.514(c)", "section": "164.514", "status": "implementation specification", "gate": "de_identifies_phi", "title": "Re-identification"},
	{"id": "164.514(d)(1)", "section": "164.514", "status": "standard", "gate": "covered_entity", "title": "Minimum necessary requirements"},
	{"id": "164.514(d)(2)", "section": "164.514", "status": "implementation specification", "gate": "covered_entity", "title": "Minimum necessary uses of protected health information"},
	{"id": "164.514(d)(3)", "section": "164.514", "status": "implementation specification", "gate": "covered_entity", "title": "Minimum necessary disclosures of protected health information"},
	{"id": "164.514(d)(4)", "section": "164.514", "status": "implementation specification", "gate": "covered_entity", "title": "Minimum necessary requests for protected health information"},
	{"id": "164.514(d)(5)", "section": "164.514", "status": "implementation specification", "gate": "covered_entity", "title": "Other content requirement"},
	{"id": "164.514(e)(1)", "section": "164.514", "status": "standard", "gate": "covered_entity", "title": "Limited data set"},
	{"id": "164.514(e)(2)", "section": "164.514", "status": "implementation specification", "gate": "covered_entity", "title": "Limited data set (direct identifiers that must be excluded)"},
	{"id": "164.514(e)(3)", "section": "164.514", "status": "implementation specification", "gate": "covered_entity", "title": "Permitted purposes for uses and disclosures"},
	{"id": "164.514(e)(4)", "section": "164.514", "status": "implementation specification", "gate": "covered_entity", "title": "Data use agreement"},
	{"id": "164.514(f)(1)", "section": "164.514", "status": "standard", "gate": "conducts_fundraising", "title": "Uses and disclosures for fundraising"},
	{"id": "164.514(f)(2)", "section": "164.514", "status": "implementation specification", "gate": "conducts_fundraising", "title": "Fundraising requirements"},
	{"id": "164.514(g)", "section": "164.514", "status": "standard", "gate": "health_plan", "title": "Uses and disclosures for underwriting and related purposes"},
	{"id": "164.514(h)(1)", "section": "164.514", "status": "standard", "gate": "covered_entity", "title": "Verification requirements"},
	{"id": "164.514(h)(2)", "section": "164.514", "status": "implementation specification", "gate": "covered_entity", "title": "Verification"},
	{"id": "164.520(a)", "section": "164.520", "status": "standard", "gate": "covered_entity", "title": "Notice of privacy practices"},
	{"id": "164.520(b)", "section": "164.520", "status": "implementation specification", "gate": "covered_entity", "title": "Content of notice"},
	{"id": "164.520(c)", "section": "164.520", "status": "implementation specification", "gate": "covered_entity", "title": "Provision of notice"},
	{"id": "164.520(d)", "section": "164.520", "status": "implementation specification", "gate": "covered_entity", "title": "Joint notice by separate covered entities"},
	{"id": "164.520(e)", "section": "164.520", "status": "implementation specification", "gate": "covered_entity", "title": "Documentation"},
	{"id": "164.522(a)(1)", "section": "164.522", "status": "standard", "gate": "covered_entity", "title": "Right of an individual to request restriction of uses and disclosures"},
	{"id": "164.522(a)(2)", "section": "164.522", "status": "implementation specification", "gate": "covered_entity", "title": "Terminating a restriction"},
	{"id": "164.522(a)(3)", "section": "164.522", "status": "implementation specification", "gate": "covered_entity", "title": "Documentation"},
	{"id": "164.522(b)(1)", "section": "164.522", "status": "standard", "gate": "provider_or_plan", "title": "Confidential communications requirements"},
	{"id": "164.522(b)(2)", "section": "164.522", "status": "implementation specification", "gate": "provider_or_plan", "title": "Conditions on providing confidential communications"},
	{"id": "164.524(a)", "section": "164.524", "status": "standard", "gate": "covered_entity", "title": "Access to protected health information"},
	{"id": "164.524(b)", "section": "164.524", "status": "implementation specification", "gate": "covered_entity", "title": "Requests for access and timely action"},
	{"id": "164.524(c)", "section": "164.524", "status": "implementation specification", "gate": "covered_entity", "title": "Provision of access"},
	{"id": "164.524(d)", "section": "164.524", "status": "implementation specification", "gate": "covered_entity", "title": "Denial of access"},
	{"id": "164.524(e)", "section": "164.524", "status": "implementation specification", "gate": "covered_entity", "title": "Documentation"},
	{"id": "164.526(a)", "section": "164.526", "status": "standard", "gate": "covered_entity", "title": "Right to amend"},
	{"id": "164.526(b)", "section": "164.526", "status": "implementation specification", "gate": "covered_entity", "title": "Requests for amendment and timely action"},
	{"id": "164.526(c)", "section": "164.526", "status": "implementation specification", "gate": "covered_entity", "title": "Accepting the amendment"},
	{"id": "164.526(d)", "section": "164.526", "status": "implementation specification", "gate": "covered_entity", "title": "Denying the amendment"},
	{"id": "164.526(e)", "section": "164.526", "status": "implementation specification", "gate": "covered_entity", "title": "Actions on notices of amendment"},
	{"id": "164.526(f)", "section": "164.526", "status": "implementation specification", "gate": "covered_entity", "title": "Documentation"},
	{"id": "164.528(a)", "section": "164.528", "status": "standard", "gate": "covered_entity", "title": "Right to an accounting of disclosures of protected health information"},
	{"id": "164.528(b)", "section": "164.528", "status": "implementation specification", "gate": "covered_entity", "title": "Content of the accounting"},
	{"id": "164.528(c)", "section": "164.528", "status": "implementation specification", "gate": "covered_entity", "title": "Provision of the accounting"},
	{"id": "164.528(d)", "section": "164.528", "status": "implementation specification", "gate": "covered_entity", "title": "Documentation"},
	{"id": "164.530(a)(1)", "section": "164.530", "status": "standard", "gate": "covered_entity", "title": "Personnel designations"},
	{"id": "164.530(a)(2)", "section": "164.530", "status": "implementation specification", "gate": "covered_entity", "title": "Personnel designations"},
	{"id": "164.530(b)(1)", "section": "164.530", "status": "standard", "gate": "covered_entity", "title": "Training"},
	{"id": "164.530(b)(2)", "section": "164.530", "status": "implementation specification", "gate": "covered_entity", "title": "Training"},
	{"id": "164.530(c)(1)", "section": "164.530", "status": "standard", "gate": "covered_entity", "title": "Safeguards"},
	{"id": "164.530(c)(2)", "section": "164.530", "status": "implementation specification", "gate": "covered_entity", "title": "Safeguards"},
	{"id": "164.530(d)(1)", "section": "164.530", "status": "standard", "gate": "covered_entity", "title": "Complaints to the covered entity"},
	{"id": "164.530(d)(2)", "section": "164.530", "status": "implementation specification", "gate": "covered_entity", "title": "Documentation of complaints"},
	{"id": "164.530(e)(1)", "section": "164.530", "status": "standard", "gate": "covered_entity", "title": "Sanctions"},
	{"id": "164.530(e)(2)", "section": "164.530", "status": "implementation specification", "gate": "covered_entity", "title": "Documentation"},
	{"id": "164.530(f)", "section": "164.530", "status": "standard", "gate": "covered_entity", "title": "Mitigation"},
	{"id": "164.530(g)", "section": "164.530", "status": "standard", "gate": "covered_entity", "title": "Refraining from intimidating or retaliatory acts"},
	{"id": "164.530(h)", "section": "164.530", "status": "standard", "gate": "covered_entity", "title": "Waiver of rights"},
	{"id": "164.530(i)(1)", "section": "164.530", "status": "standard", "gate": "covered_entity", "title": "Policies and procedures"},
	{"id": "164.530(i)(2)", "section": "164.530", "status": "standard", "gate": "covered_entity", "title": "Changes to policies and procedures"},
	{"id": "164.530(i)(3)", "section": "164.530", "status": "implementation specification", "gate": "covered_entity", "title": "Changes in law"},
	{"id": "164.530(i)(4)", "section": "164.530", "status": "implementation specification", "gate": "covered_entity", "title": "Changes to privacy practices stated in the notice"},
	{"id": "164.530(i)(5)", "section": "164.530", "status": "implementation specification", "gate": "covered_entity", "title": "Changes to other policies or procedures"},
	{"id": "164.530(j)(1)", "section": "164.530", "status": "standard", "gate": "covered_entity", "title": "Documentation"},
	{"id": "164.530(j)(2)", "section": "164.530", "status": "implementation specification", "gate": "covered_entity", "title": "Retention period"},
	{"id": "164.530(k)", "section": "164.530", "status": "standard", "gate": "health_plan", "title": "Group health plans"},
]

requirements := {r.id: r | some r in requirements_table}

# Paragraphs of Subpart E that are not controls, with the reason.
out_of_scope := {
	"164.500": "Applicability - scoping, not an obligation",
	"164.501": "Definitions",
	"164.532": "Transition provisions (effect of prior authorizations and prior business associate contracts; deemed-compliance windows) - permissions for legacy instruments, not standing controls",
	"164.534": "Compliance dates for initial implementation of the privacy standards (2003/2004)",
	"164.535": "Severability",
}

fact_basis := {
	"164.502(b)": "input.hipaa.privacy.tpo.minimum_necessary.applied",
	"164.502(e)(2)": "input.hipaa.privacy.baa.{required_for_all_bas,inventory.maintained}",
	"164.504(e)(2)": "input.hipaa.privacy.baa.{uses_and_disclosures.limited,safeguards.required,phi_return_or_destruction.required,breach_reporting.required}",
	"164.504(e)(5)": "input.hipaa.privacy.baa.subcontractors.covered",
	"164.506(c)": "input.hipaa.privacy.tpo.{treatment,payment,operations}.uses_defined",
	"164.508(a)": "input.hipaa.privacy.authorization.required_for_non_tpo and input.hipaa.privacy.prohibited.{marketing.not_without_auth,sale_of_phi.not_permitted_without_auth}",
	"164.508(b)": "input.hipaa.privacy.authorization.records.retained_six_years",
	"164.508(c)": "input.hipaa.privacy.authorization.{elements.all_required_elements,elements.expiration_date,elements.revocation_right,copies_provided_to_individual}",
	"164.510(a)": "input.hipaa.privacy.rights.opt_out.facility_directory",
	"164.514(b)": "input.hipaa.privacy.de_identification.method.documented and the safe-harbor identifier removals (input.hipaa.privacy.de_identification.safe_harbor.*)",
	"164.514(d)(1)": "input.hipaa.privacy.minimum_necessary.policies.documented",
	"164.514(d)(2)": "input.hipaa.privacy.minimum_necessary.{role_based_access.implemented,workforce_access.limited_to_job_function}",
	"164.514(d)(3)": "input.hipaa.privacy.minimum_necessary.routine_disclosures.limited",
	"164.514(d)(4)": "input.hipaa.privacy.minimum_necessary.requests.limited_to_needed",
	"164.514(f)(2)": "input.hipaa.privacy.prohibited.fundraising.opt_out_provided and input.hipaa.privacy.rights.opt_out.fundraising",
	"164.520(b)": "input.hipaa.privacy.npp.{documented,plain_language,includes_uses_and_disclosures,includes_individual_rights,includes_complaint_process,includes_contact_info,reviewed_and_updated_as_needed}",
	"164.520(c)": "input.hipaa.privacy.npp.{provided_at_first_service,posted_in_facility,available_on_website}",
	"164.522(a)(1)": "input.hipaa.privacy.rights.restrictions.{process_defined,out_of_pocket_payment.must_honor}",
	"164.522(b)(1)": "input.hipaa.privacy.rights.confidential_communications.{process_defined,reasonable_requests_accommodated}",
	"164.524(b)": "input.hipaa.privacy.rights.access.{process_defined,response_within_30_days,extension_allowed_30_days}",
	"164.524(c)": "input.hipaa.privacy.rights.access.{fee_limited_to_cost,electronic_format_available,third_party_directed_allowed}",
	"164.524(d)": "input.hipaa.privacy.rights.access.denials.documented",
	"164.526(b)": "input.hipaa.privacy.rights.amendment.{process_defined,response_within_60_days}",
	"164.526(c)": "input.hipaa.privacy.rights.amendment.accepted.propagated_to_relevant_parties",
	"164.526(d)": "input.hipaa.privacy.rights.amendment.denials.basis_documented",
	"164.528(a)": "input.hipaa.privacy.rights.accounting.{tracking_implemented,six_years_retained,excludes_tpo}",
	"164.528(c)": "input.hipaa.privacy.rights.accounting.{provided_within_60_days,first_request_free}",
	"164.530(a)(1)": "input.hipaa.privacy.privacy_officer.{designated,contact_info.published}",
	"164.530(a)(2)": "input.hipaa.privacy.privacy_officer.responsibilities.documented",
	"164.530(b)(1)": "input.hipaa.privacy.workforce.training.{all_staff.completed,role_specific.implemented}",
	"164.530(b)(2)": "input.hipaa.privacy.workforce.training.{documented,new_hires.within_30_days,frequency.annual,records.maintained}",
	"164.530(d)(1)": "input.hipaa.privacy.complaints.{process.documented,contact_info.published,hhs_complaint_right.communicated,investigation.conducted}",
	"164.530(d)(2)": "input.hipaa.privacy.complaints.log.maintained",
	"164.530(e)(1)": "input.hipaa.privacy.sanctions.{policy.documented,applied_to_all_workforce,violations.investigated,consistent_application}",
	"164.530(g)": "input.hipaa.privacy.complaints.retaliation.prohibited",
	"164.530(j)(1)": "input.hipaa.privacy.documentation.{policies_and_procedures.maintained,accessible,communications.retained}",
	"164.530(j)(2)": "input.hipaa.privacy.documentation.retention_years >= 6",
}

# -----------------------------------------------------------------------------
# Fact checks, one per CFR paragraph (re-keyed from this module's former booleans)
# -----------------------------------------------------------------------------

_p := object.get(input, ["hipaa", "privacy"], {})

_fact_pass contains "164.502(b)" if _p.tpo.minimum_necessary.applied == true

_fact_pass contains "164.502(e)(2)" if {
	_p.baa.required_for_all_bas == true
	_p.baa.inventory.maintained == true
}

_fact_pass contains "164.504(e)(2)" if {
	_p.baa.uses_and_disclosures.limited == true
	_p.baa.safeguards.required == true
	_p.baa.phi_return_or_destruction.required == true
	_p.baa.breach_reporting.required == true
}

_fact_pass contains "164.504(e)(5)" if _p.baa.subcontractors.covered == true

_fact_pass contains "164.506(c)" if {
	_p.tpo.treatment.uses_defined == true
	_p.tpo.payment.uses_defined == true
	_p.tpo.operations.uses_defined == true
}

_fact_pass contains "164.508(a)" if {
	_p.authorization.required_for_non_tpo == true
	_p.prohibited.marketing.not_without_auth == true
	_p.prohibited.sale_of_phi.not_permitted_without_auth == true
}

_fact_pass contains "164.508(b)" if _p.authorization.records.retained_six_years == true

_fact_pass contains "164.508(c)" if {
	_p.authorization.elements.all_required_elements == true
	_p.authorization.elements.expiration_date == true
	_p.authorization.elements.revocation_right == true
	_p.authorization.copies_provided_to_individual == true
}

_fact_pass contains "164.510(a)" if _p.rights.opt_out.facility_directory == true

_fact_pass contains "164.514(b)" if {
	_p.de_identification.method.documented == true
	safe_harbor_de_identification
}

_fact_pass contains "164.514(d)(1)" if _p.minimum_necessary.policies.documented == true

_fact_pass contains "164.514(d)(2)" if {
	_p.minimum_necessary.role_based_access.implemented == true
	_p.minimum_necessary.workforce_access.limited_to_job_function == true
}

_fact_pass contains "164.514(d)(3)" if _p.minimum_necessary.routine_disclosures.limited == true

_fact_pass contains "164.514(d)(4)" if _p.minimum_necessary.requests.limited_to_needed == true

_fact_pass contains "164.514(f)(2)" if {
	_p.prohibited.fundraising.opt_out_provided == true
	_p.rights.opt_out.fundraising == true
}

_fact_pass contains "164.520(b)" if {
	_p.npp.documented == true
	_p.npp.plain_language == true
	_p.npp.includes_uses_and_disclosures == true
	_p.npp.includes_individual_rights == true
	_p.npp.includes_complaint_process == true
	_p.npp.includes_contact_info == true
	_p.npp.reviewed_and_updated_as_needed == true
}

_fact_pass contains "164.520(c)" if {
	_p.npp.provided_at_first_service == true
	_p.npp.posted_in_facility == true
	_p.npp.available_on_website == true
}

_fact_pass contains "164.522(a)(1)" if {
	_p.rights.restrictions.process_defined == true
	_p.rights.restrictions.out_of_pocket_payment.must_honor == true
}

_fact_pass contains "164.522(b)(1)" if {
	_p.rights.confidential_communications.process_defined == true
	_p.rights.confidential_communications.reasonable_requests_accommodated == true
}

_fact_pass contains "164.524(b)" if {
	_p.rights.access.process_defined == true
	_p.rights.access.response_within_30_days == true
	_p.rights.access.extension_allowed_30_days == true
}

_fact_pass contains "164.524(c)" if {
	_p.rights.access.fee_limited_to_cost == true
	_p.rights.access.electronic_format_available == true
	_p.rights.access.third_party_directed_allowed == true
}

_fact_pass contains "164.524(d)" if _p.rights.access.denials.documented == true

_fact_pass contains "164.526(b)" if {
	_p.rights.amendment.process_defined == true
	_p.rights.amendment.response_within_60_days == true
}

_fact_pass contains "164.526(c)" if _p.rights.amendment.accepted.propagated_to_relevant_parties == true

_fact_pass contains "164.526(d)" if _p.rights.amendment.denials.basis_documented == true

_fact_pass contains "164.528(a)" if {
	_p.rights.accounting.tracking_implemented == true
	_p.rights.accounting.six_years_retained == true
	_p.rights.accounting.excludes_tpo == true
}

_fact_pass contains "164.528(c)" if {
	_p.rights.accounting.provided_within_60_days == true
	_p.rights.accounting.first_request_free == true
}

_fact_pass contains "164.530(a)(1)" if {
	_p.privacy_officer.designated == true
	_p.privacy_officer.contact_info.published == true
}

_fact_pass contains "164.530(a)(2)" if _p.privacy_officer.responsibilities.documented == true

_fact_pass contains "164.530(b)(1)" if {
	_p.workforce.training.all_staff.completed == true
	_p.workforce.training.role_specific.implemented == true
}

_fact_pass contains "164.530(b)(2)" if {
	_p.workforce.training.documented == true
	_p.workforce.training.new_hires.within_30_days == true
	_p.workforce.training.frequency.annual == true
	_p.workforce.training.records.maintained == true
}

_fact_pass contains "164.530(d)(1)" if {
	_p.complaints.process.documented == true
	_p.complaints.contact_info.published == true
	_p.complaints.hhs_complaint_right.communicated == true
	_p.complaints.investigation.conducted == true
}

_fact_pass contains "164.530(d)(2)" if _p.complaints.log.maintained == true

_fact_pass contains "164.530(e)(1)" if {
	_p.sanctions.policy.documented == true
	_p.sanctions.applied_to_all_workforce == true
	_p.sanctions.violations.investigated == true
	_p.sanctions.consistent_application == true
}

_fact_pass contains "164.530(g)" if _p.complaints.retaliation.prohibited == true

_fact_pass contains "164.530(j)(1)" if {
	_p.documentation.policies_and_procedures.maintained == true
	_p.documentation.accessible == true
	_p.documentation.communications.retained == true
}

_fact_pass contains "164.530(j)(2)" if {
	is_number(_p.documentation.retention_years)
	_p.documentation.retention_years >= 6
}

# Safe-harbor identifier removals (§ 164.514(b)(2)), used by the 164.514(b) fact check.
default safe_harbor_de_identification := false

safe_harbor_de_identification if {
	input.hipaa.privacy.de_identification.safe_harbor.names.removed == true
	input.hipaa.privacy.de_identification.safe_harbor.geographic.zip_to_3digits_or_less == true
	input.hipaa.privacy.de_identification.safe_harbor.dates.age_over_89_obscured == true
	input.hipaa.privacy.de_identification.safe_harbor.phone_numbers.removed == true
	input.hipaa.privacy.de_identification.safe_harbor.ssn.removed == true
	input.hipaa.privacy.de_identification.safe_harbor.mrn.removed == true
	input.hipaa.privacy.de_identification.safe_harbor.health_plan_numbers.removed == true
	input.hipaa.privacy.de_identification.safe_harbor.account_numbers.removed == true
	input.hipaa.privacy.de_identification.safe_harbor.certificate_numbers.removed == true
	input.hipaa.privacy.de_identification.safe_harbor.device_identifiers.removed == true
	input.hipaa.privacy.de_identification.safe_harbor.urls.removed == true
	input.hipaa.privacy.de_identification.safe_harbor.ip_addresses.removed == true
	input.hipaa.privacy.de_identification.safe_harbor.biometric_identifiers.removed == true
	input.hipaa.privacy.de_identification.safe_harbor.full_face_photos.removed == true
	input.hipaa.privacy.de_identification.safe_harbor.unique_identifiers.removed == true
	input.hipaa.privacy.de_identification.safe_harbor.no_re_identification_knowledge == true
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
	msg := sprintf("HIPAA Privacy Rule Input Contract: %v (input.hipaa.scope.%v undeclared)", [text, k])
}

violations contains "HIPAA Privacy Rule Input Contract: FAIL-CLOSED - input.hipaa.scope declares no regulated role (health_plan, health_care_provider, health_care_clearinghouse or business_associate true); applicability under 45 CFR 160.102 cannot be established" if {
	count({k | some k in _roles; _scope[k] == true}) == 0
}

_attestations := a if {
	a := object.get(input, ["hipaa", "subpart_e"], null)
	is_object(a)
}

violations contains "HIPAA Privacy Rule: FAIL-CLOSED - attestations 'input.hipaa.subpart_e' were not supplied (or are not an object); this module cannot be evaluated and is reported non-compliant" if {
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
	some id, r in requirements
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

else := sprintf("not attested - input.hipaa.subpart_e[\"%v\"] must be true", [id])

violations contains msg if {
	some id, r in applicable
	not _satisfied(id)
	msg := sprintf("HIPAA %v %v (%v): %v", [id, r.title, r.status, _unmet(id)])
}

violations contains msg if {
	some id, _ in _attestations
	not requirements[id]
	msg := sprintf("HIPAA Privacy Rule Input Contract: attestation for unknown id %v - ids are the 45 CFR citations this module carries, for example 164.502(b)", [id])
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
	some id, r in requirements
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
	ids := {id | some id; r := requirements[id]; r.section == s}
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

report := {
	"standard": "HIPAA Privacy Rule (45 CFR Part 164 Subpart E, §§ 164.500-164.534)",
	"source": source,
	"compliant": compliant,
	"id_scheme": "45 CFR paragraph citation of each labelled Standard / Implementation specification, e.g. 164.514(d)(3)",
	"controls_total": count(requirements),
	"standard_total": 110, # 45 CFR 164.502-164.530: 55 Standard + 55 Implementation specification paragraphs (164.532 out of scope)
	"standards": count({id | some id; r := requirements[id]; r.status == "standard"}),
	"implementation_specifications": count({id | some id; r := requirements[id]; r.status == "implementation specification"}),
	"fact_evaluated": count(fact_basis),
	"attested": count(requirements) - count(fact_basis),
	"applicable": _n_applicable,
	"satisfied": _n_satisfied,
	"sections": section_reports,
	"requirements": row_status,
	"out_of_scope": out_of_scope,
	"violation_count": count(violations),
	"violations": violations,
}
