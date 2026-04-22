package tisax.main

import rego.v1

# TISAX — Trusted Information Security Assessment Exchange
# Assessment Levels: AL 1 (normal), AL 2 (high), AL 3 (very high)
# Based on: VDA ISA (Information Security Assessment) Catalog v6.0.3 (2023)
# Managed by: ENX Association (European automotive exchange network)
#
# Applies to:
#   - Automotive OEMs (BMW, VW, Mercedes, Stellantis, Renault, etc.)
#   - Tier 1, 2, and 3 automotive suppliers
#   - Engineering service providers handling vehicle designs, prototypes, test data
#   - IT/technology vendors to automotive industry
#
# Three assessment objectives:
#   IS  — Information Security (all three ALs)
#   PD  — Prototype and Test Vehicle Protection (AL 2 and 3 for prototype handling)
#   SD  — Connection to Third Parties / Availability of IT Systems (AL 2 and 3 for special requirements)
#
# VDA ISA Control Domains:
#   1.x — Information Security Management
#   2.x — Security Organization and Responsibilities
#   3.x — Asset Management
#   4.x — Physical Security
#   5.x — IT Security
#   6.x — Identity and Access Management
#   7.x — Third Party Management
#   8.x — Incident Management
#   9.x — Compliance and Auditing
#
# OPA endpoint: POST http://<host>:8182/v1/data/tisax/main/compliance_report

default compliant := false

compliant if {
    count(violations) == 0
}

# ── 1.x — Information Security Management ────────────────────────────────────

violations contains msg if {
    not input.isms.established
    msg := "TISAX VDA ISA 1.1.1: Information Security Management System (ISMS) not established and maintained"
}

violations contains msg if {
    not input.isms.scope.defined
    msg := "TISAX VDA ISA 1.1.2: ISMS scope not formally defined to include automotive customer information"
}

violations contains msg if {
    not input.isms.policies.information_security.documented
    msg := "TISAX VDA ISA 1.2.1: Information security policy not documented and approved by top management"
}

violations contains msg if {
    not input.isms.policies.annual_review
    msg := "TISAX VDA ISA 1.2.2: Information security policies not reviewed at least annually"
}

violations contains msg if {
    not input.isms.risk_assessment.conducted
    msg := "TISAX VDA ISA 1.3.1: Information security risk assessment not conducted for automotive customer data"
}

violations contains msg if {
    not input.isms.risk_treatment.plan_documented
    msg := "TISAX VDA ISA 1.3.2: Risk treatment plan not documented with accepted residual risks"
}

violations contains msg if {
    not input.isms.internal_audit.conducted_annually
    msg := "TISAX VDA ISA 1.4.1: Internal ISMS audits not conducted at least annually"
}

violations contains msg if {
    not input.isms.management_review.conducted
    msg := "TISAX VDA ISA 1.4.2: Management review of ISMS not conducted at defined intervals"
}

violations contains msg if {
    not input.isms.continuous_improvement.process
    msg := "TISAX VDA ISA 1.5.1: Continual improvement process not established for the ISMS"
}

# ── 2.x — Security Organization and Responsibilities ─────────────────────────

violations contains msg if {
    not input.organization.isms_responsible.designated
    msg := "TISAX VDA ISA 2.1.1: Responsible person for information security not designated (CISO or equivalent)"
}

violations contains msg if {
    not input.organization.security_roles.defined
    msg := "TISAX VDA ISA 2.1.2: Information security roles and responsibilities not defined and communicated"
}

violations contains msg if {
    not input.organization.confidentiality.agreements_signed
    msg := "TISAX VDA ISA 2.2.1: Confidentiality agreements not signed by personnel handling OEM sensitive information"
}

violations contains msg if {
    not input.organization.hr_security.joiners_process
    msg := "TISAX VDA ISA 2.2.2: Security screening and onboarding process not established for new employees with sensitive access"
}

violations contains msg if {
    not input.organization.hr_security.leavers_process
    msg := "TISAX VDA ISA 2.2.3: Offboarding process not established — access rights not revoked upon termination"
}

violations contains msg if {
    not input.organization.training.security_awareness.annual
    msg := "TISAX VDA ISA 2.3.1: Annual security awareness training not provided to all personnel handling OEM data"
}

# ── 3.x — Asset Management ────────────────────────────────────────────────────

violations contains msg if {
    not input.assets.inventory.maintained
    msg := "TISAX VDA ISA 3.1.1: Asset inventory not maintained for information assets containing OEM sensitive data"
}

violations contains msg if {
    not input.assets.classification.scheme
    msg := "TISAX VDA ISA 3.1.2: Information classification scheme not established (e.g., confidential, internal, public)"
}

violations contains msg if {
    not input.assets.oem_data.classified_appropriately
    msg := "TISAX VDA ISA 3.1.3: OEM-provided information not classified according to OEM classification requirements"
}

violations contains msg if {
    not input.assets.media.secure_handling
    msg := "TISAX VDA ISA 3.2.1: Removable media containing OEM sensitive data not securely handled and controlled"
}

violations contains msg if {
    not input.assets.disposal.secure_data_destruction
    msg := "TISAX VDA ISA 3.2.2: Secure data destruction process not established for media containing OEM sensitive information"
}

# ── 4.x — Physical Security ───────────────────────────────────────────────────

violations contains msg if {
    not input.physical_security.zones.defined
    msg := "TISAX VDA ISA 4.1.1: Physical security zones for OEM sensitive information not defined"
}

violations contains msg if {
    not input.physical_security.access_control.implemented
    msg := "TISAX VDA ISA 4.1.2: Physical access controls not implemented for areas containing OEM sensitive systems"
}

violations contains msg if {
    not input.physical_security.visitor_management.logged
    msg := "TISAX VDA ISA 4.1.3: Visitor access to secured areas not logged and escorted"
}

violations contains msg if {
    not input.physical_security.clear_desk.policy
    msg := "TISAX VDA ISA 4.2.1: Clear desk and clear screen policy not established for OEM sensitive information"
}

# ── 5.x — IT Security ──────────────────────────────────────────────────────────

violations contains msg if {
    not input.it_security.network_segmentation.ot_it_separated
    msg := "TISAX VDA ISA 5.1.1: Network not segmented to separate OEM sensitive systems from general IT"
}

violations contains msg if {
    not input.it_security.encryption.data_at_rest
    msg := "TISAX VDA ISA 5.1.2: OEM sensitive data not encrypted at rest on storage systems"
}

violations contains msg if {
    not input.it_security.encryption.data_in_transit
    msg := "TISAX VDA ISA 5.1.3: OEM sensitive data not encrypted in transit (TLS 1.2+ required)"
}

violations contains msg if {
    not input.it_security.vulnerability_management.scanning
    msg := "TISAX VDA ISA 5.2.1: Regular vulnerability scanning not performed on systems processing OEM data"
}

violations contains msg if {
    not input.it_security.patch_management.timely
    msg := "TISAX VDA ISA 5.2.2: Timely patching of systems processing OEM sensitive data not implemented"
}

violations contains msg if {
    not input.it_security.malware.protection_deployed
    msg := "TISAX VDA ISA 5.3.1: Malware protection not deployed on all systems processing OEM data"
}

violations contains msg if {
    not input.it_security.backup.tested_regularly
    msg := "TISAX VDA ISA 5.4.1: Backup procedures for OEM data not established and regularly tested"
}

violations contains msg if {
    not input.it_security.change_management.formal_process
    msg := "TISAX VDA ISA 5.5.1: Formal change management process not established for systems processing OEM data"
}

violations contains msg if {
    not input.it_security.penetration_testing.conducted
    msg := "TISAX VDA ISA 5.6.1: Penetration testing not conducted to verify security of OEM data systems"
}

# ── 6.x — Identity and Access Management ─────────────────────────────────────

violations contains msg if {
    not input.iam.access_control.least_privilege
    msg := "TISAX VDA ISA 6.1.1: Least privilege not enforced for access to OEM sensitive information"
}

violations contains msg if {
    not input.iam.access_control.need_to_know
    msg := "TISAX VDA ISA 6.1.2: Access to OEM sensitive data not restricted on need-to-know basis"
}

violations contains msg if {
    not input.iam.authentication.strong_policy
    msg := "TISAX VDA ISA 6.2.1: Strong authentication not enforced for access to OEM sensitive systems"
}

violations contains msg if {
    not input.iam.privileged_access.managed
    msg := "TISAX VDA ISA 6.2.2: Privileged access to OEM data systems not managed through formal process"
}

violations contains msg if {
    not input.iam.remote_access.mfa_enforced
    msg := "TISAX VDA ISA 6.3.1: MFA not enforced for remote access to systems containing OEM data"
}

violations contains msg if {
    not input.iam.access_review.periodic
    msg := "TISAX VDA ISA 6.4.1: Periodic review of access rights to OEM sensitive data not conducted"
}

# ── 7.x — Third Party Management ──────────────────────────────────────────────

violations contains msg if {
    not input.third_party.assessment.security_evaluation
    msg := "TISAX VDA ISA 7.1.1: Security evaluation not performed for third parties accessing OEM sensitive information"
}

violations contains msg if {
    not input.third_party.contracts.security_requirements
    msg := "TISAX VDA ISA 7.1.2: Security requirements not included in contracts with third parties handling OEM data"
}

violations contains msg if {
    not input.third_party.subcontractors.tisax_or_equivalent
    msg := "TISAX VDA ISA 7.1.3: Subcontractors handling OEM data not required to meet TISAX or equivalent security standard"
}

violations contains msg if {
    not input.third_party.cloud.assessment_performed
    msg := "TISAX VDA ISA 7.2.1: Security assessment not performed before storing OEM sensitive data in cloud environments"
}

# ── 8.x — Incident Management ─────────────────────────────────────────────────

violations contains msg if {
    not input.incident_management.plan.documented
    msg := "TISAX VDA ISA 8.1.1: Information security incident management plan not documented"
}

violations contains msg if {
    not input.incident_management.oem_notification.process
    msg := "TISAX VDA ISA 8.1.2: Process not established to notify OEM customers of security incidents affecting their data"
}

violations contains msg if {
    not input.incident_management.plan.tested
    msg := "TISAX VDA ISA 8.1.3: Incident management plan not periodically tested"
}

# ── 9.x — Compliance and Auditing ─────────────────────────────────────────────

violations contains msg if {
    not input.compliance.legal_requirements.identified
    msg := "TISAX VDA ISA 9.1.1: Legal, regulatory, and contractual information security requirements not identified"
}

violations contains msg if {
    not input.compliance.oem_requirements.implemented
    msg := "TISAX VDA ISA 9.1.2: OEM-specific information security contractual requirements not fully implemented"
}

violations contains msg if {
    not input.compliance.audit_trail.maintained
    msg := "TISAX VDA ISA 9.2.1: Audit trail not maintained for access to and processing of OEM sensitive data"
}

# ── Prototype and Test Vehicle Protection (PD) — AL 2/3 ──────────────────────

violations contains msg if {
    input.assessment_level >= 2
    not input.prototype_protection.handling.procedures_documented
    msg := "TISAX PD AL2: Prototype handling procedures not documented — physical protection of pre-series vehicles not defined"
}

violations contains msg if {
    input.assessment_level >= 2
    not input.prototype_protection.photography.controls
    msg := "TISAX PD AL2: Photography and recording controls not established for prototype/test vehicle environments"
}

violations contains msg if {
    input.assessment_level >= 2
    not input.prototype_protection.transport.secured
    msg := "TISAX PD AL2: Secure transport procedures not established for prototypes and test vehicles"
}

# ── Compliance Report ────────────────────────────────────────────────────────

compliance_report := {
    "framework":           "TISAX (Trusted Information Security Assessment Exchange)",
    "catalog":             "VDA ISA v6.0.3",
    "assessment_level":    input.assessment_level,
    "entity_name":         input.entity_name,
    "company_scope":       input.company_scope,
    "assessed_at":         input.assessment_date,
    "compliant":           compliant,
    "total_controls":      51,
    "violations":          violations,
    "violation_count":     count(violations),
    "domain_summary": {
        "isms_management":          [v | some v in violations; contains(v, "ISA 1.")],
        "security_organization":    [v | some v in violations; contains(v, "ISA 2.")],
        "asset_management":         [v | some v in violations; contains(v, "ISA 3.")],
        "physical_security":        [v | some v in violations; contains(v, "ISA 4.")],
        "it_security":              [v | some v in violations; contains(v, "ISA 5.")],
        "iam":                      [v | some v in violations; contains(v, "ISA 6.")],
        "third_party":              [v | some v in violations; contains(v, "ISA 7.")],
        "incident_management":      [v | some v in violations; contains(v, "ISA 8.")],
        "compliance_auditing":      [v | some v in violations; contains(v, "ISA 9.")],
        "prototype_protection":     [v | some v in violations; contains(v, "TISAX PD")],
    },
}
