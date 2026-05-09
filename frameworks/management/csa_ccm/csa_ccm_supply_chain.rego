package csa_ccm.supply_chain

import rego.v1

default compliant := false

violations contains msg if {
    not input.csa_ccm.supply_chain.supplier_policy.policy_established
    msg := "STA-01: Supply chain security and third-party risk management policy not formally established"
}

violations contains msg if {
    not input.csa_ccm.supply_chain.supplier_policy.cloud_suppliers_in_scope
    msg := "STA-01: Cloud service providers and SaaS vendors not included in supply chain security policy scope"
}

violations contains msg if {
    not input.csa_ccm.supply_chain.supplier_policy.policy_reviewed_annually
    msg := "STA-01: Supply chain security policy not reviewed and updated at least annually"
}

violations contains msg if {
    not input.csa_ccm.supply_chain.supplier_assessments.assessments_conducted
    msg := "STA-02: Supplier security assessments not conducted before onboarding new cloud or technology vendors"
}

violations contains msg if {
    not input.csa_ccm.supply_chain.supplier_assessments.risk_tiering_applied
    msg := "STA-02: Risk tiering not applied to suppliers — assessment depth must be commensurate with the risk level of access granted"
}

violations contains msg if {
    not input.csa_ccm.supply_chain.supplier_assessments.reassessments_conducted_periodically
    msg := "STA-02: Supplier security reassessments not conducted periodically — third-party risk must be reviewed regularly"
}

violations contains msg if {
    not input.csa_ccm.supply_chain.supplier_assessments.questionnaires_or_audits_used
    msg := "STA-02: Standardized security questionnaires (CAIQ, SIG) or audits not used for supplier assessments"
}

violations contains msg if {
    not input.csa_ccm.supply_chain.supplier_assessments.certifications_reviewed
    msg := "STA-02: Supplier security certifications (ISO 27001, SOC 2, FedRAMP) not reviewed as part of assessment"
}

violations contains msg if {
    not input.csa_ccm.supply_chain.third_party_risk.risk_management_program_exists
    msg := "STA-03: Third-party risk management program not established — structured approach to managing vendor risk required"
}

violations contains msg if {
    not input.csa_ccm.supply_chain.third_party_risk.risk_register_includes_vendors
    msg := "STA-03: Third-party and vendor risks not included in enterprise risk register"
}

violations contains msg if {
    not input.csa_ccm.supply_chain.third_party_risk.critical_vendors_identified
    msg := "STA-03: Critical vendors and dependencies not identified — concentration risk and single-vendor dependency must be assessed"
}

violations contains msg if {
    not input.csa_ccm.supply_chain.third_party_risk.vendor_risk_monitoring_ongoing
    msg := "STA-03: Ongoing vendor risk monitoring not implemented — continuous monitoring for changes in vendor risk posture required"
}

violations contains msg if {
    not input.csa_ccm.supply_chain.subprocessor_inventory.inventory_maintained
    msg := "STA-04: Subprocessor inventory not maintained — all third parties that process data on behalf of the organization must be catalogued"
}

violations contains msg if {
    not input.csa_ccm.supply_chain.subprocessor_inventory.data_sharing_documented
    msg := "STA-04: Data sharing with subprocessors not documented — what data is shared, why, and under what terms must be recorded"
}

violations contains msg if {
    not input.csa_ccm.supply_chain.subprocessor_inventory.subprocessor_changes_managed
    msg := "STA-04: Process not defined for managing changes to the subprocessor inventory — customers must be notified where required"
}

violations contains msg if {
    not input.csa_ccm.supply_chain.subprocessor_inventory.subprocessors_assessed
    msg := "STA-04: Subprocessors not assessed for security controls — downstream data processors must meet equivalent security standards"
}

violations contains msg if {
    not input.csa_ccm.supply_chain.contract_requirements.security_requirements_in_contracts
    msg := "STA-05: Security requirements not included in supplier and cloud provider contracts"
}

violations contains msg if {
    not input.csa_ccm.supply_chain.contract_requirements.right_to_audit_included
    msg := "STA-05: Right to audit or audit report provision not included in supplier contracts"
}

violations contains msg if {
    not input.csa_ccm.supply_chain.contract_requirements.incident_notification_sla_included
    msg := "STA-05: Incident notification SLA not included in supplier contracts — vendors must notify of breaches within required timeframe"
}

violations contains msg if {
    not input.csa_ccm.supply_chain.contract_requirements.data_handling_requirements_specified
    msg := "STA-05: Data handling, protection, and deletion requirements not specified in supplier contracts"
}

violations contains msg if {
    not input.csa_ccm.supply_chain.contract_requirements.termination_provisions_included
    msg := "STA-05: Contract termination provisions not included — data return and deletion upon contract end must be addressed"
}

violations contains msg if {
    not input.csa_ccm.supply_chain.transparency.csp_transparency_report_reviewed
    msg := "STA-06: Cloud service provider transparency reports not reviewed — government access requests and security disclosures must be assessed"
}

violations contains msg if {
    not input.csa_ccm.supply_chain.transparency.csp_shared_responsibility_understood
    msg := "STA-06: Cloud shared responsibility model not formally documented and understood for each cloud service used"
}

violations contains msg if {
    not input.csa_ccm.supply_chain.transparency.csp_security_posture_reviewed
    msg := "STA-06: CSP security posture reports (SOC 2, ISO 27001 certificates) not reviewed at least annually"
}

violations contains msg if {
    not input.csa_ccm.supply_chain.software_supply_chain.sbom_maintained
    msg := "STA-07: Software bill of materials (SBOM) not maintained — software components and their origins must be tracked"
}

violations contains msg if {
    not input.csa_ccm.supply_chain.software_supply_chain.build_pipeline_integrity
    msg := "STA-07: Build pipeline integrity not verified — CI/CD pipelines must be secured against supply chain compromise"
}

violations contains msg if {
    not input.csa_ccm.supply_chain.software_supply_chain.third_party_code_reviewed
    msg := "STA-07: Third-party code and libraries not reviewed for security risks before use in production"
}

violations contains msg if {
    not input.csa_ccm.supply_chain.offboarding.vendor_offboarding_procedure_defined
    msg := "STA-08: Vendor offboarding procedure not defined — structured process for terminating supplier relationships required"
}

violations contains msg if {
    not input.csa_ccm.supply_chain.offboarding.data_retrieved_or_deleted_on_exit
    msg := "STA-08: Data retrieval or deletion from outgoing vendors not verified — all organizational data must be accounted for at contract end"
}

violations contains msg if {
    not input.csa_ccm.supply_chain.offboarding.access_revoked_on_termination
    msg := "STA-08: Supplier access revoked promptly upon contract termination — all credentials and access paths must be removed"
}

violations contains msg if {
    not input.csa_ccm.supply_chain.incident_response.vendor_ir_coordination_defined
    msg := "STA-09: Vendor incident response coordination not defined — process for coordinating response with suppliers during shared incidents required"
}

violations contains msg if {
    not input.csa_ccm.supply_chain.incident_response.vendor_notification_requirements_enforced
    msg := "STA-09: Vendor security incident notification requirements not enforced through contracts and monitoring"
}

compliant if { count(violations) == 0 }

compliance_report := {
    "domain": "STA — Supply Chain Management, Transparency & Accountability",
    "compliant": compliant,
    "violation_count": count(violations),
    "violations": violations,
}
