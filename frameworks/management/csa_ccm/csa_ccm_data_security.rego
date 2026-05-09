package csa_ccm.data_security

import rego.v1

default compliant := false

violations contains msg if {
    not input.csa_ccm.data_security.classification.policy_established
    msg := "DSP-01: Data security and privacy lifecycle management policy not formally established"
}

violations contains msg if {
    not input.csa_ccm.data_security.classification.classification_scheme_defined
    msg := "DSP-01: Data classification scheme not defined — categories and handling requirements must be documented"
}

violations contains msg if {
    not input.csa_ccm.data_security.classification.cloud_data_in_scope
    msg := "DSP-01: Cloud-stored and cloud-processed data not included in data security policy scope"
}

violations contains msg if {
    not input.csa_ccm.data_security.classification.policy_reviewed_annually
    msg := "DSP-01: Data security policy not reviewed and updated at least annually"
}

violations contains msg if {
    not input.csa_ccm.data_security.labeling.labeling_implemented
    msg := "DSP-02: Data labeling not implemented — data must be labeled according to classification scheme"
}

violations contains msg if {
    not input.csa_ccm.data_security.labeling.sensitive_data_labeled
    msg := "DSP-02: Sensitive and regulated data not consistently labeled across all storage and processing systems"
}

violations contains msg if {
    not input.csa_ccm.data_security.labeling.labeling_enforced_at_creation
    msg := "DSP-02: Data labeling not enforced at the time of data creation or ingestion"
}

violations contains msg if {
    not input.csa_ccm.data_security.retention.retention_policy_defined
    msg := "DSP-03: Data retention policy not defined — retention periods must align with legal and regulatory requirements"
}

violations contains msg if {
    not input.csa_ccm.data_security.retention.retention_schedules_documented
    msg := "DSP-03: Data retention schedules not documented per data classification category"
}

violations contains msg if {
    not input.csa_ccm.data_security.retention.retention_enforced_technically
    msg := "DSP-03: Data retention not enforced through technical controls — automated retention mechanisms must be implemented"
}

violations contains msg if {
    not input.csa_ccm.data_security.retention.legal_hold_process_defined
    msg := "DSP-03: Legal hold process not defined to preserve data beyond normal retention periods when required"
}

violations contains msg if {
    not input.csa_ccm.data_security.disposal.disposal_procedures_defined
    msg := "DSP-04: Data disposal procedures not defined — secure deletion methods must be documented per data type"
}

violations contains msg if {
    not input.csa_ccm.data_security.disposal.secure_deletion_used
    msg := "DSP-04: Secure deletion techniques not used — data must be rendered unrecoverable upon disposal"
}

violations contains msg if {
    not input.csa_ccm.data_security.disposal.cloud_data_deletion_verified
    msg := "DSP-04: Deletion of data from cloud provider systems not verified — confirmation of deletion must be obtained"
}

violations contains msg if {
    not input.csa_ccm.data_security.disposal.disposal_records_maintained
    msg := "DSP-04: Records of data disposal not maintained for audit and compliance purposes"
}

violations contains msg if {
    not input.csa_ccm.data_security.dlp.dlp_controls_implemented
    msg := "DSP-05: Data loss prevention (DLP) controls not implemented for sensitive data"
}

violations contains msg if {
    not input.csa_ccm.data_security.dlp.egress_monitoring_enabled
    msg := "DSP-05: Data egress monitoring not enabled — unauthorized data exfiltration must be detected"
}

violations contains msg if {
    not input.csa_ccm.data_security.dlp.dlp_policies_cover_cloud
    msg := "DSP-05: DLP policies do not cover cloud storage and SaaS applications"
}

violations contains msg if {
    not input.csa_ccm.data_security.dlp.dlp_alerts_reviewed
    msg := "DSP-05: DLP alerts not reviewed by security personnel within defined response timeframe"
}

violations contains msg if {
    not input.csa_ccm.data_security.privacy.privacy_notice_provided
    msg := "DSP-06: Privacy notice not provided to data subjects informing them of data collection and use"
}

violations contains msg if {
    not input.csa_ccm.data_security.privacy.consent_mechanism_implemented
    msg := "DSP-06: Consent mechanism not implemented where required by applicable privacy regulations"
}

violations contains msg if {
    not input.csa_ccm.data_security.privacy.data_subject_rights_honored
    msg := "DSP-06: Data subject rights (access, erasure, portability, correction) not honored within required timeframes"
}

violations contains msg if {
    not input.csa_ccm.data_security.privacy.privacy_impact_assessments_conducted
    msg := "DSP-06: Privacy impact assessments not conducted for new processing activities involving personal data"
}

violations contains msg if {
    not input.csa_ccm.data_security.data_flows.data_flows_mapped
    msg := "DSP-07: Data flows not mapped — movement of sensitive data across systems and boundaries must be documented"
}

violations contains msg if {
    not input.csa_ccm.data_security.data_flows.data_flow_diagrams_maintained
    msg := "DSP-07: Data flow diagrams not maintained and updated when systems or processes change"
}

violations contains msg if {
    not input.csa_ccm.data_security.data_flows.unauthorized_flows_detected
    msg := "DSP-07: Controls not implemented to detect unauthorized data flows or unexpected data movement"
}

violations contains msg if {
    not input.csa_ccm.data_security.cross_border.transfer_restrictions_assessed
    msg := "DSP-08: Cross-border data transfer restrictions not assessed for applicable jurisdictions"
}

violations contains msg if {
    not input.csa_ccm.data_security.cross_border.transfer_mechanisms_documented
    msg := "DSP-08: Legal mechanisms for cross-border data transfers (SCCs, BCRs, adequacy decisions) not documented"
}

violations contains msg if {
    not input.csa_ccm.data_security.cross_border.cloud_region_data_residency_enforced
    msg := "DSP-08: Data residency requirements not enforced in cloud provider configuration"
}

violations contains msg if {
    not input.csa_ccm.data_security.data_inventory.inventory_maintained
    msg := "DSP-09: Data inventory not maintained — all sensitive and regulated data assets must be catalogued"
}

violations contains msg if {
    not input.csa_ccm.data_security.data_inventory.data_owners_assigned
    msg := "DSP-09: Data owners not assigned for sensitive and regulated data assets"
}

violations contains msg if {
    not input.csa_ccm.data_security.data_inventory.inventory_reviewed_regularly
    msg := "DSP-09: Data inventory not reviewed and updated regularly to reflect changes in data holdings"
}

violations contains msg if {
    not input.csa_ccm.data_security.access_to_data.access_based_on_classification
    msg := "DSP-10: Access to sensitive data not restricted based on data classification level"
}

violations contains msg if {
    not input.csa_ccm.data_security.access_to_data.least_privilege_enforced
    msg := "DSP-10: Least-privilege access not enforced for systems and users accessing sensitive data"
}

violations contains msg if {
    not input.csa_ccm.data_security.access_to_data.privileged_data_access_logged
    msg := "DSP-10: Access to sensitive and regulated data not logged for audit and anomaly detection purposes"
}

compliant if { count(violations) == 0 }

compliance_report := {
    "domain": "DSP — Data Security & Privacy Lifecycle Management",
    "compliant": compliant,
    "violation_count": count(violations),
    "violations": violations,
}
