package iso27701.pii_controller

import rego.v1

violations contains msg if {
	not input.iso27701.pii_controller.collection_conditions.purposes_documented
	msg := "ISO 27701 7.2.1: Purposes of PII processing not identified and documented"
}

violations contains msg if {
	not input.iso27701.pii_controller.collection_conditions.lawful_basis_per_purpose
	msg := "ISO 27701 7.2.2: Lawful basis not identified for each processing purpose"
}

violations contains msg if {
	not input.iso27701.pii_controller.collection_conditions.consent_timing_defined
	msg := "ISO 27701 7.2.3: When and how consent is to be obtained not determined"
}

violations contains msg if {
	not input.iso27701.pii_controller.collection_conditions.consent_obtained_and_recorded
	msg := "ISO 27701 7.2.4: Consent not obtained and recorded from PII principals"
}

violations contains msg if {
	not input.iso27701.pii_controller.collection_conditions.privacy_notices_provided
	msg := "ISO 27701 7.2.5: Privacy notices not provided to PII principals"
}

violations contains msg if {
	not input.iso27701.pii_controller.collection_conditions.processor_contracts_include_dpo
	msg := "ISO 27701 7.2.6: Contracts with PII processors do not include data protection obligations"
}

violations contains msg if {
	not input.iso27701.pii_controller.collection_conditions.joint_controllership_documented
	msg := "ISO 27701 7.2.7: Joint controllership arrangements not documented"
}

violations contains msg if {
	not input.iso27701.pii_controller.pii_principal_obligations.obligations_determined
	msg := "ISO 27701 7.3.1: Obligations to PII principals and means to fulfill them not determined"
}

violations contains msg if {
	not input.iso27701.pii_controller.pii_principal_obligations.notice_at_collection
	msg := "ISO 27701 7.3.2: Privacy notice not provided to PII principals at point of collection"
}

violations contains msg if {
	not input.iso27701.pii_controller.pii_principal_obligations.consent_modification_mechanism
	msg := "ISO 27701 7.3.3: Mechanism for PII principals to modify or withdraw consent not provided"
}

violations contains msg if {
	not input.iso27701.pii_controller.pii_principal_obligations.access_mechanism
	msg := "ISO 27701 7.3.4: Mechanism for PII principals to access their PII upon request not provided"
}

violations contains msg if {
	not input.iso27701.pii_controller.pii_principal_obligations.erasure_mechanism
	msg := "ISO 27701 7.3.5: Mechanism for erasure and right to be forgotten not provided"
}

violations contains msg if {
	not input.iso27701.pii_controller.pii_principal_obligations.portability_mechanism
	msg := "ISO 27701 7.3.6: Mechanism for data portability not provided"
}

violations contains msg if {
	not input.iso27701.pii_controller.pii_principal_obligations.complaints_handled
	msg := "ISO 27701 7.3.7: Process to handle complaints from PII principals not established"
}

violations contains msg if {
	not input.iso27701.pii_controller.pii_principal_obligations.automated_decision_safeguards
	msg := "ISO 27701 7.3.8: Safeguards for automated decision-making not implemented"
}

violations contains msg if {
	not input.iso27701.pii_controller.privacy_by_design.collection_limited
	msg := "ISO 27701 7.4.1: PII collection not limited (data minimization principle not applied)"
}

violations contains msg if {
	not input.iso27701.pii_controller.privacy_by_design.processing_limited
	msg := "ISO 27701 7.4.2: PII processing not limited to disclosed purposes (purpose limitation not applied)"
}

violations contains msg if {
	not input.iso27701.pii_controller.privacy_by_design.accuracy_maintained
	msg := "ISO 27701 7.4.3: Accuracy and quality of PII not maintained"
}

violations contains msg if {
	not input.iso27701.pii_controller.privacy_by_design.minimization_goals_defined
	msg := "ISO 27701 7.4.4: PII minimization goals not defined"
}

violations contains msg if {
	not input.iso27701.pii_controller.privacy_by_design.deidentification_and_deletion
	msg := "ISO 27701 7.4.5: PII de-identification and deletion processes not established"
}

violations contains msg if {
	not input.iso27701.pii_controller.privacy_by_design.temporary_files_disposed
	msg := "ISO 27701 7.4.6: Temporary files containing PII not disposed of appropriately"
}

violations contains msg if {
	not input.iso27701.pii_controller.privacy_by_design.retention_schedule_enforced
	msg := "ISO 27701 7.4.7: Retention schedule for PII not established or not enforced"
}

violations contains msg if {
	not input.iso27701.pii_controller.privacy_by_design.transmission_controls
	msg := "ISO 27701 7.4.8: Transmission controls for PII not implemented"
}

violations contains msg if {
	not input.iso27701.pii_controller.pii_sharing.transfer_basis_established
	msg := "ISO 27701 7.5.1: Basis for PII transfer to third parties not established"
}

violations contains msg if {
	not input.iso27701.pii_controller.pii_sharing.transfer_destinations_documented
	msg := "ISO 27701 7.5.2: Countries and organizations PII is transferred to not documented"
}

violations contains msg if {
	not input.iso27701.pii_controller.pii_sharing.disclosure_records_maintained
	msg := "ISO 27701 7.5.3: Records of PII disclosures to third parties not maintained"
}

default compliant := false

compliant if {
	count(violations) == 0
}

compliance_report := {
	"standard": "ISO/IEC 27701:2019",
	"domain": "Clause 7 — PII Controller Requirements",
	"compliant": compliant,
	"violation_count": count(violations),
	"violations": violations,
}
