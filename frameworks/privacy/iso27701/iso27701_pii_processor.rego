package iso27701.pii_processor

import rego.v1

violations contains msg if {
	not input.iso27701.pii_processor.collection_conditions.customer_instructions_documented
	msg := "ISO 27701 8.2.1: PII not processed only under documented customer instructions"
}

violations contains msg if {
	not input.iso27701.pii_processor.collection_conditions.purposes_limited_to_customer
	msg := "ISO 27701 8.2.2: Organization's processing purposes not limited to fulfilling customer's purposes"
}

violations contains msg if {
	not input.iso27701.pii_processor.collection_conditions.subprocessor_equivalent_obligations
	msg := "ISO 27701 8.2.3: Subprocessors not contracted with equivalent data protection obligations"
}

violations contains msg if {
	not input.iso27701.pii_processor.collection_conditions.marketing_use_prohibited
	msg := "ISO 27701 8.2.4: Marketing use of PII not prohibited without explicit customer authorization"
}

violations contains msg if {
	not input.iso27701.pii_processor.pii_principal_obligations.principal_rights_mechanism
	msg := "ISO 27701 8.3.1: Mechanism to support PII principal rights fulfillment by controller not provided"
}

violations contains msg if {
	not input.iso27701.pii_processor.pii_principal_obligations.records_traceable
	msg := "ISO 27701 8.3.2: Records do not enable PII principal requests to be traced"
}

violations contains msg if {
	not input.iso27701.pii_processor.privacy_by_design.controls_throughout_lifecycle
	msg := "ISO 27701 8.4.1: Privacy controls not maintained throughout processing lifecycle"
}

violations contains msg if {
	not input.iso27701.pii_processor.privacy_by_design.temporary_files_documented_and_disposed
	msg := "ISO 27701 8.4.2: Temporary files not documented and disposed of appropriately"
}

violations contains msg if {
	not input.iso27701.pii_processor.privacy_by_design.return_transfer_disposal_on_termination
	msg := "ISO 27701 8.4.3: Return, transfer, or disposal of PII not defined for contract termination"
}

violations contains msg if {
	not input.iso27701.pii_processor.pii_sharing.third_party_disclosure_basis
	msg := "ISO 27701 8.5.1: Basis for disclosure of PII to third parties or law enforcement not established"
}

violations contains msg if {
	not input.iso27701.pii_processor.pii_sharing.binding_disclosure_info_to_customer
	msg := "ISO 27701 8.5.2: Information about legally binding disclosure requests not provided to customer"
}

violations contains msg if {
	not input.iso27701.pii_processor.pii_sharing.subprocessor_disclosures_documented
	msg := "ISO 27701 8.5.3: Subprocessor disclosures not documented"
}

violations contains msg if {
	not input.iso27701.pii_processor.pii_sharing.jurisdictional_transfer_notification
	msg := "ISO 27701 8.5.4: Notification of PII transfers between jurisdictions not provided"
}

default compliant := false

compliant if {
	count(violations) == 0
}

compliance_report := {
	"standard": "ISO/IEC 27701:2019",
	"domain": "Clause 8 — PII Processor Requirements",
	"compliant": compliant,
	"violation_count": count(violations),
	"violations": violations,
}
