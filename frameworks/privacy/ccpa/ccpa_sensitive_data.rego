package ccpa.sensitive_data

import rego.v1

violations contains msg if {
	not input.ccpa.sensitive_data.government_ids.access_limited_and_encrypted
	msg := "CPRA §1798.140(ae): SSN and government ID data not access-limited and not encrypted"
}

violations contains msg if {
	not input.ccpa.sensitive_data.account_credentials.not_stored_in_plaintext
	msg := "CPRA §1798.140(ae): Account credentials stored in plaintext"
}

violations contains msg if {
	not input.ccpa.sensitive_data.precise_geolocation.explicit_purpose_limitation
	msg := "CPRA §1798.140(ae): Precise geolocation data (within 1,852m) collected without explicit purpose limitation"
}

violations contains msg if {
	not input.ccpa.sensitive_data.racial_ethnic_origin.dpias_conducted
	msg := "CPRA §1798.140(ae): Data Protection Impact Assessments not conducted for processing racial or ethnic origin data"
}

violations contains msg if {
	not input.ccpa.sensitive_data.religious_beliefs.collection_minimized
	msg := "CPRA §1798.140(ae): Collection of religious or philosophical beliefs data not minimized"
}

violations contains msg if {
	not input.ccpa.sensitive_data.union_membership.collection_minimized
	msg := "CPRA §1798.140(ae): Collection of union membership data not minimized"
}

violations contains msg if {
	not input.ccpa.sensitive_data.mail_email_text.not_accessed_except_for_delivery
	msg := "CPRA §1798.140(ae): Mail, email, or text message content accessed for purposes other than delivery"
}

violations contains msg if {
	not input.ccpa.sensitive_data.genetic_data.access_controls_implemented
	msg := "CPRA §1798.140(ae): Access controls for genetic data not implemented"
}

violations contains msg if {
	not input.ccpa.sensitive_data.genetic_data.not_sold
	msg := "CPRA §1798.140(ae): Genetic data sold or shared without restriction"
}

violations contains msg if {
	not input.ccpa.sensitive_data.biometric_data.consent_obtained
	msg := "CPRA §1798.140(ae): Consent not obtained for collection of biometric data"
}

violations contains msg if {
	not input.ccpa.sensitive_data.biometric_data.retention_limited
	msg := "CPRA §1798.140(ae): Retention of biometric data not limited to stated purpose"
}

violations contains msg if {
	not input.ccpa.sensitive_data.health_information.hipaa_aligned_controls
	msg := "CPRA §1798.140(ae): HIPAA-aligned controls not applied to health information where applicable"
}

violations contains msg if {
	not input.ccpa.sensitive_data.sex_life_orientation.not_collected_unless_necessary
	msg := "CPRA §1798.140(ae): Sex life or sexual orientation data collected without demonstrated necessity"
}

violations contains msg if {
	not input.ccpa.sensitive_data.automated_decisions.opt_out_available
	msg := "CPRA §1798.185(a)(21): Consumers cannot opt out of automated decisions affecting them significantly"
}

violations contains msg if {
	not input.ccpa.sensitive_data.automated_decisions.logic_explanation_available
	msg := "CPRA §1798.185(a)(21): Explanation of automated decision-making logic not available upon request"
}

default compliant := false

compliant if {
	count(violations) == 0
}

compliance_report := {
	"standard": "CCPA/CPRA",
	"domain": "Sensitive Personal Information (§1798.140(ae), §1798.185(a)(21))",
	"compliant": compliant,
	"violation_count": count(violations),
	"violations": violations,
}
