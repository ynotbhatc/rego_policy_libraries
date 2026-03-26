package nerc_cip.cip_011

import rego.v1

# CIP-011-3: Information Protection
# Requirement: Prevent unauthorized access to BES Cyber System Information
# by specifying information protection requirements in support of protecting
# BES Cyber Systems against compromise.
#
# NERC Standards Reference: CIP-011-3

# =============================================================================
# R1: Information Protection Program
# =============================================================================

# R1.1 - Identify BES Cyber System Information
bes_cyber_system_information_identified if {
	input.bes_cyber_system_information.inventory_maintained == true
	input.bes_cyber_system_information.classification_performed == true
	input.bes_cyber_system_information.handling_procedures_defined == true
}

# BES Cyber System Information includes: OCA, network diagrams, device configs,
# policy and procedure documents, system security plans, vulnerability assessments
bcsi_categories_addressed if {
	input.bes_cyber_system_information.categories.oca_addressed == true # Operational or Control Area
	input.bes_cyber_system_information.categories.network_diagrams == true
	input.bes_cyber_system_information.categories.device_configurations == true
	input.bes_cyber_system_information.categories.vulnerability_assessments == true
	input.bes_cyber_system_information.categories.security_plans == true
	input.bes_cyber_system_information.categories.incident_response_plans == true
}

# R1.2 - Establish an information protection program
information_protection_program if {
	input.information_protection.program_documented == true
	input.information_protection.procedures_documented == true
	input.information_protection.storage_controls_implemented == true
	input.information_protection.transmission_controls_implemented == true
	input.information_protection.access_controls_enforced == true
}

# =============================================================================
# R2: Information Access Controls
# =============================================================================

# R2 - Implement access controls for BCSI that allow only authorized access
information_access_controls_enforced if {
	violations := [access |
		access := input.information_access[_]
		not information_access_adequate(access)
	]
	count(violations) == 0
}

information_access_adequate(access) if {
	access.authorization_documented == true
	access.need_to_know_verified == true
	access.access_review_performed == true
	access.access_termination_timely == true
}

# Authorization based on job function / need to know
bcsi_access_need_to_know if {
	violations := [person |
		person := input.bcsi_access_list[_]
		not person.need_to_know_documented == true
	]
	count(violations) == 0
}

# Access authorization reviewed at least every 15 calendar months
bcsi_access_reviewed if {
	violations := [person |
		person := input.bcsi_access_list[_]
		review_age_days := (time.now_ns() - person.last_review_date) / (24 * 60 * 60 * 1000000000)
		review_age_days > 455
	]
	count(violations) == 0
}

# =============================================================================
# R3: Storage Protection
# =============================================================================

# BCSI in storage must be protected from unauthorized access
bcsi_storage_protected if {
	input.bcsi_storage.encryption_at_rest == true
	input.bcsi_storage.access_controls_implemented == true
	input.bcsi_storage.physical_protection_implemented == true
}

# Electronic access: authentication required
bcsi_electronic_access_controlled if {
	input.bcsi_storage.electronic.authentication_required == true
	input.bcsi_storage.electronic.authorization_enforced == true
	input.bcsi_storage.electronic.logging_enabled == true
}

# Physical access: access controlled and logged
bcsi_physical_access_controlled if {
	input.bcsi_storage.physical.access_controlled == true
	input.bcsi_storage.physical.access_logged == true
}

# =============================================================================
# R4: Transmission Protection
# =============================================================================

# BCSI transmitted outside the ESP must be protected
bcsi_transmission_protected if {
	violations := [transmission |
		transmission := input.bcsi_transmissions[_]
		transmission.outside_esp == true
		not transmission_protected(transmission)
	]
	count(violations) == 0
}

transmission_protected(transmission) if {
	transmission.encryption_used == true
	transmission.recipient_authorized == true
	transmission.transmission_logged == true
}

# =============================================================================
# R5: Disposal and Redeployment
# =============================================================================

# R5 - Protect BCSI on devices being disposed or redeployed
information_disposal_procedures_implemented if {
	input.information_disposal.procedures_documented == true
	input.information_disposal.secure_deletion_methods == true
	input.information_disposal.disposal_documentation == true
	input.information_disposal.media_sanitization == true
}

# Verification that media is sanitized before disposal
media_sanitization_verified if {
	every disposal in input.media_disposals {
		disposal.sanitization_performed == true
		disposal.sanitization_method_documented == true
		disposal.verification_completed == true
	}
}

# Before redeployment, verify BCSI removed
redeployment_bcsi_cleared if {
	every redeployment in input.system_redeployments {
		redeployment.bcsi_cleared == true
		redeployment.clearing_method_documented == true
	}
}

# =============================================================================
# R6: Third-Party Sharing
# =============================================================================

# BCSI shared with third parties must have appropriate agreements
third_party_bcsi_agreements if {
	violations := [sharing |
		sharing := input.bcsi_third_party_sharing[_]
		not third_party_agreement_in_place(sharing)
	]
	count(violations) == 0
}

third_party_agreement_in_place(sharing) if {
	sharing.nda_or_agreement_in_place == true
	sharing.agreement_includes_security_requirements == true
	sharing.recipient_access_need_documented == true
	sharing.sharing_logged == true
}

# =============================================================================
# VIOLATIONS
# =============================================================================

violations contains v if {
	not bes_cyber_system_information_identified
	v := {
		"standard": "CIP-011",
		"requirement": "R1.1",
		"severity": "high",
		"description": "BES Cyber System Information not identified or classified",
		"remediation": "Identify and classify all BCSI with documented handling procedures",
	}
}

violations contains v if {
	not information_protection_program
	v := {
		"standard": "CIP-011",
		"requirement": "R1.2",
		"severity": "high",
		"description": "Information protection program not documented or inadequate",
		"remediation": "Establish documented information protection program with storage, transmission, and access controls",
	}
}

violations contains v if {
	not information_access_controls_enforced
	v := {
		"standard": "CIP-011",
		"requirement": "R2",
		"severity": "critical",
		"description": "Access controls for BCSI inadequate or unauthorized access possible",
		"remediation": "Implement and enforce access controls limiting BCSI to authorized personnel with need to know",
	}
}

violations contains v if {
	not bcsi_access_reviewed
	v := {
		"standard": "CIP-011",
		"requirement": "R2",
		"severity": "high",
		"description": "BCSI access authorization not reviewed within 15 calendar months",
		"remediation": "Review and reauthorize BCSI access for all personnel within 15 calendar months",
	}
}

violations contains v if {
	not bcsi_storage_protected
	v := {
		"standard": "CIP-011",
		"requirement": "R1.2",
		"severity": "critical",
		"description": "BCSI in storage not adequately protected (encryption, access controls, physical protection)",
		"remediation": "Implement encryption at rest, logical access controls, and physical protection for BCSI storage",
	}
}

violations contains v if {
	not bcsi_transmission_protected
	v := {
		"standard": "CIP-011",
		"requirement": "R1.2",
		"severity": "critical",
		"description": "BCSI transmitted outside ESP is not encrypted or recipient not authorized",
		"remediation": "Encrypt all BCSI transmitted outside the ESP and verify recipient authorization",
	}
}

violations contains v if {
	not information_disposal_procedures_implemented
	v := {
		"standard": "CIP-011",
		"requirement": "R3",
		"severity": "high",
		"description": "BCSI disposal procedures not documented or media sanitization not implemented",
		"remediation": "Implement documented media sanitization and disposal procedures per NIST SP 800-88",
	}
}

# =============================================================================
# OVERALL COMPLIANCE
# =============================================================================

default compliant := false

compliant if {
	bes_cyber_system_information_identified
	bcsi_categories_addressed
	information_protection_program
	information_access_controls_enforced
	bcsi_access_need_to_know
	bcsi_access_reviewed
	bcsi_storage_protected
	bcsi_electronic_access_controlled
	bcsi_physical_access_controlled
	bcsi_transmission_protected
	information_disposal_procedures_implemented
	media_sanitization_verified
}

report := {
	"standard": "CIP-011-3",
	"title": "Information Protection",
	"compliant": compliant,
	"requirements": {
		"R1_1_bcsi_identified": bes_cyber_system_information_identified,
		"R1_1_categories_addressed": bcsi_categories_addressed,
		"R1_2_protection_program": information_protection_program,
		"R2_access_controls": information_access_controls_enforced,
		"R2_need_to_know": bcsi_access_need_to_know,
		"R2_access_reviewed": bcsi_access_reviewed,
		"R_storage_protected": bcsi_storage_protected,
		"R_electronic_access_controlled": bcsi_electronic_access_controlled,
		"R_physical_access_controlled": bcsi_physical_access_controlled,
		"R_transmission_protected": bcsi_transmission_protected,
		"R3_disposal_procedures": information_disposal_procedures_implemented,
		"R3_media_sanitization": media_sanitization_verified,
	},
	"violations": violations,
	"violation_count": count(violations),
}
