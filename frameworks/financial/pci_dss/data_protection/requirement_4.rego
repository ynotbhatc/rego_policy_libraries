# PCI DSS v4.0 Requirement 4 - Protect Cardholder Data with Strong Cryptography
# During Transmission Over Open, Public Networks

package pci_dss.data_protection.requirement_4

import rego.v1

# =================================================================
# 4.1 - Processes and mechanisms for protecting CHD in transit
# =================================================================

transmission_security_policies_established if {
	input.pci.transmission_security.policies.documented == true
	input.pci.transmission_security.policies.approved == true
	input.pci.transmission_security.policies.current == true
	input.pci.transmission_security.policies.reviewed_annually == true
}

transmission_security_roles_defined if {
	input.pci.transmission_security.roles.defined == true
	input.pci.transmission_security.responsibilities.assigned == true
	input.pci.transmission_security.accountability.established == true
}

# =================================================================
# 4.2 - PAN is protected with strong cryptography during transmission
# =================================================================

# Strong cryptography used for PAN transmission over open networks
strong_cryptography_for_pan if {
	input.pci.transmission.pan.strong_cryptography == true
	input.pci.transmission.pan.trusted_keys_certificates == true
	input.pci.transmission.pan.open_public_networks_encrypted == true
}

# Accepted cryptography standards in use
accepted_cryptography_standards if {
	input.pci.cryptography.tls.minimum_version >= "1.2"
	input.pci.cryptography.tls.tls_1_0.disabled == true
	input.pci.cryptography.tls.tls_1_1.disabled == true
	input.pci.cryptography.tls.weak_cipher_suites.disabled == true
	input.pci.cryptography.tls.strong_cipher_suites.configured == true
}

# Certificate management
certificate_management_secure if {
	input.pci.certificates.trusted_ca.used == true
	input.pci.certificates.validity.monitored == true
	input.pci.certificates.expiry.alerts_configured == true
	input.pci.certificates.revocation.checked == true
	input.pci.certificates.wildcard.usage_justified == true
}

# =================================================================
# 4.2.1 - Strong cryptography is in use wherever PAN is transmitted
# =================================================================

# Payment page encryption (e-commerce)
payment_page_encryption if {
	# Only required if e-commerce is in scope
	not input.pci.ecommerce.in_scope
} else if {
	input.pci.ecommerce.in_scope
	input.pci.ecommerce.payment_pages.tls_enforced == true
	input.pci.ecommerce.payment_pages.https_only == true
	input.pci.ecommerce.payment_pages.hsts_enabled == true
	input.pci.ecommerce.payment_pages.mixed_content.blocked == true
}

# Point-of-sale terminal encryption
pos_terminal_encryption if {
	# Only required if POS terminals are in scope
	not input.pci.pos.in_scope
} else if {
	input.pci.pos.in_scope
	input.pci.pos.terminals.point_to_point_encryption == true
	input.pci.pos.terminals.p2pe_solution.validated == true
	input.pci.pos.terminals.terminal_management.secure == true
}

# API transmission encryption
api_transmission_encrypted if {
	input.pci.api.tls_required == true
	input.pci.api.minimum_tls_version >= "1.2"
	input.pci.api.certificate_pinning.implemented == true
	input.pci.api.payload.pan_not_in_url == true
	input.pci.api.payload.pan_not_in_logs == true
}

# =================================================================
# 4.2.2 - Trusted keys/certificates are used in PAN transmission
# =================================================================

trusted_keys_certificates_managed if {
	input.pci.key_management.pan_transmission.inventory_maintained == true
	input.pci.key_management.pan_transmission.trusted_issuers_only == true
	input.pci.key_management.pan_transmission.key_rotation.documented == true
	input.pci.key_management.pan_transmission.compromise_procedures.defined == true
}

# =================================================================
# 4.2.1.1 - Wireless networks transmitting PAN
# =================================================================

wireless_pan_transmission_secure if {
	# Only required if wireless in scope transmits PAN
	not input.pci.wireless.transmits_pan
} else if {
	input.pci.wireless.transmits_pan
	input.pci.wireless.pan_transmission.strong_cryptography == true
	input.pci.wireless.pan_transmission.wpa3_or_wpa2_enterprise == true
	input.pci.wireless.pan_transmission.aes_encryption == true
}

# =================================================================
# 4.2.2.1 - PAN in messaging technologies
# =================================================================

pan_in_messaging_secured if {
	# End-user messaging (email, SMS, chat) should never transmit PAN
	input.pci.messaging.pan_transmission.prohibited == true
	input.pci.messaging.pan_transmission.dlp_controls.implemented == true
	input.pci.messaging.pan_transmission.policy.documented == true
}

# =================================================================
# Weak or prohibited protocols inventory
# =================================================================

weak_protocols_inventory_current if {
	input.pci.weak_protocols.inventory.maintained == true
	input.pci.weak_protocols.ssl.disabled == true
	input.pci.weak_protocols.tls_1_0.disabled == true
	input.pci.weak_protocols.tls_1_1.disabled == true
	input.pci.weak_protocols.early_tls.migration_plan.completed == true
}

# =================================================================
# Scoring
# =================================================================

pci_requirement_4_compliant if {
	transmission_security_policies_established
	transmission_security_roles_defined
	strong_cryptography_for_pan
	accepted_cryptography_standards
	certificate_management_secure
	payment_page_encryption
	pos_terminal_encryption
	api_transmission_encrypted
	trusted_keys_certificates_managed
	weak_protocols_inventory_current
}

pci_requirement_4_score := score if {
	controls := [
		transmission_security_policies_established,
		transmission_security_roles_defined,
		strong_cryptography_for_pan,
		accepted_cryptography_standards,
		certificate_management_secure,
		payment_page_encryption,
		pos_terminal_encryption,
		api_transmission_encrypted,
		trusted_keys_certificates_managed,
		wireless_pan_transmission_secure,
		pan_in_messaging_secured,
		weak_protocols_inventory_current,
	]
	passed := count([c | some c in controls; c == true])
	total := count(controls)
	score := (passed / total) * 100
}

pci_requirement_4_findings := {
	"requirement_4_1": {
		"policies_established": transmission_security_policies_established,
		"roles_defined": transmission_security_roles_defined,
	},
	"requirement_4_2": {
		"strong_cryptography_for_pan": strong_cryptography_for_pan,
		"accepted_standards": accepted_cryptography_standards,
		"certificate_management": certificate_management_secure,
		"payment_page_encryption": payment_page_encryption,
		"pos_terminal_encryption": pos_terminal_encryption,
		"api_transmission": api_transmission_encrypted,
		"trusted_keys_certificates": trusted_keys_certificates_managed,
		"wireless_pan_transmission": wireless_pan_transmission_secure,
		"messaging_pan_prohibited": pan_in_messaging_secured,
		"weak_protocols_disabled": weak_protocols_inventory_current,
	},
	"overall_score": pci_requirement_4_score,
	"overall_compliant": pci_requirement_4_compliant,
}
