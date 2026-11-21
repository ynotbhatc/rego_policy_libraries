# PCI DSS v4.0.1 Requirement 4 - Protect Cardholder Data with Strong Cryptography
# During Transmission Over Open, Public Networks

# METADATA
# title: "PCI DSS v4.0.1 Requirement 4 - Protect Cardholder Data with Strong Cryptography"
# custom:
#   class: compliance
#   framework: pci_dss
#   source: pci-ssc
#   domains: [financial, payment-cards]
#   coverage:
#     checks: 12
#     cited: 2
#     density: sized
#     basis: size
#     tested: true
#     entrypoint: none
#     guard: n/a
#     as_of: v2.4.2
package pci_dss.data_protection.requirement_4

import rego.v1

# =================================================================
# 4.1 - Processes and mechanisms for protecting CHD in transit
# =================================================================

# x.1.1: documented, kept up to date (current), in use (approved). No annual review is part of x.1.1; the
# annual review is 12.1.2 for the information security policy (audit 2026-11-17 follow-up).
transmission_security_policies_established if {
	input.pci.transmission_security.policies.documented == true
	input.pci.transmission_security.policies.approved == true
	input.pci.transmission_security.policies.current == true
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
	input.pci.ecommerce.in_scope == false
} else if {
	input.pci.ecommerce.in_scope == true
	input.pci.ecommerce.payment_pages.tls_enforced == true
	input.pci.ecommerce.payment_pages.https_only == true
	input.pci.ecommerce.payment_pages.hsts_enabled == true
	input.pci.ecommerce.payment_pages.mixed_content.blocked == true
}

# Point-of-sale terminal encryption
pos_terminal_encryption if {
	# Only required if POS terminals are in scope
	input.pci.pos.in_scope == false
} else if {
	input.pci.pos.in_scope == true
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
	input.pci.wireless.transmits_pan == false
} else if {
	input.pci.wireless.transmits_pan == true
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

# Every control referenced by the score, findings and roll-up has a default so a failing
# control reports false instead of making the whole score/findings undefined.
default transmission_security_policies_established := false

default transmission_security_roles_defined := false

default strong_cryptography_for_pan := false

default accepted_cryptography_standards := false

default certificate_management_secure := false

default payment_page_encryption := false

default pos_terminal_encryption := false

default api_transmission_encrypted := false

default trusted_keys_certificates_managed := false

default wireless_pan_transmission_secure := false

default pan_in_messaging_secured := false

default weak_protocols_inventory_current := false

default pci_requirement_4_compliant := false

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
	wireless_pan_transmission_secure
	pan_in_messaging_secured
	weak_protocols_inventory_current
}

default pci_requirement_4_score := 0

default pci_requirement_4_findings := {}

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

# BEGIN evidence_spec (generated by scripts/gen_pci_dss_evidence_spec.py; do not edit by hand)
# The facts each check that gates pci_requirement_4_compliant reads, for pci_dss.main: a failing check is
# "evidence missing" when no alternative holds a present, non-compliant fact and some fact is absent or of
# the wrong type. Term tests are described in the generator's docstring.
evidence_spec := {
	"transmission_security_policies_established": {
		"passed": transmission_security_policies_established,
		"alternatives": [
			[["pci.transmission_security.policies.documented", "true"], ["pci.transmission_security.policies.approved", "true"], ["pci.transmission_security.policies.current", "true"]],
		],
	},
	"transmission_security_roles_defined": {
		"passed": transmission_security_roles_defined,
		"alternatives": [
			[["pci.transmission_security.roles.defined", "true"], ["pci.transmission_security.responsibilities.assigned", "true"], ["pci.transmission_security.accountability.established", "true"]],
		],
	},
	"strong_cryptography_for_pan": {
		"passed": strong_cryptography_for_pan,
		"alternatives": [
			[["pci.transmission.pan.strong_cryptography", "true"], ["pci.transmission.pan.trusted_keys_certificates", "true"], ["pci.transmission.pan.open_public_networks_encrypted", "true"]],
		],
	},
	"accepted_cryptography_standards": {
		"passed": accepted_cryptography_standards,
		"alternatives": [
			[["pci.cryptography.tls.minimum_version", "str_ge", "1.2"], ["pci.cryptography.tls.tls_1_0.disabled", "true"], ["pci.cryptography.tls.tls_1_1.disabled", "true"], ["pci.cryptography.tls.weak_cipher_suites.disabled", "true"], ["pci.cryptography.tls.strong_cipher_suites.configured", "true"]],
		],
	},
	"certificate_management_secure": {
		"passed": certificate_management_secure,
		"alternatives": [
			[["pci.certificates.trusted_ca.used", "true"], ["pci.certificates.validity.monitored", "true"], ["pci.certificates.expiry.alerts_configured", "true"], ["pci.certificates.revocation.checked", "true"], ["pci.certificates.wildcard.usage_justified", "true"]],
		],
	},
	"payment_page_encryption": {
		"passed": payment_page_encryption,
		"alternatives": [
			[["pci.ecommerce.in_scope", "false"]],
			[["pci.ecommerce.in_scope", "true"], ["pci.ecommerce.payment_pages.tls_enforced", "true"], ["pci.ecommerce.payment_pages.https_only", "true"], ["pci.ecommerce.payment_pages.hsts_enabled", "true"], ["pci.ecommerce.payment_pages.mixed_content.blocked", "true"]],
		],
	},
	"pos_terminal_encryption": {
		"passed": pos_terminal_encryption,
		"alternatives": [
			[["pci.pos.in_scope", "false"]],
			[["pci.pos.in_scope", "true"], ["pci.pos.terminals.point_to_point_encryption", "true"], ["pci.pos.terminals.p2pe_solution.validated", "true"], ["pci.pos.terminals.terminal_management.secure", "true"]],
		],
	},
	"api_transmission_encrypted": {
		"passed": api_transmission_encrypted,
		"alternatives": [
			[["pci.api.tls_required", "true"], ["pci.api.minimum_tls_version", "str_ge", "1.2"], ["pci.api.certificate_pinning.implemented", "true"], ["pci.api.payload.pan_not_in_url", "true"], ["pci.api.payload.pan_not_in_logs", "true"]],
		],
	},
	"trusted_keys_certificates_managed": {
		"passed": trusted_keys_certificates_managed,
		"alternatives": [
			[["pci.key_management.pan_transmission.inventory_maintained", "true"], ["pci.key_management.pan_transmission.trusted_issuers_only", "true"], ["pci.key_management.pan_transmission.key_rotation.documented", "true"], ["pci.key_management.pan_transmission.compromise_procedures.defined", "true"]],
		],
	},
	"wireless_pan_transmission_secure": {
		"passed": wireless_pan_transmission_secure,
		"alternatives": [
			[["pci.wireless.transmits_pan", "false"]],
			[["pci.wireless.transmits_pan", "true"], ["pci.wireless.pan_transmission.strong_cryptography", "true"], ["pci.wireless.pan_transmission.wpa3_or_wpa2_enterprise", "true"], ["pci.wireless.pan_transmission.aes_encryption", "true"]],
		],
	},
	"pan_in_messaging_secured": {
		"passed": pan_in_messaging_secured,
		"alternatives": [
			[["pci.messaging.pan_transmission.prohibited", "true"], ["pci.messaging.pan_transmission.dlp_controls.implemented", "true"], ["pci.messaging.pan_transmission.policy.documented", "true"]],
		],
	},
	"weak_protocols_inventory_current": {
		"passed": weak_protocols_inventory_current,
		"alternatives": [
			[["pci.weak_protocols.inventory.maintained", "true"], ["pci.weak_protocols.ssl.disabled", "true"], ["pci.weak_protocols.tls_1_0.disabled", "true"], ["pci.weak_protocols.tls_1_1.disabled", "true"], ["pci.weak_protocols.early_tls.migration_plan.completed", "true"]],
		],
	},
}

# END evidence_spec
