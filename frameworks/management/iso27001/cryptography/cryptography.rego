# METADATA
# title: "ISO/IEC 27001 technical fact checks — 2013 group A.10 Cryptography, re-keyed to 2022 Annex A A.8.24"
# custom:
#   class: compliance
#   framework: iso27001
#   source: iso
#   domains: [isms]
#   coverage:
#     checks: 22
#     cited: 5
#     density: sized
#     basis: size
#     tested: true
#     entrypoint: none
#     guard: n/a
#     as_of: v2.5.0
package iso27001.cryptography

import rego.v1

# Defaults so report/details never collapse to {} on empty input
default cryptographic_controls := false

default cryptographic_policy := false

default key_management := false

default key_generation_secure := false

default key_distribution_secure := false

default key_usage_controlled := false

default key_destruction_secure := false

default data_encryption := false

default data_at_rest_encrypted := false

default data_in_transit_encrypted := false

default network_protocols_secure := false

default api_encryption_enforced := false

default database_encryption_enabled := false

default backup_encryption_enabled := false

default digital_signatures := false

default certificate_management_secure := false

default digital_signature_implementation := false

default pki_implementation := false

default algorithm_compliance := false

default weak_algorithms_disabled := false

default quantum_resistance_planned := false

default hsm_usage := false

default compliant := false

# ISO/IEC 27001 fact checks, written against the ISO/IEC 27001:2013 Annex A group A.10 Cryptography.
# The 2013 ids in the comments below are kept for traceability; the 2022 Annex A control each check
# decides is noted as (2022: A.x.y) and is wired in data.iso27001.fact_checks (../iso27001_policy.rego).
# Technical controls for cryptographic information protection

# A.10.1 - Cryptographic controls
cryptographic_controls if {
	# A.10.1.1 - Policy on the use of cryptographic controls
	cryptographic_policy

	# A.10.1.2 - Key management
	key_management
}

# What decides A.8.24 here (2026-11-17). ISO/IEC 27002:2022 is licensed and its text was not read;
# public descriptions of 8.24 say rules for the effective use of cryptography, including cryptographic
# key management, are defined and implemented. Only that is scored:
#   cryptographic_policy  the rules for use exist (policy statements, attested)
#   key_management        the key lifecycle (generation, distribution and storage, use and rotation,
#                         destruction) follows the organisation's own documented rules; key lifetime is
#                         compared with the organisation's stated maximum
#                         (input.iso27001.org_defined.max_key_lifetime_days)
#   algorithm_compliance  every algorithm in use is on the organisation's approved list
# Specific mechanisms the public descriptions do not name are reported as non-scoring advisories
# (compliance_details.advisory): HSM key storage, audit logging of key operations, automated rotation,
# encrypted key backups, data_encryption (TLS pinning, payload encryption, key escrow, filesystem and
# database encryption), digital_signatures (code and document signing, OCSP, PKI), the library's
# weak-algorithm list and post-quantum planning.

# A.10.1.1 - Policy on the use of cryptographic controls (2022: A.8.24)
# Evidence kind: attestation. Every value read is a statement the assessed party
# makes about its own policy (flags and the list of approved algorithms); nothing
# here is observed on a system. iso27001.fact_checks labels it so.
cryptographic_policy if {
	input.cryptography.policy.documented == true
	input.cryptography.policy.approved == true
	input.cryptography.policy.communicated == true
	input.cryptography.policy.regularly_reviewed == true

	# Policy should specify approved algorithms
	count(input.cryptography.policy.approved_algorithms) > 0

	# Policy should address key management
	input.cryptography.policy.key_management_addressed == true

	# Policy should specify encryption requirements
	input.cryptography.policy.encryption_requirements == true
}

# A.10.1.2 - Key management (2022: A.8.24)
key_management if {
	# Key generation requirements
	key_generation_secure

	# Key distribution and storage
	key_distribution_secure

	# Key usage and rotation
	key_usage_controlled

	# Key destruction
	key_destruction_secure
}

# Secure key generation
key_generation_secure if {
	input.key_management.generation.random_source_secure == true
	input.key_management.generation.approved_algorithms == true
	input.key_management.generation.sufficient_entropy == true
	input.key_management.generation.documented_process == true

	# Key specifications should be properly configured
	count(input.key_management.key_specifications) > 0
}

# Minimum key lengths based on algorithm
minimum_key_length(algorithm) := 2048 if {
	algorithm == "RSA"
}

minimum_key_length(algorithm) := 256 if {
	algorithm == "AES"
}

minimum_key_length(algorithm) := 256 if {
	algorithm == "ECC"
}

minimum_key_length(algorithm) := 160 if {
	algorithm == "SHA"
}

minimum_key_length(_) := 128 # Default minimum

# Secure key distribution and storage
key_distribution_secure if {
	input.key_management.distribution.encrypted_channels == true
	input.key_management.distribution.authentication_required == true
	input.key_management.distribution.integrity_protected == true

	input.key_management.storage.access_controlled == true
}

# Controlled key usage and rotation
key_usage_controlled if {
	input.key_management.usage.purpose_specific == true
	input.key_management.usage.access_restricted == true

	input.key_management.rotation.regular_schedule == true
	input.key_management.rotation.emergency_procedures == true

	# Key lifetime within the organisation's own stated maximum (no library-chosen period)
	is_number(input.key_management.rotation.max_lifetime_days)
	is_number(input.iso27001.org_defined.max_key_lifetime_days)
	input.key_management.rotation.max_lifetime_days <= input.iso27001.org_defined.max_key_lifetime_days
}

# Advisory (non-scoring): key-management mechanisms 8.24 is not publicly described as requiring.
default key_management_mechanisms := false

key_management_mechanisms if {
	input.key_management.storage.hardware_security_modules == true
	input.key_management.storage.audit_logged == true
	input.key_management.storage.backup_encrypted == true
	input.key_management.usage.audit_logged == true
	input.key_management.rotation.automated_process == true
}

# Secure key destruction
key_destruction_secure if {
	input.key_management.destruction.secure_deletion == true
	input.key_management.destruction.verification_required == true
	input.key_management.destruction.documented_process == true
}

# Data encryption requirements (2022: A.8.24)
data_encryption if {
	# Data at rest encryption
	data_at_rest_encrypted

	# Data in transit encryption
	data_in_transit_encrypted

	# Database encryption
	database_encryption_enabled

	# Backup encryption
	backup_encryption_enabled
}

# Data at rest encryption
data_at_rest_encrypted if {
	input.encryption.data_at_rest.enabled == true
	input.encryption.data_at_rest.strong_algorithms == true
	input.encryption.data_at_rest.key_management_integrated == true

	# File system encryption
	input.encryption.filesystem.full_disk_encryption == true
	input.encryption.filesystem.secure_boot == true

	# Application data encryption
	input.encryption.application_data.sensitive_fields == true
	input.encryption.application_data.configuration_files == true
}

# Data in transit encryption
data_in_transit_encrypted if {
	input.encryption.data_in_transit.tls_enforced == true
	_tls_version_acceptable(input.encryption.data_in_transit.minimum_tls_version)
	input.encryption.data_in_transit.certificate_validation == true
	input.encryption.data_in_transit.perfect_forward_secrecy == true

	# Network protocols encryption
	network_protocols_secure

	# API encryption
	api_encryption_enforced
}

# Secure network protocols
network_protocols_secure if {
	# SSH configuration
	input.network.ssh.protocol_version >= 2
	input.network.ssh.strong_ciphers == true
	input.network.ssh.key_based_auth == true

	# HTTPS enforcement
	input.network.https.enforced == true
	input.network.https.hsts_enabled == true
	input.network.https.secure_cookies == true

	# VPN encryption
	input.network.vpn.strong_encryption == true
	input.network.vpn.certificate_based == true
}

# API encryption enforcement
api_encryption_enforced if {
	input.api.tls_required == true
	input.api.token_encryption == true
	input.api.payload_encryption == true
	input.api.certificate_pinning == true
}

# Database encryption
database_encryption_enabled if {
	input.database.encryption.at_rest == true
	input.database.encryption.in_transit == true
	input.database.encryption.key_rotation == true
	input.database.encryption.transparent_encryption == true

	# Connection encryption
	input.database.connections.ssl_required == true
	input.database.connections.certificate_validation == true
}

# Backup encryption
backup_encryption_enabled if {
	input.backup.encryption.enabled == true
	input.backup.encryption.separate_keys == true
	input.backup.encryption.key_escrow == true
	input.backup.encryption.integrity_verification == true
}

# Digital signatures and certificates (2022: A.8.24)
digital_signatures if {
	# Certificate management
	certificate_management_secure

	# Digital signature usage
	digital_signature_implementation

	# Public Key Infrastructure (PKI)
	pki_implementation
}

# Secure certificate management
certificate_management_secure if {
	input.certificates.trusted_ca_only == true
	input.certificates.regular_renewal == true
	input.certificates.revocation_checking == true
	input.certificates.secure_storage == true

	# Certificate lifecycle management
	input.certificates.lifecycle.automated_renewal == true
	input.certificates.lifecycle.expiry_monitoring == true
	input.certificates.lifecycle.secure_generation == true
}

# Digital signature implementation
digital_signature_implementation if {
	input.digital_signatures.code_signing == true
	input.digital_signatures.document_signing == true
	input.digital_signatures.timestamp_verification == true
	input.digital_signatures.non_repudiation == true
}

# PKI implementation
pki_implementation if {
	input.pki.certificate_authority.trusted == true
	input.pki.certificate_authority.audited == true
	input.pki.certificate_policies.documented == true
	input.pki.certificate_revocation.crl_available == true
	input.pki.certificate_revocation.ocsp_enabled == true
}

# Cryptographic algorithm compliance (2022: A.8.24)
# Post-quantum migration planning is not part of this decision: A.8.24 is about
# rules for the effective use of cryptography, including key management, and
# public descriptions of the control do not name post-quantum planning. It is
# reported separately as a non-scoring advisory (quantum_resistance_planned,
# listed in iso27001.unmapped_fact_rules).
algorithm_compliance if {
	# The organisation's rules are the yardstick: every algorithm in use is on its approved list.
	# (The library's weak-algorithm list is an advisory: weak_algorithms_disabled.)
	is_array(input.cryptography.algorithms_in_use)
	is_array(input.cryptography.approved_algorithms)
	count(input.cryptography.algorithms_in_use) > 0
	count(input.cryptography.approved_algorithms) > 0
	count(unapproved_algorithms_in_use) == 0
}

_norm_alg(a) := lower(replace(replace(replace(sprintf("%v", [a]), "-", ""), "_", ""), " ", ""))

unapproved_algorithms_in_use := [a |
	some a in input.cryptography.algorithms_in_use
	not _norm_alg(a) in {_norm_alg(b) | some b in input.cryptography.approved_algorithms}
]

# Weak algorithms disabled
weak_algorithms_disabled if {
	# Check no weak algorithms are in use; spellings are normalised (case, "-", "_", spaces) so SHA-1, sha1,
	# TLSv1.0 and 3des are all recognised.
	count([alg | some alg in input.cryptography.algorithms_in_use; _weak_algorithm(alg)]) == 0
}

_weak_algorithm(alg) if {
	norm := lower(replace(replace(replace(sprintf("%v", [alg]), "-", ""), "_", ""), " ", ""))
	regex.match(`^(md5|sha1|des|3des|tripledes|desede|rc4|ssl(v?[23])?|tlsv?1(\.?[01])?)$`, norm)
}

# TLS minimum version: accepts 1.2 / 1.3 with optional "TLS", "TLSv", "v" prefixes (string or number).
_tls_version_acceptable(v) if {
	regex.match(`^(tls)?v?[ ]?1\.[23]$`, lower(sprintf("%v", [v])))
}

# Quantum resistance planning — ADVISORY, decides no control (see algorithm_compliance)
quantum_resistance_planned if {
	input.cryptography.quantum_resistance.assessment_completed == true
	input.cryptography.quantum_resistance.migration_plan == true
	input.cryptography.quantum_resistance.timeline_defined == true
}

# Hardware Security Module (HSM) usage
hsm_usage if {
	input.hsm.available == true
	input.hsm.key_generation == true
	input.hsm.key_storage == true
	input.hsm.cryptographic_operations == true
	input.hsm.tamper_protection == true
	input.hsm.fips_140_2_level >= 2
}

# Overall cryptography compliance: the A.8.24 scoring checks only (see header)
compliant if {
	cryptographic_controls
	algorithm_compliance
}

# Detailed compliance reporting
compliance_details := {
	"cryptographic_policy": cryptographic_policy,
	"key_management": {
		"generation": key_generation_secure,
		"distribution_storage": key_distribution_secure,
		"usage_rotation": key_usage_controlled,
		"destruction": key_destruction_secure,
	},
	"data_encryption": {
		"at_rest": data_at_rest_encrypted,
		"in_transit": data_in_transit_encrypted,
		"database": database_encryption_enabled,
		"backup": backup_encryption_enabled,
	},
	"digital_signatures": {
		"certificate_management": certificate_management_secure,
		"signature_implementation": digital_signature_implementation,
		"pki": pki_implementation,
	},
	"algorithm_compliance": {
		"approved_only": algorithm_compliance,
		"unapproved_in_use": unapproved_algorithms_in_use,
	},
	"advisory": {
		"scoring": false,
		"quantum_resistance_planned": quantum_resistance_planned,
		"key_management_mechanisms": key_management_mechanisms,
		"data_encryption": data_encryption,
		"digital_signatures": digital_signatures,
		"weak_algorithms_disabled": weak_algorithms_disabled,
		"hsm_usage": hsm_usage,
	},
	"hsm_usage": hsm_usage,
	"overall_compliant": compliant,
}
