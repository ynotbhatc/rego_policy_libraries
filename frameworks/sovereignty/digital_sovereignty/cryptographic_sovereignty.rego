# METADATA
# title: "Digital Sovereignty — Cryptographic Sovereignty"
# custom:
#   class: compliance
#   framework: digital_sovereignty
#   source: aac
#   domains: [sovereignty, data-residency]
#   coverage:
#     checks: 23
#     cited: 12
#     density: sized
#     basis: size
#     tested: true
#     entrypoint: report
#     guard: self
#     as_of: v2.4.2
package digital_sovereignty.cryptographic_sovereignty

import rego.v1

# Digital Sovereignty — Cryptographic Sovereignty
# Ensures the organisation holds exclusive control over encryption keys,
# uses auditable algorithms, and that no foreign entity can compel key disclosure.
#
# Input schema:
#   input.encrypted_resources[]
#     .resource_id, .resource_type, .data_classification
#     .key_management                    — customer_managed | provider_managed | unencrypted
#     .key_provider                      — e.g. "aws_kms" | "azure_key_vault" | "on_prem_hsm"
#     .key_location_country
#     .byok_enabled                      — Bring Your Own Key
#     .hyok_enabled                      — Hold Your Own Key (on-prem root)
#   input.hsm_configuration
#     .deployed                          — bool
#     .type                              — cloud_hsm | on_prem_hsm | fips_140_2_level3 | fips_140_3
#     .location_country
#     .vendor_access_possible            — bool
#     .key_material_leaves_hsm           — bool
#   input.key_management_policies
#     .rotation_policy_documented
#     .rotation_frequency_days
#     .key_ceremony_documented
#     .dual_control_enforced
#     .split_knowledge_enforced
#     .escrow.exists                     — bool (escrow to third party is a risk)
#     .escrow.foreign_entity_holds_keys  — bool
#   input.encryption_standards
#     .algorithms_approved[]             — e.g. ["AES-256", "RSA-4096", "ECDSA-P-384"]
#     .tls_minimum_version               — "1.2" | "1.3"
#     .prohibited_algorithms[]           — e.g. ["DES", "3DES", "RC4", "MD5", "SHA-1"]
#   input.encrypted_resources_in_transit[]
#     .connection_id, .protocol, .tls_version, .cipher_suite
#     .involves_regulated_data
#   input.code_signing
#     .implemented
#     .key_location_country
#     .private_key_in_approved_jurisdiction

# =============================================================================
# KEY MANAGEMENT SOVEREIGNTY
# =============================================================================

# NOTE (undefined trap): `not x.field in list` and `x.field != "v"` are undefined
# when the field is ABSENT (the reference is hoisted outside the negation), so an
# offender with missing evidence used to be skipped. Fields are read with
# object.get() so absence counts against the resource, and `approved` is []
# when input.approved_jurisdictions is missing (fail closed).
approved := object.get(input, "approved_jurisdictions", [])

regulated_classes := {"sensitive", "restricted", "sovereign"}

resources := object.get(input, "encrypted_resources", [])

# All resources containing sensitive or higher data must use customer-managed keys
cmk_offenders contains r if {
	some r in resources
	object.get(r, "data_classification", "") in regulated_classes
	object.get(r, "key_management", "") != "customer_managed"
}

default sensitive_data_uses_customer_managed_keys := false

sensitive_data_uses_customer_managed_keys if count(cmk_offenders) == 0

# Sovereign/restricted data must use HYOK (Hold Your Own Key — on-prem root)
hyok_offenders contains r if {
	some r in resources
	object.get(r, "data_classification", "") in {"sovereign", "restricted"}
	not r.hyok_enabled == true
}

default sovereign_data_uses_hyok := false

sovereign_data_uses_hyok if count(hyok_offenders) == 0

# No resource containing regulated data should be unencrypted. A resource with
# no recorded classification is not assumed to be public.
unencrypted_offenders contains r if {
	some r in resources
	object.get(r, "data_classification", "") != "public"
	r.key_management == "unencrypted"
}

default no_unencrypted_regulated_data := false

no_unencrypted_regulated_data if count(unencrypted_offenders) == 0

# Encryption keys for regulated data must be physically located in approved jurisdiction
key_location_offenders contains r if {
	some r in resources
	object.get(r, "data_classification", "") in regulated_classes
	r.key_management == "customer_managed"
	not object.get(r, "key_location_country", "") in approved
}

default keys_in_approved_jurisdiction := false

keys_in_approved_jurisdiction if count(key_location_offenders) == 0

# =============================================================================
# HSM CONTROLS
# =============================================================================

# An HSM must be deployed for key protection
hsm_deployed if {
	input.hsm_configuration.deployed == true
}

# HSM must meet minimum assurance level
hsm_assurance_adequate if {
	input.hsm_configuration.type in ["fips_140_2_level3", "fips_140_3", "on_prem_hsm"]
}

# HSM must be located in approved jurisdiction
hsm_in_approved_jurisdiction if {
	input.hsm_configuration.location_country in input.approved_jurisdictions
}

# HSM vendor must not have access to key material
no_hsm_vendor_backdoor if {
	input.hsm_configuration.vendor_access_possible == false
}

# Key material must never leave the HSM boundary unencrypted
key_material_stays_in_hsm if {
	input.hsm_configuration.key_material_leaves_hsm == false
}

# =============================================================================
# KEY MANAGEMENT PROCEDURES
# =============================================================================

# Key rotation policy must be documented and enforced
key_rotation_policy if {
	input.key_management_policies.rotation_policy_documented == true
	input.key_management_policies.rotation_frequency_days <= 365
}

# Dual control / split knowledge for high-value key operations
dual_control_enforced if {
	input.key_management_policies.dual_control_enforced == true
	input.key_management_policies.split_knowledge_enforced == true
}

# Key ceremony must be documented
key_ceremony_documented if {
	input.key_management_policies.key_ceremony_documented == true
}

# Keys must not be escrowed with a foreign entity. Fail closed: an absent
# escrow.exists is not evidence of "no escrow"; it must be reported explicitly.
default no_foreign_key_escrow := false

no_foreign_key_escrow if {
	input.key_management_policies.escrow.exists == false
}

no_foreign_key_escrow if {
	input.key_management_policies.escrow.exists == true
	input.key_management_policies.escrow.foreign_entity_holds_keys == false
}

# =============================================================================
# ALGORITHM STANDARDS
# =============================================================================

# Only approved algorithms may be used
only_approved_algorithms_in_use if {
	violations := [r |
		r := input.encrypted_resources[_]
		r.algorithm
		not r.algorithm in input.encryption_standards.algorithms_approved
	]
	count(violations) == 0
}

# Prohibited algorithms must not be in use. The configured list is extended with
# a baseline so a missing list cannot let DES/RC4/MD5 through, and the control
# still fails (CS-009) until the list is configured.
baseline_prohibited := {"DES", "3DES", "RC4", "MD5", "SHA-1"}

configured_prohibited := object.get(object.get(input, "encryption_standards", {}), "prohibited_algorithms", null)

prohibited_algorithms := baseline_prohibited | {a | some a in configured_prohibited}

prohibited_offenders contains r if {
	some r in resources
	r.algorithm
	r.algorithm in prohibited_algorithms
}

default no_prohibited_algorithms := false

no_prohibited_algorithms if {
	is_array(configured_prohibited)
	count(prohibited_offenders) == 0
}

# TLS minimum version enforced on all connections involving regulated data
default tls_minimum_version_enforced := false

tls_minimum_version_enforced if {
	violations := [conn |
		conn := input.encrypted_resources_in_transit[_]
		conn.involves_regulated_data == true
		not tls_version_acceptable(object.get(conn, "tls_version", ""))
	]
	count(violations) == 0
}

tls_version_acceptable(version) if { version == "1.3" }
tls_version_acceptable(version) if { version == "1.2" }

# No weak cipher suites
no_weak_cipher_suites if {
	weak_ciphers := {"RC4", "NULL", "EXPORT", "DES", "3DES", "anon", "MD5"}
	violations := [conn |
		conn := input.encrypted_resources_in_transit[_]
		conn.involves_regulated_data == true
		some weak in weak_ciphers
		contains(conn.cipher_suite, weak)
	]
	count(violations) == 0
}

# =============================================================================
# CODE SIGNING
# =============================================================================

# Code signing must be implemented for sovereign deployments
code_signing_implemented if {
	input.code_signing.implemented == true
	input.code_signing.private_key_in_approved_jurisdiction == true
	input.code_signing.key_location_country in input.approved_jurisdictions
}

# =============================================================================
# VIOLATIONS
# =============================================================================

violations contains v if {
	some r in cmk_offenders
	v := {
		"domain": "cryptographic_sovereignty",
		"control": "CS-001",
		"severity": "critical",
		"resource_id": object.get(r, "resource_id", "unknown"),
		"description": concat("", ["Sensitive data encrypted with provider-managed key (or key management not recorded): ", object.get(r, "resource_id", "unknown")]),
		"remediation": "Enable CMEK (Customer-Managed Encryption Keys) or BYOK for this resource",
	}
}

violations contains v if {
	some r in hyok_offenders
	v := {
		"domain": "cryptographic_sovereignty",
		"control": "CS-002",
		"severity": "critical",
		"resource_id": object.get(r, "resource_id", "unknown"),
		"description": concat("", ["Sovereign/restricted data does not use HYOK: ", object.get(r, "resource_id", "unknown")]),
		"remediation": "Implement Hold Your Own Key (HYOK) with on-premises HSM root of trust",
	}
}

violations contains v if {
	some r in unencrypted_offenders
	v := {
		"domain": "cryptographic_sovereignty",
		"control": "CS-003",
		"severity": "critical",
		"resource_id": object.get(r, "resource_id", "unknown"),
		"description": concat("", ["Non-public data stored unencrypted: ", object.get(r, "resource_id", "unknown")]),
		"remediation": "Enable encryption for all non-public data resources immediately",
	}
}

violations contains v if {
	some r in key_location_offenders
	v := {
		"domain": "cryptographic_sovereignty",
		"control": "CS-004",
		"severity": "critical",
		"resource_id": object.get(r, "resource_id", "unknown"),
		"description": concat("", ["Encryption keys stored outside approved jurisdiction (or location not recorded): ", object.get(r, "key_location_country", "unknown")]),
		"remediation": "Move key material to KMS/HSM located within approved jurisdiction",
	}
}

violations contains v if {
	not hsm_deployed
	v := {
		"domain": "cryptographic_sovereignty",
		"control": "CS-005",
		"severity": "high",
		"description": "No Hardware Security Module (HSM) deployed for key protection",
		"remediation": "Deploy FIPS 140-2 Level 3 or higher HSM for key material protection",
	}
}

violations contains v if {
	not no_hsm_vendor_backdoor
	v := {
		"domain": "cryptographic_sovereignty",
		"control": "CS-006",
		"severity": "critical",
		"description": "HSM vendor has potential access to key material (backdoor risk)",
		"remediation": "Use HSM with verifiable no-vendor-access architecture or on-premises HSM",
	}
}

violations contains v if {
	not key_rotation_policy
	v := {
		"domain": "cryptographic_sovereignty",
		"control": "CS-007",
		"severity": "high",
		"description": "Key rotation policy not documented or rotation interval exceeds 365 days",
		"remediation": "Document and enforce annual (or more frequent) key rotation policy",
	}
}

violations contains v if {
	not no_foreign_key_escrow
	v := {
		"domain": "cryptographic_sovereignty",
		"control": "CS-008",
		"severity": "critical",
		"description": "Encryption keys held in escrow by a foreign entity — compelled disclosure risk",
		"remediation": "Remove foreign key escrow arrangements; retain sole custody of key material",
	}
}

violations contains v if {
	some r in prohibited_offenders
	v := {
		"domain": "cryptographic_sovereignty",
		"control": "CS-009",
		"severity": "critical",
		"resource_id": object.get(r, "resource_id", "unknown"),
		"description": concat("", ["Prohibited algorithm in use: ", r.algorithm, " on resource ", object.get(r, "resource_id", "unknown")]),
		"remediation": "Migrate to approved algorithm (AES-256, RSA-4096, ECDSA P-384, or equivalent)",
	}
}

violations contains v if {
	not is_array(configured_prohibited)
	v := {
		"domain": "cryptographic_sovereignty",
		"control": "CS-009",
		"severity": "high",
		"description": "Evidence missing: encryption_standards.prohibited_algorithms is not configured, so prohibited algorithm use cannot be verified",
		"remediation": "Provide the list of prohibited algorithms in encryption_standards.prohibited_algorithms",
	}
}

violations contains v if {
	not tls_minimum_version_enforced
	conn := input.encrypted_resources_in_transit[_]
	conn.involves_regulated_data == true
	not tls_version_acceptable(object.get(conn, "tls_version", ""))
	v := {
		"domain": "cryptographic_sovereignty",
		"control": "CS-010",
		"severity": "high",
		"connection_id": object.get(conn, "connection_id", "unknown"),
		"description": concat("", ["TLS version below minimum on regulated data connection: ", object.get(conn, "tls_version", "not recorded")]),
		"remediation": "Upgrade to TLS 1.2 minimum; TLS 1.3 preferred",
	}
}

violations contains v if {
	not dual_control_enforced
	v := {
		"domain": "cryptographic_sovereignty",
		"control": "CS-011",
		"severity": "high",
		"description": "Dual control and split knowledge not enforced for key management operations",
		"remediation": "Require at least two authorised personnel for key generation, import, and destruction",
	}
}

# =============================================================================
# OVERALL COMPLIANCE
# =============================================================================

default compliant := false

compliant if {
	sensitive_data_uses_customer_managed_keys
	sovereign_data_uses_hyok
	no_unencrypted_regulated_data
	keys_in_approved_jurisdiction
	hsm_deployed
	hsm_assurance_adequate
	hsm_in_approved_jurisdiction
	no_hsm_vendor_backdoor
	key_material_stays_in_hsm
	key_rotation_policy
	dual_control_enforced
	key_ceremony_documented
	no_foreign_key_escrow
	only_approved_algorithms_in_use
	no_prohibited_algorithms
	tls_minimum_version_enforced
	no_weak_cipher_suites
	code_signing_implemented
}

report := {
	"domain": "Cryptographic Sovereignty",
	"compliant": compliant,
	"controls": {
		"CS-001_customer_managed_keys": sensitive_data_uses_customer_managed_keys,
		"CS-002_sovereign_data_hyok": sovereign_data_uses_hyok,
		"CS-003_no_unencrypted_regulated": no_unencrypted_regulated_data,
		"CS-004_keys_in_jurisdiction": keys_in_approved_jurisdiction,
		"CS-005_hsm_deployed": hsm_deployed,
		"CS-006_no_hsm_backdoor": no_hsm_vendor_backdoor,
		"CS-007_key_rotation_policy": key_rotation_policy,
		"CS-008_no_foreign_key_escrow": no_foreign_key_escrow,
		"CS-009_no_prohibited_algorithms": no_prohibited_algorithms,
		"CS-010_tls_minimum_version": tls_minimum_version_enforced,
		"CS-011_dual_control": dual_control_enforced,
	},
	"violations": violations,
	"violation_count": count(violations),
}

# Defaults for control rules — ensure report never collapses to {} on absent facts
default dual_control_enforced := false
default hsm_deployed := false
default key_rotation_policy := false
default no_hsm_vendor_backdoor := false
