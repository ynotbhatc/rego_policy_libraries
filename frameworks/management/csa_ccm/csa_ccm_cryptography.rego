# METADATA
# title: "Csa Ccm Cryptography"
# custom:
#   class: compliance
#   framework: csa_ccm
#   source: csa
#   domains: [cloud]
#   coverage:
#     checks: 34
#     cited: 9
#     density: sized
#     basis: size
#     tested: true
#     entrypoint: compliance_report
#     guard: self
#     as_of: v2.4.2
package csa_ccm.cryptography

import rego.v1

default compliant := false

_base := ["csa_ccm", "cryptography"]

# Evidence rule: only the boolean true passes a yes/no fact. A fact that is missing or null was not
# collected, and any other type (the strings "true" and "false", numbers) is a collection error. Both fail
# the check, and the finding names the problem. Boolean false keeps the plain finding text.
_fact(path) := object.get(_doc, array.concat(_base, path), null)

# No input document, or one that is not an object, reads as empty: every fact is then missing.
_doc := input if {
	is_object(input)
} else := {}

_field(path) := concat(".", array.concat(["input"], array.concat(_base, path)))

_finding(text, path) := text if _fact(path) == false

_finding(text, path) := sprintf("%s — evidence missing: %s not collected", [text, _field(path)]) if {
	_fact(path) == null
}

_finding(text, path) := sprintf("%s — evidence invalid: %s is not a boolean (got %s)", [text, _field(path), type_name(value)]) if {
	value := _fact(path)
	value != null
	not is_boolean(value)
}

violations contains msg if {
	msg := _finding("CEK-01: Cryptography and key management policy not formally established", ["crypto_policy", "policy_established"])
}

violations contains msg if {
	msg := _finding("CEK-01: Approved cryptographic algorithms not listed in policy — permitted algorithms must be enumerated", ["crypto_policy", "approved_algorithms_listed"])
}

violations contains msg if {
	msg := _finding("CEK-01: Key management procedures not defined within the cryptography policy", ["crypto_policy", "key_management_procedures_defined"])
}

violations contains msg if {
	msg := _finding("CEK-01: Cryptography policy not reviewed at least annually or when cryptographic standards change", ["crypto_policy", "policy_reviewed_annually"])
}

violations contains msg if {
	msg := _finding("CEK-02: Sensitive data not encrypted at rest — data classification must drive encryption requirements", ["encryption_at_rest", "sensitive_data_encrypted"])
}

violations contains msg if {
	msg := _finding("CEK-02: Database encryption at rest not enabled for databases containing sensitive or regulated data", ["encryption_at_rest", "database_encryption_enabled"])
}

violations contains msg if {
	msg := _finding("CEK-02: Storage-level encryption not enabled for cloud storage containing sensitive data", ["encryption_at_rest", "storage_encryption_enabled"])
}

violations contains msg if {
	msg := _finding("CEK-02: Backup data not encrypted — backup storage must enforce encryption at rest", ["encryption_at_rest", "backup_encryption_enabled"])
}

violations contains msg if {
	msg := _finding("CEK-03: TLS not enforced for data in transit — all network communications must use TLS 1.2 or higher", ["encryption_in_transit", "tls_enforced"])
}

violations contains msg if {
	_fact(["encryption_in_transit", "tls_enforced"]) == true
	msg := _finding("CEK-03: TLS version below minimum required — TLS 1.2 is the minimum; TLS 1.3 is preferred", ["encryption_in_transit", "minimum_tls_version_met"])
}

violations contains msg if {
	msg := _finding("CEK-03: Weak cipher suites not disabled — RC4, DES, 3DES, and export ciphers must be disabled", ["encryption_in_transit", "weak_ciphers_disabled"])
}

violations contains msg if {
	msg := _finding("CEK-03: Certificate validity not enforced — expired or self-signed certificates must be rejected", ["encryption_in_transit", "certificate_validity_enforced"])
}

violations contains msg if {
	msg := _finding("CEK-04: Key generation does not use approved algorithms — AES-256, RSA-2048+, or ECC-256+ required", ["key_generation", "approved_algorithms_used"])
}

violations contains msg if {
	msg := _finding("CEK-04: Cryptographic key length does not meet minimum standards for the algorithm in use", ["key_generation", "key_length_meets_standard"])
}

violations contains msg if {
	msg := _finding("CEK-04: Random number generator used for key generation not validated as cryptographically secure", ["key_generation", "random_number_generator_validated"])
}

violations contains msg if {
	msg := _finding("CEK-04: Weak or deprecated key types (MD5, SHA-1 for signing, DSA-1024) not explicitly prohibited", ["key_generation", "weak_keys_prohibited"])
}

violations contains msg if {
	msg := _finding("CEK-05: Cryptographic keys not protected using HSM or equivalent key management service", ["key_storage", "hsm_or_equivalent_used"])
}

violations contains msg if {
	msg := _finding("CEK-05: Cryptographic keys stored in plaintext — keys must be encrypted when stored", ["key_storage", "keys_never_stored_in_plaintext"])
}

violations contains msg if {
	msg := _finding("CEK-05: Access to cryptographic keys not restricted — least-privilege access to keys must be enforced", ["key_storage", "key_access_restricted"])
}

violations contains msg if {
	msg := _finding("CEK-05: Access to cryptographic keys not logged — all key access must generate an audit record", ["key_storage", "key_access_logged"])
}

violations contains msg if {
	msg := _finding("CEK-06: Key rotation schedule not defined — rotation frequency must be specified per key type", ["key_rotation", "rotation_schedule_defined"])
}

violations contains msg if {
	msg := _finding("CEK-06: Key rotation not enforced per defined schedule — keys must be rotated automatically or with documented process", ["key_rotation", "rotation_enforced"])
}

violations contains msg if {
	msg := _finding("CEK-06: Emergency key rotation procedure not defined for use when compromise is suspected", ["key_rotation", "emergency_rotation_procedure"])
}

violations contains msg if {
	msg := _finding("CEK-06: Key rotation events not logged — rotation history must be maintained for audit", ["key_rotation", "rotation_logged"])
}

violations contains msg if {
	msg := _finding("CEK-07: Key destruction and revocation procedures not defined", ["key_destruction", "destruction_procedure_defined"])
}

violations contains msg if {
	msg := _finding("CEK-07: Key destruction process does not guarantee keys are cryptographically irrecoverable", ["key_destruction", "destroyed_keys_irrecoverable"])
}

violations contains msg if {
	msg := _finding("CEK-07: Key revocation does not occur within defined timeframe upon suspected compromise or employee departure", ["key_destruction", "revocation_timely"])
}

violations contains msg if {
	msg := _finding("CEK-08: Certificate lifecycle management not implemented — issuance, renewal, and revocation must be managed", ["certificate_management", "lifecycle_management_implemented"])
}

violations contains msg if {
	msg := _finding("CEK-08: Certificate expiry monitoring not enabled — alerts must fire before certificate expiration", ["certificate_management", "expiry_monitoring_enabled"])
}

violations contains msg if {
	msg := _finding("CEK-08: Certificate inventory not maintained — all issued certificates must be catalogued", ["certificate_management", "certificate_inventory_maintained"])
}

violations contains msg if {
	msg := _finding("CEK-08: Certificate revocation (CRL or OCSP) not implemented and checked by relying parties", ["certificate_management", "crl_or_ocsp_implemented"])
}

violations contains msg if {
	msg := _finding("CEK-09: Process not defined for reviewing cryptographic controls when industry standards change", ["crypto_review", "standards_review_process"])
}

violations contains msg if {
	msg := _finding("CEK-09: Deprecated or weak cryptographic implementations not proactively identified across the environment", ["crypto_review", "deprecated_crypto_identified"])
}

violations contains msg if {
	msg := _finding("CEK-09: Migration plan not defined for transitioning away from deprecated cryptographic algorithms", ["crypto_review", "migration_plan_when_deprecated"])
}

compliant if count(violations) == 0

# The control ids this module carries checks for. A control can have several checks, so the report counts
# both: violations lists one finding per failed check, failed_controls counts the controls they belong to.
_control_ids := ["CEK-01", "CEK-02", "CEK-03", "CEK-04", "CEK-05", "CEK-06", "CEK-07", "CEK-08", "CEK-09"]

failed_control_ids := sort({id |
	some msg in violations
	id := split(msg, ":")[0]
})

compliance_report := {
	"domain": "CEK — Cryptography, Encryption & Key Management",
	"compliant": compliant,
	"controls_checked": count(_control_ids),
	"failed_controls": count(failed_control_ids),
	"passed_controls": count(_control_ids) - count(failed_control_ids),
	"failed_control_ids": failed_control_ids,
	"checks_total": 34,
	"violation_count": count(violations),
	"violations": violations,
}
