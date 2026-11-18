# METADATA
# title: "NIST SP 800-53 Rev 5 — System and Communications Protection (SC) Family"
# custom:
#   class: compliance
#   framework: nist_sp_800_53
#   source: nist
#   domains: [us-federal, security-controls]
#   coverage:
#     checks: 17
#     cited: 17
#     density: sized
#     basis: size
#     tested: true
#     entrypoint: compliance_report
#     guard: self
#     as_of: v2.4.2
package nist.sp800_53.system_communications

import rego.v1

# NIST SP 800-53 Rev 5 — System and Communications Protection (SC) Family
# Boundary protection, transmission confidentiality/integrity, key management.
#
# Control ids and titles checked against the NIST OSCAL catalog, SP 800-53 Rev 5 release 5.2.0.
# Evaluated: SC-1, SC-2, SC-3, SC-5, SC-7, SC-8, SC-8(1), SC-10, SC-12, SC-13, SC-15, SC-17, SC-18,
# SC-20, SC-21, SC-23, SC-28, SC-28(1) (18 ids). SC-19 (Voice over Internet Protocol) is WITHDRAWN in Rev 5
# ("Technology-specific; addressed as any other technology or protocol") and is not assessed.
#
# SC-8 and SC-28 protect "the [Selection: confidentiality; integrity]" of information: the selection is an
# organization-defined parameter and the mechanism is the organisation's choice. Cryptography is the
# enhancement SC-8(1) / SC-28(1), evaluated as its own control.

_sc := object.get(input, "sc_controls", {})

_valid_properties := {"confidentiality", "integrity"}

# The organisation's SC-8 selection, when supplied as a non-empty list of confidentiality / integrity.
_sc8_selection := {p | some p in object.get(_sc, ["transmission_protection", "odp", "properties"], [])}

_sc8_selection_valid if {
	count(_sc8_selection) > 0
	every p in _sc8_selection {
		p in _valid_properties
	}
}

# Without a valid selection both properties are required: protecting both satisfies any selection.
default sc8_required_properties := {"confidentiality", "integrity"}

sc8_required_properties := _sc8_selection if _sc8_selection_valid

_sc8_protected contains "confidentiality" if object.get(_sc, ["transmission_confidentiality", "protected"], false) == true

_sc8_protected contains "confidentiality" if object.get(_sc, ["transmission_confidentiality", "encrypted"], false) == true

_sc8_protected contains "integrity" if object.get(_sc, ["transmission_integrity", "protected"], false) == true

_sc8_protected contains "integrity" if object.get(_sc, ["transmission_integrity", "cryptographic"], false) == true

_sc8_1_crypto contains "confidentiality" if object.get(_sc, ["transmission_confidentiality", "encrypted"], false) == true

_sc8_1_crypto contains "integrity" if object.get(_sc, ["transmission_integrity", "cryptographic"], false) == true

sc8_unprotected := sc8_required_properties - _sc8_protected

sc8_1_uncovered := sc8_required_properties - _sc8_1_crypto

_sc28 := object.get(_sc, "protection_of_info_at_rest", {})

# SC-28 base: protection by the organisation's chosen mechanism (protected) or by encryption (encrypted).
sc28_protected if object.get(_sc28, "protected", false) == true

sc28_protected if object.get(_sc28, "encrypted", false) == true

default compliant := false

violation contains msg if {
	not input.sc_controls.policy.documented
	msg := "NIST SC-1: System and communications protection policy not documented"
}

violation contains msg if {
	not input.sc_controls.app_partitioning.separated
	msg := "NIST SC-2: User functionality is not separated from system management functionality"
}

violation contains msg if {
	not input.sc_controls.security_function_isolation.implemented
	msg := "NIST SC-3: Security functions not isolated from non-security functions"
}

violation contains msg if {
	not input.sc_controls.denial_of_service.protections
	msg := "NIST SC-5: Denial-of-service protections not in place"
}

violation contains msg if {
	not input.sc_controls.boundary_protection.deployed
	msg := "NIST SC-7: System boundary protection not deployed at managed interfaces"
}

violation contains msg if {
	count(sc8_unprotected) > 0
	msg := sprintf(
		"NIST SC-8: Transmission confidentiality and integrity — selected properties %v not evidenced as protected (unprotected or not collected: %v; selection from input.sc_controls.transmission_protection.odp.properties, both when not supplied)",
		[sort(sc8_required_properties), sort(sc8_unprotected)],
	)
}

violation contains msg if {
	count(sc8_1_uncovered) > 0
	msg := sprintf(
		"NIST SC-8(1): Cryptographic protection — cryptographic mechanisms not evidenced for transmitted-information properties %v (confidentiality: input.sc_controls.transmission_confidentiality.encrypted; integrity: input.sc_controls.transmission_integrity.cryptographic)",
		[sort(sc8_1_uncovered)],
	)
}

violation contains msg if {
	not input.sc_controls.network_disconnect.timeout_configured
	msg := "NIST SC-10: Network session disconnect timeout not configured"
}

violation contains msg if {
	not input.sc_controls.cryptographic_key_mgmt.documented
	msg := "NIST SC-12: Cryptographic key management process not documented"
}

violation contains msg if {
	not input.sc_controls.cryptographic_protection.fips_validated
	msg := "NIST SC-13: Cryptographic mechanisms not FIPS-validated"
}

violation contains msg if {
	not input.sc_controls.collaborative_devices.disabled_when_unused
	msg := "NIST SC-15: Collaborative computing devices (mic/camera) not disabled when unused"
}

violation contains msg if {
	not input.sc_controls.public_key_infrastructure.certificates_managed
	msg := "NIST SC-17: Public key certificates not issued/managed by authorized PKI"
}

violation contains msg if {
	not input.sc_controls.mobile_code.controls_enforced
	msg := "NIST SC-18: Mobile code controls (allow/deny lists) not enforced"
}

violation contains msg if {
	not input.sc_controls.secure_dns.dnssec_enforced
	msg := "NIST SC-20: Authoritative name resolution does not provide origin authentication and integrity artifacts (DNSSEC signing not evidenced: input.sc_controls.secure_dns.dnssec_enforced)"
}

violation contains msg if {
	not input.sc_controls.secure_dns.dnssec_enforced
	msg := "NIST SC-21: Recursive or caching resolver does not validate origin and integrity of responses (DNSSEC validation not evidenced: input.sc_controls.secure_dns.dnssec_enforced)"
}

violation contains msg if {
	not input.sc_controls.session_authenticity.protected
	msg := "NIST SC-23: Session authenticity not protected (session ID randomness, timeouts)"
}

violation contains msg if {
	not sc28_protected
	msg := "NIST SC-28: evidence missing — protection of information at rest not evidenced by the organization-chosen mechanism (input.sc_controls.protection_of_info_at_rest.protected) or by encryption (.encrypted)"
}

violation contains msg if {
	object.get(_sc28, "encrypted", false) != true
	msg := "NIST SC-28(1): Cryptographic protection of information at rest not evidenced (input.sc_controls.protection_of_info_at_rest.encrypted is not true)"
}

compliant if count(violation) == 0

# The control and enhancement ids this family evaluates; each has exactly one finding when it fails.
evaluated_controls := {
	"SC-1", "SC-2", "SC-3", "SC-5", "SC-7", "SC-8", "SC-8(1)", "SC-10", "SC-12",
	"SC-13", "SC-15", "SC-17", "SC-18", "SC-20", "SC-21", "SC-23", "SC-28", "SC-28(1)",
}

compliance_report := {
	"family": "SC",
	"name": "System and Communications Protection",
	"controls_evaluated": count(evaluated_controls),
	"violations": violation,
	"violation_count": count(violation),
	"compliant": compliant,
}
