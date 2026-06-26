package nist.sp800_53.system_communications

import rego.v1

# NIST SP 800-53 Rev 5 — System and Communications Protection (SC) Family
# Boundary protection, transmission confidentiality/integrity, key management.

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
    not input.sc_controls.transmission_confidentiality.encrypted
    msg := "NIST SC-8: Transmission confidentiality not protected via cryptographic mechanisms"
}

violation contains msg if {
    not input.sc_controls.transmission_integrity.protected
    msg := "NIST SC-8(1): Transmission integrity not protected via cryptographic mechanisms"
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
    not input.sc_controls.voip.controls_enforced
    msg := "NIST SC-19: VoIP usage restrictions and implementation guidance not enforced"
}

violation contains msg if {
    not input.sc_controls.secure_dns.dnssec_enforced
    msg := "NIST SC-20/21: Secure name/address resolution (DNSSEC) not enforced"
}

violation contains msg if {
    not input.sc_controls.session_authenticity.protected
    msg := "NIST SC-23: Session authenticity not protected (session ID randomness, timeouts)"
}

violation contains msg if {
    not input.sc_controls.protection_of_info_at_rest.encrypted
    msg := "NIST SC-28: Information at rest not protected via encryption"
}

compliant if { count(violation) == 0 }

compliance_report := {
    "family": "SC",
    "name":   "System and Communications Protection",
    "controls_evaluated": 17,
    "violations": violation,
    "violation_count": count(violation),
    "compliant": compliant,
}
