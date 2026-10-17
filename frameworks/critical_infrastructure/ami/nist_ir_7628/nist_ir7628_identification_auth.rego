# METADATA
# title: "NIST IR 7628 Rev 1 - Smart Grid Cybersecurity"
# custom:
#   class: ot
#   framework: ami
#   source: nist
#   domains: [ot, energy, smart-grid]
#   coverage:
#     checks: 6
#     cited: 4
#     density: section
#     basis: role
#     tested: true
#     entrypoint: compliance_report
#     guard: self
#     as_of: v2.4.1
package ami.nist_ir7628.identification_auth

import rego.v1

# NIST IR 7628 Rev 1 - Smart Grid Cybersecurity
# Control Family: SG.IA - Identification and Authentication
# Scope: AMI meters, head-end systems, communication network devices

# SG.IA-3: Device Identification and Authentication
# Every AMI device must authenticate to the network using a unique credential
device_authentication_enforced if {
    input.identification_auth.devices.unique_identity_per_device == true
    input.identification_auth.devices.authentication_required == true
    input.identification_auth.devices.unauthenticated_devices_blocked == true
}

# SG.IA-5: Authenticator Management - PKI Certificate Requirements
# Device certificates must use strong algorithms and have valid expiry
pki_certificates_valid if {
    input.identification_auth.pki.certificate_authority_trusted == true
    input.identification_auth.pki.certificate_algorithm in {"RSA-2048", "RSA-4096", "ECDSA-P256", "ECDSA-P384"}
    input.identification_auth.pki.certificate_revocation_checking == true
}

# SG.IA-5: Certificate expiry — warn if any device cert expires within 30 days
thirty_days_ns := 30 * 24 * 60 * 60 * 1000000000

ninety_days_ns := 90 * 24 * 60 * 60 * 1000000000

# A certificate with an unparseable or missing expiry_date is not "fine".
cert_not_expiring_soon(cert) if {
    expiry_ns := time.parse_rfc3339_ns(cert.expiry_date)
    (expiry_ns - time.now_ns()) > thirty_days_ns
}

# No certificate inventory is no evidence (an empty list is vacuously "fine").
certs_inventory_present if {
    is_array(input.identification_auth.pki.device_certificates)
    count(input.identification_auth.pki.device_certificates) > 0
}

no_certs_expiring_soon if {
    certs_inventory_present
    every cert in input.identification_auth.pki.device_certificates {
        cert_not_expiring_soon(cert)
    }
}

# SG.IA-5: Key rotation — device credentials must be rotated at least every 90 days
rotated_recently(device) if {
    last_rotation_ns := time.parse_rfc3339_ns(device.last_key_rotation_date)
    (time.now_ns() - last_rotation_ns) <= ninety_days_ns
}

credential_inventory_present if {
    is_array(input.identification_auth.devices.credential_inventory)
    count(input.identification_auth.devices.credential_inventory) > 0
}

key_rotation_current if {
    credential_inventory_present
    every device in input.identification_auth.devices.credential_inventory {
        rotated_recently(device)
    }
}

# SG.IA-7: Cryptographic Module Authentication
# Head-end must use FIPS 140-2/3 validated cryptographic modules
cryptographic_modules_validated if {
    input.identification_auth.cryptography.fips_validated == true
    input.identification_auth.cryptography.validation_level >= 2
}

# SG.IA-8: MFA for privileged users on head-end systems
mfa_for_privileged_users if {
    input.identification_auth.mfa.enabled == true
    input.identification_auth.mfa.required_for_privileged == true
    input.identification_auth.mfa.second_factor in {"hardware_token", "pki_smartcard", "totp"}
}

# Violations

violations contains msg if {
    not device_authentication_enforced
    msg := "SG.IA-3: Device identification and authentication not enforced for all AMI devices"
}

violations contains msg if {
    not pki_certificates_valid
    msg := "SG.IA-5: PKI certificate configuration is invalid — verify CA trust, algorithm strength, and CRL checking"
}

violations contains msg if {
    pki_certificates_valid
    not certs_inventory_present
    msg := "SG.IA-5: evidence missing — pki.device_certificates not collected (certificate expiry cannot be assessed)"
}

violations contains msg if {
    pki_certificates_valid
    certs_inventory_present
    not no_certs_expiring_soon
    expiring := [cert.device_id |
        cert := input.identification_auth.pki.device_certificates[_]
        not cert_not_expiring_soon(cert)
    ]
    msg := sprintf("SG.IA-5: Device certificates expiring within 30 days (or with unreadable expiry_date): %v", [expiring])
}

violations contains msg if {
    not credential_inventory_present
    msg := "SG.IA-5: evidence missing — devices.credential_inventory not collected (key rotation cannot be assessed)"
}

violations contains msg if {
    credential_inventory_present
    not key_rotation_current
    overdue := [device.device_id |
        device := input.identification_auth.devices.credential_inventory[_]
        not rotated_recently(device)
    ]
    msg := sprintf("SG.IA-5: Key rotation overdue (>90 days) or last_key_rotation_date unreadable for devices: %v", [overdue])
}

violations contains msg if {
    not cryptographic_modules_validated
    msg := "SG.IA-7: Cryptographic modules are not FIPS 140-2/3 validated at Level 2 or higher"
}

violations contains msg if {
    not mfa_for_privileged_users
    msg := "SG.IA-8: Multi-Factor Authentication not enforced for privileged head-end users"
}

default compliant := false

compliant if {
    count(violations) == 0
}

compliance_report := {
    "control_family": "SG.IA",
    "framework": "NIST IR 7628 Rev 1",
    "controls_assessed": ["SG.IA-3", "SG.IA-5", "SG.IA-7", "SG.IA-8"],
    "total_violations": count(violations),
    "compliant": compliant,
    "violations": violations,
}
