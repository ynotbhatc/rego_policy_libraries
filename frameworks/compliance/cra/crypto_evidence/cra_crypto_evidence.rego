package cra.crypto_evidence

import rego.v1
import data.iso27001.cryptography as iso_crypto

# CRA — Cryptography evidence integration.
#
# Re-uses findings from the ISO 27001 cryptography module
# (data.iso27001.cryptography) and re-frames them as CRA Annex I.5
# (confidentiality) and Annex I.6 (integrity) violations. Organisations
# already maintaining ISO 27001 A.10 compliance produce the input shape
# this module consumes — no second attestation is required.
#
# Input shape: input.cryptography.* + input.key_management.* exactly as
# data.iso27001.cryptography expects.

default compliant := false

# Helper — true if the named ISO 27001 boolean rule does NOT hold.
iso_failed(rule_name) if {
    rule_name == "cryptographic_policy"
    not iso_crypto.cryptographic_policy
}

iso_failed(rule_name) if {
    rule_name == "key_management"
    not iso_crypto.key_management
}

iso_failed(rule_name) if {
    rule_name == "key_generation_secure"
    not iso_crypto.key_generation_secure
}

iso_failed(rule_name) if {
    rule_name == "key_distribution_secure"
    not iso_crypto.key_distribution_secure
}

iso_failed(rule_name) if {
    rule_name == "key_usage_controlled"
    not iso_crypto.key_usage_controlled
}

iso_failed(rule_name) if {
    rule_name == "key_destruction_secure"
    not iso_crypto.key_destruction_secure
}

# ── CRA Annex I.5 — Confidentiality (encryption) ────────────────────────

# Annex I.5 demands appropriate confidentiality protection. A missing
# crypto policy means the manufacturer cannot demonstrate "appropriate
# level of cryptographic protection" — the auditor will refuse the claim.
violation contains msg if {
    iso_failed("cryptographic_policy")
    msg := "CRA Annex I.5 (via ISO 27001 A.10.1.1): No documented cryptographic policy — Annex I.5 cannot be attested without a policy that specifies approved algorithms + key management"
}

violation contains msg if {
    iso_failed("key_generation_secure")
    msg := "CRA Annex I.5 (via ISO 27001 A.10.1.2): Key generation is not demonstrably secure (random source / entropy / approved algorithms) — undermines confidentiality of encrypted data"
}

violation contains msg if {
    iso_failed("key_distribution_secure")
    msg := "CRA Annex I.5 (via ISO 27001 A.10.1.2): Key distribution is not secure — keys in transit may be intercepted, breaking confidentiality at the boundary"
}

# Annex I.5(b) — data in transit. State-of-the-art encryption means TLS 1.2+
# with current cipher suites, no deprecated protocols.
violation contains msg if {
    some proto in input.cryptography.protocols_in_use
    proto in {"SSLv2", "SSLv3", "TLS1.0", "TLS1.1"}
    msg := sprintf("CRA Annex I.5(b): Deprecated transport protocol '%s' in use — not state-of-the-art for transmission confidentiality", [proto])
}

violation contains msg if {
    some cipher in input.cryptography.ciphers_in_use
    cipher in {"DES", "3DES", "RC4", "MD5", "SHA1", "RC2", "EXPORT"}
    msg := sprintf("CRA Annex I.5(b): Weak cipher '%s' in use — not state-of-the-art for transmission confidentiality", [cipher])
}

# Annex I.5(a) — data at rest.
violation contains msg if {
    not input.cryptography.at_rest.disk_encryption_enabled
    msg := "CRA Annex I.5(a) (via ISO 27001 A.10): Disk-level encryption not enabled for stored data — at-rest confidentiality not protected"
}

violation contains msg if {
    not input.cryptography.at_rest.database_encryption_enabled
    msg := "CRA Annex I.5(a) (via ISO 27001 A.10): Database encryption not enabled — stored personal/sensitive data confidentiality not protected"
}

# ── CRA Annex I.6 — Integrity (code signing, anti-tamper) ─────────────────

violation contains msg if {
    iso_failed("key_usage_controlled")
    msg := "CRA Annex I.6 (via ISO 27001 A.10.1.2): Key usage not controlled — signing keys may be used by unauthorised processes, undermining code-signing integrity"
}

violation contains msg if {
    iso_failed("key_destruction_secure")
    msg := "CRA Annex I.6 (via ISO 27001 A.10.1.2): Expired key destruction not secure — superseded signing keys may still produce valid-looking signatures, breaking tamper detection"
}

# Anti-rollback (Annex I.6(b)) — old signed firmware should not be installable.
violation contains msg if {
    not input.cryptography.signing.anti_rollback_enforced
    msg := "CRA Annex I.6(b): Anti-rollback enforcement not in place — older signed firmware can be re-installed, defeating tamper detection"
}

# Hardware-backed key storage (Annex I.4 + I.6 interaction)
violation contains msg if {
    input.cryptography.signing.in_use
    not input.cryptography.signing.hardware_backed_key_storage
    msg := "CRA Annex I.6 (interaction with I.4): Signing keys not held in hardware-backed storage — chain of trust depends on a key the host OS can read"
}

# ── CRA Annex I.4 — authentication state-of-the-art ─────────────────────

# FIPS validation (FIPS 140-2 Level 2+) is the closest commonly-recognised
# objective standard. Annex I.4 says "state-of-the-art" without naming a
# specific standard, but absence of FIPS validation is rarely defensible.
violation contains msg if {
    not input.cryptography.fips_validated
    msg := "CRA Annex I.4 (auth interaction): Cryptographic modules used for authentication are not FIPS 140-2/3 validated — state-of-the-art claim is not defensible"
}

# ── Manufacturer obligation (Art.13(1) interaction) ─────────────────────

violation contains msg if {
    iso_failed("key_management")
    msg := "CRA Art.13(1) (via ISO 27001 A.10.1.2): Manufacturer cannot attest to ensuring essential requirements compliance — key management foundation is incomplete"
}

# ── Compliance + report ─────────────────────────────────────────────────

compliant if { count(violation) == 0 }

iso_27001_crypto_compliant := iso_crypto.cryptographic_controls

compliance_report := {
    "family": "Cryptography evidence integration",
    "name":   "CRA × ISO 27001 A.10 findings bridge",
    "controls_evaluated": 13,
    "violations": violation,
    "violation_count": count(violation),
    "compliant": compliant,
    "upstream": {
        "module": "data.iso27001.cryptography",
        "iso_a10_compliant": iso_27001_crypto_compliant,
    },
}
