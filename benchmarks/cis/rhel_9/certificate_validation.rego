package cis_rhel9.certificate_validation

import rego.v1

# System Certificate and PKI Validation
# Standards: NIST SP 800-53 SC-17 (Public Key Infrastructure Certificates)
#            NIST SP 800-53 IA-5  (Authenticator Management)
#            NIST SP 800-53 SC-13 (Cryptographic Protection)
#            CIS RHEL 9 v2.0.0 Section 1.8 (System Crypto Policy)
# Use case: EDA drift detection on /etc/pki, /etc/ssl, /etc/certs changes
#           and scheduled certificate expiry monitoring.
#
# Expected input.certificates keys:
#   system_certs       array  — [{subject, days_until_expiry, key_type, key_bits, signature_algorithm}]
#   trust_store_certs  array  — [{subject, issuer, self_signed: bool, explicitly_trusted: bool}]
#   unexpected_cas     array  — [{subject, issuer}] CAs added outside package management
#   ca_bundle_intact   bool   — true if /etc/pki/ca-trust matches rpm -V output
#   crypto_policy      string — update-crypto-policies --show

default compliant := false

expiry_warning_days := 30

expiry_critical_days := 7

# ── Helpers ───────────────────────────────────────────────────────────────────

weak_signature(alg) if {
	weak := {"md5", "sha1", "md2", "md4"}
	some w in weak
	contains(lower(alg), w)
}

weak_key(cert) if {
	cert.key_type == "RSA"
	cert.key_bits < 2048
}

weak_key(cert) if {
	cert.key_type == "EC"
	cert.key_bits < 256
}

weak_key(cert) if {
	cert.key_type == "DSA"
}

# ── Certificate Expiry ────────────────────────────────────────────────────────

# NIST IA-5: Expired certificates
violations contains msg if {
	some cert in input.certificates.system_certs
	cert.days_until_expiry < 0
	msg := sprintf(
		"NIST IA-5: Certificate '%v' EXPIRED %v days ago — replace immediately",
		[cert.subject, cert.days_until_expiry * -1],
	)
}

# Critical: expiring within 7 days
violations contains msg if {
	some cert in input.certificates.system_certs
	cert.days_until_expiry >= 0
	cert.days_until_expiry <= expiry_critical_days
	msg := sprintf(
		"NIST IA-5: Certificate '%v' expires in %v days (CRITICAL — renew now)",
		[cert.subject, cert.days_until_expiry],
	)
}

# Warning: expiring within 30 days
violations contains msg if {
	some cert in input.certificates.system_certs
	cert.days_until_expiry > expiry_critical_days
	cert.days_until_expiry <= expiry_warning_days
	msg := sprintf(
		"NIST IA-5: Certificate '%v' expires in %v days (WARNING — schedule renewal)",
		[cert.subject, cert.days_until_expiry],
	)
}

# ── Weak Keys ─────────────────────────────────────────────────────────────────

violations contains msg if {
	some cert in input.certificates.system_certs
	weak_key(cert)
	msg := sprintf(
		"NIST SC-13: Certificate '%v' uses weak %v key (%v bits) — minimum: RSA 2048, EC P-256",
		[cert.subject, cert.key_type, cert.key_bits],
	)
}

# ── Weak Signature Algorithms ─────────────────────────────────────────────────

violations contains msg if {
	some cert in input.certificates.system_certs
	weak_signature(cert.signature_algorithm)
	msg := sprintf(
		"NIST SC-13: Certificate '%v' uses deprecated signature algorithm '%v' — use SHA-256 or stronger",
		[cert.subject, cert.signature_algorithm],
	)
}

# ── Trust Store Integrity ─────────────────────────────────────────────────────

# Unapproved self-signed certificate in trust store
violations contains msg if {
	some cert in input.certificates.trust_store_certs
	cert.self_signed
	not cert.explicitly_trusted
	msg := sprintf(
		"NIST SC-17: Self-signed certificate '%v' in trust store has not been explicitly approved",
		[cert.subject],
	)
}

# CA added to trust store outside of package management (possible MitM staging)
violations contains msg if {
	some ca in input.certificates.unexpected_cas
	msg := sprintf(
		"NIST SC-17: Unexpected CA '%v' (issuer: %v) added to trust store — verify this is not a MitM intercept certificate",
		[ca.subject, ca.issuer],
	)
}

# CA bundle modified outside package management
violations contains msg if {
	not input.certificates.ca_bundle_intact
	msg := "NIST SC-17: System CA bundle (/etc/pki/ca-trust) has been modified outside of package management — audit for unauthorized CAs"
}

# ── Crypto Policy ─────────────────────────────────────────────────────────────

# CIS 1.8.1: LEGACY policy allows MD5, RC4, DES, SHA-1 — all cryptographically broken
violations contains msg if {
	input.certificates.crypto_policy == "LEGACY"
	msg := "CIS 1.8.1: System crypto policy is LEGACY — permits MD5, RC4, and DES. Upgrade to DEFAULT or FUTURE."
}

# ── Compliance ────────────────────────────────────────────────────────────────

compliant if {
	count(violations) == 0
}

compliance_report := {
	"section": "certificate_validation",
	"standards": ["NIST SP 800-53 SC-17", "NIST SP 800-53 IA-5", "NIST SP 800-53 SC-13", "CIS 1.8"],
	"violations": violations,
	"compliant": compliant,
	"total_certs": count(object.get(input.certificates, "system_certs", [])),
	"expired": count([c |
		some c in input.certificates.system_certs
		c.days_until_expiry < 0
	]),
	"expiring_critical": count([c |
		some c in input.certificates.system_certs
		c.days_until_expiry >= 0
		c.days_until_expiry <= expiry_critical_days
	]),
	"expiring_warning": count([c |
		some c in input.certificates.system_certs
		c.days_until_expiry > expiry_critical_days
		c.days_until_expiry <= expiry_warning_days
	]),
}
