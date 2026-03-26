package hipaa.transmission_security

import rego.v1

# =============================================================================
# HIPAA Security Rule — 45 CFR 164.312(e)
# Technical Safeguard: Transmission Security
#
# Implement technical security measures to guard against unauthorized access
# to ePHI transmitted over electronic communications networks.
#
# Required:    164.312(e)(1) - Transmission security
# Addressable: 164.312(e)(2)(i)  - Integrity controls
#              164.312(e)(2)(ii) - Encryption
#
# Input shape:
#   input.network               - network configuration
#   input.tls                   - TLS/SSL configuration
#   input.vpn                   - VPN configuration
#   input.phi_systems[]         - systems transmitting ePHI
#   input.email                 - email configuration
#   input.api                   - API security configuration
# =============================================================================

# ---------------------------------------------------------------------------
# Deprecated protocols — never acceptable for ePHI
# ---------------------------------------------------------------------------

deprecated_protocols := {"SSLv2", "SSLv3", "TLSv1.0", "TLSv1.1", "HTTP", "FTP", "Telnet", "SMTP_plaintext"}

weak_ciphers := {
    "RC4", "DES", "3DES", "EXPORT", "NULL", "ANON",
    "MD5", "RC2", "IDEA",
}

# ---------------------------------------------------------------------------
# 164.312(e)(1) — Transmission Security (Required)
# Guard against unauthorized access to ePHI in transit
# ---------------------------------------------------------------------------

violation_transmission_security contains msg if {
    some phi_system in input.phi_systems
    not phi_system.transmission_encrypted
    msg := sprintf(
        "HIPAA 164.312(e)(1): System '%v' transmits ePHI without encryption. All ePHI in transit must be protected.",
        [phi_system.name]
    )
}

violation_transmission_security contains msg if {
    some phi_system in input.phi_systems
    some protocol in phi_system.protocols_in_use
    protocol in deprecated_protocols
    msg := sprintf(
        "HIPAA 164.312(e)(1): System '%v' uses deprecated protocol '%v' for ePHI transmission. Use TLS 1.2 or higher.",
        [phi_system.name, protocol]
    )
}

violation_transmission_security contains msg if {
    not input.network.phi_network_segmented
    msg := "HIPAA 164.312(e)(1): Network carrying ePHI is not segmented. ePHI traffic should be isolated from general network traffic."
}

# ---------------------------------------------------------------------------
# TLS Configuration
# ---------------------------------------------------------------------------

violation_tls contains msg if {
    input.tls.minimum_version in {"TLSv1.0", "TLSv1.1"}
    msg := sprintf(
        "HIPAA 164.312(e)(2)(ii): Minimum TLS version is %v. TLS 1.2 is the minimum acceptable; TLS 1.3 is recommended.",
        [input.tls.minimum_version]
    )
}

violation_tls contains msg if {
    some cipher in input.tls.enabled_ciphers
    cipher in weak_ciphers
    msg := sprintf(
        "HIPAA 164.312(e)(2)(ii): Weak cipher suite '%v' is enabled. Remove all weak ciphers from TLS configuration.",
        [cipher]
    )
}

violation_tls contains msg if {
    not input.tls.certificate_expiry_monitoring
    msg := "HIPAA 164.312(e)(2)(ii): TLS certificate expiry is not monitored. Expired certificates break encrypted ePHI transmission."
}

violation_tls contains msg if {
    input.tls.certificate_expiry_days < 30
    msg := sprintf(
        "HIPAA 164.312(e)(2)(ii): TLS certificate expires in %v days. Renew immediately to prevent unencrypted ePHI exposure.",
        [input.tls.certificate_expiry_days]
    )
}

violation_tls contains msg if {
    not input.tls.mutual_tls_for_phi_apis
    msg := "HIPAA 164.312(e)(2)(ii): APIs transmitting ePHI do not use mutual TLS (mTLS). mTLS provides stronger authentication for ePHI endpoints."
}

# ---------------------------------------------------------------------------
# VPN Requirements
# ---------------------------------------------------------------------------

violation_vpn contains msg if {
    input.network.remote_phi_access_enabled
    not input.vpn.required_for_remote_phi_access
    msg := "HIPAA 164.312(e)(1): Remote ePHI access is permitted without VPN. VPN or equivalent encrypted tunnel is required."
}

violation_vpn contains msg if {
    input.vpn.required_for_remote_phi_access
    input.vpn.protocol in {"PPTP", "L2TP_no_ipsec"}
    msg := sprintf(
        "HIPAA 164.312(e)(1): VPN protocol '%v' is insecure. Use IKEv2/IPsec, OpenVPN, or WireGuard.",
        [input.vpn.protocol]
    )
}

violation_vpn contains msg if {
    input.vpn.split_tunneling_enabled
    msg := "HIPAA 164.312(e)(1): VPN split tunneling is enabled. ePHI traffic must route entirely through the encrypted VPN tunnel."
}

# ---------------------------------------------------------------------------
# 164.312(e)(2)(i) — Integrity Controls for Transmission (Addressable)
# Ensure ePHI is not improperly modified during transmission
# ---------------------------------------------------------------------------

violation_transmission_integrity contains msg if {
    not input.network.message_authentication_enabled
    msg := "HIPAA 164.312(e)(2)(i): Message authentication (MAC/HMAC) is not enabled for ePHI transmission. Transmission integrity cannot be verified."
}

violation_transmission_integrity contains msg if {
    some phi_system in input.phi_systems
    phi_system.api_endpoint == true
    not phi_system.request_signing_enabled
    msg := sprintf(
        "HIPAA 164.312(e)(2)(i): API endpoint '%v' transmitting ePHI does not use request signing. Implement HMAC or digital signatures.",
        [phi_system.name]
    )
}

# ---------------------------------------------------------------------------
# Email with ePHI
# ---------------------------------------------------------------------------

violation_email contains msg if {
    input.email.phi_sent_via_email
    not input.email.encrypted_email_required
    msg := "HIPAA 164.312(e)(2)(ii): ePHI is sent via email without encryption enforcement. Require S/MIME or PGP for all ePHI email."
}

violation_email contains msg if {
    input.email.phi_sent_via_email
    not input.email.dlp_enabled
    msg := "HIPAA 164.312(e)(1): Data Loss Prevention (DLP) is not enabled on email. DLP prevents accidental unencrypted ePHI transmission."
}

# ---------------------------------------------------------------------------
# All violations
# ---------------------------------------------------------------------------

violations contains msg if { some msg in violation_transmission_security }
violations contains msg if { some msg in violation_tls }
violations contains msg if { some msg in violation_vpn }
violations contains msg if { some msg in violation_transmission_integrity }
violations contains msg if { some msg in violation_email }

# ---------------------------------------------------------------------------
# Compliance
# ---------------------------------------------------------------------------

compliant if {
    count(violations) == 0
}

compliance_report := {
    "section":        "164.312(e)",
    "title":          "Transmission Security",
    "required":       true,
    "compliant":      compliant,
    "violation_count": count(violations),
    "violations":     violations,
    "controls": {
        "transmission_encrypted":   count(violation_transmission_security) == 0,
        "tls_configuration":        count(violation_tls) == 0,
        "vpn_required":             count(violation_vpn) == 0,
        "transmission_integrity":   count(violation_transmission_integrity) == 0,
        "email_protection":         count(violation_email) == 0,
    },
}
