# METADATA
# title: "HIPAA Security Rule — 45 CFR 164.312(e)"
# custom:
#   class: compliance
#   framework: hipaa
#   source: hhs
#   domains: [privacy, healthcare]
#   coverage:
#     checks: 8
#     cited: 3
#     density: section
#     basis: role
#     tested: true
#     entrypoint: compliance_report
#     guard: self
#     as_of: v2.5.0
package hipaa.transmission_security

import rego.v1

# =============================================================================
# HIPAA Security Rule — 45 CFR 164.312(e)
# Technical Safeguard: Transmission Security
#
# Implement technical security measures to guard against unauthorized access
# to ePHI transmitted over electronic communications networks.
#
# Standard:    164.312(e)(1) - Transmission security
# Addressable: 164.312(e)(2)(i)  - Integrity controls
#              164.312(e)(2)(ii) - Encryption
# Findings about the absence of encryption in transit are cited to (e)(2)(ii), the addressable
# specification, not to the (e)(1) standard, so the 164.306(d)(3) alternative applies to them.
#
# Input shape:
#   input.network               - network configuration
#   input.tls                   - TLS/SSL configuration
#   input.vpn                   - VPN configuration
#   input.phi_systems[]         - systems transmitting ePHI
#   input.email                 - email configuration
# =============================================================================

_addressable_ids := {"164.312(e)(2)(i)", "164.312(e)(2)(ii)"}

# Addressable specifications (45 CFR 164.306(d)(3)): implemented, or documented as not reasonable and
# appropriate together with an equivalent alternative measure (or documentation that none is reasonable
# and appropriate), read from input.hipaa.addressable_decisions["<cfr id>"] =
#   {"not_reasonable_and_appropriate_documented": true,
#    "equivalent_alternative_implemented": true  OR  "no_reasonable_alternative_documented": true}
# A finding cited to an addressable paragraph with that decision evidenced is not a violation (listed in
# addressed_by_alternative); with neither path evidenced the finding stands (fail closed).
_decision(id) := d if {
	d := object.get(input, ["hipaa", "addressable_decisions", id], null)
	is_object(d)
}

_alternative_documented(id) if {
	id in _addressable_ids
	d := _decision(id)
	d.not_reasonable_and_appropriate_documented == true
	_alternative_or_none(d)
}

_alternative_or_none(d) if d.equivalent_alternative_implemented == true

_alternative_or_none(d) if d.no_reasonable_alternative_documented == true

_cited(msg) := trim_space(split(trim_prefix(msg, "HIPAA "), ":")[0])

_kept(msg) if not _alternative_documented(_cited(msg))

addressed_by_alternative contains id if {
	some id in _addressable_ids
	_alternative_documented(id)
}

# ---------------------------------------------------------------------------
# Deprecated protocols — never acceptable for ePHI
# ---------------------------------------------------------------------------

# Plaintext protocols carry ePHI unencrypted (164.312(e)(2)(ii)); old SSL/TLS versions are encryption the
# library considers weak, which the regulation does not grade (advisory).
plaintext_protocols := {"HTTP", "FTP", "Telnet", "SMTP_plaintext"}

deprecated_protocols := {"SSLv2", "SSLv3", "TLSv1.0", "TLSv1.1"} | plaintext_protocols

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
	not phi_system.transmission_encrypted == true
	msg := sprintf(
		"HIPAA 164.312(e)(2)(ii): System '%v' transmits ePHI without encryption. All ePHI in transit must be protected.",
		[phi_system.name],
	)
}

violation_transmission_security contains msg if {
	some phi_system in input.phi_systems
	some protocol in phi_system.protocols_in_use
	protocol in plaintext_protocols
	msg := sprintf(
		"HIPAA 164.312(e)(2)(ii): System '%v' uses unencrypted protocol '%v' for ePHI transmission.",
		[phi_system.name, protocol],
	)
}

advisories contains msg if {
	some phi_system in input.phi_systems
	some protocol in phi_system.protocols_in_use
	protocol in deprecated_protocols
	not protocol in plaintext_protocols
	msg := sprintf(
		"Advisory (library practice, not a 45 CFR requirement): system '%v' uses '%v'; the library suggests TLS 1.2 or higher.",
		[phi_system.name, protocol],
	)
}

advisories contains msg if {
	not input.network.phi_network_segmented == true
	msg := "Advisory (library practice, not a 45 CFR requirement): Network carrying ePHI is not segmented. ePHI traffic should be isolated from general network traffic."
}

# ---------------------------------------------------------------------------
# TLS Configuration
# ---------------------------------------------------------------------------

advisories contains msg if {
	object.get(input, ["tls", "minimum_version"], null) != null
	not _tls_version_acceptable(input.tls.minimum_version)
	msg := sprintf(
		"Advisory (library practice, not a 45 CFR requirement): Minimum TLS version is %v. TLS 1.2 is the minimum acceptable; TLS 1.3 is recommended.",
		[input.tls.minimum_version],
	)
}

# Accepts 1.2 / 1.3 with optional "TLS", "TLSv", "v" prefixes and spaces (string or number).
_tls_version_acceptable(v) if {
	regex.match(`^(tls)?v?[ ]?1\.[23]$`, lower(sprintf("%v", [v])))
}

advisories contains msg if {
	not is_string(object.get(input, ["tls", "minimum_version"], null))
	not is_number(object.get(input, ["tls", "minimum_version"], null))
	msg := "Advisory (library practice, not a 45 CFR requirement): evidence missing — tls.minimum_version not collected. TLS 1.2 is the minimum acceptable; TLS 1.3 is recommended."
}

advisories contains msg if {
	some cipher in input.tls.enabled_ciphers
	cipher in weak_ciphers
	msg := sprintf(
		"Advisory (library practice, not a 45 CFR requirement): Weak cipher suite '%v' is enabled. Remove all weak ciphers from TLS configuration.",
		[cipher],
	)
}

advisories contains msg if {
	not input.tls.certificate_expiry_monitoring == true
	msg := "Advisory (library practice, not a 45 CFR requirement): TLS certificate expiry is not monitored. Expired certificates break encrypted ePHI transmission."
}

advisories contains msg if {
	is_number(input.tls.certificate_expiry_days)
	input.tls.certificate_expiry_days < 30
	msg := sprintf(
		"Advisory (library practice, not a 45 CFR requirement): TLS certificate expires in %v days. Renew immediately to prevent unencrypted ePHI exposure.",
		[input.tls.certificate_expiry_days],
	)
}

advisories contains msg if {
	not input.tls.mutual_tls_for_phi_apis == true
	msg := "Advisory (library practice, not a 45 CFR requirement): APIs transmitting ePHI do not use mutual TLS (mTLS). mTLS provides stronger authentication for ePHI endpoints."
}

# ---------------------------------------------------------------------------
# VPN Requirements
# ---------------------------------------------------------------------------

advisories contains msg if {
	input.network.remote_phi_access_enabled == true
	not input.vpn.required_for_remote_phi_access == true
	msg := "Advisory (library practice, not a 45 CFR requirement): Remote ePHI access is permitted without VPN. VPN or equivalent encrypted tunnel is required."
}

advisories contains msg if {
	input.vpn.required_for_remote_phi_access == true
	input.vpn.protocol in {"PPTP", "L2TP_no_ipsec"}
	msg := sprintf(
		"Advisory (library practice, not a 45 CFR requirement): VPN protocol '%v' is insecure. Use IKEv2/IPsec, OpenVPN, or WireGuard.",
		[input.vpn.protocol],
	)
}

advisories contains msg if {
	input.vpn.split_tunneling_enabled == true
	msg := "Advisory (library practice, not a 45 CFR requirement): VPN split tunneling is enabled. ePHI traffic must route entirely through the encrypted VPN tunnel."
}

# ---------------------------------------------------------------------------
# 164.312(e)(2)(i) — Integrity Controls for Transmission (Addressable)
# Ensure ePHI is not improperly modified during transmission
# ---------------------------------------------------------------------------

# 164.312(e)(2)(i): measures ensuring transmitted ePHI is not improperly modified without detection. Message
# authentication is one; a direct statement of the implemented measure is the other.
violation_transmission_integrity contains msg if {
	not input.network.message_authentication_enabled == true
	not input.network.transmission_integrity_controls_implemented == true
	msg := "HIPAA 164.312(e)(2)(i): no measure ensuring transmitted ePHI is not improperly modified without detection is evidenced (network.message_authentication_enabled or network.transmission_integrity_controls_implemented not true)."
}

advisories contains msg if {
	some phi_system in input.phi_systems
	phi_system.api_endpoint == true
	not phi_system.request_signing_enabled == true
	msg := sprintf(
		"Advisory (library practice, not a 45 CFR requirement): API endpoint '%v' transmitting ePHI does not use request signing. Implement HMAC or digital signatures.",
		[phi_system.name],
	)
}

# ---------------------------------------------------------------------------
# Email with ePHI
# ---------------------------------------------------------------------------

violation_email contains msg if {
	input.email.phi_sent_via_email == true
	not input.email.encrypted_email_required == true
	msg := "HIPAA 164.312(e)(2)(ii): ePHI is sent via email without encryption enforcement."
}

# Whether ePHI is sent by email is stated, true or false: an absent answer is not "no email".
violation_email contains msg if {
	object.get(input, ["email", "phi_sent_via_email"], null) == null
	msg := "HIPAA 164.312(e)(2)(ii): evidence missing — email.phi_sent_via_email not collected. Whether ePHI is sent by email must be stated (true or false) before email encryption can be judged."
}

advisories contains msg if {
	input.email.phi_sent_via_email == true
	not input.email.dlp_enabled == true
	msg := "Advisory (library practice, not a 45 CFR requirement): Data Loss Prevention (DLP) is not enabled on email. DLP prevents accidental unencrypted ePHI transmission."
}

# ---------------------------------------------------------------------------
# All violations
# ---------------------------------------------------------------------------

violations contains msg if {
	some msg in violation_transmission_security
	_kept(msg)
}

violations contains msg if {
	some msg in violation_transmission_integrity
	_kept(msg)
}

violations contains msg if {
	some msg in violation_email
	_kept(msg)
}

# Fail-closed: no ePHI systems in scope → cannot certify this safeguard
violations contains msg if {
	count(object.get(input, "phi_systems", [])) == 0
	msg := "HIPAA 164.312(e): no ePHI systems in scope (input.phi_systems is empty) — cannot certify Transmission Security. Declare the ePHI systems to be evaluated."
}

# ---------------------------------------------------------------------------
# Evidence typing (bad input never passes, issue #301)
# Only the booleans true and false are yes/no evidence, and only a number is a count or a period. A section
# sent as null, a string such as "true", "false" or "90", or a number where a yes/no belongs is a collection
# error: it is a finding against this standard whether the fact decides a control or only feeds an
# advisory, because the verdict cannot rest on evidence of the wrong type. A fact that is absent is handled
# by the rule that reads it (a required fact fails its control; an advisory fact is reported as an advisory).
# ---------------------------------------------------------------------------

_std := "164.312(e)"

# section -> the yes/no facts and the numeric facts this module reads from it
_typed_sections := {
	"network": {"bool": {"phi_network_segmented", "remote_phi_access_enabled", "message_authentication_enabled", "transmission_integrity_controls_implemented"}, "num": {}},
	"tls": {"bool": {"certificate_expiry_monitoring", "mutual_tls_for_phi_apis"}, "num": {"certificate_expiry_days"}},
	"vpn": {"bool": {"required_for_remote_phi_access", "split_tunneling_enabled"}, "num": {}},
	"email": {"bool": {"phi_sent_via_email", "encrypted_email_required", "dlp_enabled"}, "num": {}},
}

# list -> the yes/no facts and the numeric facts this module reads from each entry
_typed_items := {
	"phi_systems": {"bool": {"transmission_encrypted", "request_signing_enabled"}, "num": {}},
}

evidence_invalid contains msg if {
	some s, _ in _typed_sections
	v := input[s]
	not is_object(v)
	msg := sprintf("HIPAA %s: evidence invalid — input.%s is not an object (got %s)", [_std, s, type_name(v)])
}

evidence_invalid contains msg if {
	some s, _ in _typed_items
	v := input[s]
	not is_array(v)
	msg := sprintf("HIPAA %s: evidence invalid — input.%s is not a list (got %s)", [_std, s, type_name(v)])
}

evidence_invalid contains msg if {
	some s, t in _typed_sections
	some f in t.bool
	v := input[s][f]
	not is_boolean(v)
	msg := sprintf("HIPAA %s: evidence invalid — input.%s.%s is not a boolean (got %s)", [_std, s, f, type_name(v)])
}

evidence_invalid contains msg if {
	some s, t in _typed_sections
	some f in t.num
	v := input[s][f]
	not is_number(v)
	msg := sprintf("HIPAA %s: evidence invalid — input.%s.%s is not a number (got %s)", [_std, s, f, type_name(v)])
}

evidence_invalid contains msg if {
	some s, _ in _typed_items
	is_array(input[s])
	some i, item in input[s]
	not is_object(item)
	msg := sprintf("HIPAA %s: evidence invalid — input.%s[%d] is not an object (got %s)", [_std, s, i, type_name(item)])
}

evidence_invalid contains msg if {
	some s, t in _typed_items
	is_array(input[s])
	some i, item in input[s]
	some f in t.bool
	v := item[f]
	not is_boolean(v)
	msg := sprintf("HIPAA %s: evidence invalid — input.%s[%d].%s is not a boolean (got %s)", [_std, s, i, f, type_name(v)])
}

evidence_invalid contains msg if {
	some s, t in _typed_items
	is_array(input[s])
	some i, item in input[s]
	some f in t.num
	v := item[f]
	not is_number(v)
	msg := sprintf("HIPAA %s: evidence invalid — input.%s[%d].%s is not a number (got %s)", [_std, s, i, f, type_name(v)])
}

violations contains msg if some msg in evidence_invalid

# ---------------------------------------------------------------------------
# Compliance
# ---------------------------------------------------------------------------

default compliant := false

compliant if {
	count(violations) == 0
}

compliance_report := {
	"section": "164.312(e)",
	"title": "Transmission Security",
	"required": true,
	"compliant": compliant,
	"violation_count": count(violations),
	"violations": violations,
	"advisories": advisories,
	"addressed_by_alternative": addressed_by_alternative,
	"controls": {
		"transmission_encrypted": count(violation_transmission_security) == 0,
		"transmission_integrity": count(violation_transmission_integrity) == 0,
		"email_protection": count(violation_email) == 0,
	},
}
