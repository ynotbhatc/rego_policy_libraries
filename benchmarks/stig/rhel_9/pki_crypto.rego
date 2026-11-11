# METADATA
# title: "DISA STIG for RHEL 9 - PKI and Cryptography Module"
# custom:
#   class: security
#   framework: stig_rhel_9
#   source: disa
#   domains: [linux, rhel]
#   coverage:
#     checks: 7
#     cited: 6
#     density: section
#     basis: role
#     tested: true
#     entrypoint: compliance_report
#     guard: self
#     as_of: v2.4.2
package stig.rhel_9.pki_crypto

# DISA STIG for RHEL 9 - PKI and Cryptography Module
# STIG Version: V2R10 | Released: 30 Sep 2026
# Rule ids, vuln ids, severities and titles stamped from the October 2026 SRG-STIG library XCCDF on 2026-11-10
# (tools/stig_generators/stamp_catalog.py); each finding is keyed on the fact its logic checks.
# Covers: FIPS 140-3, PKI/CAC authentication, certificate management, crypto policies

import rego.v1

default compliant := false

# =============================================================================
# CAT I - HIGH SEVERITY
# =============================================================================

# =============================================================================
# CAT I - HIGH SEVERITY
# =============================================================================

# RHEL-09-672020 | V-258236 | CAT I
# Crypto policy must not be overridden
default crypto_policy_not_overridden := false

crypto_policy_not_overridden if {
	count(input.crypto_policy_overrides) == 0
}

crypto_policy_not_overridden if {
	not input.crypto_policy_overrides
}

status_rhel_09_672020 := "Not_a_Finding" if crypto_policy_not_overridden

else := "Open"

finding_rhel_09_672020 := {
	"vuln_id": "V-258236",
	"stig_id": "RHEL-09-672020",
	"severity": "CAT I",
	"rule_title": "RHEL 9 cryptographic policy must not be overridden.",
	"status": status_rhel_09_672020,
	"fix_text": "Remove any CRYPTO_POLICY overrides from application config files",
}

# RHEL-09-672055 | V-288833 | CAT I
# openssl must use system crypto policy
default openssl_system_policy := false

openssl_system_policy if {
	input.openssl_config.system_policy == true
}

openssl_system_policy if {
	not input.openssl_config.legacy_override
}

status_rhel_09_672055 := "Not_a_Finding" if openssl_system_policy

else := "Open"

finding_rhel_09_672055 := {
	"vuln_id": "V-288833",
	"stig_id": "RHEL-09-672055",
	"severity": "CAT I",
	"rule_title": "RHEL 9 must implement DoW-approved encryption in the OpenSSL package.",
	"status": status_rhel_09_672055,
	"fix_text": "Ensure /etc/crypto-policies/ is configured and not overriding system-wide policy",
}

# =============================================================================
# CAT II - MEDIUM SEVERITY
# =============================================================================

# RHEL-09-611170 | V-258123 | CAT II
# Certificate revocation must be checked (OCSP/CRL)
default cert_revocation_check := false

cert_revocation_check if {
	input.pki_config.ocsp_enabled == true
}

cert_revocation_check if {
	input.pki_config.crl_checking == true
}

status_rhel_09_611170 := "Not_a_Finding" if cert_revocation_check

else := "Open"

finding_rhel_09_611170 := {
	"vuln_id": "V-258123",
	"stig_id": "RHEL-09-611170",
	"severity": "CAT II",
	"rule_title": "RHEL 9 must implement certificate status checking for multifactor authentication.",
	"status": status_rhel_09_611170,
	"fix_text": "Configure OCSP: Set ocsp_stapling=yes and enable CRL checking in SSSD",
}

# RHEL-09-631010 | V-258131 | CAT II
# The system must use a DoD-approved PKI to authenticate
default dod_ca_trusted := false

dod_ca_trusted if {
	input.certificates.dod_root_ca_installed == true
}

status_rhel_09_631010 := "Not_a_Finding" if dod_ca_trusted

else := "Open"

finding_rhel_09_631010 := {
	"vuln_id": "V-258131",
	"stig_id": "RHEL-09-631010",
	"severity": "CAT II",
	"rule_title": "RHEL 9, for PKI-based authentication, must validate certificates by constructing a certification path (which includes status information) to an accepted trust anchor.",
	"status": status_rhel_09_631010,
	"fix_text": "Install DoD Root CA: trust anchor --store DoD_PKE_CA_chain.pem",
}

# RHEL-09-271045 | V-258019 | CAT II
# smartcard removal must lock the session
default smartcard_lock_on_removal := false

smartcard_lock_on_removal if {
	input.pam_config.smartcard_removal_lock == true
}

status_rhel_09_271045 := "Not_a_Finding" if smartcard_lock_on_removal

else := "Open"

finding_rhel_09_271045 := {
	"vuln_id": "V-258019",
	"stig_id": "RHEL-09-271045",
	"severity": "CAT II",
	"rule_title": "RHEL 9 must be able to initiate directly a session lock for all connection types using smart card when the smart card is removed.",
	"status": status_rhel_09_271045,
	"fix_text": "Configure pcscd and GNOME smart card removal action to lock session",
}

# RHEL-09-631015 | V-258132 | CAT II
# System must map certificate to user
default cert_user_mapping := false

cert_user_mapping if {
	input.sssd_config.cert_user_mapping != ""
}

cert_user_mapping if {
	input.pam_config.cert_mapping_configured == true
}

status_rhel_09_631015 := "Not_a_Finding" if cert_user_mapping

else := "Open"

finding_rhel_09_631015 := {
	"vuln_id": "V-258132",
	"stig_id": "RHEL-09-631015",
	"severity": "CAT II",
	"rule_title": "RHEL 9 must map the authenticated identity to the user or group account for PKI-based authentication.",
	"status": status_rhel_09_631015,
	"fix_text": "Configure certificate to user mapping in SSSD configuration",
}

# =============================================================================
# COMPLIANCE AGGREGATION
# =============================================================================

cat_i_findings := [
	finding_rhel_09_672020,
	finding_rhel_09_672055,
]

cat_ii_findings := [
	finding_rhel_09_611170,
	finding_rhel_09_631010,
	finding_rhel_09_271045,
	finding_rhel_09_631015,
]

# No CAT III rule in this module. array.concat rather than the literal `[]`: OPA >= 1.22 types a literal
# empty array as having no members and rejects iterating it (scripts/check_per_file_load.py).
cat_iii_findings := array.concat([], [])

findings := array.concat(cat_i_findings, array.concat(cat_ii_findings, cat_iii_findings))

violations contains finding.stig_id if {
	some finding in findings
	finding.status == "Open"
}

open_cat_i contains f if {
	some f in cat_i_findings
	f.status == "Open"
}

# `compliant`: no open finding at ANY category (CAT I, II or III).
# `cat_i_compliant`: the former CAT-I-only meaning, for gating on the critical subset.
default cat_i_compliant := false

open_all_findings := [f | some f in findings; f.status == "Open"]

compliant if {
	count(open_all_findings) == 0
}

cat_i_compliant if {
	count(open_cat_i) == 0
}

compliance_report := {
	"module": "pki_crypto",
	"total_findings": count(findings),
	"open_findings": count(violations),
	"cat_i_open": count(open_cat_i),
	"findings": findings,
	"compliant": compliant,
	"cat_i_compliant": cat_i_compliant,
}
