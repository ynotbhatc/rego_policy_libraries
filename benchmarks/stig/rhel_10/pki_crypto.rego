# METADATA
# title: "DISA STIG for RHEL 10 - PKI and Cryptography Module"
# custom:
#   class: security
#   framework: stig_rhel_10
#   source: disa
#   domains: [linux, rhel]
#   coverage:
#     checks: 5
#     cited: 4
#     density: section
#     basis: role
#     tested: true
#     entrypoint: compliance_report
#     guard: self
#     as_of: v2.4.2
package stig.rhel_10.pki_crypto

# DISA STIG for RHEL 10 - PKI and Cryptography Module
# STIG Version: V1R2 | Released: 01 Jul 2026
# Derived from stig/rhel_9/pki_crypto.rego by DISA rule title: RHEL 10 and RHEL 9 share the rule text;
# ids, vuln ids, severities and titles are the RHEL 10 XCCDF's (tools/stig_generators/gen_oracle_linux.py).
# Covers: FIPS 140-3, PKI/CAC authentication, certificate management, crypto policies

import rego.v1

default compliant := false

# =============================================================================
# CAT I - HIGH SEVERITY
# =============================================================================

# RHEL-10-300090 | V-281016 | CAT I
# Crypto policy must not be overridden
default crypto_policy_not_overridden := false

crypto_policy_not_overridden if {
	count(input.crypto_policy_overrides) == 0
}

crypto_policy_not_overridden if {
	not input.crypto_policy_overrides
}

status_rhel_10_300090 := "Not_a_Finding" if crypto_policy_not_overridden

else := "Open"

finding_rhel_10_300090 := {
	"vuln_id": "V-281016",
	"stig_id": "RHEL-10-300090",
	"severity": "CAT I",
	"rule_title": "RHEL 10 cryptographic policy must not be overridden.",
	"status": status_rhel_10_300090,
	"fix_text": "Remove any CRYPTO_POLICY overrides from application config files",
}

# =============================================================================
# CAT II - MEDIUM SEVERITY
# =============================================================================

# RHEL-10-701230 | V-281325 | CAT II
# Certificate revocation must be checked (OCSP/CRL)
default cert_revocation_check := false

cert_revocation_check if {
	input.pki_config.ocsp_enabled == true
}

cert_revocation_check if {
	input.pki_config.crl_checking == true
}

status_rhel_10_701230 := "Not_a_Finding" if cert_revocation_check

else := "Open"

finding_rhel_10_701230 := {
	"vuln_id": "V-281325",
	"stig_id": "RHEL-10-701230",
	"severity": "CAT II",
	"rule_title": "RHEL 10 must implement certificate status checking for multifactor authentication.",
	"status": status_rhel_10_701230,
	"fix_text": "Configure OCSP: Set ocsp_stapling=yes and enable CRL checking in SSSD",
}

# RHEL-10-701270 | V-281329 | CAT II
# The system must use a DoD-approved PKI to authenticate
default dod_ca_trusted := false

dod_ca_trusted if {
	input.certificates.dod_root_ca_installed == true
}

status_rhel_10_701270 := "Not_a_Finding" if dod_ca_trusted

else := "Open"

finding_rhel_10_701270 := {
	"vuln_id": "V-281329",
	"stig_id": "RHEL-10-701270",
	"severity": "CAT II",
	"rule_title": "RHEL 10 must, for PKI-based authentication, validate certificates by constructing a certification path (which includes status information) to an accepted trust anchor.",
	"status": status_rhel_10_701270,
	"fix_text": "Install DoD Root CA: trust anchor --store DoD_PKE_CA_chain.pem",
}

# RHEL-10-701280 | V-281330 | CAT II
# System must map certificate to user
default cert_user_mapping := false

cert_user_mapping if {
	input.sssd_config.cert_user_mapping != ""
}

cert_user_mapping if {
	input.pam_config.cert_mapping_configured == true
}

status_rhel_10_701280 := "Not_a_Finding" if cert_user_mapping

else := "Open"

finding_rhel_10_701280 := {
	"vuln_id": "V-281330",
	"stig_id": "RHEL-10-701280",
	"severity": "CAT II",
	"rule_title": "RHEL 10 must map the authenticated identity to the user or group account for public key infrastructure (PKI)-based authentication.",
	"status": status_rhel_10_701280,
	"fix_text": "Configure certificate to user mapping in SSSD configuration",
}

# =============================================================================
# COMPLIANCE AGGREGATION
# =============================================================================

cat_i_findings := [finding_rhel_10_300090]

cat_ii_findings := [
	finding_rhel_10_701230,
	finding_rhel_10_701270,
	finding_rhel_10_701280,
]

cat_iii_findings := []

findings := array.concat(cat_i_findings, array.concat(cat_ii_findings, cat_iii_findings))

violations contains finding.stig_id if {
	some finding in findings
	finding.status == "Open"
}

open_cat_i contains f if {
	some f in cat_i_findings
	f.status == "Open"
}

compliant if {
	count(open_cat_i) == 0
}

compliance_report := {
	"module": "pki_crypto",
	"total_findings": count(findings),
	"open_findings": count(violations),
	"cat_i_open": count(open_cat_i),
	"findings": findings,
	"compliant": compliant,
}
