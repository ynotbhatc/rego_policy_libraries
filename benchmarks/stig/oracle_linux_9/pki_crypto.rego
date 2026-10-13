# METADATA
# title: "DISA STIG for Oracle Linux 9 - PKI and Cryptography Module"
# custom:
#   class: security
#   framework: stig_oracle_linux_9
#   source: disa
#   domains: [linux, oracle_linux]
#   coverage:
#     checks: 6
#     cited: 5
#     density: section
#     basis: role
#     tested: true
#     entrypoint: compliance_report
#     guard: self
#     as_of: v2.4.0
package stig.oracle_linux_9.pki_crypto

# DISA STIG for Oracle Linux 9 - PKI and Cryptography Module
# STIG Version: V1R7 | Released: 30 Sep 2026
# Derived from stig/rhel_9/pki_crypto.rego by DISA rule title: Oracle Linux 9 and RHEL 9 share the rule text;
# ids, vuln ids, severities and titles are the Oracle Linux 9 XCCDF's (tools/stig_generators/gen_oracle_linux.py).
# Covers: FIPS 140-3, PKI/CAC authentication, certificate management, crypto policies

import rego.v1

default compliant := false

# =============================================================================
# CAT I - HIGH SEVERITY
# =============================================================================

# OL09-00-000241 | V-271478 | CAT I
# FIPS 140-3-approved algorithms must be used for hashing
default fips_hashing := false

fips_hashing if {
	input.fips_mode == true
}

fips_hashing if {
	input.crypto_policy == "FIPS"
}

status_ol09_00_000241 := "Not_a_Finding" if { fips_hashing } else := "Open"

finding_ol09_00_000241 := {
	"vuln_id": "V-271478",
	"stig_id": "OL09-00-000241",
	"severity": "CAT I",
	"rule_title": "OL 9 must implement a FIPS 140-3 compliant systemwide cryptographic policy.",
	"status": status_ol09_00_000241,
	"fix_text": "Enable FIPS mode: fips-mode-setup --enable",
}

# OL09-00-000242 | V-271479 | CAT I
# Crypto policy must not be overridden
default crypto_policy_not_overridden := false

crypto_policy_not_overridden if {
	count(input.crypto_policy_overrides) == 0
}

crypto_policy_not_overridden if {
	not input.crypto_policy_overrides
}

status_ol09_00_000242 := "Not_a_Finding" if { crypto_policy_not_overridden } else := "Open"

finding_ol09_00_000242 := {
	"vuln_id": "V-271479",
	"stig_id": "OL09-00-000242",
	"severity": "CAT I",
	"rule_title": "OL 9 must not allow the cryptographic policy to be overridden.",
	"status": status_ol09_00_000242,
	"fix_text": "Remove any CRYPTO_POLICY overrides from application config files",
}

# =============================================================================
# CAT II - MEDIUM SEVERITY
# =============================================================================

# OL09-00-000930 | V-271608 | CAT II
# DoD PKI/CAC must be enabled for authentication
default dod_pki_enabled := false

dod_pki_enabled if {
	input.pam_config.piv_enabled == true
}

dod_pki_enabled if {
	input.pam_config.sssd_pki == true
}

dod_pki_enabled if {
	input.certificates.dod_root_ca_installed == true
	input.pam_config.pkcs11_enabled == true
}

status_ol09_00_000930 := "Not_a_Finding" if { dod_pki_enabled } else := "Open"

finding_ol09_00_000930 := {
	"vuln_id": "V-271608",
	"stig_id": "OL09-00-000930",
	"severity": "CAT II",
	"rule_title": "OL 9 must implement certificate status checking for multifactor authentication (MFA).",
	"status": status_ol09_00_000930,
	"fix_text": "Configure SSSD for PIV/CAC authentication with OCSP checking enabled",
}

# OL09-00-000925 | V-271607 | CAT II
# SSSD must be configured for certificate authentication
default sssd_cert_auth := false

sssd_cert_auth if {
	input.sssd_config.certificate_authentication == true
}

sssd_cert_auth if {
	input.sssd_config.piv_enabled == true
}

status_ol09_00_000925 := "Not_a_Finding" if { sssd_cert_auth } else := "Open"

finding_ol09_00_000925 := {
	"vuln_id": "V-271607",
	"stig_id": "OL09-00-000925",
	"severity": "CAT II",
	"rule_title": "OL 9 must enable certificate-based smart card authentication.",
	"status": status_ol09_00_000925,
	"fix_text": "Configure SSSD: add certificate_verification=ocsp_dgst:sha256 to [domain] section",
}

# OL09-00-000910 | V-271606 | CAT II
# System must map certificate to user
default cert_user_mapping := false

cert_user_mapping if {
	input.sssd_config.cert_user_mapping != ""
}

cert_user_mapping if {
	input.pam_config.cert_mapping_configured == true
}

status_ol09_00_000910 := "Not_a_Finding" if { cert_user_mapping } else := "Open"

finding_ol09_00_000910 := {
	"vuln_id": "V-271606",
	"stig_id": "OL09-00-000910",
	"severity": "CAT II",
	"rule_title": "OL 9 must map the authenticated identity to the user or group account for PKI-based authentication.",
	"status": status_ol09_00_000910,
	"fix_text": "Configure certificate to user mapping in SSSD configuration",
}

# =============================================================================
# COMPLIANCE AGGREGATION
# =============================================================================

cat_i_findings := [
	finding_ol09_00_000241,
	finding_ol09_00_000242,
]

cat_ii_findings := [
	finding_ol09_00_000930,
	finding_ol09_00_000925,
	finding_ol09_00_000910,
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
