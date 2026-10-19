# METADATA
# title: "DISA STIG for Oracle Linux 8 - PKI and Cryptography Module"
# custom:
#   class: security
#   framework: stig_oracle_linux_8
#   source: disa
#   domains: [linux, oracle]
#   coverage:
#     checks: 4
#     cited: 3
#     density: section
#     basis: role
#     tested: true
#     entrypoint: compliance_report
#     guard: self
#     as_of: v2.4.2
package stig.oracle_linux_8.pki_crypto

# DISA STIG for Oracle Linux 8 - PKI and Cryptography Module
# STIG Version: V2R10 | Released: 30 Sep 2026
# Derived from stig/oracle_linux_9/pki_crypto.rego by DISA rule title: Oracle Linux 8 and Oracle Linux 9 share the rule text;
# ids, vuln ids, severities and titles are the Oracle Linux 8 XCCDF's (tools/stig_generators/gen_oracle_linux.py).
# Covers: FIPS 140-3, PKI/CAC authentication, certificate management, crypto policies

import rego.v1

default compliant := false

# =============================================================================
# CAT I - HIGH SEVERITY
# =============================================================================

# OL08-00-010183 | V-283447 | CAT I
# Crypto policy must not be overridden
default crypto_policy_not_overridden := false

# Missing evidence is not a pass: the overrides collection must be present (empty = none found).
crypto_policy_not_overridden if {
	object.get(input, "crypto_policy_overrides", null) != null
	count(input.crypto_policy_overrides) == 0
}

status_ol08_00_010183 := "Not_a_Finding" if { crypto_policy_not_overridden } else := "Open"

finding_ol08_00_010183 := {
	"vuln_id": "V-283447",
	"stig_id": "OL08-00-010183",
	"severity": "CAT I",
	"rule_title": "OL 8 cryptographic policy must not be overridden.",
	"status": status_ol08_00_010183,
	"fix_text": "Remove any CRYPTO_POLICY overrides from application config files",
}

# =============================================================================
# CAT II - MEDIUM SEVERITY
# =============================================================================

# OL08-00-010400 | V-248587 | CAT II
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

status_ol08_00_010400 := "Not_a_Finding" if { dod_pki_enabled } else := "Open"

finding_ol08_00_010400 := {
	"vuln_id": "V-248587",
	"stig_id": "OL08-00-010400",
	"severity": "CAT II",
	"rule_title": "OL 8 must implement certificate status checking for multifactor authentication.",
	"status": status_ol08_00_010400,
	"fix_text": "Configure SSSD for PIV/CAC authentication with OCSP checking enabled",
}

# OL08-00-020090 | V-248685 | CAT II
# System must map certificate to user
default cert_user_mapping := false

cert_user_mapping if {
	is_string(input.sssd_config.cert_user_mapping)
	input.sssd_config.cert_user_mapping != ""
}

cert_user_mapping if {
	input.pam_config.cert_mapping_configured == true
}

status_ol08_00_020090 := "Not_a_Finding" if { cert_user_mapping } else := "Open"

finding_ol08_00_020090 := {
	"vuln_id": "V-248685",
	"stig_id": "OL08-00-020090",
	"severity": "CAT II",
	"rule_title": "OL 8 must map the authenticated identity to the user or group account for PKI-based authentication.",
	"status": status_ol08_00_020090,
	"fix_text": "Configure certificate to user mapping in SSSD configuration",
}

# =============================================================================
# COMPLIANCE AGGREGATION
# =============================================================================

cat_i_findings := [
	finding_ol08_00_010183,
]

cat_ii_findings := [
	finding_ol08_00_010400,
	finding_ol08_00_020090,
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
