package stig.rhel_9.pki_crypto

# DISA STIG for RHEL 9 - PKI and Cryptography Module
# STIG Version: V2R2 | Released: October 2024
# Covers: FIPS 140-3, PKI/CAC authentication, certificate management, crypto policies

import rego.v1

default compliant := false

# =============================================================================
# CAT I - HIGH SEVERITY
# =============================================================================

# RHEL-09-671010 | V-258150 | CAT I
# FIPS 140-3-approved algorithms must be used for hashing
default fips_hashing := false

fips_hashing if {
	input.fips_mode == true
}

fips_hashing if {
	input.crypto_policy == "FIPS"
}

status_rhel_09_671010 := "Not_a_Finding" if { fips_hashing } else := "Open"

finding_rhel_09_671010 := {
	"vuln_id": "V-258150",
	"stig_id": "RHEL-09-671010",
	"severity": "CAT I",
	"rule_title": "RHEL 9 must use FIPS 140-3-approved cryptographic hashing algorithms",
	"status": status_rhel_09_671010,
	"fix_text": "Enable FIPS mode: fips-mode-setup --enable",
}

# RHEL-09-671015 | V-258151 | CAT I
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

status_rhel_09_671015 := "Not_a_Finding" if { dod_pki_enabled } else := "Open"

finding_rhel_09_671015 := {
	"vuln_id": "V-258151",
	"stig_id": "RHEL-09-671015",
	"severity": "CAT I",
	"rule_title": "RHEL 9 must implement certificate status checking for multifactor authentication",
	"status": status_rhel_09_671015,
	"fix_text": "Configure SSSD for PIV/CAC authentication with OCSP checking enabled",
}

# RHEL-09-671020 | V-258152 | CAT I
# Certificate revocation must be checked (OCSP/CRL)
default cert_revocation_check := false

cert_revocation_check if {
	input.pki_config.ocsp_enabled == true
}

cert_revocation_check if {
	input.pki_config.crl_checking == true
}

status_rhel_09_671020 := "Not_a_Finding" if { cert_revocation_check } else := "Open"

finding_rhel_09_671020 := {
	"vuln_id": "V-258152",
	"stig_id": "RHEL-09-671020",
	"severity": "CAT I",
	"rule_title": "RHEL 9 must implement certificate status checking for DoD PKI authentication",
	"status": status_rhel_09_671020,
	"fix_text": "Configure OCSP: Set ocsp_stapling=yes and enable CRL checking in SSSD",
}

# RHEL-09-672010 | V-258155 | CAT I
# The system must use a DoD-approved PKI to authenticate
default dod_ca_trusted := false

dod_ca_trusted if {
	input.certificates.dod_root_ca_installed == true
}

status_rhel_09_672010 := "Not_a_Finding" if { dod_ca_trusted } else := "Open"

finding_rhel_09_672010 := {
	"vuln_id": "V-258155",
	"stig_id": "RHEL-09-672010",
	"severity": "CAT I",
	"rule_title": "RHEL 9 must have the DoD Root CA certificates installed as a trusted CA",
	"status": status_rhel_09_672010,
	"fix_text": "Install DoD Root CA: trust anchor --store DoD_PKE_CA_chain.pem",
}

# =============================================================================
# CAT II - MEDIUM SEVERITY
# =============================================================================

# RHEL-09-672015 | V-258156 | CAT II
# System must use FIPS crypto policy
default fips_crypto_policy := false

fips_crypto_policy if {
	input.crypto_policy == "FIPS"
}

fips_crypto_policy if {
	input.crypto_policy == "FIPS:OSPP"
}

status_rhel_09_672015 := "Not_a_Finding" if { fips_crypto_policy } else := "Open"

finding_rhel_09_672015 := {
	"vuln_id": "V-258156",
	"stig_id": "RHEL-09-672015",
	"severity": "CAT II",
	"rule_title": "RHEL 9 must use the system-wide crypto policy",
	"status": status_rhel_09_672015,
	"fix_text": "Set FIPS crypto policy: update-crypto-policies --set FIPS",
}

# RHEL-09-672020 | V-258157 | CAT II
# Crypto policy must not be overridden
default crypto_policy_not_overridden := false

crypto_policy_not_overridden if {
	count(input.crypto_policy_overrides) == 0
}

crypto_policy_not_overridden if {
	not input.crypto_policy_overrides
}

status_rhel_09_672020 := "Not_a_Finding" if { crypto_policy_not_overridden } else := "Open"

finding_rhel_09_672020 := {
	"vuln_id": "V-258157",
	"stig_id": "RHEL-09-672020",
	"severity": "CAT II",
	"rule_title": "RHEL 9 must not override the system-wide crypto policy",
	"status": status_rhel_09_672020,
	"fix_text": "Remove any CRYPTO_POLICY overrides from application config files",
}

# RHEL-09-672025 | V-258158 | CAT II
# SSSD must be configured for certificate authentication
default sssd_cert_auth := false

sssd_cert_auth if {
	input.sssd_config.certificate_authentication == true
}

sssd_cert_auth if {
	input.sssd_config.piv_enabled == true
}

status_rhel_09_672025 := "Not_a_Finding" if { sssd_cert_auth } else := "Open"

finding_rhel_09_672025 := {
	"vuln_id": "V-258158",
	"stig_id": "RHEL-09-672025",
	"severity": "CAT II",
	"rule_title": "RHEL 9 must be configured to use SSSD for certificate authentication",
	"status": status_rhel_09_672025,
	"fix_text": "Configure SSSD: add certificate_verification=ocsp_dgst:sha256 to [domain] section",
}

# RHEL-09-672030 | V-258159 | CAT II
# No expired certificates must exist in the trust store
default no_expired_certs := false

no_expired_certs if {
	count(input.certificates.expired_certs) == 0
}

no_expired_certs if {
	not input.certificates.expired_certs
}

status_rhel_09_672030 := "Not_a_Finding" if { no_expired_certs } else := "Open"

finding_rhel_09_672030 := {
	"vuln_id": "V-258159",
	"stig_id": "RHEL-09-672030",
	"severity": "CAT II",
	"rule_title": "RHEL 9 must not have expired certificates in the trust store",
	"status": status_rhel_09_672030,
	"fix_text": "Remove expired certs: trust list | grep -A2 'pkcs11:id=' | grep 'label' to identify and remove",
}

# RHEL-09-672035 | V-258160 | CAT II
# pam_pkcs11 or pam_sss must be configured
default pam_pki_configured := false

pam_pki_configured if {
	input.pam_config.pkcs11_enabled == true
}

pam_pki_configured if {
	input.pam_config.sssd_pki == true
}

status_rhel_09_672035 := "Not_a_Finding" if { pam_pki_configured } else := "Open"

finding_rhel_09_672035 := {
	"vuln_id": "V-258160",
	"stig_id": "RHEL-09-672035",
	"severity": "CAT II",
	"rule_title": "RHEL 9 must configure the use of the pam_sss module for SSSD authentication",
	"status": status_rhel_09_672035,
	"fix_text": "Configure pam_sss.so in /etc/pam.d/system-auth and /etc/pam.d/password-auth",
}

# RHEL-09-672040 | V-258161 | CAT II
# smartcard removal must lock the session
default smartcard_lock_on_removal := false

smartcard_lock_on_removal if {
	input.pam_config.smartcard_removal_lock == true
}

status_rhel_09_672040 := "Not_a_Finding" if { smartcard_lock_on_removal } else := "Open"

finding_rhel_09_672040 := {
	"vuln_id": "V-258161",
	"stig_id": "RHEL-09-672040",
	"severity": "CAT II",
	"rule_title": "RHEL 9 must enable smart card locking when smart card is removed",
	"status": status_rhel_09_672040,
	"fix_text": "Configure pcscd and GNOME smart card removal action to lock session",
}

# RHEL-09-672045 | V-258162 | CAT II
# System must map certificate to user
default cert_user_mapping := false

cert_user_mapping if {
	input.sssd_config.cert_user_mapping != ""
}

cert_user_mapping if {
	input.pam_config.cert_mapping_configured == true
}

status_rhel_09_672045 := "Not_a_Finding" if { cert_user_mapping } else := "Open"

finding_rhel_09_672045 := {
	"vuln_id": "V-258162",
	"stig_id": "RHEL-09-672045",
	"severity": "CAT II",
	"rule_title": "RHEL 9 must map authenticated identities to the system user account",
	"status": status_rhel_09_672045,
	"fix_text": "Configure certificate to user mapping in SSSD configuration",
}

# RHEL-09-672050 | V-258163 | CAT II
# openssl must use system crypto policy
default openssl_system_policy := false

openssl_system_policy if {
	input.openssl_config.system_policy == true
}

openssl_system_policy if {
	not input.openssl_config.legacy_override
}

status_rhel_09_672050 := "Not_a_Finding" if { openssl_system_policy } else := "Open"

finding_rhel_09_672050 := {
	"vuln_id": "V-258163",
	"stig_id": "RHEL-09-672050",
	"severity": "CAT II",
	"rule_title": "RHEL 9 must use the openssl-pkcs11 library for PKI operations",
	"status": status_rhel_09_672050,
	"fix_text": "Ensure /etc/crypto-policies/ is configured and not overriding system-wide policy",
}

# =============================================================================
# COMPLIANCE AGGREGATION
# =============================================================================

cat_i_findings := [
	finding_rhel_09_671010,
	finding_rhel_09_671015,
	finding_rhel_09_671020,
	finding_rhel_09_672010,
]

cat_ii_findings := [
	finding_rhel_09_672015,
	finding_rhel_09_672020,
	finding_rhel_09_672025,
	finding_rhel_09_672030,
	finding_rhel_09_672035,
	finding_rhel_09_672040,
	finding_rhel_09_672045,
	finding_rhel_09_672050,
]

findings := array.concat(cat_i_findings, cat_ii_findings)

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
