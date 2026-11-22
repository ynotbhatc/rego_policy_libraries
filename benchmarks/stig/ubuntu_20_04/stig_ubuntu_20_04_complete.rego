# METADATA
# title: "DISA STIG for Ubuntu 20.04 LTS - Simplified Complete Assessment"
# custom:
#   class: security
#   framework: stig_ubuntu_20_04
#   source: disa
#   domains: [linux, ubuntu]
#   coverage:
#     checks: 6
#     cited: 6
#     density: sparse
#     basis: size
#     tested: true
#     entrypoint: none
#     guard: n/a
#     as_of: v2.5.0
package stig.ubuntu_20_04

# DISA STIG for Ubuntu 20.04 LTS - Simplified Complete Assessment
# STIG Version: V2R4 | Released: 01 Oct 2025 (the sunset release: DISA's U_CAN_Ubuntu_20-04_LTS_V2R4_STIG.zip,
# not in the current compilation; see SUNSET.md)
# Implemented: 4 of 173 V2R4 rules, each written against its V2R4 check text (2026-11-21). Until then this stub
# carried invented ids (UBTU-20-PK-000010 ...) and thresholds that were not DISA's; the guest-account and
# antivirus checks had no Ubuntu 20.04 rule and were removed. The remaining 169 rules are not implemented:
# the platform is sunset (see SUNSET.md).

import rego.v1

# a fact the collector supplied (any non-null value)
_collected(path) if object.get(input, path, null) != null

# =============================================================================
# CAT I - HIGH SEVERITY
# =============================================================================

# UBTU-20-010001 | V-278950 | CAT I - vendor-supported release (the V2R4 sunset control)
# DISA: "If the installed version of Ubuntu 20.04 LTS is not supported, this is a finding." Standard support
# ended 31 May 2025 (ESM with Ubuntu Pro to May 2030). Whether this host is vendor supported is the SA's call,
# so the rule is Open until input.attest.ubuntu_20_04_vendor_supported is true.
default vendor_supported_status := "Open"

vendor_supported_status := "Not_a_Finding" if input.attest.ubuntu_20_04_vendor_supported == true

missing_ubtu_20_010001 := [concat(".", p) | some p in [["attest", "ubuntu_20_04_vendor_supported"]]; not _collected(p)]

vendor_supported_detail := "UBTU-20-010001: Not_a_Finding" if vendor_supported_status == "Not_a_Finding"

else := "UBTU-20-010001: evidence missing — attest.ubuntu_20_04_vendor_supported not collected" if count(missing_ubtu_20_010001) > 0

else := "UBTU-20-010001: check failed — the installed Ubuntu 20.04 LTS release is not attested as vendor supported"

finding_ubtu_20_010001 := {
	"vuln_id": "V-278950",
	"stig_id": "UBTU-20-010001",
	"severity": "CAT I",
	"rule_title": "Ubuntu 20.04 LTS must be a vendor-supported release.",
	"status": vendor_supported_status,
	"detail": vendor_supported_detail,
}

# =============================================================================
# CAT II - MEDIUM SEVERITY
# =============================================================================

# UBTU-20-010443 | V-238364 | CAT II - a certificate in /etc/ssl/certs has the subject "DOD ROOT CA"
default dod_root_ca_status := "Open"

dod_root_ca_status := "Not_a_Finding" if input.certificates.dod_root_ca_installed == true

missing_ubtu_20_010443 := [concat(".", p) | some p in [["certificates", "dod_root_ca_installed"]]; not _collected(p)]

dod_root_ca_detail := "UBTU-20-010443: Not_a_Finding" if dod_root_ca_status == "Not_a_Finding"

else := "UBTU-20-010443: evidence missing — certificates.dod_root_ca_installed not collected" if count(missing_ubtu_20_010443) > 0

else := "UBTU-20-010443: check failed — no certificate in /etc/ssl/certs has a subject matching DOD ROOT CA"

finding_ubtu_20_010443 := {
	"vuln_id": "V-238364",
	"stig_id": "UBTU-20-010443",
	"severity": "CAT II",
	"rule_title": "The Ubuntu operating system must use DoD PKI-established certificate authorities for verification of the establishment of protected sessions.",
	"status": dod_root_ca_status,
	"detail": dod_root_ca_detail,
}

# UBTU-20-010054 | V-238225 | CAT II - pwquality minlen 15 or higher
default password_length_status := "Open"

password_length_status := "Not_a_Finding" if {
	is_number(input.password_policy.minimum_password_length)
	input.password_policy.minimum_password_length >= 15
}

missing_ubtu_20_010054 := [concat(".", p) | some p in [["password_policy", "minimum_password_length"]]; not _collected(p)]

password_length_detail := "UBTU-20-010054: Not_a_Finding" if password_length_status == "Not_a_Finding"

else := "UBTU-20-010054: evidence missing — password_policy.minimum_password_length not collected" if count(missing_ubtu_20_010054) > 0

else := "UBTU-20-010054: check failed — minlen in /etc/security/pwquality.conf must be 15 or higher"

finding_ubtu_20_010054 := {
	"vuln_id": "V-238225",
	"stig_id": "UBTU-20-010054",
	"severity": "CAT II",
	"rule_title": "The Ubuntu operating system must enforce a minimum 15-character password length.",
	"status": password_length_status,
	"detail": password_length_detail,
}

# =============================================================================
# CAT III - LOW SEVERITY
# =============================================================================

# UBTU-20-010070 | V-238234 | CAT III - pam_unix remember 5 or more in /etc/pam.d/common-password
default password_history_status := "Open"

password_history_status := "Not_a_Finding" if {
	is_number(input.password_policy.password_history_size)
	input.password_policy.password_history_size >= 5
}

missing_ubtu_20_010070 := [concat(".", p) | some p in [["password_policy", "password_history_size"]]; not _collected(p)]

password_history_detail := "UBTU-20-010070: Not_a_Finding" if password_history_status == "Not_a_Finding"

else := "UBTU-20-010070: evidence missing — password_policy.password_history_size not collected" if count(missing_ubtu_20_010070) > 0

else := "UBTU-20-010070: check failed — remember in /etc/pam.d/common-password must be 5 or more"

finding_ubtu_20_010070 := {
	"vuln_id": "V-238234",
	"stig_id": "UBTU-20-010070",
	"severity": "CAT III",
	"rule_title": "The Ubuntu operating system must prohibit password reuse for a minimum of five generations.",
	"status": password_history_status,
	"detail": password_history_detail,
}

# =============================================================================
# AGGREGATE ALL FINDINGS
# =============================================================================

all_findings := [
	finding_ubtu_20_010001,
	finding_ubtu_20_010443,
	finding_ubtu_20_010054,
	finding_ubtu_20_010070,
]

open_findings := [f | some f in all_findings; f.status == "Open"]

compliant if {
	count(open_findings) == 0
} else := false

# =============================================================================
# STIG COMPLIANCE ASSESSMENT REPORT
# =============================================================================

stig_assessment := {
	"assessment_metadata": {
		"stig_title": "Canonical Ubuntu 20.04 LTS Security Technical Implementation Guide",
		"stig_version": "Version 2, Release 4 (V2R4, 01 Oct 2025, sunset release)",
		"classification": "UNCLASSIFIED",
		"hostname": object.get(input, ["system_info", "hostname"], "unknown"),
	},
	"compliance_summary": {
		"overall_status": compliance_status,
		"compliant": compliant,
		"total_checks": count(all_findings),
		"open_findings": count(open_findings),
	},
	# every rule's DISA status, as the other STIG modules report it
	"rule_results": [{"rule": f.stig_id, "status": f.status} | some f in all_findings],
	"open_findings_details": open_findings,
}

compliance_status := "Compliant" if compliant

else := "Non-Compliant"
