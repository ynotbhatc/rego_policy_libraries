package stig.cisco_ios_xe_router.core

# DISA STIG — Cisco IOS XE Router NDM Security Technical Implementation Guide
# V3R7 | Release: 7 Benchmark Date: 01 Apr 2026
# 10 rules (all CAT I + selected CAT II); IDs/severities/titles
# verified against the July 2026 SRG-STIG library XCCDF on 2026-09-03.
# Organizational rules are explicit attestation booleans — named for what
# a human verified, never silently passed. Input contract:
#   input.cisco.*                      : config-derived facts + attestations

import rego.v1

# CISC-ND-000470 | V-215823 | CAT I
default r_cisc_nd_000470 := false
r_cisc_nd_000470 if {
	input.cisco.nonsecure_services_disabled == true
}

finding_r_cisc_nd_000470 := {
	"vuln_id": "V-215823",
	"stig_id": "CISC-ND-000470",
	"severity": "CAT I",
	"rule_title": "The Cisco router must be configured to prohibit the use of all unnecessary and nonsecure functions and services.",
	"status": status_r_cisc_nd_000470,
}
status_r_cisc_nd_000470 := "Not_a_Finding" if r_cisc_nd_000470
status_r_cisc_nd_000470 := "Open" if not r_cisc_nd_000470

# CISC-ND-000550 | V-215826 | CAT II
default r_cisc_nd_000550 := false
r_cisc_nd_000550 if {
	input.cisco.min_15_char_password_enforced == true
}

finding_r_cisc_nd_000550 := {
	"vuln_id": "V-215826",
	"stig_id": "CISC-ND-000550",
	"severity": "CAT II",
	"rule_title": "The Cisco router must be configured to enforce a minimum 15-character password length.",
	"status": status_r_cisc_nd_000550,
}
status_r_cisc_nd_000550 := "Not_a_Finding" if r_cisc_nd_000550
status_r_cisc_nd_000550 := "Open" if not r_cisc_nd_000550

# CISC-ND-000620 | V-215832 | CAT I
default r_cisc_nd_000620 := false
r_cisc_nd_000620 if {
	input.cisco.passwords_stored_hashed == true
}

finding_r_cisc_nd_000620 := {
	"vuln_id": "V-215832",
	"stig_id": "CISC-ND-000620",
	"severity": "CAT I",
	"rule_title": "The Cisco router must only store cryptographic representations of passwords.",
	"status": status_r_cisc_nd_000620,
}
status_r_cisc_nd_000620 := "Not_a_Finding" if r_cisc_nd_000620
status_r_cisc_nd_000620 := "Open" if not r_cisc_nd_000620

# CISC-ND-000720 | V-215833 | CAT I
default r_cisc_nd_000720 := false
r_cisc_nd_000720 if {
	input.cisco.session_timeout_configured == true
}

finding_r_cisc_nd_000720 := {
	"vuln_id": "V-215833",
	"stig_id": "CISC-ND-000720",
	"severity": "CAT I",
	"rule_title": "The Cisco router must be configured to terminate all network connections associated with device management after five minutes of inactivity.",
	"status": status_r_cisc_nd_000720,
}
status_r_cisc_nd_000720 := "Not_a_Finding" if r_cisc_nd_000720
status_r_cisc_nd_000720 := "Open" if not r_cisc_nd_000720

# CISC-ND-001200 | V-215844 | CAT I
default r_cisc_nd_001200 := false
r_cisc_nd_001200 if {
	input.cisco.ssh_fips_hmac_configured == true
}

finding_r_cisc_nd_001200 := {
	"vuln_id": "V-215844",
	"stig_id": "CISC-ND-001200",
	"severity": "CAT I",
	"rule_title": "The Cisco router must be configured to use FIPS-validated Keyed-Hash Message Authentication Code (HMAC) to protect the integrity of remote maintenance sessions.",
	"status": status_r_cisc_nd_001200,
}
status_r_cisc_nd_001200 := "Not_a_Finding" if r_cisc_nd_001200
status_r_cisc_nd_001200 := "Open" if not r_cisc_nd_001200

# CISC-ND-001210 | V-215845 | CAT I
default r_cisc_nd_001210 := false
r_cisc_nd_001210 if {
	input.cisco.ssh_fips_ciphers_configured == true
}

finding_r_cisc_nd_001210 := {
	"vuln_id": "V-215845",
	"stig_id": "CISC-ND-001210",
	"severity": "CAT I",
	"rule_title": "The Cisco router must be configured to implement cryptographic mechanisms to protect the confidentiality of remote maintenance sessions.",
	"status": status_r_cisc_nd_001210,
}
status_r_cisc_nd_001210 := "Not_a_Finding" if r_cisc_nd_001210
status_r_cisc_nd_001210 := "Open" if not r_cisc_nd_001210

# CISC-ND-001370 | V-215854 | CAT I
default r_cisc_nd_001370 := false
r_cisc_nd_001370 if {
	input.cisco.two_authentication_servers == true
}

finding_r_cisc_nd_001370 := {
	"vuln_id": "V-215854",
	"stig_id": "CISC-ND-001370",
	"severity": "CAT I",
	"rule_title": "The Cisco router must be configured to use at least two authentication servers for the purpose of authenticating users prior to granting administrative access.",
	"status": status_r_cisc_nd_001370,
}
status_r_cisc_nd_001370 := "Not_a_Finding" if r_cisc_nd_001370
status_r_cisc_nd_001370 := "Open" if not r_cisc_nd_001370

# CISC-ND-001410 | V-215855 | CAT II
default r_cisc_nd_001410 := false
r_cisc_nd_001410 if {
	input.cisco.config_backup_on_change == true
}

finding_r_cisc_nd_001410 := {
	"vuln_id": "V-215855",
	"stig_id": "CISC-ND-001410",
	"severity": "CAT II",
	"rule_title": "The Cisco router must be configured to back up the configuration when changes occur.",
	"status": status_r_cisc_nd_001410,
}
status_r_cisc_nd_001410 := "Not_a_Finding" if r_cisc_nd_001410
status_r_cisc_nd_001410 := "Open" if not r_cisc_nd_001410

# CISC-ND-001450 | V-220139 | CAT I
default r_cisc_nd_001450 := false
r_cisc_nd_001450 if {
	input.cisco.two_syslog_servers == true
}

finding_r_cisc_nd_001450 := {
	"vuln_id": "V-220139",
	"stig_id": "CISC-ND-001450",
	"severity": "CAT I",
	"rule_title": "The Cisco router must be configured to send log data to at least two syslog servers for the purpose of forwarding alerts to the administrators and the information system security officer (ISSO).",
	"status": status_r_cisc_nd_001450,
}
status_r_cisc_nd_001450 := "Not_a_Finding" if r_cisc_nd_001450
status_r_cisc_nd_001450 := "Open" if not r_cisc_nd_001450

# CISC-ND-001470 | V-220140 | CAT I
default r_cisc_nd_001470 := false
r_cisc_nd_001470 if {
	input.cisco.supported_ios_release == true
}

finding_r_cisc_nd_001470 := {
	"vuln_id": "V-220140",
	"stig_id": "CISC-ND-001470",
	"severity": "CAT I",
	"rule_title": "The Cisco router must be running an IOS release that is currently supported by Cisco Systems.",
	"status": status_r_cisc_nd_001470,
}
status_r_cisc_nd_001470 := "Not_a_Finding" if r_cisc_nd_001470
status_r_cisc_nd_001470 := "Open" if not r_cisc_nd_001470

findings := [
	finding_r_cisc_nd_000470,
	finding_r_cisc_nd_000550,
	finding_r_cisc_nd_000620,
	finding_r_cisc_nd_000720,
	finding_r_cisc_nd_001200,
	finding_r_cisc_nd_001210,
	finding_r_cisc_nd_001370,
	finding_r_cisc_nd_001410,
	finding_r_cisc_nd_001450,
	finding_r_cisc_nd_001470,
]

default compliant := false

compliant if count([f | some f in findings; f.status == "Open"]) == 0
