package stig.vmware_vsphere_8.core

# DISA STIG — VMware vSphere 8.0 ESXi Security Technical Implementation Guide
# V2R4 | Release: 4 Benchmark Date: 01 Jul 2026
# 10 rules (all CAT I + selected CAT II); IDs/severities/titles
# verified against the July 2026 SRG-STIG library XCCDF on 2026-09-03.
# Organizational rules are explicit attestation booleans — named for what
# a human verified, never silently passed. Input contract:
#   input.esxi.advanced_settings[<key>] : Get-AdvancedSetting values
#   input.esxi.*                        : host facts + attestations

import rego.v1

# ESXI-80-000008 | V-258730 | CAT II
default r_esxi_80_000008 := false
r_esxi_80_000008 if {
	input.esxi.lockdown_mode_enabled == true
}

finding_r_esxi_80_000008 := {
	"vuln_id": "V-258730",
	"stig_id": "ESXI-80-000008",
	"severity": "CAT II",
	"rule_title": "The ESXi host must enable lockdown mode.",
	"status": status_r_esxi_80_000008,
}
status_r_esxi_80_000008 := "Not_a_Finding" if r_esxi_80_000008
status_r_esxi_80_000008 := "Open" if not r_esxi_80_000008

# ESXI-80-000014 | V-258732 | CAT I
default r_esxi_80_000014 := false
r_esxi_80_000014 if {
	input.esxi.ssh_fips_140_2_enabled == true
}

finding_r_esxi_80_000014 := {
	"vuln_id": "V-258732",
	"stig_id": "ESXI-80-000014",
	"severity": "CAT I",
	"rule_title": "The ESXi host Secure Shell (SSH) daemon must use FIPS 140-2 validated cryptographic modules to protect the confidentiality of remote access sessions.",
	"status": status_r_esxi_80_000014,
}
status_r_esxi_80_000014 := "Not_a_Finding" if r_esxi_80_000014
status_r_esxi_80_000014 := "Open" if not r_esxi_80_000014

# ESXI-80-000035 | V-258734 | CAT II
default r_esxi_80_000035 := false
r_esxi_80_000035 if {
	input.esxi.password_quality_policy_configured == true
}

finding_r_esxi_80_000035 := {
	"vuln_id": "V-258734",
	"stig_id": "ESXI-80-000035",
	"severity": "CAT II",
	"rule_title": "The ESXi host must enforce password complexity by configuring a password quality policy.",
	"status": status_r_esxi_80_000035,
}
status_r_esxi_80_000035 := "Not_a_Finding" if r_esxi_80_000035
status_r_esxi_80_000035 := "Open" if not r_esxi_80_000035

# ESXI-80-000068 | V-258739 | CAT II
default r_esxi_80_000068 := false
r_esxi_80_000068 if {
	input.esxi.shell_idle_timeout_15min == true
}

finding_r_esxi_80_000068 := {
	"vuln_id": "V-258739",
	"stig_id": "ESXI-80-000068",
	"severity": "CAT II",
	"rule_title": "The ESXi host must set a timeout to automatically end idle shell sessions after fifteen minutes.",
	"status": status_r_esxi_80_000068,
}
status_r_esxi_80_000068 := "Not_a_Finding" if r_esxi_80_000068
status_r_esxi_80_000068 := "Open" if not r_esxi_80_000068

# ESXI-80-000113 | V-258743 | CAT II
default r_esxi_80_000113 := false
r_esxi_80_000113 if {
	input.esxi.audit_storage_one_week_allocated == true
}

finding_r_esxi_80_000113 := {
	"vuln_id": "V-258743",
	"stig_id": "ESXI-80-000113",
	"severity": "CAT II",
	"rule_title": "The ESXi host must allocate audit record storage capacity to store at least one week's worth of audit records.",
	"status": status_r_esxi_80_000113,
}
status_r_esxi_80_000113 := "Not_a_Finding" if r_esxi_80_000113
status_r_esxi_80_000113 := "Open" if not r_esxi_80_000113

# ESXI-80-000124 | V-258745 | CAT II
default r_esxi_80_000124 := false
r_esxi_80_000124 if {
	input.esxi.ntp_authoritative_source_configured == true
}

finding_r_esxi_80_000124 := {
	"vuln_id": "V-258745",
	"stig_id": "ESXI-80-000124",
	"severity": "CAT II",
	"rule_title": "The ESXi host must synchronize internal information system clocks to an authoritative time source.",
	"status": status_r_esxi_80_000124,
}
status_r_esxi_80_000124 := "Not_a_Finding" if r_esxi_80_000124
status_r_esxi_80_000124 := "Open" if not r_esxi_80_000124

# ESXI-80-000133 | V-258746 | CAT I
default r_esxi_80_000133 := false
r_esxi_80_000133 if {
	input.esxi.vib_acceptance_partner_or_stricter == true
}

finding_r_esxi_80_000133 := {
	"vuln_id": "V-258746",
	"stig_id": "ESXI-80-000133",
	"severity": "CAT I",
	"rule_title": "The ESXi Image Profile and vSphere Installation Bundle (VIB) acceptance level must be verified.",
	"status": status_r_esxi_80_000133,
}
status_r_esxi_80_000133 := "Not_a_Finding" if r_esxi_80_000133
status_r_esxi_80_000133 := "Open" if not r_esxi_80_000133

# ESXI-80-000160 | V-258748 | CAT II
default r_esxi_80_000160 := false
r_esxi_80_000160 if {
	input.esxi.mgmt_traffic_isolated_or_encrypted == true
}

finding_r_esxi_80_000160 := {
	"vuln_id": "V-258748",
	"stig_id": "ESXI-80-000160",
	"severity": "CAT II",
	"rule_title": "The ESXi host must protect the confidentiality and integrity of transmitted information by isolating vMotion traffic.",
	"status": status_r_esxi_80_000160,
}
status_r_esxi_80_000160 := "Not_a_Finding" if r_esxi_80_000160
status_r_esxi_80_000160 := "Open" if not r_esxi_80_000160

# ESXI-80-000217 | V-258772 | CAT I
default r_esxi_80_000217 := false
r_esxi_80_000217 if {
	input.esxi.vswitch_mac_changes_rejected == true
}

finding_r_esxi_80_000217 := {
	"vuln_id": "V-258772",
	"stig_id": "ESXI-80-000217",
	"severity": "CAT I",
	"rule_title": "The ESXi host must configure virtual switch security policies to reject Media Access Control (MAC) address changes.",
	"status": status_r_esxi_80_000217,
}
status_r_esxi_80_000217 := "Not_a_Finding" if r_esxi_80_000217
status_r_esxi_80_000217 := "Open" if not r_esxi_80_000217

# ESXI-80-000221 | V-258776 | CAT I
default r_esxi_80_000221 := false
r_esxi_80_000221 if {
	input.esxi.patches_current == true
}

finding_r_esxi_80_000221 := {
	"vuln_id": "V-258776",
	"stig_id": "ESXI-80-000221",
	"severity": "CAT I",
	"rule_title": "The ESXi host must have all security patches and updates installed.",
	"status": status_r_esxi_80_000221,
}
status_r_esxi_80_000221 := "Not_a_Finding" if r_esxi_80_000221
status_r_esxi_80_000221 := "Open" if not r_esxi_80_000221

findings := [
	finding_r_esxi_80_000008,
	finding_r_esxi_80_000014,
	finding_r_esxi_80_000035,
	finding_r_esxi_80_000068,
	finding_r_esxi_80_000113,
	finding_r_esxi_80_000124,
	finding_r_esxi_80_000133,
	finding_r_esxi_80_000160,
	finding_r_esxi_80_000217,
	finding_r_esxi_80_000221,
]

default compliant := false

compliant if count([f | some f in findings; f.status == "Open"]) == 0
