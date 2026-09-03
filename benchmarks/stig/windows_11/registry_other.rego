package stig.windows_11.registry_other

# DISA STIG — Microsoft Windows 11 Security Technical Implementation Guide
# V2R8 | Release: 8 Benchmark Date: 01 Jul 2026
# Auto-derived registry checks (12 rules) — value expectations
# taken verbatim from the XCCDF check-content (July 2026 library).
# Input contract: input.registry["HKLM\\Path"]["ValueName"] = number|string

import rego.v1

# WN11-00-000032 | V-253261 | CAT II
default r_wn11_00_000032 := false
r_wn11_00_000032 if {
	input.registry["HKLM\\SOFTWARE\\Policies\\Microsoft\\FVE"]["MinimumPIN"] == 6
}

finding_r_wn11_00_000032 := {
	"vuln_id": "V-253261",
	"stig_id": "WN11-00-000032",
	"severity": "CAT II",
	"rule_title": "Windows 11 systems must use a BitLocker PIN with a minimum length of six digits for pre-boot authentication.",
	"status": status_r_wn11_00_000032,
}
status_r_wn11_00_000032 := "Not_a_Finding" if r_wn11_00_000032
status_r_wn11_00_000032 := "Open" if not r_wn11_00_000032

# WN11-00-000126 | V-279688 | CAT II
default r_wn11_00_000126 := false
r_wn11_00_000126 if {
	input.registry["HKLM\\SOFTWARE\\Policies\\Microsoft\\MicrosoftAccount"]["DisableUserAuth"] == 1
}

finding_r_wn11_00_000126 := {
	"vuln_id": "V-279688",
	"stig_id": "WN11-00-000126",
	"severity": "CAT II",
	"rule_title": "Windows 11 systems must block consumer account user authentication.",
	"status": status_r_wn11_00_000126,
}
status_r_wn11_00_000126 := "Not_a_Finding" if r_wn11_00_000126
status_r_wn11_00_000126 := "Open" if not r_wn11_00_000126

# WN11-00-000150 | V-253284 | CAT I
default r_wn11_00_000150 := false
r_wn11_00_000150 if {
	input.registry["HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\kernel"]["DisableExceptionChainValidation"] == 0
}

finding_r_wn11_00_000150 := {
	"vuln_id": "V-253284",
	"stig_id": "WN11-00-000150",
	"severity": "CAT I",
	"rule_title": "Structured Exception Handling Overwrite Protection (SEHOP) must be enabled.",
	"status": status_r_wn11_00_000150,
}
status_r_wn11_00_000150 := "Not_a_Finding" if r_wn11_00_000150
status_r_wn11_00_000150 := "Open" if not r_wn11_00_000150

# WN11-00-000165 | V-253287 | CAT II
default r_wn11_00_000165 := false
r_wn11_00_000165 if {
	input.registry["HKLM\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters"]["SMB1"] == 0
}

finding_r_wn11_00_000165 := {
	"vuln_id": "V-253287",
	"stig_id": "WN11-00-000165",
	"severity": "CAT II",
	"rule_title": "The Server Message Block (SMB) v1 protocol must be disabled on the SMB server.",
	"status": status_r_wn11_00_000165,
}
status_r_wn11_00_000165 := "Not_a_Finding" if r_wn11_00_000165
status_r_wn11_00_000165 := "Open" if not r_wn11_00_000165

# WN11-00-000170 | V-253288 | CAT II
default r_wn11_00_000170 := false
r_wn11_00_000170 if {
	input.registry["HKLM\\SYSTEM\\CurrentControlSet\\Services\\mrxsmb10"]["Start"] == 4
}

finding_r_wn11_00_000170 := {
	"vuln_id": "V-253288",
	"stig_id": "WN11-00-000170",
	"severity": "CAT II",
	"rule_title": "The Server Message Block (SMB) v1 protocol must be disabled on the SMB client.",
	"status": status_r_wn11_00_000170,
}
status_r_wn11_00_000170 := "Not_a_Finding" if r_wn11_00_000170
status_r_wn11_00_000170 := "Open" if not r_wn11_00_000170

# WN11-00-000210 | V-253291 | CAT II
default r_wn11_00_000210 := false
r_wn11_00_000210 if {
	input.registry["HKLM\\SOFTWARE\\Microsoft\\PolicyManager\\current\\device\\Connectivity"]["AllowBluetooth"] == 0
}

finding_r_wn11_00_000210 := {
	"vuln_id": "V-253291",
	"stig_id": "WN11-00-000210",
	"severity": "CAT II",
	"rule_title": "Bluetooth must be turned off unless approved by the organization.",
	"status": status_r_wn11_00_000210,
}
status_r_wn11_00_000210 := "Not_a_Finding" if r_wn11_00_000210
status_r_wn11_00_000210 := "Open" if not r_wn11_00_000210

# WN11-AU-000500 | V-253337 | CAT II
default r_wn11_au_000500 := false
r_wn11_au_000500 if {
	input.registry["HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\EventLog\\Application"]["MaxSize"] >= 32768
}

finding_r_wn11_au_000500 := {
	"vuln_id": "V-253337",
	"stig_id": "WN11-AU-000500",
	"severity": "CAT II",
	"rule_title": "The Application event log size must be configured to 32768 KB or greater.",
	"status": status_r_wn11_au_000500,
}
status_r_wn11_au_000500 := "Not_a_Finding" if r_wn11_au_000500
status_r_wn11_au_000500 := "Open" if not r_wn11_au_000500

# WN11-AU-000505 | V-253338 | CAT II
default r_wn11_au_000505 := false
r_wn11_au_000505 if {
	input.registry["HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\EventLog\\Security"]["MaxSize"] >= 5120000
}

finding_r_wn11_au_000505 := {
	"vuln_id": "V-253338",
	"stig_id": "WN11-AU-000505",
	"severity": "CAT II",
	"rule_title": "The security event log size must be configured to a value that holds at least one week's worth of audit records.",
	"status": status_r_wn11_au_000505,
}
status_r_wn11_au_000505 := "Not_a_Finding" if r_wn11_au_000505
status_r_wn11_au_000505 := "Open" if not r_wn11_au_000505

# WN11-AU-000510 | V-253339 | CAT II
default r_wn11_au_000510 := false
r_wn11_au_000510 if {
	input.registry["HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\EventLog\\System"]["MaxSize"] >= 32768
}

finding_r_wn11_au_000510 := {
	"vuln_id": "V-253339",
	"stig_id": "WN11-AU-000510",
	"severity": "CAT II",
	"rule_title": "The System event log size must be configured to 32768 KB or greater.",
	"status": status_r_wn11_au_000510,
}
status_r_wn11_au_000510 := "Not_a_Finding" if r_wn11_au_000510
status_r_wn11_au_000510 := "Open" if not r_wn11_au_000510

# WN11-EP-000310 | V-253426 | CAT II
default r_wn11_ep_000310 := false
r_wn11_ep_000310 if {
	input.registry["HKLM\\Software\\Policies\\Microsoft\\Windows\\Kernel DMA Protection"]["DeviceEnumerationPolicy"] == 0
}

finding_r_wn11_ep_000310 := {
	"vuln_id": "V-253426",
	"stig_id": "WN11-EP-000310",
	"severity": "CAT II",
	"rule_title": "Windows 11 Kernel (Direct Memory Access) DMA Protection must be enabled.",
	"status": status_r_wn11_ep_000310,
}
status_r_wn11_ep_000310 := "Not_a_Finding" if r_wn11_ep_000310
status_r_wn11_ep_000310 := "Open" if not r_wn11_ep_000310

# WN11-UC-000015 | V-253477 | CAT III
default r_wn11_uc_000015 := false
r_wn11_uc_000015 if {
	input.registry["HKCU\\SOFTWARE\\Policies\\Microsoft\\Windows\\CurrentVersion\\PushNotifications"]["NoToastApplicationNotificationOnLockScreen"] == 1
}

finding_r_wn11_uc_000015 := {
	"vuln_id": "V-253477",
	"stig_id": "WN11-UC-000015",
	"severity": "CAT III",
	"rule_title": "Toast notifications to the lock screen must be turned off.",
	"status": status_r_wn11_uc_000015,
}
status_r_wn11_uc_000015 := "Not_a_Finding" if r_wn11_uc_000015
status_r_wn11_uc_000015 := "Open" if not r_wn11_uc_000015

# WN11-UC-000020 | V-253478 | CAT II
default r_wn11_uc_000020 := false
r_wn11_uc_000020 if {
	input.registry["HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Attachments"]["SaveZoneInformation"] == 2
}

finding_r_wn11_uc_000020 := {
	"vuln_id": "V-253478",
	"stig_id": "WN11-UC-000020",
	"severity": "CAT II",
	"rule_title": "Zone information must be preserved when saving attachments.",
	"status": status_r_wn11_uc_000020,
}
status_r_wn11_uc_000020 := "Not_a_Finding" if r_wn11_uc_000020
status_r_wn11_uc_000020 := "Open" if not r_wn11_uc_000020

findings := [
	finding_r_wn11_00_000032,
	finding_r_wn11_00_000126,
	finding_r_wn11_00_000150,
	finding_r_wn11_00_000165,
	finding_r_wn11_00_000170,
	finding_r_wn11_00_000210,
	finding_r_wn11_au_000500,
	finding_r_wn11_au_000505,
	finding_r_wn11_au_000510,
	finding_r_wn11_ep_000310,
	finding_r_wn11_uc_000015,
	finding_r_wn11_uc_000020,
]

default compliant := false

compliant if count([f | some f in findings; f.status == "Open"]) == 0
