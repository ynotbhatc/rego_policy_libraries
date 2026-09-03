package stig.windows_server_2025.registry_other

# DISA STIG — Microsoft Windows Server 2025 Security Technical Implementation Guide
# V1R2 | Release: 2 Benchmark Date: 01 Jul 2026
# Auto-derived registry checks (8 rules) — value expectations
# taken verbatim from the XCCDF check-content (July 2026 library).
# Input contract: input.registry["HKLM\\Path"]["ValueName"] = number|string

import rego.v1

# WN25-00-000390 | V-278024 | CAT II
default r_wn25_00_000390 := false
r_wn25_00_000390 if {
	input.registry["HKLM\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters"]["SMB1"] == 0
}

finding_r_wn25_00_000390 := {
	"vuln_id": "V-278024",
	"stig_id": "WN25-00-000390",
	"severity": "CAT II",
	"rule_title": "Windows Server 2025 must have the Server Message Block (SMB) v1 protocol disabled on the SMB server.",
	"status": status_r_wn25_00_000390,
}
status_r_wn25_00_000390 := "Not_a_Finding" if r_wn25_00_000390
status_r_wn25_00_000390 := "Open" if not r_wn25_00_000390

# WN25-00-000400 | V-278025 | CAT II
default r_wn25_00_000400 := false
r_wn25_00_000400 if {
	input.registry["HKLM\\SYSTEM\\CurrentControlSet\\Services\\mrxsmb10"]["Start"] == 4
}

finding_r_wn25_00_000400 := {
	"vuln_id": "V-278025",
	"stig_id": "WN25-00-000400",
	"severity": "CAT II",
	"rule_title": "Windows Server 2025 must have the Server Message Block (SMB) v1 protocol disabled on the SMB client.",
	"status": status_r_wn25_00_000400,
}
status_r_wn25_00_000400 := "Not_a_Finding" if r_wn25_00_000400
status_r_wn25_00_000400 := "Open" if not r_wn25_00_000400

# WN25-DC-000320 | V-278163 | CAT II
default r_wn25_dc_000320 := false
r_wn25_dc_000320 if {
	input.registry["HKLM\\SYSTEM\\CurrentControlSet\\Services\\NTDS\\Parameters"]["LDAPServerIntegrity"] == 2
}

finding_r_wn25_dc_000320 := {
	"vuln_id": "V-278163",
	"stig_id": "WN25-DC-000320",
	"severity": "CAT II",
	"rule_title": "Windows Server 2025 domain controllers must require LDAP access signing.",
	"status": status_r_wn25_dc_000320,
}
status_r_wn25_dc_000320 := "Not_a_Finding" if r_wn25_dc_000320
status_r_wn25_dc_000320 := "Open" if not r_wn25_dc_000320

# WN25-DC-000330 | V-278164 | CAT II
default r_wn25_dc_000330 := false
r_wn25_dc_000330 if {
	input.registry["HKLM\\SYSTEM\\CurrentControlSet\\Services\\Netlogon\\Parameters"]["RefusePasswordChange"] == 0
}

finding_r_wn25_dc_000330 := {
	"vuln_id": "V-278164",
	"stig_id": "WN25-DC-000330",
	"severity": "CAT II",
	"rule_title": "Windows Server 2025 domain controllers must be configured to allow reset of machine account passwords.",
	"status": status_r_wn25_dc_000330,
}
status_r_wn25_dc_000330 := "Not_a_Finding" if r_wn25_dc_000330
status_r_wn25_dc_000330 := "Open" if not r_wn25_dc_000330

# WN25-MS-000030 | V-278179 | CAT II
default r_wn25_ms_000030 := false
r_wn25_ms_000030 if {
	input.registry["HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\System"]["EnumerateLocalUsers"] == 0
}

finding_r_wn25_ms_000030 := {
	"vuln_id": "V-278179",
	"stig_id": "WN25-MS-000030",
	"severity": "CAT II",
	"rule_title": "Windows Server 2025 local users on domain-joined member servers must not be enumerated.",
	"status": status_r_wn25_ms_000030,
}
status_r_wn25_ms_000030 := "Not_a_Finding" if r_wn25_ms_000030
status_r_wn25_ms_000030 := "Open" if not r_wn25_ms_000030

# WN25-MS-000060 | V-278182 | CAT II
default r_wn25_ms_000060 := false
r_wn25_ms_000060 if {
	input.registry["HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa"]["RestrictRemoteSAM"] == "O:BAG:BAD:(A;;RC;;;BA)"
}

finding_r_wn25_ms_000060 := {
	"vuln_id": "V-278182",
	"stig_id": "WN25-MS-000060",
	"severity": "CAT II",
	"rule_title": "Windows Server 2025 must restrict remote calls to the Security Account Manager (SAM) to Administrators on domain-joined member servers and stand-alone or nondomain-joined systems.",
	"status": status_r_wn25_ms_000060,
}
status_r_wn25_ms_000060 := "Not_a_Finding" if r_wn25_ms_000060
status_r_wn25_ms_000060 := "Open" if not r_wn25_ms_000060

# WN25-MS-000140 | V-278190 | CAT I
default r_wn25_ms_000140 := false
r_wn25_ms_000140 if {
	input.registry["HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\DeviceGuard"]["LsaCfgFlags"] == 1
}

finding_r_wn25_ms_000140 := {
	"vuln_id": "V-278190",
	"stig_id": "WN25-MS-000140",
	"severity": "CAT I",
	"rule_title": "Windows Server 2025 must be running Credential Guard on domain-joined member servers.",
	"status": status_r_wn25_ms_000140,
}
status_r_wn25_ms_000140 := "Not_a_Finding" if r_wn25_ms_000140
status_r_wn25_ms_000140 := "Open" if not r_wn25_ms_000140

# WN25-UC-000010 | V-278240 | CAT II
default r_wn25_uc_000010 := false
r_wn25_uc_000010 if {
	input.registry["HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Attachments"]["SaveZoneInformation"] == 2
}

finding_r_wn25_uc_000010 := {
	"vuln_id": "V-278240",
	"stig_id": "WN25-UC-000010",
	"severity": "CAT II",
	"rule_title": "Windows Server 2025 must preserve zone information when saving attachments.",
	"status": status_r_wn25_uc_000010,
}
status_r_wn25_uc_000010 := "Not_a_Finding" if r_wn25_uc_000010
status_r_wn25_uc_000010 := "Open" if not r_wn25_uc_000010

findings := [
	finding_r_wn25_00_000390,
	finding_r_wn25_00_000400,
	finding_r_wn25_dc_000320,
	finding_r_wn25_dc_000330,
	finding_r_wn25_ms_000030,
	finding_r_wn25_ms_000060,
	finding_r_wn25_ms_000140,
	finding_r_wn25_uc_000010,
]

default compliant := false

compliant if count([f | some f in findings; f.status == "Open"]) == 0
