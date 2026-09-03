package stig.windows_server_2022.registry_other

# DISA STIG — Microsoft Windows Server 2022 Security Technical Implementation Guide
# V2R9 | Release: 9 Benchmark Date: 01 Jul 2026
# Auto-derived registry checks (11 rules) — value expectations
# taken verbatim from the XCCDF check-content (July 2026 library).
# Input contract: input.registry["HKLM\\Path"]["ValueName"] = number|string

import rego.v1

# WN22-00-000390 | V-254276 | CAT II
default r_wn22_00_000390 := false
r_wn22_00_000390 if {
	input.registry["HKLM\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters"]["SMB1"] == 0
}

finding_r_wn22_00_000390 := {
	"vuln_id": "V-254276",
	"stig_id": "WN22-00-000390",
	"severity": "CAT II",
	"rule_title": "Windows Server 2022 must have the Server Message Block (SMB) v1 protocol disabled on the SMB server.",
	"status": status_r_wn22_00_000390,
}
status_r_wn22_00_000390 := "Not_a_Finding" if r_wn22_00_000390
status_r_wn22_00_000390 := "Open" if not r_wn22_00_000390

# WN22-00-000400 | V-254277 | CAT II
default r_wn22_00_000400 := false
r_wn22_00_000400 if {
	input.registry["HKLM\\SYSTEM\\CurrentControlSet\\Services\\mrxsmb10"]["Start"] == 4
}

finding_r_wn22_00_000400 := {
	"vuln_id": "V-254277",
	"stig_id": "WN22-00-000400",
	"severity": "CAT II",
	"rule_title": "Windows Server 2022 must have the Server Message Block (SMB) v1 protocol disabled on the SMB client.",
	"status": status_r_wn22_00_000400,
}
status_r_wn22_00_000400 := "Not_a_Finding" if r_wn22_00_000400
status_r_wn22_00_000400 := "Open" if not r_wn22_00_000400

# WN22-DC-000320 | V-254416 | CAT II
default r_wn22_dc_000320 := false
r_wn22_dc_000320 if {
	input.registry["HKLM\\SYSTEM\\CurrentControlSet\\Services\\NTDS\\Parameters"]["LDAPServerIntegrity"] == 2
}

finding_r_wn22_dc_000320 := {
	"vuln_id": "V-254416",
	"stig_id": "WN22-DC-000320",
	"severity": "CAT II",
	"rule_title": "Windows Server 2022 domain controllers must require LDAP access signing.",
	"status": status_r_wn22_dc_000320,
}
status_r_wn22_dc_000320 := "Not_a_Finding" if r_wn22_dc_000320
status_r_wn22_dc_000320 := "Open" if not r_wn22_dc_000320

# WN22-DC-000330 | V-254417 | CAT II
default r_wn22_dc_000330 := false
r_wn22_dc_000330 if {
	input.registry["HKLM\\SYSTEM\\CurrentControlSet\\Services\\Netlogon\\Parameters"]["RefusePasswordChange"] == 0
}

finding_r_wn22_dc_000330 := {
	"vuln_id": "V-254417",
	"stig_id": "WN22-DC-000330",
	"severity": "CAT II",
	"rule_title": "Windows Server 2022 domain controllers must be configured to allow reset of machine account passwords.",
	"status": status_r_wn22_dc_000330,
}
status_r_wn22_dc_000330 := "Not_a_Finding" if r_wn22_dc_000330
status_r_wn22_dc_000330 := "Open" if not r_wn22_dc_000330

# WN22-MS-000020 | V-254429 | CAT II
default r_wn22_ms_000020 := false
r_wn22_ms_000020 if {
	input.registry["HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System"]["LocalAccountTokenFilterPolicy"] == 0
}

finding_r_wn22_ms_000020 := {
	"vuln_id": "V-254429",
	"stig_id": "WN22-MS-000020",
	"severity": "CAT II",
	"rule_title": "Windows Server 2022 local administrator accounts must have their privileged token filtered to prevent elevated privileges from being used over the network on domain-joined member servers.",
	"status": status_r_wn22_ms_000020,
}
status_r_wn22_ms_000020 := "Not_a_Finding" if r_wn22_ms_000020
status_r_wn22_ms_000020 := "Open" if not r_wn22_ms_000020

# WN22-MS-000030 | V-254430 | CAT II
default r_wn22_ms_000030 := false
r_wn22_ms_000030 if {
	input.registry["HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\System"]["EnumerateLocalUsers"] == 0
}

finding_r_wn22_ms_000030 := {
	"vuln_id": "V-254430",
	"stig_id": "WN22-MS-000030",
	"severity": "CAT II",
	"rule_title": "Windows Server 2022 local users on domain-joined member servers must not be enumerated.",
	"status": status_r_wn22_ms_000030,
}
status_r_wn22_ms_000030 := "Not_a_Finding" if r_wn22_ms_000030
status_r_wn22_ms_000030 := "Open" if not r_wn22_ms_000030

# WN22-MS-000040 | V-254431 | CAT II
default r_wn22_ms_000040 := false
r_wn22_ms_000040 if {
	input.registry["HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Rpc"]["RestrictRemoteClients"] == 1
}

finding_r_wn22_ms_000040 := {
	"vuln_id": "V-254431",
	"stig_id": "WN22-MS-000040",
	"severity": "CAT II",
	"rule_title": "Windows Server 2022 must restrict unauthenticated Remote Procedure Call (RPC) clients from connecting to the RPC server on domain-joined member servers and standalone or nondomain-joined systems.",
	"status": status_r_wn22_ms_000040,
}
status_r_wn22_ms_000040 := "Not_a_Finding" if r_wn22_ms_000040
status_r_wn22_ms_000040 := "Open" if not r_wn22_ms_000040

# WN22-MS-000050 | V-254432 | CAT II
default r_wn22_ms_000050 := false
r_wn22_ms_000050 if {
	input.registry["HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon"]["CachedLogonsCount"] == "4 (or less)"
}

finding_r_wn22_ms_000050 := {
	"vuln_id": "V-254432",
	"stig_id": "WN22-MS-000050",
	"severity": "CAT II",
	"rule_title": "Windows Server 2022 must limit the caching of logon credentials to four or less on domain-joined member servers.",
	"status": status_r_wn22_ms_000050,
}
status_r_wn22_ms_000050 := "Not_a_Finding" if r_wn22_ms_000050
status_r_wn22_ms_000050 := "Open" if not r_wn22_ms_000050

# WN22-MS-000060 | V-254433 | CAT II
default r_wn22_ms_000060 := false
r_wn22_ms_000060 if {
	input.registry["HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa"]["RestrictRemoteSAM"] == "O:BAG:BAD:(A;;RC;;;BA)"
}

finding_r_wn22_ms_000060 := {
	"vuln_id": "V-254433",
	"stig_id": "WN22-MS-000060",
	"severity": "CAT II",
	"rule_title": "Windows Server 2022 must restrict remote calls to the Security Account Manager (SAM) to Administrators on domain-joined member servers and standalone or nondomain-joined systems.",
	"status": status_r_wn22_ms_000060,
}
status_r_wn22_ms_000060 := "Not_a_Finding" if r_wn22_ms_000060
status_r_wn22_ms_000060 := "Open" if not r_wn22_ms_000060

# WN22-MS-000140 | V-254441 | CAT I
default r_wn22_ms_000140 := false
r_wn22_ms_000140 if {
	input.registry["HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\DeviceGuard"]["LsaCfgFlags"] == 1
}

finding_r_wn22_ms_000140 := {
	"vuln_id": "V-254441",
	"stig_id": "WN22-MS-000140",
	"severity": "CAT I",
	"rule_title": "Windows Server 2022 must be running Credential Guard on domain-joined member servers.",
	"status": status_r_wn22_ms_000140,
}
status_r_wn22_ms_000140 := "Not_a_Finding" if r_wn22_ms_000140
status_r_wn22_ms_000140 := "Open" if not r_wn22_ms_000140

# WN22-UC-000010 | V-254490 | CAT II
default r_wn22_uc_000010 := false
r_wn22_uc_000010 if {
	input.registry["HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Attachments"]["SaveZoneInformation"] == 2
}

finding_r_wn22_uc_000010 := {
	"vuln_id": "V-254490",
	"stig_id": "WN22-UC-000010",
	"severity": "CAT II",
	"rule_title": "Windows Server 2022 must preserve zone information when saving attachments.",
	"status": status_r_wn22_uc_000010,
}
status_r_wn22_uc_000010 := "Not_a_Finding" if r_wn22_uc_000010
status_r_wn22_uc_000010 := "Open" if not r_wn22_uc_000010

findings := [
	finding_r_wn22_00_000390,
	finding_r_wn22_00_000400,
	finding_r_wn22_dc_000320,
	finding_r_wn22_dc_000330,
	finding_r_wn22_ms_000020,
	finding_r_wn22_ms_000030,
	finding_r_wn22_ms_000040,
	finding_r_wn22_ms_000050,
	finding_r_wn22_ms_000060,
	finding_r_wn22_ms_000140,
	finding_r_wn22_uc_000010,
]

default compliant := false

compliant if count([f | some f in findings; f.status == "Open"]) == 0
