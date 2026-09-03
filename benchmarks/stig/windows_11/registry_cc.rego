package stig.windows_11.registry_cc

# DISA STIG — Microsoft Windows 11 Security Technical Implementation Guide
# V2R8 | Release: 8 Benchmark Date: 01 Jul 2026
# Auto-derived registry checks (54 rules) — value expectations
# taken verbatim from the XCCDF check-content (July 2026 library).
# Input contract: input.registry["HKLM\\Path"]["ValueName"] = number|string

import rego.v1

# WN11-CC-000005 | V-253350 | CAT II
default r_wn11_cc_000005 := false
r_wn11_cc_000005 if {
	input.registry["HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\Personalization"]["NoLockScreenCamera"] == 1
}

finding_r_wn11_cc_000005 := {
	"vuln_id": "V-253350",
	"stig_id": "WN11-CC-000005",
	"severity": "CAT II",
	"rule_title": "Camera access from the lock screen must be disabled.",
	"status": status_r_wn11_cc_000005,
}
status_r_wn11_cc_000005 := "Not_a_Finding" if r_wn11_cc_000005
status_r_wn11_cc_000005 := "Open" if not r_wn11_cc_000005

# WN11-CC-000010 | V-253352 | CAT II
default r_wn11_cc_000010 := false
r_wn11_cc_000010 if {
	input.registry["HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\Personalization"]["NoLockScreenSlideshow"] == 1
}

finding_r_wn11_cc_000010 := {
	"vuln_id": "V-253352",
	"stig_id": "WN11-CC-000010",
	"severity": "CAT II",
	"rule_title": "The display of slide shows on the lock screen must be disabled.",
	"status": status_r_wn11_cc_000010,
}
status_r_wn11_cc_000010 := "Not_a_Finding" if r_wn11_cc_000010
status_r_wn11_cc_000010 := "Open" if not r_wn11_cc_000010

# WN11-CC-000020 | V-253353 | CAT II
default r_wn11_cc_000020 := false
r_wn11_cc_000020 if {
	input.registry["HKLM\\SYSTEM\\CurrentControlSet\\Services\\Tcpip6\\Parameters"]["DisableIpSourceRouting"] == 2
}

finding_r_wn11_cc_000020 := {
	"vuln_id": "V-253353",
	"stig_id": "WN11-CC-000020",
	"severity": "CAT II",
	"rule_title": "IPv6 source routing must be configured to highest protection.",
	"status": status_r_wn11_cc_000020,
}
status_r_wn11_cc_000020 := "Not_a_Finding" if r_wn11_cc_000020
status_r_wn11_cc_000020 := "Open" if not r_wn11_cc_000020

# WN11-CC-000025 | V-253354 | CAT II
default r_wn11_cc_000025 := false
r_wn11_cc_000025 if {
	input.registry["HKLM\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters"]["DisableIPSourceRouting"] == 2
}

finding_r_wn11_cc_000025 := {
	"vuln_id": "V-253354",
	"stig_id": "WN11-CC-000025",
	"severity": "CAT II",
	"rule_title": "The system must be configured to prevent IP source routing.",
	"status": status_r_wn11_cc_000025,
}
status_r_wn11_cc_000025 := "Not_a_Finding" if r_wn11_cc_000025
status_r_wn11_cc_000025 := "Open" if not r_wn11_cc_000025

# WN11-CC-000030 | V-253355 | CAT III
default r_wn11_cc_000030 := false
r_wn11_cc_000030 if {
	input.registry["HKLM\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters"]["EnableICMPRedirect"] == 0
}

finding_r_wn11_cc_000030 := {
	"vuln_id": "V-253355",
	"stig_id": "WN11-CC-000030",
	"severity": "CAT III",
	"rule_title": "The system must be configured to prevent Internet Control Message Protocol (ICMP) redirects from overriding Open Shortest Path First (OSPF) generated routes.",
	"status": status_r_wn11_cc_000030,
}
status_r_wn11_cc_000030 := "Not_a_Finding" if r_wn11_cc_000030
status_r_wn11_cc_000030 := "Open" if not r_wn11_cc_000030

# WN11-CC-000035 | V-253356 | CAT III
default r_wn11_cc_000035 := false
r_wn11_cc_000035 if {
	input.registry["HKLM\\SYSTEM\\CurrentControlSet\\Services\\Netbt\\Parameters"]["NoNameReleaseOnDemand"] == 1
}

finding_r_wn11_cc_000035 := {
	"vuln_id": "V-253356",
	"stig_id": "WN11-CC-000035",
	"severity": "CAT III",
	"rule_title": "The system must be configured to ignore NetBIOS name release requests except from WINS servers.",
	"status": status_r_wn11_cc_000035,
}
status_r_wn11_cc_000035 := "Not_a_Finding" if r_wn11_cc_000035
status_r_wn11_cc_000035 := "Open" if not r_wn11_cc_000035

# WN11-CC-000038 | V-253358 | CAT II
default r_wn11_cc_000038 := false
r_wn11_cc_000038 if {
	input.registry["HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\Wdigest"]["UseLogonCredential"] == 0
}

finding_r_wn11_cc_000038 := {
	"vuln_id": "V-253358",
	"stig_id": "WN11-CC-000038",
	"severity": "CAT II",
	"rule_title": "WDigest Authentication must be disabled.",
	"status": status_r_wn11_cc_000038,
}
status_r_wn11_cc_000038 := "Not_a_Finding" if r_wn11_cc_000038
status_r_wn11_cc_000038 := "Open" if not r_wn11_cc_000038

# WN11-CC-000040 | V-253360 | CAT II
default r_wn11_cc_000040 := false
r_wn11_cc_000040 if {
	input.registry["HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\LanmanWorkstation"]["AllowInsecureGuestAuth"] == 0
}

finding_r_wn11_cc_000040 := {
	"vuln_id": "V-253360",
	"stig_id": "WN11-CC-000040",
	"severity": "CAT II",
	"rule_title": "Insecure logons to an SMB server must be disabled.",
	"status": status_r_wn11_cc_000040,
}
status_r_wn11_cc_000040 := "Not_a_Finding" if r_wn11_cc_000040
status_r_wn11_cc_000040 := "Open" if not r_wn11_cc_000040

# WN11-CC-000044 | V-253361 | CAT II
default r_wn11_cc_000044 := false
r_wn11_cc_000044 if {
	input.registry["HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\Network Connections"]["NC_ShowSharedAccessUI"] == 0
}

finding_r_wn11_cc_000044 := {
	"vuln_id": "V-253361",
	"stig_id": "WN11-CC-000044",
	"severity": "CAT II",
	"rule_title": "Internet connection sharing must be disabled.",
	"status": status_r_wn11_cc_000044,
}
status_r_wn11_cc_000044 := "Not_a_Finding" if r_wn11_cc_000044
status_r_wn11_cc_000044 := "Open" if not r_wn11_cc_000044

# WN11-CC-000050 | V-253362 | CAT II
default r_wn11_cc_000050 := false
r_wn11_cc_000050 if {
	input.registry["HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\NetworkProvider\\HardenedPaths"]["\\\\*\\NETLOGON"] == "RequireMutualAuthentication=1, RequireIntegrity=1"
}

finding_r_wn11_cc_000050 := {
	"vuln_id": "V-253362",
	"stig_id": "WN11-CC-000050",
	"severity": "CAT II",
	"rule_title": "Hardened UNC Paths must be defined to require mutual authentication and integrity for at least the \\\\*\\SYSVOL and \\\\*\\NETLOGON shares.",
	"status": status_r_wn11_cc_000050,
}
status_r_wn11_cc_000050 := "Not_a_Finding" if r_wn11_cc_000050
status_r_wn11_cc_000050 := "Open" if not r_wn11_cc_000050

# WN11-CC-000060 | V-253365 | CAT II
default r_wn11_cc_000060 := false
r_wn11_cc_000060 if {
	input.registry["HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\WcmSvc\\GroupPolicy"]["fBlockNonDomain"] == 1
}

finding_r_wn11_cc_000060 := {
	"vuln_id": "V-253365",
	"stig_id": "WN11-CC-000060",
	"severity": "CAT II",
	"rule_title": "Connections to non-domain networks when connected to a domain authenticated network must be blocked.",
	"status": status_r_wn11_cc_000060,
}
status_r_wn11_cc_000060 := "Not_a_Finding" if r_wn11_cc_000060
status_r_wn11_cc_000060 := "Open" if not r_wn11_cc_000060

# WN11-CC-000066 | V-253367 | CAT II
default r_wn11_cc_000066 := false
r_wn11_cc_000066 if {
	input.registry["HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\Audit"]["ProcessCreationIncludeCmdLine_Enabled"] == 1
}

finding_r_wn11_cc_000066 := {
	"vuln_id": "V-253367",
	"stig_id": "WN11-CC-000066",
	"severity": "CAT II",
	"rule_title": "Command line data must be included in process creation events.",
	"status": status_r_wn11_cc_000066,
}
status_r_wn11_cc_000066 := "Not_a_Finding" if r_wn11_cc_000066
status_r_wn11_cc_000066 := "Open" if not r_wn11_cc_000066

# WN11-CC-000068 | V-253368 | CAT II
default r_wn11_cc_000068 := false
r_wn11_cc_000068 if {
	input.registry["HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\CredentialsDelegation"]["AllowProtectedCreds"] == 1
}

finding_r_wn11_cc_000068 := {
	"vuln_id": "V-253368",
	"stig_id": "WN11-CC-000068",
	"severity": "CAT II",
	"rule_title": "Windows 11 must be configured to enable Remote host allows delegation of non-exportable credentials.",
	"status": status_r_wn11_cc_000068,
}
status_r_wn11_cc_000068 := "Not_a_Finding" if r_wn11_cc_000068
status_r_wn11_cc_000068 := "Open" if not r_wn11_cc_000068

# WN11-CC-000070 | V-253369 | CAT II
default r_wn11_cc_000070 := false
r_wn11_cc_000070 if {
	input.registry["HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\DeviceGuard"]["EnableVirtualizationBasedSecurity"] == 1
}

finding_r_wn11_cc_000070 := {
	"vuln_id": "V-253369",
	"stig_id": "WN11-CC-000070",
	"severity": "CAT II",
	"rule_title": "Virtualization-Based Security (VBS) must be enabled on Windows 11 with the platform security level configured to Secure Boot or Secure Boot with DMA Protection.",
	"status": status_r_wn11_cc_000070,
}
status_r_wn11_cc_000070 := "Not_a_Finding" if r_wn11_cc_000070
status_r_wn11_cc_000070 := "Open" if not r_wn11_cc_000070

# WN11-CC-000075 | V-253370 | CAT I
default r_wn11_cc_000075 := false
r_wn11_cc_000075 if {
	input.registry["HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\DeviceGuard"]["LsaCfgFlags"] == 1
}

finding_r_wn11_cc_000075 := {
	"vuln_id": "V-253370",
	"stig_id": "WN11-CC-000075",
	"severity": "CAT I",
	"rule_title": "Credential Guard must be running on Windows 11 systems.",
	"status": status_r_wn11_cc_000075,
}
status_r_wn11_cc_000075 := "Not_a_Finding" if r_wn11_cc_000075
status_r_wn11_cc_000075 := "Open" if not r_wn11_cc_000075

# WN11-CC-000080 | V-253371 | CAT II
default r_wn11_cc_000080 := false
r_wn11_cc_000080 if {
	input.registry["HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\DeviceGuard"]["HypervisorEnforcedCodeIntegrity"] == 1
}

finding_r_wn11_cc_000080 := {
	"vuln_id": "V-253371",
	"stig_id": "WN11-CC-000080",
	"severity": "CAT II",
	"rule_title": "Virtualization-based protection of code integrity must be enabled.",
	"status": status_r_wn11_cc_000080,
}
status_r_wn11_cc_000080 := "Not_a_Finding" if r_wn11_cc_000080
status_r_wn11_cc_000080 := "Open" if not r_wn11_cc_000080

# WN11-CC-000090 | V-253373 | CAT II
default r_wn11_cc_000090 := false
r_wn11_cc_000090 if {
	input.registry["HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\Group Policy\\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}"]["NoGPOListChanges"] == 0
}

finding_r_wn11_cc_000090 := {
	"vuln_id": "V-253373",
	"stig_id": "WN11-CC-000090",
	"severity": "CAT II",
	"rule_title": "Group Policy objects must be reprocessed even if they have not changed.",
	"status": status_r_wn11_cc_000090,
}
status_r_wn11_cc_000090 := "Not_a_Finding" if r_wn11_cc_000090
status_r_wn11_cc_000090 := "Open" if not r_wn11_cc_000090

# WN11-CC-000100 | V-253374 | CAT II
default r_wn11_cc_000100 := false
r_wn11_cc_000100 if {
	input.registry["HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Printers"]["DisableWebPnPDownload"] == 1
}

finding_r_wn11_cc_000100 := {
	"vuln_id": "V-253374",
	"stig_id": "WN11-CC-000100",
	"severity": "CAT II",
	"rule_title": "Downloading print driver packages over HTTP must be prevented.",
	"status": status_r_wn11_cc_000100,
}
status_r_wn11_cc_000100 := "Not_a_Finding" if r_wn11_cc_000100
status_r_wn11_cc_000100 := "Open" if not r_wn11_cc_000100

# WN11-CC-000105 | V-253375 | CAT II
default r_wn11_cc_000105 := false
r_wn11_cc_000105 if {
	input.registry["HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer"]["NoWebServices"] == 1
}

finding_r_wn11_cc_000105 := {
	"vuln_id": "V-253375",
	"stig_id": "WN11-CC-000105",
	"severity": "CAT II",
	"rule_title": "Web publishing and online ordering wizards must be prevented from downloading a list of providers.",
	"status": status_r_wn11_cc_000105,
}
status_r_wn11_cc_000105 := "Not_a_Finding" if r_wn11_cc_000105
status_r_wn11_cc_000105 := "Open" if not r_wn11_cc_000105

# WN11-CC-000110 | V-253376 | CAT II
default r_wn11_cc_000110 := false
r_wn11_cc_000110 if {
	input.registry["HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Printers"]["DisableHTTPPrinting"] == 1
}

finding_r_wn11_cc_000110 := {
	"vuln_id": "V-253376",
	"stig_id": "WN11-CC-000110",
	"severity": "CAT II",
	"rule_title": "Printing over HTTP must be prevented.",
	"status": status_r_wn11_cc_000110,
}
status_r_wn11_cc_000110 := "Not_a_Finding" if r_wn11_cc_000110
status_r_wn11_cc_000110 := "Open" if not r_wn11_cc_000110

# WN11-CC-000120 | V-253378 | CAT II
default r_wn11_cc_000120 := false
r_wn11_cc_000120 if {
	input.registry["HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\System"]["DontDisplayNetworkSelectionUI"] == 1
}

finding_r_wn11_cc_000120 := {
	"vuln_id": "V-253378",
	"stig_id": "WN11-CC-000120",
	"severity": "CAT II",
	"rule_title": "The network selection user interface (UI) must not be displayed on the logon screen.",
	"status": status_r_wn11_cc_000120,
}
status_r_wn11_cc_000120 := "Not_a_Finding" if r_wn11_cc_000120
status_r_wn11_cc_000120 := "Open" if not r_wn11_cc_000120

# WN11-CC-000130 | V-253379 | CAT II
default r_wn11_cc_000130 := false
r_wn11_cc_000130 if {
	input.registry["HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\System"]["EnumerateLocalUsers"] == 0
}

finding_r_wn11_cc_000130 := {
	"vuln_id": "V-253379",
	"stig_id": "WN11-CC-000130",
	"severity": "CAT II",
	"rule_title": "Local users on domain-joined computers must not be enumerated.",
	"status": status_r_wn11_cc_000130,
}
status_r_wn11_cc_000130 := "Not_a_Finding" if r_wn11_cc_000130
status_r_wn11_cc_000130 := "Open" if not r_wn11_cc_000130

# WN11-CC-000145 | V-253380 | CAT II
default r_wn11_cc_000145 := false
r_wn11_cc_000145 if {
	input.registry["HKLM\\SOFTWARE\\Policies\\Microsoft\\Power\\PowerSettings\\0e796bdb-100d-47d6-a2d5-f7d2daa51f51"]["DCSettingIndex"] == 1
}

finding_r_wn11_cc_000145 := {
	"vuln_id": "V-253380",
	"stig_id": "WN11-CC-000145",
	"severity": "CAT II",
	"rule_title": "Users must be prompted for a password on resume from sleep (on battery).",
	"status": status_r_wn11_cc_000145,
}
status_r_wn11_cc_000145 := "Not_a_Finding" if r_wn11_cc_000145
status_r_wn11_cc_000145 := "Open" if not r_wn11_cc_000145

# WN11-CC-000150 | V-253381 | CAT II
default r_wn11_cc_000150 := false
r_wn11_cc_000150 if {
	input.registry["HKLM\\SOFTWARE\\Policies\\Microsoft\\Power\\PowerSettings\\0e796bdb-100d-47d6-a2d5-f7d2daa51f51"]["ACSettingIndex"] == 1
}

finding_r_wn11_cc_000150 := {
	"vuln_id": "V-253381",
	"stig_id": "WN11-CC-000150",
	"severity": "CAT II",
	"rule_title": "The user must be prompted for a password on resume from sleep (plugged in).",
	"status": status_r_wn11_cc_000150,
}
status_r_wn11_cc_000150 := "Not_a_Finding" if r_wn11_cc_000150
status_r_wn11_cc_000150 := "Open" if not r_wn11_cc_000150

# WN11-CC-000155 | V-253382 | CAT I
default r_wn11_cc_000155 := false
r_wn11_cc_000155 if {
	input.registry["HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services"]["fAllowToGetHelp"] == 0
}

finding_r_wn11_cc_000155 := {
	"vuln_id": "V-253382",
	"stig_id": "WN11-CC-000155",
	"severity": "CAT I",
	"rule_title": "Solicited Remote Assistance must not be allowed.",
	"status": status_r_wn11_cc_000155,
}
status_r_wn11_cc_000155 := "Not_a_Finding" if r_wn11_cc_000155
status_r_wn11_cc_000155 := "Open" if not r_wn11_cc_000155

# WN11-CC-000165 | V-253383 | CAT II
default r_wn11_cc_000165 := false
r_wn11_cc_000165 if {
	input.registry["HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Rpc"]["RestrictRemoteClients"] == 1
}

finding_r_wn11_cc_000165 := {
	"vuln_id": "V-253383",
	"stig_id": "WN11-CC-000165",
	"severity": "CAT II",
	"rule_title": "Unauthenticated RPC clients must be restricted from connecting to the RPC server.",
	"status": status_r_wn11_cc_000165,
}
status_r_wn11_cc_000165 := "Not_a_Finding" if r_wn11_cc_000165
status_r_wn11_cc_000165 := "Open" if not r_wn11_cc_000165

# WN11-CC-000170 | V-253384 | CAT III
default r_wn11_cc_000170 := false
r_wn11_cc_000170 if {
	input.registry["HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System"]["MSAOptional"] == 1
}

finding_r_wn11_cc_000170 := {
	"vuln_id": "V-253384",
	"stig_id": "WN11-CC-000170",
	"severity": "CAT III",
	"rule_title": "The setting to allow Microsoft accounts to be optional for modern style apps must be enabled.",
	"status": status_r_wn11_cc_000170,
}
status_r_wn11_cc_000170 := "Not_a_Finding" if r_wn11_cc_000170
status_r_wn11_cc_000170 := "Open" if not r_wn11_cc_000170

# WN11-CC-000175 | V-253385 | CAT III
default r_wn11_cc_000175 := false
r_wn11_cc_000175 if {
	input.registry["HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\AppCompat"]["DisableInventory"] == 1
}

finding_r_wn11_cc_000175 := {
	"vuln_id": "V-253385",
	"stig_id": "WN11-CC-000175",
	"severity": "CAT III",
	"rule_title": "The Application Compatibility Program Inventory must be prevented from collecting data and sending the information to Microsoft.",
	"status": status_r_wn11_cc_000175,
}
status_r_wn11_cc_000175 := "Not_a_Finding" if r_wn11_cc_000175
status_r_wn11_cc_000175 := "Open" if not r_wn11_cc_000175

# WN11-CC-000180 | V-253386 | CAT I
default r_wn11_cc_000180 := false
r_wn11_cc_000180 if {
	input.registry["HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\Explorer"]["NoAutoplayfornonVolume"] == 1
}

finding_r_wn11_cc_000180 := {
	"vuln_id": "V-253386",
	"stig_id": "WN11-CC-000180",
	"severity": "CAT I",
	"rule_title": "Autoplay must be turned off for non-volume devices.",
	"status": status_r_wn11_cc_000180,
}
status_r_wn11_cc_000180 := "Not_a_Finding" if r_wn11_cc_000180
status_r_wn11_cc_000180 := "Open" if not r_wn11_cc_000180

# WN11-CC-000185 | V-253387 | CAT I
default r_wn11_cc_000185 := false
r_wn11_cc_000185 if {
	input.registry["HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer"]["NoAutorun"] == 1
}

finding_r_wn11_cc_000185 := {
	"vuln_id": "V-253387",
	"stig_id": "WN11-CC-000185",
	"severity": "CAT I",
	"rule_title": "The default autorun behavior must be configured to prevent autorun commands.",
	"status": status_r_wn11_cc_000185,
}
status_r_wn11_cc_000185 := "Not_a_Finding" if r_wn11_cc_000185
status_r_wn11_cc_000185 := "Open" if not r_wn11_cc_000185

# WN11-CC-000190 | V-253388 | CAT I
default r_wn11_cc_000190 := false
r_wn11_cc_000190 if {
	input.registry["HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\policies\\Explorer"]["NoDriveTypeAutoRun"] == 255
}

finding_r_wn11_cc_000190 := {
	"vuln_id": "V-253388",
	"stig_id": "WN11-CC-000190",
	"severity": "CAT I",
	"rule_title": "Autoplay must be disabled for all drives.",
	"status": status_r_wn11_cc_000190,
}
status_r_wn11_cc_000190 := "Not_a_Finding" if r_wn11_cc_000190
status_r_wn11_cc_000190 := "Open" if not r_wn11_cc_000190

# WN11-CC-000200 | V-253391 | CAT II
default r_wn11_cc_000200 := false
r_wn11_cc_000200 if {
	input.registry["HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\CredUI"]["EnumerateAdministrators"] == 0
}

finding_r_wn11_cc_000200 := {
	"vuln_id": "V-253391",
	"stig_id": "WN11-CC-000200",
	"severity": "CAT II",
	"rule_title": "Administrator accounts must not be enumerated during elevation.",
	"status": status_r_wn11_cc_000200,
}
status_r_wn11_cc_000200 := "Not_a_Finding" if r_wn11_cc_000200
status_r_wn11_cc_000200 := "Open" if not r_wn11_cc_000200

# WN11-CC-000204 | V-253392 | CAT II
default r_wn11_cc_000204 := false
r_wn11_cc_000204 if {
	input.registry["HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\DataCollection"]["LimitEnhancedDiagnosticDataWindowsAnalytics"] == 1
}

finding_r_wn11_cc_000204 := {
	"vuln_id": "V-253392",
	"stig_id": "WN11-CC-000204",
	"severity": "CAT II",
	"rule_title": "Enhanced diagnostic data must be limited to the minimum required to support Windows Analytics.",
	"status": status_r_wn11_cc_000204,
}
status_r_wn11_cc_000204 := "Not_a_Finding" if r_wn11_cc_000204
status_r_wn11_cc_000204 := "Open" if not r_wn11_cc_000204

# WN11-CC-000210 | V-253395 | CAT II
default r_wn11_cc_000210 := false
r_wn11_cc_000210 if {
	input.registry["HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\System"]["EnableSmartScreen"] == 1
	input.registry["HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\System"]["ShellSmartScreenLevel"] == "Block"
}

finding_r_wn11_cc_000210 := {
	"vuln_id": "V-253395",
	"stig_id": "WN11-CC-000210",
	"severity": "CAT II",
	"rule_title": "The Microsoft Defender SmartScreen for Explorer must be enabled.",
	"status": status_r_wn11_cc_000210,
}
status_r_wn11_cc_000210 := "Not_a_Finding" if r_wn11_cc_000210
status_r_wn11_cc_000210 := "Open" if not r_wn11_cc_000210

# WN11-CC-000220 | V-253397 | CAT III
default r_wn11_cc_000220 := false
r_wn11_cc_000220 if {
	input.registry["HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\Explorer"]["NoHeapTerminationOnCorruption"] == 0
}

finding_r_wn11_cc_000220 := {
	"vuln_id": "V-253397",
	"stig_id": "WN11-CC-000220",
	"severity": "CAT III",
	"rule_title": "File Explorer heap termination on corruption must be disabled.",
	"status": status_r_wn11_cc_000220,
}
status_r_wn11_cc_000220 := "Not_a_Finding" if r_wn11_cc_000220
status_r_wn11_cc_000220 := "Open" if not r_wn11_cc_000220

# WN11-CC-000255 | V-253400 | CAT II
default r_wn11_cc_000255 := false
r_wn11_cc_000255 if {
	input.registry["HKLM\\SOFTWARE\\Policies\\Microsoft\\PassportForWork"]["RequireSecurityDevice"] == 1
}

finding_r_wn11_cc_000255 := {
	"vuln_id": "V-253400",
	"stig_id": "WN11-CC-000255",
	"severity": "CAT II",
	"rule_title": "The use of a hardware security device with Windows Hello for Business must be enabled.",
	"status": status_r_wn11_cc_000255,
}
status_r_wn11_cc_000255 := "Not_a_Finding" if r_wn11_cc_000255
status_r_wn11_cc_000255 := "Open" if not r_wn11_cc_000255

# WN11-CC-000270 | V-253402 | CAT II
default r_wn11_cc_000270 := false
r_wn11_cc_000270 if {
	input.registry["HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services"]["DisablePasswordSaving"] == 1
}

finding_r_wn11_cc_000270 := {
	"vuln_id": "V-253402",
	"stig_id": "WN11-CC-000270",
	"severity": "CAT II",
	"rule_title": "Passwords must not be saved in the Remote Desktop Client.",
	"status": status_r_wn11_cc_000270,
}
status_r_wn11_cc_000270 := "Not_a_Finding" if r_wn11_cc_000270
status_r_wn11_cc_000270 := "Open" if not r_wn11_cc_000270

# WN11-CC-000275 | V-253403 | CAT II
default r_wn11_cc_000275 := false
r_wn11_cc_000275 if {
	input.registry["HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services"]["fDisableCdm"] == 1
}

finding_r_wn11_cc_000275 := {
	"vuln_id": "V-253403",
	"stig_id": "WN11-CC-000275",
	"severity": "CAT II",
	"rule_title": "Local drives must be prevented from sharing with Remote Desktop Session Hosts.",
	"status": status_r_wn11_cc_000275,
}
status_r_wn11_cc_000275 := "Not_a_Finding" if r_wn11_cc_000275
status_r_wn11_cc_000275 := "Open" if not r_wn11_cc_000275

# WN11-CC-000280 | V-253404 | CAT II
default r_wn11_cc_000280 := false
r_wn11_cc_000280 if {
	input.registry["HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services"]["fPromptForPassword"] == 1
}

finding_r_wn11_cc_000280 := {
	"vuln_id": "V-253404",
	"stig_id": "WN11-CC-000280",
	"severity": "CAT II",
	"rule_title": "Remote Desktop Services must always prompt a client for passwords upon connection.",
	"status": status_r_wn11_cc_000280,
}
status_r_wn11_cc_000280 := "Not_a_Finding" if r_wn11_cc_000280
status_r_wn11_cc_000280 := "Open" if not r_wn11_cc_000280

# WN11-CC-000285 | V-253405 | CAT II
default r_wn11_cc_000285 := false
r_wn11_cc_000285 if {
	input.registry["HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services"]["fEncryptRPCTraffic"] == 1
}

finding_r_wn11_cc_000285 := {
	"vuln_id": "V-253405",
	"stig_id": "WN11-CC-000285",
	"severity": "CAT II",
	"rule_title": "The Remote Desktop Session Host must require secure RPC communications.",
	"status": status_r_wn11_cc_000285,
}
status_r_wn11_cc_000285 := "Not_a_Finding" if r_wn11_cc_000285
status_r_wn11_cc_000285 := "Open" if not r_wn11_cc_000285

# WN11-CC-000290 | V-253406 | CAT II
default r_wn11_cc_000290 := false
r_wn11_cc_000290 if {
	input.registry["HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services"]["MinEncryptionLevel"] == 3
}

finding_r_wn11_cc_000290 := {
	"vuln_id": "V-253406",
	"stig_id": "WN11-CC-000290",
	"severity": "CAT II",
	"rule_title": "Remote Desktop Services must be configured with the client connection encryption set to the required level.",
	"status": status_r_wn11_cc_000290,
}
status_r_wn11_cc_000290 := "Not_a_Finding" if r_wn11_cc_000290
status_r_wn11_cc_000290 := "Open" if not r_wn11_cc_000290

# WN11-CC-000295 | V-253407 | CAT II
default r_wn11_cc_000295 := false
r_wn11_cc_000295 if {
	input.registry["HKLM\\SOFTWARE\\Policies\\Microsoft\\Internet Explorer\\Feeds"]["DisableEnclosureDownload"] == 1
}

finding_r_wn11_cc_000295 := {
	"vuln_id": "V-253407",
	"stig_id": "WN11-CC-000295",
	"severity": "CAT II",
	"rule_title": "Attachments must be prevented from being downloaded from RSS feeds.",
	"status": status_r_wn11_cc_000295,
}
status_r_wn11_cc_000295 := "Not_a_Finding" if r_wn11_cc_000295
status_r_wn11_cc_000295 := "Open" if not r_wn11_cc_000295

# WN11-CC-000310 | V-253410 | CAT II
default r_wn11_cc_000310 := false
r_wn11_cc_000310 if {
	input.registry["HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer"]["EnableUserControl"] == 0
}

finding_r_wn11_cc_000310 := {
	"vuln_id": "V-253410",
	"stig_id": "WN11-CC-000310",
	"severity": "CAT II",
	"rule_title": "Users must be prevented from changing installation options.",
	"status": status_r_wn11_cc_000310,
}
status_r_wn11_cc_000310 := "Not_a_Finding" if r_wn11_cc_000310
status_r_wn11_cc_000310 := "Open" if not r_wn11_cc_000310

# WN11-CC-000315 | V-253411 | CAT I
default r_wn11_cc_000315 := false
r_wn11_cc_000315 if {
	input.registry["HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer"]["AlwaysInstallElevated"] == 0
}

finding_r_wn11_cc_000315 := {
	"vuln_id": "V-253411",
	"stig_id": "WN11-CC-000315",
	"severity": "CAT I",
	"rule_title": "The Windows Installer feature \"Always install with elevated privileges\" must be disabled.",
	"status": status_r_wn11_cc_000315,
}
status_r_wn11_cc_000315 := "Not_a_Finding" if r_wn11_cc_000315
status_r_wn11_cc_000315 := "Open" if not r_wn11_cc_000315

# WN11-CC-000325 | V-253413 | CAT II
default r_wn11_cc_000325 := false
r_wn11_cc_000325 if {
	input.registry["HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System"]["DisableAutomaticRestartSignOn"] == 1
}

finding_r_wn11_cc_000325 := {
	"vuln_id": "V-253413",
	"stig_id": "WN11-CC-000325",
	"severity": "CAT II",
	"rule_title": "Automatically signing in the last interactive user after a system-initiated restart must be disabled.",
	"status": status_r_wn11_cc_000325,
}
status_r_wn11_cc_000325 := "Not_a_Finding" if r_wn11_cc_000325
status_r_wn11_cc_000325 := "Open" if not r_wn11_cc_000325

# WN11-CC-000326 | V-253414 | CAT II
default r_wn11_cc_000326 := false
r_wn11_cc_000326 if {
	input.registry["HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging"]["EnableScriptBlockLogging"] == 1
}

finding_r_wn11_cc_000326 := {
	"vuln_id": "V-253414",
	"stig_id": "WN11-CC-000326",
	"severity": "CAT II",
	"rule_title": "PowerShell script block logging must be enabled on Windows 11.",
	"status": status_r_wn11_cc_000326,
}
status_r_wn11_cc_000326 := "Not_a_Finding" if r_wn11_cc_000326
status_r_wn11_cc_000326 := "Open" if not r_wn11_cc_000326

# WN11-CC-000327 | V-253415 | CAT II
default r_wn11_cc_000327 := false
r_wn11_cc_000327 if {
	input.registry["HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\Transcription"]["EnableTranscripting"] == 1
}

finding_r_wn11_cc_000327 := {
	"vuln_id": "V-253415",
	"stig_id": "WN11-CC-000327",
	"severity": "CAT II",
	"rule_title": "PowerShell Transcription must be enabled on Windows 11.",
	"status": status_r_wn11_cc_000327,
}
status_r_wn11_cc_000327 := "Not_a_Finding" if r_wn11_cc_000327
status_r_wn11_cc_000327 := "Open" if not r_wn11_cc_000327

# WN11-CC-000330 | V-253416 | CAT I
default r_wn11_cc_000330 := false
r_wn11_cc_000330 if {
	input.registry["HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\WinRM\\Client"]["AllowBasic"] == 0
}

finding_r_wn11_cc_000330 := {
	"vuln_id": "V-253416",
	"stig_id": "WN11-CC-000330",
	"severity": "CAT I",
	"rule_title": "The Windows Remote Management (WinRM) client must not use Basic authentication.",
	"status": status_r_wn11_cc_000330,
}
status_r_wn11_cc_000330 := "Not_a_Finding" if r_wn11_cc_000330
status_r_wn11_cc_000330 := "Open" if not r_wn11_cc_000330

# WN11-CC-000335 | V-253417 | CAT II
default r_wn11_cc_000335 := false
r_wn11_cc_000335 if {
	input.registry["HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\WinRM\\Client"]["AllowUnencryptedTraffic"] == 0
}

finding_r_wn11_cc_000335 := {
	"vuln_id": "V-253417",
	"stig_id": "WN11-CC-000335",
	"severity": "CAT II",
	"rule_title": "The Windows Remote Management (WinRM) client must not allow unencrypted traffic.",
	"status": status_r_wn11_cc_000335,
}
status_r_wn11_cc_000335 := "Not_a_Finding" if r_wn11_cc_000335
status_r_wn11_cc_000335 := "Open" if not r_wn11_cc_000335

# WN11-CC-000345 | V-253418 | CAT I
default r_wn11_cc_000345 := false
r_wn11_cc_000345 if {
	input.registry["HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\WinRM\\Service"]["AllowBasic"] == 0
}

finding_r_wn11_cc_000345 := {
	"vuln_id": "V-253418",
	"stig_id": "WN11-CC-000345",
	"severity": "CAT I",
	"rule_title": "The Windows Remote Management (WinRM) service must not use Basic authentication.",
	"status": status_r_wn11_cc_000345,
}
status_r_wn11_cc_000345 := "Not_a_Finding" if r_wn11_cc_000345
status_r_wn11_cc_000345 := "Open" if not r_wn11_cc_000345

# WN11-CC-000350 | V-253419 | CAT II
default r_wn11_cc_000350 := false
r_wn11_cc_000350 if {
	input.registry["HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\WinRM\\Service"]["AllowUnencryptedTraffic"] == 0
}

finding_r_wn11_cc_000350 := {
	"vuln_id": "V-253419",
	"stig_id": "WN11-CC-000350",
	"severity": "CAT II",
	"rule_title": "The Windows Remote Management (WinRM) service must not allow unencrypted traffic.",
	"status": status_r_wn11_cc_000350,
}
status_r_wn11_cc_000350 := "Not_a_Finding" if r_wn11_cc_000350
status_r_wn11_cc_000350 := "Open" if not r_wn11_cc_000350

# WN11-CC-000355 | V-253420 | CAT II
default r_wn11_cc_000355 := false
r_wn11_cc_000355 if {
	input.registry["HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\WinRM\\Service"]["DisableRunAs"] == 1
}

finding_r_wn11_cc_000355 := {
	"vuln_id": "V-253420",
	"stig_id": "WN11-CC-000355",
	"severity": "CAT II",
	"rule_title": "The Windows Remote Management (WinRM) service must not store RunAs credentials.",
	"status": status_r_wn11_cc_000355,
}
status_r_wn11_cc_000355 := "Not_a_Finding" if r_wn11_cc_000355
status_r_wn11_cc_000355 := "Open" if not r_wn11_cc_000355

# WN11-CC-000360 | V-253421 | CAT II
default r_wn11_cc_000360 := false
r_wn11_cc_000360 if {
	input.registry["HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\WinRM\\Client"]["AllowDigest"] == 0
}

finding_r_wn11_cc_000360 := {
	"vuln_id": "V-253421",
	"stig_id": "WN11-CC-000360",
	"severity": "CAT II",
	"rule_title": "The Windows Remote Management (WinRM) client must not use Digest authentication.",
	"status": status_r_wn11_cc_000360,
}
status_r_wn11_cc_000360 := "Not_a_Finding" if r_wn11_cc_000360
status_r_wn11_cc_000360 := "Open" if not r_wn11_cc_000360

# WN11-CC-000390 | V-253425 | CAT III
default r_wn11_cc_000390 := false
r_wn11_cc_000390 if {
	input.registry["HKCU\\SOFTWARE\\Policies\\Microsoft\\Windows\\CloudContent"]["DisableThirdPartySuggestions"] == 1
}

finding_r_wn11_cc_000390 := {
	"vuln_id": "V-253425",
	"stig_id": "WN11-CC-000390",
	"severity": "CAT III",
	"rule_title": "Windows 11 must be configured to prevent users from receiving suggestions for third-party or additional applications.",
	"status": status_r_wn11_cc_000390,
}
status_r_wn11_cc_000390 := "Not_a_Finding" if r_wn11_cc_000390
status_r_wn11_cc_000390 := "Open" if not r_wn11_cc_000390

findings := [
	finding_r_wn11_cc_000005,
	finding_r_wn11_cc_000010,
	finding_r_wn11_cc_000020,
	finding_r_wn11_cc_000025,
	finding_r_wn11_cc_000030,
	finding_r_wn11_cc_000035,
	finding_r_wn11_cc_000038,
	finding_r_wn11_cc_000040,
	finding_r_wn11_cc_000044,
	finding_r_wn11_cc_000050,
	finding_r_wn11_cc_000060,
	finding_r_wn11_cc_000066,
	finding_r_wn11_cc_000068,
	finding_r_wn11_cc_000070,
	finding_r_wn11_cc_000075,
	finding_r_wn11_cc_000080,
	finding_r_wn11_cc_000090,
	finding_r_wn11_cc_000100,
	finding_r_wn11_cc_000105,
	finding_r_wn11_cc_000110,
	finding_r_wn11_cc_000120,
	finding_r_wn11_cc_000130,
	finding_r_wn11_cc_000145,
	finding_r_wn11_cc_000150,
	finding_r_wn11_cc_000155,
	finding_r_wn11_cc_000165,
	finding_r_wn11_cc_000170,
	finding_r_wn11_cc_000175,
	finding_r_wn11_cc_000180,
	finding_r_wn11_cc_000185,
	finding_r_wn11_cc_000190,
	finding_r_wn11_cc_000200,
	finding_r_wn11_cc_000204,
	finding_r_wn11_cc_000210,
	finding_r_wn11_cc_000220,
	finding_r_wn11_cc_000255,
	finding_r_wn11_cc_000270,
	finding_r_wn11_cc_000275,
	finding_r_wn11_cc_000280,
	finding_r_wn11_cc_000285,
	finding_r_wn11_cc_000290,
	finding_r_wn11_cc_000295,
	finding_r_wn11_cc_000310,
	finding_r_wn11_cc_000315,
	finding_r_wn11_cc_000325,
	finding_r_wn11_cc_000326,
	finding_r_wn11_cc_000327,
	finding_r_wn11_cc_000330,
	finding_r_wn11_cc_000335,
	finding_r_wn11_cc_000345,
	finding_r_wn11_cc_000350,
	finding_r_wn11_cc_000355,
	finding_r_wn11_cc_000360,
	finding_r_wn11_cc_000390,
]

default compliant := false

compliant if count([f | some f in findings; f.status == "Open"]) == 0
