package stig.windows_server_2025.registry_cc

# DISA STIG — Microsoft Windows Server 2025 Security Technical Implementation Guide
# V1R2 | Release: 2 Benchmark Date: 01 Jul 2026
# Auto-derived registry checks (48 rules) — value expectations
# taken verbatim from the XCCDF check-content (July 2026 library).
# Input contract: input.registry["HKLM\\Path"]["ValueName"] = number|string

import rego.v1

# WN25-CC-000010 | V-278080 | CAT II
default r_wn25_cc_000010 := false
r_wn25_cc_000010 if {
	input.registry["HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\Personalization"]["NoLockScreenSlideshow"] == 1
}

finding_r_wn25_cc_000010 := {
	"vuln_id": "V-278080",
	"stig_id": "WN25-CC-000010",
	"severity": "CAT II",
	"rule_title": "Windows Server 2025 must prevent the display of slide shows on the lock screen.",
	"status": status_r_wn25_cc_000010,
}
status_r_wn25_cc_000010 := "Not_a_Finding" if r_wn25_cc_000010
status_r_wn25_cc_000010 := "Open" if not r_wn25_cc_000010

# WN25-CC-000030 | V-278082 | CAT III
default r_wn25_cc_000030 := false
r_wn25_cc_000030 if {
	input.registry["HKLM\\SYSTEM\\CurrentControlSet\\Services\\Tcpip6\\Parameters"]["DisableIPSourceRouting"] == 2
}

finding_r_wn25_cc_000030 := {
	"vuln_id": "V-278082",
	"stig_id": "WN25-CC-000030",
	"severity": "CAT III",
	"rule_title": "Windows Server 2025 Internet Protocol version 6 (IPv6) source routing must be configured to the highest protection level to prevent IP source routing.",
	"status": status_r_wn25_cc_000030,
}
status_r_wn25_cc_000030 := "Not_a_Finding" if r_wn25_cc_000030
status_r_wn25_cc_000030 := "Open" if not r_wn25_cc_000030

# WN25-CC-000040 | V-278083 | CAT III
default r_wn25_cc_000040 := false
r_wn25_cc_000040 if {
	input.registry["HKLM\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters"]["DisableIPSourceRouting"] == 2
}

finding_r_wn25_cc_000040 := {
	"vuln_id": "V-278083",
	"stig_id": "WN25-CC-000040",
	"severity": "CAT III",
	"rule_title": "Windows Server 2025 source routing must be configured to the highest protection level to prevent Internet Protocol (IP) source routing.",
	"status": status_r_wn25_cc_000040,
}
status_r_wn25_cc_000040 := "Not_a_Finding" if r_wn25_cc_000040
status_r_wn25_cc_000040 := "Open" if not r_wn25_cc_000040

# WN25-CC-000050 | V-278084 | CAT III
default r_wn25_cc_000050 := false
r_wn25_cc_000050 if {
	input.registry["HKLM\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters"]["EnableICMPRedirect"] == 0
}

finding_r_wn25_cc_000050 := {
	"vuln_id": "V-278084",
	"stig_id": "WN25-CC-000050",
	"severity": "CAT III",
	"rule_title": "Windows Server 2025 must be configured to prevent Internet Control Message Protocol (ICMP) redirects from overriding Open Shortest Path First (OSPF)-generated routes.",
	"status": status_r_wn25_cc_000050,
}
status_r_wn25_cc_000050 := "Not_a_Finding" if r_wn25_cc_000050
status_r_wn25_cc_000050 := "Open" if not r_wn25_cc_000050

# WN25-CC-000070 | V-278086 | CAT II
default r_wn25_cc_000070 := false
r_wn25_cc_000070 if {
	input.registry["HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\LanmanWorkstation"]["AllowInsecureGuestAuth"] == 0
}

finding_r_wn25_cc_000070 := {
	"vuln_id": "V-278086",
	"stig_id": "WN25-CC-000070",
	"severity": "CAT II",
	"rule_title": "Windows Server 2025 insecure logons to an SMB server must be disabled.",
	"status": status_r_wn25_cc_000070,
}
status_r_wn25_cc_000070 := "Not_a_Finding" if r_wn25_cc_000070
status_r_wn25_cc_000070 := "Open" if not r_wn25_cc_000070

# WN25-CC-000080 | V-278087 | CAT II
default r_wn25_cc_000080 := false
r_wn25_cc_000080 if {
	input.registry["HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\NetworkProvider\\HardenedPaths"]["\\\\*\\NETLOGON"] == "RequireMutualAuthentication=1, RequireIntegrity=1"
}

finding_r_wn25_cc_000080 := {
	"vuln_id": "V-278087",
	"stig_id": "WN25-CC-000080",
	"severity": "CAT II",
	"rule_title": "Windows Server 2025 hardened Universal Naming Convention (UNC) paths must be defined to require mutual authentication and integrity for at least the \\\\*\\SYSVOL and \\\\*\\NETLOGON shares.",
	"status": status_r_wn25_cc_000080,
}
status_r_wn25_cc_000080 := "Not_a_Finding" if r_wn25_cc_000080
status_r_wn25_cc_000080 := "Open" if not r_wn25_cc_000080

# WN25-CC-000090 | V-278088 | CAT II
default r_wn25_cc_000090 := false
r_wn25_cc_000090 if {
	input.registry["HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\Audit"]["ProcessCreationIncludeCmdLine_Enabled"] == 1
}

finding_r_wn25_cc_000090 := {
	"vuln_id": "V-278088",
	"stig_id": "WN25-CC-000090",
	"severity": "CAT II",
	"rule_title": "Windows Server 2025 command line data must be included in process creation events.",
	"status": status_r_wn25_cc_000090,
}
status_r_wn25_cc_000090 := "Not_a_Finding" if r_wn25_cc_000090
status_r_wn25_cc_000090 := "Open" if not r_wn25_cc_000090

# WN25-CC-000100 | V-278089 | CAT II
default r_wn25_cc_000100 := false
r_wn25_cc_000100 if {
	input.registry["HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\CredentialsDelegation"]["AllowProtectedCreds"] == 1
}

finding_r_wn25_cc_000100 := {
	"vuln_id": "V-278089",
	"stig_id": "WN25-CC-000100",
	"severity": "CAT II",
	"rule_title": "Windows Server 2025 must be configured to enable Remote host allows delegation of nonexportable credentials.",
	"status": status_r_wn25_cc_000100,
}
status_r_wn25_cc_000100 := "Not_a_Finding" if r_wn25_cc_000100
status_r_wn25_cc_000100 := "Open" if not r_wn25_cc_000100

# WN25-CC-000110 | V-278090 | CAT II
default r_wn25_cc_000110 := false
r_wn25_cc_000110 if {
	input.registry["HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\DeviceGuard"]["EnableVirtualizationBasedSecurity"] == 1
}

finding_r_wn25_cc_000110 := {
	"vuln_id": "V-278090",
	"stig_id": "WN25-CC-000110",
	"severity": "CAT II",
	"rule_title": "Windows Server 2025 virtualization-based security must be enabled with the platform security level configured to Secure Boot or Secure Boot with DMA Protection.",
	"status": status_r_wn25_cc_000110,
}
status_r_wn25_cc_000110 := "Not_a_Finding" if r_wn25_cc_000110
status_r_wn25_cc_000110 := "Open" if not r_wn25_cc_000110

# WN25-CC-000130 | V-278091 | CAT II
default r_wn25_cc_000130 := false
r_wn25_cc_000130 if {
	input.registry["HKLM\\SYSTEM\\CurrentControlSet\\Policies\\EarlyLaunch"]["DriverLoadPolicy"] == 1
}

finding_r_wn25_cc_000130 := {
	"vuln_id": "V-278091",
	"stig_id": "WN25-CC-000130",
	"severity": "CAT II",
	"rule_title": "Windows Server 2025 Early Launch Antimalware, Boot-Start Driver Initialization Policy must prevent boot drivers identified as bad.",
	"status": status_r_wn25_cc_000130,
}
status_r_wn25_cc_000130 := "Not_a_Finding" if r_wn25_cc_000130
status_r_wn25_cc_000130 := "Open" if not r_wn25_cc_000130

# WN25-CC-000140 | V-278092 | CAT II
default r_wn25_cc_000140 := false
r_wn25_cc_000140 if {
	input.registry["HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\Group Policy\\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}"]["NoGPOListChanges"] == 0
}

finding_r_wn25_cc_000140 := {
	"vuln_id": "V-278092",
	"stig_id": "WN25-CC-000140",
	"severity": "CAT II",
	"rule_title": "Windows Server 2025 group policy objects must be reprocessed even if they have not changed.",
	"status": status_r_wn25_cc_000140,
}
status_r_wn25_cc_000140 := "Not_a_Finding" if r_wn25_cc_000140
status_r_wn25_cc_000140 := "Open" if not r_wn25_cc_000140

# WN25-CC-000150 | V-278093 | CAT II
default r_wn25_cc_000150 := false
r_wn25_cc_000150 if {
	input.registry["HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Printers"]["DisableWebPnPDownload"] == 1
}

finding_r_wn25_cc_000150 := {
	"vuln_id": "V-278093",
	"stig_id": "WN25-CC-000150",
	"severity": "CAT II",
	"rule_title": "Windows Server 2025 downloading print driver packages over HTTP must be turned off.",
	"status": status_r_wn25_cc_000150,
}
status_r_wn25_cc_000150 := "Not_a_Finding" if r_wn25_cc_000150
status_r_wn25_cc_000150 := "Open" if not r_wn25_cc_000150

# WN25-CC-000160 | V-278094 | CAT II
default r_wn25_cc_000160 := false
r_wn25_cc_000160 if {
	input.registry["HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Printers"]["DisableHTTPPrinting"] == 1
}

finding_r_wn25_cc_000160 := {
	"vuln_id": "V-278094",
	"stig_id": "WN25-CC-000160",
	"severity": "CAT II",
	"rule_title": "Windows Server 2025 printing over HTTP must be turned off.",
	"status": status_r_wn25_cc_000160,
}
status_r_wn25_cc_000160 := "Not_a_Finding" if r_wn25_cc_000160
status_r_wn25_cc_000160 := "Open" if not r_wn25_cc_000160

# WN25-CC-000170 | V-278095 | CAT II
default r_wn25_cc_000170 := false
r_wn25_cc_000170 if {
	input.registry["HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\System"]["DontDisplayNetworkSelectionUI"] == 1
}

finding_r_wn25_cc_000170 := {
	"vuln_id": "V-278095",
	"stig_id": "WN25-CC-000170",
	"severity": "CAT II",
	"rule_title": "Windows Server 2025 network selection user interface (UI) must not be displayed on the logon screen.",
	"status": status_r_wn25_cc_000170,
}
status_r_wn25_cc_000170 := "Not_a_Finding" if r_wn25_cc_000170
status_r_wn25_cc_000170 := "Open" if not r_wn25_cc_000170

# WN25-CC-000180 | V-278096 | CAT II
default r_wn25_cc_000180 := false
r_wn25_cc_000180 if {
	input.registry["HKLM\\SOFTWARE\\Policies\\Microsoft\\Power\\PowerSettings\\0e796bdb-100d-47d6-a2d5-f7d2daa51f51"]["DCSettingIndex"] == 1
}

finding_r_wn25_cc_000180 := {
	"vuln_id": "V-278096",
	"stig_id": "WN25-CC-000180",
	"severity": "CAT II",
	"rule_title": "Windows Server 2025 users must be prompted to authenticate when the system wakes from sleep (on battery).",
	"status": status_r_wn25_cc_000180,
}
status_r_wn25_cc_000180 := "Not_a_Finding" if r_wn25_cc_000180
status_r_wn25_cc_000180 := "Open" if not r_wn25_cc_000180

# WN25-CC-000190 | V-278097 | CAT II
default r_wn25_cc_000190 := false
r_wn25_cc_000190 if {
	input.registry["HKLM\\SOFTWARE\\Policies\\Microsoft\\Power\\PowerSettings\\0e796bdb-100d-47d6-a2d5-f7d2daa51f51"]["ACSettingIndex"] == 1
}

finding_r_wn25_cc_000190 := {
	"vuln_id": "V-278097",
	"stig_id": "WN25-CC-000190",
	"severity": "CAT II",
	"rule_title": "Windows Server 2025 users must be prompted to authenticate when the system wakes from sleep (plugged in).",
	"status": status_r_wn25_cc_000190,
}
status_r_wn25_cc_000190 := "Not_a_Finding" if r_wn25_cc_000190
status_r_wn25_cc_000190 := "Open" if not r_wn25_cc_000190

# WN25-CC-000200 | V-278098 | CAT III
default r_wn25_cc_000200 := false
r_wn25_cc_000200 if {
	input.registry["HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\AppCompat"]["DisableInventory"] == 1
}

finding_r_wn25_cc_000200 := {
	"vuln_id": "V-278098",
	"stig_id": "WN25-CC-000200",
	"severity": "CAT III",
	"rule_title": "Windows Server 2025 Application Compatibility Program Inventory must be prevented from collecting data and sending the information to Microsoft.",
	"status": status_r_wn25_cc_000200,
}
status_r_wn25_cc_000200 := "Not_a_Finding" if r_wn25_cc_000200
status_r_wn25_cc_000200 := "Open" if not r_wn25_cc_000200

# WN25-CC-000210 | V-278099 | CAT I
default r_wn25_cc_000210 := false
r_wn25_cc_000210 if {
	input.registry["HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\Explorer"]["NoAutoplayfornonVolume"] == 1
}

finding_r_wn25_cc_000210 := {
	"vuln_id": "V-278099",
	"stig_id": "WN25-CC-000210",
	"severity": "CAT I",
	"rule_title": "Windows Server 2025 AutoPlay must be turned off for nonvolume devices.",
	"status": status_r_wn25_cc_000210,
}
status_r_wn25_cc_000210 := "Not_a_Finding" if r_wn25_cc_000210
status_r_wn25_cc_000210 := "Open" if not r_wn25_cc_000210

# WN25-CC-000220 | V-278100 | CAT I
default r_wn25_cc_000220 := false
r_wn25_cc_000220 if {
	input.registry["HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer"]["NoAutorun"] == 1
}

finding_r_wn25_cc_000220 := {
	"vuln_id": "V-278100",
	"stig_id": "WN25-CC-000220",
	"severity": "CAT I",
	"rule_title": "Windows Server 2025 default AutoRun behavior must be configured to prevent AutoRun commands.",
	"status": status_r_wn25_cc_000220,
}
status_r_wn25_cc_000220 := "Not_a_Finding" if r_wn25_cc_000220
status_r_wn25_cc_000220 := "Open" if not r_wn25_cc_000220

# WN25-CC-000240 | V-278102 | CAT II
default r_wn25_cc_000240 := false
r_wn25_cc_000240 if {
	input.registry["HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\CredUI"]["EnumerateAdministrators"] == 0
}

finding_r_wn25_cc_000240 := {
	"vuln_id": "V-278102",
	"stig_id": "WN25-CC-000240",
	"severity": "CAT II",
	"rule_title": "Windows Server 2025 administrator accounts must not be enumerated during elevation.",
	"status": status_r_wn25_cc_000240,
}
status_r_wn25_cc_000240 := "Not_a_Finding" if r_wn25_cc_000240
status_r_wn25_cc_000240 := "Open" if not r_wn25_cc_000240

# WN25-CC-000260 | V-278104 | CAT III
default r_wn25_cc_000260 := false
r_wn25_cc_000260 if {
	input.registry["HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\DeliveryOptimization"]["DODownloadMode"] == 0
}

finding_r_wn25_cc_000260 := {
	"vuln_id": "V-278104",
	"stig_id": "WN25-CC-000260",
	"severity": "CAT III",
	"rule_title": "Windows Server 2025 Windows Update must not obtain updates from other PCs on the internet.",
	"status": status_r_wn25_cc_000260,
}
status_r_wn25_cc_000260 := "Not_a_Finding" if r_wn25_cc_000260
status_r_wn25_cc_000260 := "Open" if not r_wn25_cc_000260

# WN25-CC-000270 | V-278105 | CAT II
default r_wn25_cc_000270 := false
r_wn25_cc_000270 if {
	input.registry["HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\EventLog\\Application"]["MaxSize"] >= 32768
}

finding_r_wn25_cc_000270 := {
	"vuln_id": "V-278105",
	"stig_id": "WN25-CC-000270",
	"severity": "CAT II",
	"rule_title": "Windows Server 2025 Application event log size must be configured to 32768 KB or greater.",
	"status": status_r_wn25_cc_000270,
}
status_r_wn25_cc_000270 := "Not_a_Finding" if r_wn25_cc_000270
status_r_wn25_cc_000270 := "Open" if not r_wn25_cc_000270

# WN25-CC-000280 | V-278106 | CAT II
default r_wn25_cc_000280 := false
r_wn25_cc_000280 if {
	input.registry["HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\EventLog\\Security"]["MaxSize"] >= 5120000
}

finding_r_wn25_cc_000280 := {
	"vuln_id": "V-278106",
	"stig_id": "WN25-CC-000280",
	"severity": "CAT II",
	"rule_title": "Windows Server 2025 Security event log size must be configured to a value that holds at least one week of audit records.",
	"status": status_r_wn25_cc_000280,
}
status_r_wn25_cc_000280 := "Not_a_Finding" if r_wn25_cc_000280
status_r_wn25_cc_000280 := "Open" if not r_wn25_cc_000280

# WN25-CC-000290 | V-278107 | CAT II
default r_wn25_cc_000290 := false
r_wn25_cc_000290 if {
	input.registry["HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\EventLog\\System"]["MaxSize"] >= 32768
}

finding_r_wn25_cc_000290 := {
	"vuln_id": "V-278107",
	"stig_id": "WN25-CC-000290",
	"severity": "CAT II",
	"rule_title": "Windows Server 2025 System event log size must be configured to 32768 KB or greater.",
	"status": status_r_wn25_cc_000290,
}
status_r_wn25_cc_000290 := "Not_a_Finding" if r_wn25_cc_000290
status_r_wn25_cc_000290 := "Open" if not r_wn25_cc_000290

# WN25-CC-000300 | V-278108 | CAT II
default r_wn25_cc_000300 := false
r_wn25_cc_000300 if {
	input.registry["HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\System"]["EnableSmartScreen"] == 1
}

finding_r_wn25_cc_000300 := {
	"vuln_id": "V-278108",
	"stig_id": "WN25-CC-000300",
	"severity": "CAT II",
	"rule_title": "Windows Server 2025 Microsoft Defender antivirus SmartScreen must be enabled.",
	"status": status_r_wn25_cc_000300,
}
status_r_wn25_cc_000300 := "Not_a_Finding" if r_wn25_cc_000300
status_r_wn25_cc_000300 := "Open" if not r_wn25_cc_000300

# WN25-CC-000310 | V-278109 | CAT II
default r_wn25_cc_000310 := false
r_wn25_cc_000310 if {
	input.registry["HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\Explorer"]["NoDataExecutionPrevention"] == 0
}

finding_r_wn25_cc_000310 := {
	"vuln_id": "V-278109",
	"stig_id": "WN25-CC-000310",
	"severity": "CAT II",
	"rule_title": "Windows Server 2025 Explorer Data Execution Prevention must be enabled.",
	"status": status_r_wn25_cc_000310,
}
status_r_wn25_cc_000310 := "Not_a_Finding" if r_wn25_cc_000310
status_r_wn25_cc_000310 := "Open" if not r_wn25_cc_000310

# WN25-CC-000320 | V-278110 | CAT III
default r_wn25_cc_000320 := false
r_wn25_cc_000320 if {
	input.registry["HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\Explorer"]["NoHeapTerminationOnCorruption"] == 0
}

finding_r_wn25_cc_000320 := {
	"vuln_id": "V-278110",
	"stig_id": "WN25-CC-000320",
	"severity": "CAT III",
	"rule_title": "Windows Server 2025 Turning off File Explorer heap termination on corruption must be disabled.",
	"status": status_r_wn25_cc_000320,
}
status_r_wn25_cc_000320 := "Not_a_Finding" if r_wn25_cc_000320
status_r_wn25_cc_000320 := "Open" if not r_wn25_cc_000320

# WN25-CC-000330 | V-278111 | CAT II
default r_wn25_cc_000330 := false
r_wn25_cc_000330 if {
	input.registry["HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer"]["PreXPSP2ShellProtocolBehavior"] == 0
}

finding_r_wn25_cc_000330 := {
	"vuln_id": "V-278111",
	"stig_id": "WN25-CC-000330",
	"severity": "CAT II",
	"rule_title": "Windows Server 2025 File Explorer shell protocol must run in protected mode.",
	"status": status_r_wn25_cc_000330,
}
status_r_wn25_cc_000330 := "Not_a_Finding" if r_wn25_cc_000330
status_r_wn25_cc_000330 := "Open" if not r_wn25_cc_000330

# WN25-CC-000340 | V-278112 | CAT II
default r_wn25_cc_000340 := false
r_wn25_cc_000340 if {
	input.registry["HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services"]["DisablePasswordSaving"] == 1
}

finding_r_wn25_cc_000340 := {
	"vuln_id": "V-278112",
	"stig_id": "WN25-CC-000340",
	"severity": "CAT II",
	"rule_title": "Windows Server 2025 must not save passwords in the Remote Desktop Client.",
	"status": status_r_wn25_cc_000340,
}
status_r_wn25_cc_000340 := "Not_a_Finding" if r_wn25_cc_000340
status_r_wn25_cc_000340 := "Open" if not r_wn25_cc_000340

# WN25-CC-000350 | V-278113 | CAT II
default r_wn25_cc_000350 := false
r_wn25_cc_000350 if {
	input.registry["HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services"]["fDisableCdm"] == 1
}

finding_r_wn25_cc_000350 := {
	"vuln_id": "V-278113",
	"stig_id": "WN25-CC-000350",
	"severity": "CAT II",
	"rule_title": "Windows Server 2025 Remote Desktop Services must prevent drive redirection.",
	"status": status_r_wn25_cc_000350,
}
status_r_wn25_cc_000350 := "Not_a_Finding" if r_wn25_cc_000350
status_r_wn25_cc_000350 := "Open" if not r_wn25_cc_000350

# WN25-CC-000360 | V-278114 | CAT II
default r_wn25_cc_000360 := false
r_wn25_cc_000360 if {
	input.registry["HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services"]["fPromptForPassword"] == 1
}

finding_r_wn25_cc_000360 := {
	"vuln_id": "V-278114",
	"stig_id": "WN25-CC-000360",
	"severity": "CAT II",
	"rule_title": "Windows Server 2025 Remote Desktop Services must always prompt a client for passwords upon connection.",
	"status": status_r_wn25_cc_000360,
}
status_r_wn25_cc_000360 := "Not_a_Finding" if r_wn25_cc_000360
status_r_wn25_cc_000360 := "Open" if not r_wn25_cc_000360

# WN25-CC-000370 | V-278115 | CAT II
default r_wn25_cc_000370 := false
r_wn25_cc_000370 if {
	input.registry["HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services"]["fEncryptRPCTraffic"] == 1
}

finding_r_wn25_cc_000370 := {
	"vuln_id": "V-278115",
	"stig_id": "WN25-CC-000370",
	"severity": "CAT II",
	"rule_title": "Windows Server 2025 Remote Desktop Services must require secure Remote Procedure Call (RPC) communications.",
	"status": status_r_wn25_cc_000370,
}
status_r_wn25_cc_000370 := "Not_a_Finding" if r_wn25_cc_000370
status_r_wn25_cc_000370 := "Open" if not r_wn25_cc_000370

# WN25-CC-000380 | V-278116 | CAT II
default r_wn25_cc_000380 := false
r_wn25_cc_000380 if {
	input.registry["HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services"]["MinEncryptionLevel"] == 3
}

finding_r_wn25_cc_000380 := {
	"vuln_id": "V-278116",
	"stig_id": "WN25-CC-000380",
	"severity": "CAT II",
	"rule_title": "Windows Server 2025 Remote Desktop Services must be configured with the client connection encryption set to High Level.",
	"status": status_r_wn25_cc_000380,
}
status_r_wn25_cc_000380 := "Not_a_Finding" if r_wn25_cc_000380
status_r_wn25_cc_000380 := "Open" if not r_wn25_cc_000380

# WN25-CC-000390 | V-278117 | CAT II
default r_wn25_cc_000390 := false
r_wn25_cc_000390 if {
	input.registry["HKLM\\SOFTWARE\\Policies\\Microsoft\\Internet Explorer\\Feeds"]["DisableEnclosureDownload"] == 1
}

finding_r_wn25_cc_000390 := {
	"vuln_id": "V-278117",
	"stig_id": "WN25-CC-000390",
	"severity": "CAT II",
	"rule_title": "Windows Server 2025 must prevent attachments from being downloaded from RSS feeds.",
	"status": status_r_wn25_cc_000390,
}
status_r_wn25_cc_000390 := "Not_a_Finding" if r_wn25_cc_000390
status_r_wn25_cc_000390 := "Open" if not r_wn25_cc_000390

# WN25-CC-000400 | V-278118 | CAT II
default r_wn25_cc_000400 := false
r_wn25_cc_000400 if {
	input.registry["HKLM\\SOFTWARE\\Policies\\Microsoft\\Internet Explorer\\Feeds"]["AllowBasicAuthInClear"] == 0
}

finding_r_wn25_cc_000400 := {
	"vuln_id": "V-278118",
	"stig_id": "WN25-CC-000400",
	"severity": "CAT II",
	"rule_title": "Windows Server 2025 must disable Basic authentication for RSS feeds over HTTP.",
	"status": status_r_wn25_cc_000400,
}
status_r_wn25_cc_000400 := "Not_a_Finding" if r_wn25_cc_000400
status_r_wn25_cc_000400 := "Open" if not r_wn25_cc_000400

# WN25-CC-000410 | V-278119 | CAT II
default r_wn25_cc_000410 := false
r_wn25_cc_000410 if {
	input.registry["HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\Windows Search"]["AllowIndexingEncryptedStoresOrItems"] == 0
}

finding_r_wn25_cc_000410 := {
	"vuln_id": "V-278119",
	"stig_id": "WN25-CC-000410",
	"severity": "CAT II",
	"rule_title": "Windows Server 2025 must prevent Indexing of encrypted files.",
	"status": status_r_wn25_cc_000410,
}
status_r_wn25_cc_000410 := "Not_a_Finding" if r_wn25_cc_000410
status_r_wn25_cc_000410 := "Open" if not r_wn25_cc_000410

# WN25-CC-000420 | V-278120 | CAT II
default r_wn25_cc_000420 := false
r_wn25_cc_000420 if {
	input.registry["HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer"]["EnableUserControl"] == 0
}

finding_r_wn25_cc_000420 := {
	"vuln_id": "V-278120",
	"stig_id": "WN25-CC-000420",
	"severity": "CAT II",
	"rule_title": "Windows Server 2025 must prevent users from changing installation options.",
	"status": status_r_wn25_cc_000420,
}
status_r_wn25_cc_000420 := "Not_a_Finding" if r_wn25_cc_000420
status_r_wn25_cc_000420 := "Open" if not r_wn25_cc_000420

# WN25-CC-000430 | V-278121 | CAT I
default r_wn25_cc_000430 := false
r_wn25_cc_000430 if {
	input.registry["HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer"]["AlwaysInstallElevated"] == 0
}

finding_r_wn25_cc_000430 := {
	"vuln_id": "V-278121",
	"stig_id": "WN25-CC-000430",
	"severity": "CAT I",
	"rule_title": "Windows Server 2025 must disable the Windows Installer Always install with elevated privileges option.",
	"status": status_r_wn25_cc_000430,
}
status_r_wn25_cc_000430 := "Not_a_Finding" if r_wn25_cc_000430
status_r_wn25_cc_000430 := "Open" if not r_wn25_cc_000430

# WN25-CC-000440 | V-278122 | CAT II
default r_wn25_cc_000440 := false
r_wn25_cc_000440 if {
	input.registry["HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer"]["SafeForScripting"] == 0
}

finding_r_wn25_cc_000440 := {
	"vuln_id": "V-278122",
	"stig_id": "WN25-CC-000440",
	"severity": "CAT II",
	"rule_title": "Windows Server 2025 users must be notified if a web-based program attempts to install software.",
	"status": status_r_wn25_cc_000440,
}
status_r_wn25_cc_000440 := "Not_a_Finding" if r_wn25_cc_000440
status_r_wn25_cc_000440 := "Open" if not r_wn25_cc_000440

# WN25-CC-000450 | V-278123 | CAT II
default r_wn25_cc_000450 := false
r_wn25_cc_000450 if {
	input.registry["HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System"]["DisableAutomaticRestartSignOn"] == 1
}

finding_r_wn25_cc_000450 := {
	"vuln_id": "V-278123",
	"stig_id": "WN25-CC-000450",
	"severity": "CAT II",
	"rule_title": "Windows Server 2025 must disable automatically signing in the last interactive user after a system-initiated restart.",
	"status": status_r_wn25_cc_000450,
}
status_r_wn25_cc_000450 := "Not_a_Finding" if r_wn25_cc_000450
status_r_wn25_cc_000450 := "Open" if not r_wn25_cc_000450

# WN25-CC-000460 | V-278124 | CAT II
default r_wn25_cc_000460 := false
r_wn25_cc_000460 if {
	input.registry["HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging"]["EnableScriptBlockLogging"] == 1
}

finding_r_wn25_cc_000460 := {
	"vuln_id": "V-278124",
	"stig_id": "WN25-CC-000460",
	"severity": "CAT II",
	"rule_title": "Windows Server 2025 PowerShell script block logging must be enabled.",
	"status": status_r_wn25_cc_000460,
}
status_r_wn25_cc_000460 := "Not_a_Finding" if r_wn25_cc_000460
status_r_wn25_cc_000460 := "Open" if not r_wn25_cc_000460

# WN25-CC-000470 | V-278125 | CAT I
default r_wn25_cc_000470 := false
r_wn25_cc_000470 if {
	input.registry["HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\WinRM\\Client"]["AllowBasic"] == 0
}

finding_r_wn25_cc_000470 := {
	"vuln_id": "V-278125",
	"stig_id": "WN25-CC-000470",
	"severity": "CAT I",
	"rule_title": "Windows Server 2025 Windows Remote Management (WinRM) client must not use Basic authentication.",
	"status": status_r_wn25_cc_000470,
}
status_r_wn25_cc_000470 := "Not_a_Finding" if r_wn25_cc_000470
status_r_wn25_cc_000470 := "Open" if not r_wn25_cc_000470

# WN25-CC-000480 | V-278126 | CAT II
default r_wn25_cc_000480 := false
r_wn25_cc_000480 if {
	input.registry["HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\WinRM\\Client"]["AllowUnencryptedTraffic"] == 0
}

finding_r_wn25_cc_000480 := {
	"vuln_id": "V-278126",
	"stig_id": "WN25-CC-000480",
	"severity": "CAT II",
	"rule_title": "Windows Server 2025 Windows Remote Management (WinRM) client must not allow unencrypted traffic.",
	"status": status_r_wn25_cc_000480,
}
status_r_wn25_cc_000480 := "Not_a_Finding" if r_wn25_cc_000480
status_r_wn25_cc_000480 := "Open" if not r_wn25_cc_000480

# WN25-CC-000490 | V-278127 | CAT II
default r_wn25_cc_000490 := false
r_wn25_cc_000490 if {
	input.registry["HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\WinRM\\Client"]["AllowDigest"] == 0
}

finding_r_wn25_cc_000490 := {
	"vuln_id": "V-278127",
	"stig_id": "WN25-CC-000490",
	"severity": "CAT II",
	"rule_title": "Windows Server 2025 Windows Remote Management (WinRM) client must not use Digest authentication.",
	"status": status_r_wn25_cc_000490,
}
status_r_wn25_cc_000490 := "Not_a_Finding" if r_wn25_cc_000490
status_r_wn25_cc_000490 := "Open" if not r_wn25_cc_000490

# WN25-CC-000500 | V-278128 | CAT I
default r_wn25_cc_000500 := false
r_wn25_cc_000500 if {
	input.registry["HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\WinRM\\Service"]["AllowBasic"] == 0
}

finding_r_wn25_cc_000500 := {
	"vuln_id": "V-278128",
	"stig_id": "WN25-CC-000500",
	"severity": "CAT I",
	"rule_title": "Windows Server 2025 Windows Remote Management (WinRM) service must not use Basic authentication.",
	"status": status_r_wn25_cc_000500,
}
status_r_wn25_cc_000500 := "Not_a_Finding" if r_wn25_cc_000500
status_r_wn25_cc_000500 := "Open" if not r_wn25_cc_000500

# WN25-CC-000510 | V-278129 | CAT II
default r_wn25_cc_000510 := false
r_wn25_cc_000510 if {
	input.registry["HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\WinRM\\Service"]["AllowUnencryptedTraffic"] == 0
}

finding_r_wn25_cc_000510 := {
	"vuln_id": "V-278129",
	"stig_id": "WN25-CC-000510",
	"severity": "CAT II",
	"rule_title": "Windows Server 2025 Windows Remote Management (WinRM) service must not allow unencrypted traffic.",
	"status": status_r_wn25_cc_000510,
}
status_r_wn25_cc_000510 := "Not_a_Finding" if r_wn25_cc_000510
status_r_wn25_cc_000510 := "Open" if not r_wn25_cc_000510

# WN25-CC-000520 | V-278130 | CAT II
default r_wn25_cc_000520 := false
r_wn25_cc_000520 if {
	input.registry["HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\WinRM\\Service"]["DisableRunAs"] == 1
}

finding_r_wn25_cc_000520 := {
	"vuln_id": "V-278130",
	"stig_id": "WN25-CC-000520",
	"severity": "CAT II",
	"rule_title": "Windows Server 2025 Windows Remote Management (WinRM) service must not store RunAs credentials.",
	"status": status_r_wn25_cc_000520,
}
status_r_wn25_cc_000520 := "Not_a_Finding" if r_wn25_cc_000520
status_r_wn25_cc_000520 := "Open" if not r_wn25_cc_000520

# WN25-CC-000530 | V-278131 | CAT II
default r_wn25_cc_000530 := false
r_wn25_cc_000530 if {
	input.registry["HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\Transcription"]["EnableTranscripting"] == 1
}

finding_r_wn25_cc_000530 := {
	"vuln_id": "V-278131",
	"stig_id": "WN25-CC-000530",
	"severity": "CAT II",
	"rule_title": "Windows Server 2025 must have PowerShell Transcription enabled.",
	"status": status_r_wn25_cc_000530,
}
status_r_wn25_cc_000530 := "Not_a_Finding" if r_wn25_cc_000530
status_r_wn25_cc_000530 := "Open" if not r_wn25_cc_000530

findings := [
	finding_r_wn25_cc_000010,
	finding_r_wn25_cc_000030,
	finding_r_wn25_cc_000040,
	finding_r_wn25_cc_000050,
	finding_r_wn25_cc_000070,
	finding_r_wn25_cc_000080,
	finding_r_wn25_cc_000090,
	finding_r_wn25_cc_000100,
	finding_r_wn25_cc_000110,
	finding_r_wn25_cc_000130,
	finding_r_wn25_cc_000140,
	finding_r_wn25_cc_000150,
	finding_r_wn25_cc_000160,
	finding_r_wn25_cc_000170,
	finding_r_wn25_cc_000180,
	finding_r_wn25_cc_000190,
	finding_r_wn25_cc_000200,
	finding_r_wn25_cc_000210,
	finding_r_wn25_cc_000220,
	finding_r_wn25_cc_000240,
	finding_r_wn25_cc_000260,
	finding_r_wn25_cc_000270,
	finding_r_wn25_cc_000280,
	finding_r_wn25_cc_000290,
	finding_r_wn25_cc_000300,
	finding_r_wn25_cc_000310,
	finding_r_wn25_cc_000320,
	finding_r_wn25_cc_000330,
	finding_r_wn25_cc_000340,
	finding_r_wn25_cc_000350,
	finding_r_wn25_cc_000360,
	finding_r_wn25_cc_000370,
	finding_r_wn25_cc_000380,
	finding_r_wn25_cc_000390,
	finding_r_wn25_cc_000400,
	finding_r_wn25_cc_000410,
	finding_r_wn25_cc_000420,
	finding_r_wn25_cc_000430,
	finding_r_wn25_cc_000440,
	finding_r_wn25_cc_000450,
	finding_r_wn25_cc_000460,
	finding_r_wn25_cc_000470,
	finding_r_wn25_cc_000480,
	finding_r_wn25_cc_000490,
	finding_r_wn25_cc_000500,
	finding_r_wn25_cc_000510,
	finding_r_wn25_cc_000520,
	finding_r_wn25_cc_000530,
]

default compliant := false

compliant if count([f | some f in findings; f.status == "Open"]) == 0
