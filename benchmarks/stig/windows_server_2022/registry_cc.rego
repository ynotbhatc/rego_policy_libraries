package stig.windows_server_2022.registry_cc

# DISA STIG — Microsoft Windows Server 2022 Security Technical Implementation Guide
# V2R9 | Release: 9 Benchmark Date: 01 Jul 2026
# Auto-derived registry checks (52 rules) — value expectations
# taken verbatim from the XCCDF check-content (July 2026 library).
# Input contract: input.registry["HKLM\\Path"]["ValueName"] = number|string

import rego.v1

# WN22-CC-000010 | V-254333 | CAT II
default r_wn22_cc_000010 := false
r_wn22_cc_000010 if {
	input.registry["HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\Personalization"]["NoLockScreenSlideshow"] == 1
}

finding_r_wn22_cc_000010 := {
	"vuln_id": "V-254333",
	"stig_id": "WN22-CC-000010",
	"severity": "CAT II",
	"rule_title": "Windows Server 2022 must prevent the display of slide shows on the lock screen.",
	"status": status_r_wn22_cc_000010,
}
status_r_wn22_cc_000010 := "Not_a_Finding" if r_wn22_cc_000010
status_r_wn22_cc_000010 := "Open" if not r_wn22_cc_000010

# WN22-CC-000020 | V-254334 | CAT II
default r_wn22_cc_000020 := false
r_wn22_cc_000020 if {
	input.registry["HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\Wdigest"]["UseLogonCredential"] == 0
}

finding_r_wn22_cc_000020 := {
	"vuln_id": "V-254334",
	"stig_id": "WN22-CC-000020",
	"severity": "CAT II",
	"rule_title": "Windows Server 2022 must have WDigest Authentication disabled.",
	"status": status_r_wn22_cc_000020,
}
status_r_wn22_cc_000020 := "Not_a_Finding" if r_wn22_cc_000020
status_r_wn22_cc_000020 := "Open" if not r_wn22_cc_000020

# WN22-CC-000030 | V-254335 | CAT III
default r_wn22_cc_000030 := false
r_wn22_cc_000030 if {
	input.registry["HKLM\\SYSTEM\\CurrentControlSet\\Services\\Tcpip6\\Parameters"]["DisableIPSourceRouting"] == 2
}

finding_r_wn22_cc_000030 := {
	"vuln_id": "V-254335",
	"stig_id": "WN22-CC-000030",
	"severity": "CAT III",
	"rule_title": "Windows Server 2022 Internet Protocol version 6 (IPv6) source routing must be configured to the highest protection level to prevent IP source routing.",
	"status": status_r_wn22_cc_000030,
}
status_r_wn22_cc_000030 := "Not_a_Finding" if r_wn22_cc_000030
status_r_wn22_cc_000030 := "Open" if not r_wn22_cc_000030

# WN22-CC-000040 | V-254336 | CAT III
default r_wn22_cc_000040 := false
r_wn22_cc_000040 if {
	input.registry["HKLM\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters"]["DisableIPSourceRouting"] == 2
}

finding_r_wn22_cc_000040 := {
	"vuln_id": "V-254336",
	"stig_id": "WN22-CC-000040",
	"severity": "CAT III",
	"rule_title": "Windows Server 2022 source routing must be configured to the highest protection level to prevent Internet Protocol (IP) source routing.",
	"status": status_r_wn22_cc_000040,
}
status_r_wn22_cc_000040 := "Not_a_Finding" if r_wn22_cc_000040
status_r_wn22_cc_000040 := "Open" if not r_wn22_cc_000040

# WN22-CC-000050 | V-254337 | CAT III
default r_wn22_cc_000050 := false
r_wn22_cc_000050 if {
	input.registry["HKLM\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters"]["EnableICMPRedirect"] == 0
}

finding_r_wn22_cc_000050 := {
	"vuln_id": "V-254337",
	"stig_id": "WN22-CC-000050",
	"severity": "CAT III",
	"rule_title": "Windows Server 2022 must be configured to prevent Internet Control Message Protocol (ICMP) redirects from overriding Open Shortest Path First (OSPF)-generated routes.",
	"status": status_r_wn22_cc_000050,
}
status_r_wn22_cc_000050 := "Not_a_Finding" if r_wn22_cc_000050
status_r_wn22_cc_000050 := "Open" if not r_wn22_cc_000050

# WN22-CC-000060 | V-254338 | CAT III
default r_wn22_cc_000060 := false
r_wn22_cc_000060 if {
	input.registry["HKLM\\SYSTEM\\CurrentControlSet\\Services\\Netbt\\Parameters"]["NoNameReleaseOnDemand"] == 1
}

finding_r_wn22_cc_000060 := {
	"vuln_id": "V-254338",
	"stig_id": "WN22-CC-000060",
	"severity": "CAT III",
	"rule_title": "Windows Server 2022 must be configured to ignore NetBIOS name release requests except from WINS servers.",
	"status": status_r_wn22_cc_000060,
}
status_r_wn22_cc_000060 := "Not_a_Finding" if r_wn22_cc_000060
status_r_wn22_cc_000060 := "Open" if not r_wn22_cc_000060

# WN22-CC-000070 | V-254339 | CAT II
default r_wn22_cc_000070 := false
r_wn22_cc_000070 if {
	input.registry["HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\LanmanWorkstation"]["AllowInsecureGuestAuth"] == 0
}

finding_r_wn22_cc_000070 := {
	"vuln_id": "V-254339",
	"stig_id": "WN22-CC-000070",
	"severity": "CAT II",
	"rule_title": "Windows Server 2022 insecure logons to an SMB server must be disabled.",
	"status": status_r_wn22_cc_000070,
}
status_r_wn22_cc_000070 := "Not_a_Finding" if r_wn22_cc_000070
status_r_wn22_cc_000070 := "Open" if not r_wn22_cc_000070

# WN22-CC-000080 | V-254340 | CAT II
default r_wn22_cc_000080 := false
r_wn22_cc_000080 if {
	input.registry["HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\NetworkProvider\\HardenedPaths"]["\\\\*\\NETLOGON"] == "RequireMutualAuthentication=1, RequireIntegrity=1"
}

finding_r_wn22_cc_000080 := {
	"vuln_id": "V-254340",
	"stig_id": "WN22-CC-000080",
	"severity": "CAT II",
	"rule_title": "Windows Server 2022 hardened Universal Naming Convention (UNC) paths must be defined to require mutual authentication and integrity for at least the \\\\*\\SYSVOL and \\\\*\\NETLOGON shares.",
	"status": status_r_wn22_cc_000080,
}
status_r_wn22_cc_000080 := "Not_a_Finding" if r_wn22_cc_000080
status_r_wn22_cc_000080 := "Open" if not r_wn22_cc_000080

# WN22-CC-000090 | V-254341 | CAT II
default r_wn22_cc_000090 := false
r_wn22_cc_000090 if {
	input.registry["HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\Audit"]["ProcessCreationIncludeCmdLine_Enabled"] == 1
}

finding_r_wn22_cc_000090 := {
	"vuln_id": "V-254341",
	"stig_id": "WN22-CC-000090",
	"severity": "CAT II",
	"rule_title": "Windows Server 2022 command line data must be included in process creation events.",
	"status": status_r_wn22_cc_000090,
}
status_r_wn22_cc_000090 := "Not_a_Finding" if r_wn22_cc_000090
status_r_wn22_cc_000090 := "Open" if not r_wn22_cc_000090

# WN22-CC-000100 | V-254342 | CAT II
default r_wn22_cc_000100 := false
r_wn22_cc_000100 if {
	input.registry["HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\CredentialsDelegation"]["AllowProtectedCreds"] == 1
}

finding_r_wn22_cc_000100 := {
	"vuln_id": "V-254342",
	"stig_id": "WN22-CC-000100",
	"severity": "CAT II",
	"rule_title": "Windows Server 2022 must be configured to enable Remote host allows delegation of nonexportable credentials.",
	"status": status_r_wn22_cc_000100,
}
status_r_wn22_cc_000100 := "Not_a_Finding" if r_wn22_cc_000100
status_r_wn22_cc_000100 := "Open" if not r_wn22_cc_000100

# WN22-CC-000110 | V-254343 | CAT II
default r_wn22_cc_000110 := false
r_wn22_cc_000110 if {
	input.registry["HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\DeviceGuard"]["EnableVirtualizationBasedSecurity"] == 1
}

finding_r_wn22_cc_000110 := {
	"vuln_id": "V-254343",
	"stig_id": "WN22-CC-000110",
	"severity": "CAT II",
	"rule_title": "Windows Server 2022 virtualization-based security must be enabled with the platform security level configured to Secure Boot or Secure Boot with DMA Protection.",
	"status": status_r_wn22_cc_000110,
}
status_r_wn22_cc_000110 := "Not_a_Finding" if r_wn22_cc_000110
status_r_wn22_cc_000110 := "Open" if not r_wn22_cc_000110

# WN22-CC-000130 | V-254344 | CAT II
default r_wn22_cc_000130 := false
r_wn22_cc_000130 if {
	input.registry["HKLM\\SYSTEM\\CurrentControlSet\\Policies\\EarlyLaunch"]["DriverLoadPolicy"] == 1
}

finding_r_wn22_cc_000130 := {
	"vuln_id": "V-254344",
	"stig_id": "WN22-CC-000130",
	"severity": "CAT II",
	"rule_title": "Windows Server 2022 Early Launch Antimalware, Boot-Start Driver Initialization Policy must prevent boot drivers identified as bad.",
	"status": status_r_wn22_cc_000130,
}
status_r_wn22_cc_000130 := "Not_a_Finding" if r_wn22_cc_000130
status_r_wn22_cc_000130 := "Open" if not r_wn22_cc_000130

# WN22-CC-000140 | V-254345 | CAT II
default r_wn22_cc_000140 := false
r_wn22_cc_000140 if {
	input.registry["HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\Group Policy\\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}"]["NoGPOListChanges"] == 0
}

finding_r_wn22_cc_000140 := {
	"vuln_id": "V-254345",
	"stig_id": "WN22-CC-000140",
	"severity": "CAT II",
	"rule_title": "Windows Server 2022 group policy objects must be reprocessed even if they have not changed.",
	"status": status_r_wn22_cc_000140,
}
status_r_wn22_cc_000140 := "Not_a_Finding" if r_wn22_cc_000140
status_r_wn22_cc_000140 := "Open" if not r_wn22_cc_000140

# WN22-CC-000150 | V-254346 | CAT II
default r_wn22_cc_000150 := false
r_wn22_cc_000150 if {
	input.registry["HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Printers"]["DisableWebPnPDownload"] == 1
}

finding_r_wn22_cc_000150 := {
	"vuln_id": "V-254346",
	"stig_id": "WN22-CC-000150",
	"severity": "CAT II",
	"rule_title": "Windows Server 2022 downloading print driver packages over HTTP must be turned off.",
	"status": status_r_wn22_cc_000150,
}
status_r_wn22_cc_000150 := "Not_a_Finding" if r_wn22_cc_000150
status_r_wn22_cc_000150 := "Open" if not r_wn22_cc_000150

# WN22-CC-000160 | V-254347 | CAT II
default r_wn22_cc_000160 := false
r_wn22_cc_000160 if {
	input.registry["HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Printers"]["DisableHTTPPrinting"] == 1
}

finding_r_wn22_cc_000160 := {
	"vuln_id": "V-254347",
	"stig_id": "WN22-CC-000160",
	"severity": "CAT II",
	"rule_title": "Windows Server 2022 printing over HTTP must be turned off.",
	"status": status_r_wn22_cc_000160,
}
status_r_wn22_cc_000160 := "Not_a_Finding" if r_wn22_cc_000160
status_r_wn22_cc_000160 := "Open" if not r_wn22_cc_000160

# WN22-CC-000170 | V-254348 | CAT II
default r_wn22_cc_000170 := false
r_wn22_cc_000170 if {
	input.registry["HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\System"]["DontDisplayNetworkSelectionUI"] == 1
}

finding_r_wn22_cc_000170 := {
	"vuln_id": "V-254348",
	"stig_id": "WN22-CC-000170",
	"severity": "CAT II",
	"rule_title": "Windows Server 2022 network selection user interface (UI) must not be displayed on the logon screen.",
	"status": status_r_wn22_cc_000170,
}
status_r_wn22_cc_000170 := "Not_a_Finding" if r_wn22_cc_000170
status_r_wn22_cc_000170 := "Open" if not r_wn22_cc_000170

# WN22-CC-000180 | V-254349 | CAT II
default r_wn22_cc_000180 := false
r_wn22_cc_000180 if {
	input.registry["HKLM\\SOFTWARE\\Policies\\Microsoft\\Power\\PowerSettings\\0e796bdb-100d-47d6-a2d5-f7d2daa51f51"]["DCSettingIndex"] == 1
}

finding_r_wn22_cc_000180 := {
	"vuln_id": "V-254349",
	"stig_id": "WN22-CC-000180",
	"severity": "CAT II",
	"rule_title": "Windows Server 2022 users must be prompted to authenticate when the system wakes from sleep (on battery).",
	"status": status_r_wn22_cc_000180,
}
status_r_wn22_cc_000180 := "Not_a_Finding" if r_wn22_cc_000180
status_r_wn22_cc_000180 := "Open" if not r_wn22_cc_000180

# WN22-CC-000190 | V-254350 | CAT II
default r_wn22_cc_000190 := false
r_wn22_cc_000190 if {
	input.registry["HKLM\\SOFTWARE\\Policies\\Microsoft\\Power\\PowerSettings\\0e796bdb-100d-47d6-a2d5-f7d2daa51f51"]["ACSettingIndex"] == 1
}

finding_r_wn22_cc_000190 := {
	"vuln_id": "V-254350",
	"stig_id": "WN22-CC-000190",
	"severity": "CAT II",
	"rule_title": "Windows Server 2022 users must be prompted to authenticate when the system wakes from sleep (plugged in).",
	"status": status_r_wn22_cc_000190,
}
status_r_wn22_cc_000190 := "Not_a_Finding" if r_wn22_cc_000190
status_r_wn22_cc_000190 := "Open" if not r_wn22_cc_000190

# WN22-CC-000200 | V-254351 | CAT III
default r_wn22_cc_000200 := false
r_wn22_cc_000200 if {
	input.registry["HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\AppCompat"]["DisableInventory"] == 1
}

finding_r_wn22_cc_000200 := {
	"vuln_id": "V-254351",
	"stig_id": "WN22-CC-000200",
	"severity": "CAT III",
	"rule_title": "Windows Server 2022 Application Compatibility Program Inventory must be prevented from collecting data and sending the information to Microsoft.",
	"status": status_r_wn22_cc_000200,
}
status_r_wn22_cc_000200 := "Not_a_Finding" if r_wn22_cc_000200
status_r_wn22_cc_000200 := "Open" if not r_wn22_cc_000200

# WN22-CC-000210 | V-254352 | CAT I
default r_wn22_cc_000210 := false
r_wn22_cc_000210 if {
	input.registry["HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\Explorer"]["NoAutoplayfornonVolume"] == 1
}

finding_r_wn22_cc_000210 := {
	"vuln_id": "V-254352",
	"stig_id": "WN22-CC-000210",
	"severity": "CAT I",
	"rule_title": "Windows Server 2022 Autoplay must be turned off for nonvolume devices.",
	"status": status_r_wn22_cc_000210,
}
status_r_wn22_cc_000210 := "Not_a_Finding" if r_wn22_cc_000210
status_r_wn22_cc_000210 := "Open" if not r_wn22_cc_000210

# WN22-CC-000220 | V-254353 | CAT I
default r_wn22_cc_000220 := false
r_wn22_cc_000220 if {
	input.registry["HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer"]["NoAutorun"] == 1
}

finding_r_wn22_cc_000220 := {
	"vuln_id": "V-254353",
	"stig_id": "WN22-CC-000220",
	"severity": "CAT I",
	"rule_title": "Windows Server 2022 default AutoRun behavior must be configured to prevent AutoRun commands.",
	"status": status_r_wn22_cc_000220,
}
status_r_wn22_cc_000220 := "Not_a_Finding" if r_wn22_cc_000220
status_r_wn22_cc_000220 := "Open" if not r_wn22_cc_000220

# WN22-CC-000230 | V-254354 | CAT I
default r_wn22_cc_000230 := false
r_wn22_cc_000230 if {
	input.registry["HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\policies\\Explorer"]["NoDriveTypeAutoRun"] == 255
}

finding_r_wn22_cc_000230 := {
	"vuln_id": "V-254354",
	"stig_id": "WN22-CC-000230",
	"severity": "CAT I",
	"rule_title": "Windows Server 2022 AutoPlay must be disabled for all drives.",
	"status": status_r_wn22_cc_000230,
}
status_r_wn22_cc_000230 := "Not_a_Finding" if r_wn22_cc_000230
status_r_wn22_cc_000230 := "Open" if not r_wn22_cc_000230

# WN22-CC-000240 | V-254355 | CAT II
default r_wn22_cc_000240 := false
r_wn22_cc_000240 if {
	input.registry["HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\CredUI"]["EnumerateAdministrators"] == 0
}

finding_r_wn22_cc_000240 := {
	"vuln_id": "V-254355",
	"stig_id": "WN22-CC-000240",
	"severity": "CAT II",
	"rule_title": "Windows Server 2022 administrator accounts must not be enumerated during elevation.",
	"status": status_r_wn22_cc_000240,
}
status_r_wn22_cc_000240 := "Not_a_Finding" if r_wn22_cc_000240
status_r_wn22_cc_000240 := "Open" if not r_wn22_cc_000240

# WN22-CC-000250 | V-254356 | CAT II
default r_wn22_cc_000250 := false
r_wn22_cc_000250 if {
	input.registry["HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\DataCollection"]["AllowTelemetry"] == 1
}

finding_r_wn22_cc_000250 := {
	"vuln_id": "V-254356",
	"stig_id": "WN22-CC-000250",
	"severity": "CAT II",
	"rule_title": "Windows Server 2022 Diagnostic Data must be configured to send \"required diagnostic data\" or \"optional diagnostic data\".",
	"status": status_r_wn22_cc_000250,
}
status_r_wn22_cc_000250 := "Not_a_Finding" if r_wn22_cc_000250
status_r_wn22_cc_000250 := "Open" if not r_wn22_cc_000250

# WN22-CC-000260 | V-254357 | CAT III
default r_wn22_cc_000260 := false
r_wn22_cc_000260 if {
	input.registry["HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\DeliveryOptimization"]["DODownloadMode"] == 0
}

finding_r_wn22_cc_000260 := {
	"vuln_id": "V-254357",
	"stig_id": "WN22-CC-000260",
	"severity": "CAT III",
	"rule_title": "Windows Server 2022 Windows Update must not obtain updates from other PCs on the internet.",
	"status": status_r_wn22_cc_000260,
}
status_r_wn22_cc_000260 := "Not_a_Finding" if r_wn22_cc_000260
status_r_wn22_cc_000260 := "Open" if not r_wn22_cc_000260

# WN22-CC-000270 | V-254358 | CAT II
default r_wn22_cc_000270 := false
r_wn22_cc_000270 if {
	input.registry["HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\EventLog\\Application"]["MaxSize"] >= 32768
}

finding_r_wn22_cc_000270 := {
	"vuln_id": "V-254358",
	"stig_id": "WN22-CC-000270",
	"severity": "CAT II",
	"rule_title": "Windows Server 2022 Application event log size must be configured to 32768 KB or greater.",
	"status": status_r_wn22_cc_000270,
}
status_r_wn22_cc_000270 := "Not_a_Finding" if r_wn22_cc_000270
status_r_wn22_cc_000270 := "Open" if not r_wn22_cc_000270

# WN22-CC-000280 | V-254359 | CAT II
default r_wn22_cc_000280 := false
r_wn22_cc_000280 if {
	input.registry["HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\EventLog\\Security"]["MaxSize"] >= 5120000
}

finding_r_wn22_cc_000280 := {
	"vuln_id": "V-254359",
	"stig_id": "WN22-CC-000280",
	"severity": "CAT II",
	"rule_title": "The Windows Server 2022 security event log size must be configured to a value that holds at least one week's worth of audit records.",
	"status": status_r_wn22_cc_000280,
}
status_r_wn22_cc_000280 := "Not_a_Finding" if r_wn22_cc_000280
status_r_wn22_cc_000280 := "Open" if not r_wn22_cc_000280

# WN22-CC-000290 | V-254360 | CAT II
default r_wn22_cc_000290 := false
r_wn22_cc_000290 if {
	input.registry["HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\EventLog\\System"]["MaxSize"] >= 32768
}

finding_r_wn22_cc_000290 := {
	"vuln_id": "V-254360",
	"stig_id": "WN22-CC-000290",
	"severity": "CAT II",
	"rule_title": "Windows Server 2022 System event log size must be configured to 32768 KB or greater.",
	"status": status_r_wn22_cc_000290,
}
status_r_wn22_cc_000290 := "Not_a_Finding" if r_wn22_cc_000290
status_r_wn22_cc_000290 := "Open" if not r_wn22_cc_000290

# WN22-CC-000300 | V-254361 | CAT II
default r_wn22_cc_000300 := false
r_wn22_cc_000300 if {
	input.registry["HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\System"]["EnableSmartScreen"] == 1
}

finding_r_wn22_cc_000300 := {
	"vuln_id": "V-254361",
	"stig_id": "WN22-CC-000300",
	"severity": "CAT II",
	"rule_title": "Windows Server 2022 Microsoft Defender antivirus SmartScreen must be enabled.",
	"status": status_r_wn22_cc_000300,
}
status_r_wn22_cc_000300 := "Not_a_Finding" if r_wn22_cc_000300
status_r_wn22_cc_000300 := "Open" if not r_wn22_cc_000300

# WN22-CC-000310 | V-254362 | CAT II
default r_wn22_cc_000310 := false
r_wn22_cc_000310 if {
	input.registry["HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\Explorer"]["NoDataExecutionPrevention"] == 0
}

finding_r_wn22_cc_000310 := {
	"vuln_id": "V-254362",
	"stig_id": "WN22-CC-000310",
	"severity": "CAT II",
	"rule_title": "Windows Server 2022 Explorer Data Execution Prevention must be enabled.",
	"status": status_r_wn22_cc_000310,
}
status_r_wn22_cc_000310 := "Not_a_Finding" if r_wn22_cc_000310
status_r_wn22_cc_000310 := "Open" if not r_wn22_cc_000310

# WN22-CC-000320 | V-254363 | CAT III
default r_wn22_cc_000320 := false
r_wn22_cc_000320 if {
	input.registry["HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\Explorer"]["NoHeapTerminationOnCorruption"] == 0
}

finding_r_wn22_cc_000320 := {
	"vuln_id": "V-254363",
	"stig_id": "WN22-CC-000320",
	"severity": "CAT III",
	"rule_title": "Windows Server 2022 Turning off File Explorer heap termination on corruption must be disabled.",
	"status": status_r_wn22_cc_000320,
}
status_r_wn22_cc_000320 := "Not_a_Finding" if r_wn22_cc_000320
status_r_wn22_cc_000320 := "Open" if not r_wn22_cc_000320

# WN22-CC-000330 | V-254364 | CAT II
default r_wn22_cc_000330 := false
r_wn22_cc_000330 if {
	input.registry["HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer"]["PreXPSP2ShellProtocolBehavior"] == 0
}

finding_r_wn22_cc_000330 := {
	"vuln_id": "V-254364",
	"stig_id": "WN22-CC-000330",
	"severity": "CAT II",
	"rule_title": "Windows Server 2022 File Explorer shell protocol must run in protected mode.",
	"status": status_r_wn22_cc_000330,
}
status_r_wn22_cc_000330 := "Not_a_Finding" if r_wn22_cc_000330
status_r_wn22_cc_000330 := "Open" if not r_wn22_cc_000330

# WN22-CC-000340 | V-254365 | CAT II
default r_wn22_cc_000340 := false
r_wn22_cc_000340 if {
	input.registry["HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services"]["DisablePasswordSaving"] == 1
}

finding_r_wn22_cc_000340 := {
	"vuln_id": "V-254365",
	"stig_id": "WN22-CC-000340",
	"severity": "CAT II",
	"rule_title": "Windows Server 2022 must not save passwords in the Remote Desktop Client.",
	"status": status_r_wn22_cc_000340,
}
status_r_wn22_cc_000340 := "Not_a_Finding" if r_wn22_cc_000340
status_r_wn22_cc_000340 := "Open" if not r_wn22_cc_000340

# WN22-CC-000350 | V-254366 | CAT II
default r_wn22_cc_000350 := false
r_wn22_cc_000350 if {
	input.registry["HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services"]["fDisableCdm"] == 1
}

finding_r_wn22_cc_000350 := {
	"vuln_id": "V-254366",
	"stig_id": "WN22-CC-000350",
	"severity": "CAT II",
	"rule_title": "Windows Server 2022 Remote Desktop Services must prevent drive redirection.",
	"status": status_r_wn22_cc_000350,
}
status_r_wn22_cc_000350 := "Not_a_Finding" if r_wn22_cc_000350
status_r_wn22_cc_000350 := "Open" if not r_wn22_cc_000350

# WN22-CC-000360 | V-254367 | CAT II
default r_wn22_cc_000360 := false
r_wn22_cc_000360 if {
	input.registry["HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services"]["fPromptForPassword"] == 1
}

finding_r_wn22_cc_000360 := {
	"vuln_id": "V-254367",
	"stig_id": "WN22-CC-000360",
	"severity": "CAT II",
	"rule_title": "Windows Server 2022 Remote Desktop Services must always prompt a client for passwords upon connection.",
	"status": status_r_wn22_cc_000360,
}
status_r_wn22_cc_000360 := "Not_a_Finding" if r_wn22_cc_000360
status_r_wn22_cc_000360 := "Open" if not r_wn22_cc_000360

# WN22-CC-000370 | V-254368 | CAT II
default r_wn22_cc_000370 := false
r_wn22_cc_000370 if {
	input.registry["HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services"]["fEncryptRPCTraffic"] == 1
}

finding_r_wn22_cc_000370 := {
	"vuln_id": "V-254368",
	"stig_id": "WN22-CC-000370",
	"severity": "CAT II",
	"rule_title": "Windows Server 2022 Remote Desktop Services must require secure Remote Procedure Call (RPC) communications.",
	"status": status_r_wn22_cc_000370,
}
status_r_wn22_cc_000370 := "Not_a_Finding" if r_wn22_cc_000370
status_r_wn22_cc_000370 := "Open" if not r_wn22_cc_000370

# WN22-CC-000380 | V-254369 | CAT II
default r_wn22_cc_000380 := false
r_wn22_cc_000380 if {
	input.registry["HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services"]["MinEncryptionLevel"] == 3
}

finding_r_wn22_cc_000380 := {
	"vuln_id": "V-254369",
	"stig_id": "WN22-CC-000380",
	"severity": "CAT II",
	"rule_title": "Windows Server 2022 Remote Desktop Services must be configured with the client connection encryption set to High Level.",
	"status": status_r_wn22_cc_000380,
}
status_r_wn22_cc_000380 := "Not_a_Finding" if r_wn22_cc_000380
status_r_wn22_cc_000380 := "Open" if not r_wn22_cc_000380

# WN22-CC-000390 | V-254370 | CAT II
default r_wn22_cc_000390 := false
r_wn22_cc_000390 if {
	input.registry["HKLM\\SOFTWARE\\Policies\\Microsoft\\Internet Explorer\\Feeds"]["DisableEnclosureDownload"] == 1
}

finding_r_wn22_cc_000390 := {
	"vuln_id": "V-254370",
	"stig_id": "WN22-CC-000390",
	"severity": "CAT II",
	"rule_title": "Windows Server 2022 must prevent attachments from being downloaded from RSS feeds.",
	"status": status_r_wn22_cc_000390,
}
status_r_wn22_cc_000390 := "Not_a_Finding" if r_wn22_cc_000390
status_r_wn22_cc_000390 := "Open" if not r_wn22_cc_000390

# WN22-CC-000400 | V-254371 | CAT II
default r_wn22_cc_000400 := false
r_wn22_cc_000400 if {
	input.registry["HKLM\\SOFTWARE\\Policies\\Microsoft\\Internet Explorer\\Feeds"]["AllowBasicAuthInClear"] == 0
}

finding_r_wn22_cc_000400 := {
	"vuln_id": "V-254371",
	"stig_id": "WN22-CC-000400",
	"severity": "CAT II",
	"rule_title": "Windows Server 2022 must disable Basic authentication for RSS feeds over HTTP.",
	"status": status_r_wn22_cc_000400,
}
status_r_wn22_cc_000400 := "Not_a_Finding" if r_wn22_cc_000400
status_r_wn22_cc_000400 := "Open" if not r_wn22_cc_000400

# WN22-CC-000410 | V-254372 | CAT II
default r_wn22_cc_000410 := false
r_wn22_cc_000410 if {
	input.registry["HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\Windows Search"]["AllowIndexingEncryptedStoresOrItems"] == 0
}

finding_r_wn22_cc_000410 := {
	"vuln_id": "V-254372",
	"stig_id": "WN22-CC-000410",
	"severity": "CAT II",
	"rule_title": "Windows Server 2022 must prevent Indexing of encrypted files.",
	"status": status_r_wn22_cc_000410,
}
status_r_wn22_cc_000410 := "Not_a_Finding" if r_wn22_cc_000410
status_r_wn22_cc_000410 := "Open" if not r_wn22_cc_000410

# WN22-CC-000420 | V-254373 | CAT II
default r_wn22_cc_000420 := false
r_wn22_cc_000420 if {
	input.registry["HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer"]["EnableUserControl"] == 0
}

finding_r_wn22_cc_000420 := {
	"vuln_id": "V-254373",
	"stig_id": "WN22-CC-000420",
	"severity": "CAT II",
	"rule_title": "Windows Server 2022 must prevent users from changing installation options.",
	"status": status_r_wn22_cc_000420,
}
status_r_wn22_cc_000420 := "Not_a_Finding" if r_wn22_cc_000420
status_r_wn22_cc_000420 := "Open" if not r_wn22_cc_000420

# WN22-CC-000430 | V-254374 | CAT I
default r_wn22_cc_000430 := false
r_wn22_cc_000430 if {
	input.registry["HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer"]["AlwaysInstallElevated"] == 0
}

finding_r_wn22_cc_000430 := {
	"vuln_id": "V-254374",
	"stig_id": "WN22-CC-000430",
	"severity": "CAT I",
	"rule_title": "Windows Server 2022 must disable the Windows Installer Always install with elevated privileges option.",
	"status": status_r_wn22_cc_000430,
}
status_r_wn22_cc_000430 := "Not_a_Finding" if r_wn22_cc_000430
status_r_wn22_cc_000430 := "Open" if not r_wn22_cc_000430

# WN22-CC-000440 | V-254375 | CAT II
default r_wn22_cc_000440 := false
r_wn22_cc_000440 if {
	input.registry["HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer"]["SafeForScripting"] == 0
}

finding_r_wn22_cc_000440 := {
	"vuln_id": "V-254375",
	"stig_id": "WN22-CC-000440",
	"severity": "CAT II",
	"rule_title": "Windows Server 2022 users must be notified if a web-based program attempts to install software.",
	"status": status_r_wn22_cc_000440,
}
status_r_wn22_cc_000440 := "Not_a_Finding" if r_wn22_cc_000440
status_r_wn22_cc_000440 := "Open" if not r_wn22_cc_000440

# WN22-CC-000450 | V-254376 | CAT II
default r_wn22_cc_000450 := false
r_wn22_cc_000450 if {
	input.registry["HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System"]["DisableAutomaticRestartSignOn"] == 1
}

finding_r_wn22_cc_000450 := {
	"vuln_id": "V-254376",
	"stig_id": "WN22-CC-000450",
	"severity": "CAT II",
	"rule_title": "Windows Server 2022 must disable automatically signing in the last interactive user after a system-initiated restart.",
	"status": status_r_wn22_cc_000450,
}
status_r_wn22_cc_000450 := "Not_a_Finding" if r_wn22_cc_000450
status_r_wn22_cc_000450 := "Open" if not r_wn22_cc_000450

# WN22-CC-000460 | V-254377 | CAT II
default r_wn22_cc_000460 := false
r_wn22_cc_000460 if {
	input.registry["HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging"]["EnableScriptBlockLogging"] == 1
}

finding_r_wn22_cc_000460 := {
	"vuln_id": "V-254377",
	"stig_id": "WN22-CC-000460",
	"severity": "CAT II",
	"rule_title": "Windows Server 2022 PowerShell script block logging must be enabled.",
	"status": status_r_wn22_cc_000460,
}
status_r_wn22_cc_000460 := "Not_a_Finding" if r_wn22_cc_000460
status_r_wn22_cc_000460 := "Open" if not r_wn22_cc_000460

# WN22-CC-000470 | V-254378 | CAT I
default r_wn22_cc_000470 := false
r_wn22_cc_000470 if {
	input.registry["HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\WinRM\\Client"]["AllowBasic"] == 0
}

finding_r_wn22_cc_000470 := {
	"vuln_id": "V-254378",
	"stig_id": "WN22-CC-000470",
	"severity": "CAT I",
	"rule_title": "Windows Server 2022 Windows Remote Management (WinRM) client must not use Basic authentication.",
	"status": status_r_wn22_cc_000470,
}
status_r_wn22_cc_000470 := "Not_a_Finding" if r_wn22_cc_000470
status_r_wn22_cc_000470 := "Open" if not r_wn22_cc_000470

# WN22-CC-000480 | V-254379 | CAT II
default r_wn22_cc_000480 := false
r_wn22_cc_000480 if {
	input.registry["HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\WinRM\\Client"]["AllowUnencryptedTraffic"] == 0
}

finding_r_wn22_cc_000480 := {
	"vuln_id": "V-254379",
	"stig_id": "WN22-CC-000480",
	"severity": "CAT II",
	"rule_title": "Windows Server 2022 Windows Remote Management (WinRM) client must not allow unencrypted traffic.",
	"status": status_r_wn22_cc_000480,
}
status_r_wn22_cc_000480 := "Not_a_Finding" if r_wn22_cc_000480
status_r_wn22_cc_000480 := "Open" if not r_wn22_cc_000480

# WN22-CC-000490 | V-254380 | CAT II
default r_wn22_cc_000490 := false
r_wn22_cc_000490 if {
	input.registry["HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\WinRM\\Client"]["AllowDigest"] == 0
}

finding_r_wn22_cc_000490 := {
	"vuln_id": "V-254380",
	"stig_id": "WN22-CC-000490",
	"severity": "CAT II",
	"rule_title": "Windows Server 2022 Windows Remote Management (WinRM) client must not use Digest authentication.",
	"status": status_r_wn22_cc_000490,
}
status_r_wn22_cc_000490 := "Not_a_Finding" if r_wn22_cc_000490
status_r_wn22_cc_000490 := "Open" if not r_wn22_cc_000490

# WN22-CC-000500 | V-254381 | CAT I
default r_wn22_cc_000500 := false
r_wn22_cc_000500 if {
	input.registry["HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\WinRM\\Service"]["AllowBasic"] == 0
}

finding_r_wn22_cc_000500 := {
	"vuln_id": "V-254381",
	"stig_id": "WN22-CC-000500",
	"severity": "CAT I",
	"rule_title": "Windows Server 2022 Windows Remote Management (WinRM) service must not use Basic authentication.",
	"status": status_r_wn22_cc_000500,
}
status_r_wn22_cc_000500 := "Not_a_Finding" if r_wn22_cc_000500
status_r_wn22_cc_000500 := "Open" if not r_wn22_cc_000500

# WN22-CC-000510 | V-254382 | CAT II
default r_wn22_cc_000510 := false
r_wn22_cc_000510 if {
	input.registry["HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\WinRM\\Service"]["AllowUnencryptedTraffic"] == 0
}

finding_r_wn22_cc_000510 := {
	"vuln_id": "V-254382",
	"stig_id": "WN22-CC-000510",
	"severity": "CAT II",
	"rule_title": "Windows Server 2022 Windows Remote Management (WinRM) service must not allow unencrypted traffic.",
	"status": status_r_wn22_cc_000510,
}
status_r_wn22_cc_000510 := "Not_a_Finding" if r_wn22_cc_000510
status_r_wn22_cc_000510 := "Open" if not r_wn22_cc_000510

# WN22-CC-000520 | V-254383 | CAT II
default r_wn22_cc_000520 := false
r_wn22_cc_000520 if {
	input.registry["HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\WinRM\\Service"]["DisableRunAs"] == 1
}

finding_r_wn22_cc_000520 := {
	"vuln_id": "V-254383",
	"stig_id": "WN22-CC-000520",
	"severity": "CAT II",
	"rule_title": "Windows Server 2022 Windows Remote Management (WinRM) service must not store RunAs credentials.",
	"status": status_r_wn22_cc_000520,
}
status_r_wn22_cc_000520 := "Not_a_Finding" if r_wn22_cc_000520
status_r_wn22_cc_000520 := "Open" if not r_wn22_cc_000520

# WN22-CC-000530 | V-254384 | CAT II
default r_wn22_cc_000530 := false
r_wn22_cc_000530 if {
	input.registry["HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\Transcription"]["EnableTranscripting"] == 1
}

finding_r_wn22_cc_000530 := {
	"vuln_id": "V-254384",
	"stig_id": "WN22-CC-000530",
	"severity": "CAT II",
	"rule_title": "Windows Server 2022 must have PowerShell Transcription enabled.",
	"status": status_r_wn22_cc_000530,
}
status_r_wn22_cc_000530 := "Not_a_Finding" if r_wn22_cc_000530
status_r_wn22_cc_000530 := "Open" if not r_wn22_cc_000530

findings := [
	finding_r_wn22_cc_000010,
	finding_r_wn22_cc_000020,
	finding_r_wn22_cc_000030,
	finding_r_wn22_cc_000040,
	finding_r_wn22_cc_000050,
	finding_r_wn22_cc_000060,
	finding_r_wn22_cc_000070,
	finding_r_wn22_cc_000080,
	finding_r_wn22_cc_000090,
	finding_r_wn22_cc_000100,
	finding_r_wn22_cc_000110,
	finding_r_wn22_cc_000130,
	finding_r_wn22_cc_000140,
	finding_r_wn22_cc_000150,
	finding_r_wn22_cc_000160,
	finding_r_wn22_cc_000170,
	finding_r_wn22_cc_000180,
	finding_r_wn22_cc_000190,
	finding_r_wn22_cc_000200,
	finding_r_wn22_cc_000210,
	finding_r_wn22_cc_000220,
	finding_r_wn22_cc_000230,
	finding_r_wn22_cc_000240,
	finding_r_wn22_cc_000250,
	finding_r_wn22_cc_000260,
	finding_r_wn22_cc_000270,
	finding_r_wn22_cc_000280,
	finding_r_wn22_cc_000290,
	finding_r_wn22_cc_000300,
	finding_r_wn22_cc_000310,
	finding_r_wn22_cc_000320,
	finding_r_wn22_cc_000330,
	finding_r_wn22_cc_000340,
	finding_r_wn22_cc_000350,
	finding_r_wn22_cc_000360,
	finding_r_wn22_cc_000370,
	finding_r_wn22_cc_000380,
	finding_r_wn22_cc_000390,
	finding_r_wn22_cc_000400,
	finding_r_wn22_cc_000410,
	finding_r_wn22_cc_000420,
	finding_r_wn22_cc_000430,
	finding_r_wn22_cc_000440,
	finding_r_wn22_cc_000450,
	finding_r_wn22_cc_000460,
	finding_r_wn22_cc_000470,
	finding_r_wn22_cc_000480,
	finding_r_wn22_cc_000490,
	finding_r_wn22_cc_000500,
	finding_r_wn22_cc_000510,
	finding_r_wn22_cc_000520,
	finding_r_wn22_cc_000530,
]

default compliant := false

compliant if count([f | some f in findings; f.status == "Open"]) == 0
