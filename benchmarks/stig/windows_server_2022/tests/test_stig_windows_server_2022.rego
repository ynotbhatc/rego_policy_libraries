package stig.windows_server_2022_test

import rego.v1
import data.stig.windows_server_2022

# Contract smoke: aggregate report is well-formed on empty input.
test_report_wellformed_on_empty_input if {
	report := windows_server_2022.stig_assessment with input as {}
	is_object(report)
	report.summary.total_findings > 0
	report.summary.open == report.summary.total_findings - report.summary.not_a_finding
}

# Green path: a registry set satisfying every auto-derived expectation
# closes every generated finding (hand-written modules may stay open).
green_fixture := {
	 "registry": {
	  "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\Personalization": {
	   "NoLockScreenSlideshow": 1
	  },
	  "HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\Wdigest": {
	   "UseLogonCredential": 0
	  },
	  "HKLM\\SYSTEM\\CurrentControlSet\\Services\\Tcpip6\\Parameters": {
	   "DisableIPSourceRouting": 2
	  },
	  "HKLM\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters": {
	   "DisableIPSourceRouting": 2,
	   "EnableICMPRedirect": 0
	  },
	  "HKLM\\SYSTEM\\CurrentControlSet\\Services\\Netbt\\Parameters": {
	   "NoNameReleaseOnDemand": 1
	  },
	  "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\LanmanWorkstation": {
	   "AllowInsecureGuestAuth": 0
	  },
	  "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\NetworkProvider\\HardenedPaths": {
	   "\\\\*\\NETLOGON": "RequireMutualAuthentication=1, RequireIntegrity=1"
	  },
	  "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\Audit": {
	   "ProcessCreationIncludeCmdLine_Enabled": 1
	  },
	  "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\CredentialsDelegation": {
	   "AllowProtectedCreds": 1
	  },
	  "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\DeviceGuard": {
	   "EnableVirtualizationBasedSecurity": 1,
	   "LsaCfgFlags": 1
	  },
	  "HKLM\\SYSTEM\\CurrentControlSet\\Policies\\EarlyLaunch": {
	   "DriverLoadPolicy": 1
	  },
	  "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\Group Policy\\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}": {
	   "NoGPOListChanges": 0
	  },
	  "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Printers": {
	   "DisableWebPnPDownload": 1,
	   "DisableHTTPPrinting": 1
	  },
	  "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\System": {
	   "DontDisplayNetworkSelectionUI": 1,
	   "EnableSmartScreen": 1,
	   "EnumerateLocalUsers": 0
	  },
	  "HKLM\\SOFTWARE\\Policies\\Microsoft\\Power\\PowerSettings\\0e796bdb-100d-47d6-a2d5-f7d2daa51f51": {
	   "DCSettingIndex": 1,
	   "ACSettingIndex": 1
	  },
	  "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\AppCompat": {
	   "DisableInventory": 1
	  },
	  "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\Explorer": {
	   "NoAutoplayfornonVolume": 1,
	   "NoDataExecutionPrevention": 0,
	   "NoHeapTerminationOnCorruption": 0
	  },
	  "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer": {
	   "NoAutorun": 1,
	   "PreXPSP2ShellProtocolBehavior": 0
	  },
	  "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\policies\\Explorer": {
	   "NoDriveTypeAutoRun": 255
	  },
	  "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\CredUI": {
	   "EnumerateAdministrators": 0
	  },
	  "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\DataCollection": {
	   "AllowTelemetry": 1
	  },
	  "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\DeliveryOptimization": {
	   "DODownloadMode": 0
	  },
	  "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\EventLog\\Application": {
	   "MaxSize": 32768
	  },
	  "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\EventLog\\Security": {
	   "MaxSize": 5120000
	  },
	  "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\EventLog\\System": {
	   "MaxSize": 32768
	  },
	  "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services": {
	   "DisablePasswordSaving": 1,
	   "fDisableCdm": 1,
	   "fPromptForPassword": 1,
	   "fEncryptRPCTraffic": 1,
	   "MinEncryptionLevel": 3
	  },
	  "HKLM\\SOFTWARE\\Policies\\Microsoft\\Internet Explorer\\Feeds": {
	   "DisableEnclosureDownload": 1,
	   "AllowBasicAuthInClear": 0
	  },
	  "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\Windows Search": {
	   "AllowIndexingEncryptedStoresOrItems": 0
	  },
	  "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer": {
	   "EnableUserControl": 0,
	   "AlwaysInstallElevated": 0,
	   "SafeForScripting": 0
	  },
	  "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System": {
	   "DisableAutomaticRestartSignOn": 1,
	   "LocalAccountTokenFilterPolicy": 0,
	   "InactivityTimeoutSecs": 900,
	   "LegalNoticeText": "See message text below",
	   "LegalNoticeCaption": "See message title options below",
	   "FilterAdministratorToken": 1,
	   "EnableUIADesktopToggle": 0,
	   "ConsentPromptBehaviorAdmin": 2,
	   "ConsentPromptBehaviorUser": 0,
	   "EnableInstallerDetection": 1,
	   "EnableSecureUIAPaths": 1,
	   "EnableLUA": 1,
	   "EnableVirtualization": 1
	  },
	  "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging": {
	   "EnableScriptBlockLogging": 1
	  },
	  "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\WinRM\\Client": {
	   "AllowBasic": 0,
	   "AllowUnencryptedTraffic": 0,
	   "AllowDigest": 0
	  },
	  "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\WinRM\\Service": {
	   "AllowBasic": 0,
	   "AllowUnencryptedTraffic": 0,
	   "DisableRunAs": 1
	  },
	  "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\Transcription": {
	   "EnableTranscripting": 1
	  },
	  "HKLM\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters": {
	   "SMB1": 0
	  },
	  "HKLM\\SYSTEM\\CurrentControlSet\\Services\\mrxsmb10": {
	   "Start": 4
	  },
	  "HKLM\\SYSTEM\\CurrentControlSet\\Services\\NTDS\\Parameters": {
	   "LDAPServerIntegrity": 2
	  },
	  "HKLM\\SYSTEM\\CurrentControlSet\\Services\\Netlogon\\Parameters": {
	   "RefusePasswordChange": 0,
	   "RequireSignOrSeal": 1,
	   "SealSecureChannel": 1,
	   "SignSecureChannel": 1,
	   "DisablePasswordChange": 0,
	   "MaximumPasswordAge": 30,
	   "RequireStrongKey": 1
	  },
	  "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Rpc": {
	   "RestrictRemoteClients": 1
	  },
	  "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon": {
	   "CachedLogonsCount": "4 (or less)",
	   "scremoveoption": "1 (Lock Workstation) or 2 (Force Logoff)"
	  },
	  "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa": {
	   "RestrictRemoteSAM": "O:BAG:BAD:(A;;RC;;;BA)",
	   "LimitBlankPasswordUse": 1,
	   "SCENoApplyLegacyAuditPolicy": 1,
	   "RestrictAnonymousSAM": 1,
	   "RestrictAnonymous": 1,
	   "EveryoneIncludesAnonymous": 0,
	   "NoLMHash": 1,
	   "LmCompatibilityLevel": 5
	  },
	  "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Attachments": {
	   "SaveZoneInformation": 2
	  },
	  "HKLM\\SYSTEM\\CurrentControlSet\\Services\\LanmanWorkstation\\Parameters": {
	   "RequireSecuritySignature": 1,
	   "EnableSecuritySignature": 1,
	   "EnablePlainTextPassword": 0
	  },
	  "HKLM\\SYSTEM\\CurrentControlSet\\Services\\LanManServer\\Parameters": {
	   "RequireSecuritySignature": 1,
	   "EnableSecuritySignature": 1,
	   "RestrictNullSessAccess": 1
	  },
	  "HKLM\\SYSTEM\\CurrentControlSet\\Control\\LSA": {
	   "UseMachineId": 1
	  },
	  "HKLM\\SYSTEM\\CurrentControlSet\\Control\\LSA\\MSV1_0": {
	   "allownullsessionfallback": 0
	  },
	  "HKLM\\SYSTEM\\CurrentControlSet\\Control\\LSA\\pku2u": {
	   "AllowOnlineID": 0
	  },
	  "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\Kerberos\\Parameters": {
	   "SupportedEncryptionTypes": 2147483640
	  },
	  "HKLM\\SYSTEM\\CurrentControlSet\\Services\\LDAP": {
	   "LDAPClientIntegrity": 1
	  },
	  "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\MSV1_0": {
	   "NTLMMinClientSec": 537395200,
	   "NTLMMinServerSec": 537395200
	  },
	  "HKLM\\SOFTWARE\\Policies\\Microsoft\\Cryptography": {
	   "ForceKeyProtection": 2
	  },
	  "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\FIPSAlgorithmPolicy": {
	   "Enabled": 1
	  },
	  "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager": {
	   "ProtectionMode": 1
	  }
	 }
	}

test_generated_registry_rules_pass_on_green_fixture if {
	report := windows_server_2022.stig_assessment with input as green_fixture
	open_reg := [f | some f in report.findings;
		f.status == "Open"
		startswith(f.stig_id, "WN22-")
		registry_rule_ids[f.stig_id]
	]
	count(open_reg) == 0
}

registry_rule_ids := {
	"WN22-CC-000010",
	"WN22-CC-000020",
	"WN22-CC-000030",
	"WN22-CC-000040",
	"WN22-CC-000050",
	"WN22-CC-000060",
	"WN22-CC-000070",
	"WN22-CC-000080",
	"WN22-CC-000090",
	"WN22-CC-000100",
	"WN22-CC-000110",
	"WN22-CC-000130",
	"WN22-CC-000140",
	"WN22-CC-000150",
	"WN22-CC-000160",
	"WN22-CC-000170",
	"WN22-CC-000180",
	"WN22-CC-000190",
	"WN22-CC-000200",
	"WN22-CC-000210",
	"WN22-CC-000220",
	"WN22-CC-000230",
	"WN22-CC-000240",
	"WN22-CC-000250",
	"WN22-CC-000260",
	"WN22-CC-000270",
	"WN22-CC-000280",
	"WN22-CC-000290",
	"WN22-CC-000300",
	"WN22-CC-000310",
	"WN22-CC-000320",
	"WN22-CC-000330",
	"WN22-CC-000340",
	"WN22-CC-000350",
	"WN22-CC-000360",
	"WN22-CC-000370",
	"WN22-CC-000380",
	"WN22-CC-000390",
	"WN22-CC-000400",
	"WN22-CC-000410",
	"WN22-CC-000420",
	"WN22-CC-000430",
	"WN22-CC-000440",
	"WN22-CC-000450",
	"WN22-CC-000460",
	"WN22-CC-000470",
	"WN22-CC-000480",
	"WN22-CC-000490",
	"WN22-CC-000500",
	"WN22-CC-000510",
	"WN22-CC-000520",
	"WN22-CC-000530",
	"WN22-00-000390",
	"WN22-00-000400",
	"WN22-DC-000320",
	"WN22-DC-000330",
	"WN22-MS-000020",
	"WN22-MS-000030",
	"WN22-MS-000040",
	"WN22-MS-000050",
	"WN22-MS-000060",
	"WN22-MS-000140",
	"WN22-UC-000010",
	"WN22-SO-000020",
	"WN22-SO-000050",
	"WN22-SO-000060",
	"WN22-SO-000070",
	"WN22-SO-000080",
	"WN22-SO-000090",
	"WN22-SO-000100",
	"WN22-SO-000110",
	"WN22-SO-000120",
	"WN22-SO-000130",
	"WN22-SO-000140",
	"WN22-SO-000150",
	"WN22-SO-000160",
	"WN22-SO-000170",
	"WN22-SO-000180",
	"WN22-SO-000190",
	"WN22-SO-000200",
	"WN22-SO-000220",
	"WN22-SO-000230",
	"WN22-SO-000240",
	"WN22-SO-000250",
	"WN22-SO-000260",
	"WN22-SO-000270",
	"WN22-SO-000280",
	"WN22-SO-000290",
	"WN22-SO-000300",
	"WN22-SO-000310",
	"WN22-SO-000320",
	"WN22-SO-000330",
	"WN22-SO-000340",
	"WN22-SO-000350",
	"WN22-SO-000360",
	"WN22-SO-000370",
	"WN22-SO-000380",
	"WN22-SO-000390",
	"WN22-SO-000400",
	"WN22-SO-000410",
	"WN22-SO-000420",
	"WN22-SO-000430",
	"WN22-SO-000440",
	"WN22-SO-000450",
}
