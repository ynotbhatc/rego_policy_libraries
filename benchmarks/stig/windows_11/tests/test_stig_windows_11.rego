package stig.windows_11_test

import rego.v1
import data.stig.windows_11

# Contract smoke: aggregate report is well-formed on empty input.
test_report_wellformed_on_empty_input if {
	report := windows_11.stig_assessment with input as {}
	is_object(report)
	report.summary.total_findings > 0
	report.summary.open == report.summary.total_findings - report.summary.not_a_finding
}

# Green path: a registry set satisfying every auto-derived expectation
# closes every generated finding (hand-written modules may stay open).
green_fixture := {
	 "registry": {
	  "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\Personalization": {
	   "NoLockScreenCamera": 1,
	   "NoLockScreenSlideshow": 1
	  },
	  "HKLM\\SYSTEM\\CurrentControlSet\\Services\\Tcpip6\\Parameters": {
	   "DisableIpSourceRouting": 2
	  },
	  "HKLM\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters": {
	   "DisableIPSourceRouting": 2,
	   "EnableICMPRedirect": 0
	  },
	  "HKLM\\SYSTEM\\CurrentControlSet\\Services\\Netbt\\Parameters": {
	   "NoNameReleaseOnDemand": 1
	  },
	  "HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\Wdigest": {
	   "UseLogonCredential": 0
	  },
	  "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\LanmanWorkstation": {
	   "AllowInsecureGuestAuth": 0
	  },
	  "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\Network Connections": {
	   "NC_ShowSharedAccessUI": 0
	  },
	  "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\NetworkProvider\\HardenedPaths": {
	   "\\\\*\\NETLOGON": "RequireMutualAuthentication=1, RequireIntegrity=1"
	  },
	  "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\WcmSvc\\GroupPolicy": {
	   "fBlockNonDomain": 1
	  },
	  "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\Audit": {
	   "ProcessCreationIncludeCmdLine_Enabled": 1
	  },
	  "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\CredentialsDelegation": {
	   "AllowProtectedCreds": 1
	  },
	  "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\DeviceGuard": {
	   "EnableVirtualizationBasedSecurity": 1,
	   "LsaCfgFlags": 1,
	   "HypervisorEnforcedCodeIntegrity": 1
	  },
	  "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\Group Policy\\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}": {
	   "NoGPOListChanges": 0
	  },
	  "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Printers": {
	   "DisableWebPnPDownload": 1,
	   "DisableHTTPPrinting": 1
	  },
	  "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer": {
	   "NoWebServices": 1,
	   "NoAutorun": 1
	  },
	  "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\System": {
	   "DontDisplayNetworkSelectionUI": 1,
	   "EnumerateLocalUsers": 0,
	   "EnableSmartScreen": 1,
	   "ShellSmartScreenLevel": "Block"
	  },
	  "HKLM\\SOFTWARE\\Policies\\Microsoft\\Power\\PowerSettings\\0e796bdb-100d-47d6-a2d5-f7d2daa51f51": {
	   "DCSettingIndex": 1,
	   "ACSettingIndex": 1
	  },
	  "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services": {
	   "fAllowToGetHelp": 0,
	   "DisablePasswordSaving": 1,
	   "fDisableCdm": 1,
	   "fPromptForPassword": 1,
	   "fEncryptRPCTraffic": 1,
	   "MinEncryptionLevel": 3
	  },
	  "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Rpc": {
	   "RestrictRemoteClients": 1
	  },
	  "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System": {
	   "MSAOptional": 1,
	   "DisableAutomaticRestartSignOn": 1,
	   "InactivityTimeoutSecs": 900,
	   "LegalNoticeText": "You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only.",
	   "LegalNoticeCaption": "See message title above",
	   "FilterAdministratorToken": 1,
	   "ConsentPromptBehaviorUser": 0,
	   "EnableInstallerDetection": 1,
	   "EnableSecureUIAPaths": 1,
	   "EnableLUA": 1,
	   "EnableVirtualization": 1
	  },
	  "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\AppCompat": {
	   "DisableInventory": 1
	  },
	  "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\Explorer": {
	   "NoAutoplayfornonVolume": 1,
	   "NoHeapTerminationOnCorruption": 0
	  },
	  "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\policies\\Explorer": {
	   "NoDriveTypeAutoRun": 255
	  },
	  "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\CredUI": {
	   "EnumerateAdministrators": 0
	  },
	  "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\DataCollection": {
	   "LimitEnhancedDiagnosticDataWindowsAnalytics": 1
	  },
	  "HKLM\\SOFTWARE\\Policies\\Microsoft\\PassportForWork": {
	   "RequireSecurityDevice": 1
	  },
	  "HKLM\\SOFTWARE\\Policies\\Microsoft\\Internet Explorer\\Feeds": {
	   "DisableEnclosureDownload": 1
	  },
	  "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer": {
	   "EnableUserControl": 0,
	   "AlwaysInstallElevated": 0
	  },
	  "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging": {
	   "EnableScriptBlockLogging": 1
	  },
	  "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\Transcription": {
	   "EnableTranscripting": 1
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
	  "HKCU\\SOFTWARE\\Policies\\Microsoft\\Windows\\CloudContent": {
	   "DisableThirdPartySuggestions": 1
	  },
	  "HKLM\\SOFTWARE\\Policies\\Microsoft\\FVE": {
	   "MinimumPIN": 6
	  },
	  "HKLM\\SOFTWARE\\Policies\\Microsoft\\MicrosoftAccount": {
	   "DisableUserAuth": 1
	  },
	  "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\kernel": {
	   "DisableExceptionChainValidation": 0
	  },
	  "HKLM\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters": {
	   "SMB1": 0
	  },
	  "HKLM\\SYSTEM\\CurrentControlSet\\Services\\mrxsmb10": {
	   "Start": 4
	  },
	  "HKLM\\SOFTWARE\\Microsoft\\PolicyManager\\current\\device\\Connectivity": {
	   "AllowBluetooth": 0
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
	  "HKLM\\Software\\Policies\\Microsoft\\Windows\\Kernel DMA Protection": {
	   "DeviceEnumerationPolicy": 0
	  },
	  "HKCU\\SOFTWARE\\Policies\\Microsoft\\Windows\\CurrentVersion\\PushNotifications": {
	   "NoToastApplicationNotificationOnLockScreen": 1
	  },
	  "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Attachments": {
	   "SaveZoneInformation": 2
	  },
	  "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa": {
	   "LimitBlankPasswordUse": 1,
	   "SCENoApplyLegacyAuditPolicy": 1,
	   "RestrictAnonymousSAM": 1,
	   "RestrictAnonymous": 1,
	   "EveryoneIncludesAnonymous": 0,
	   "RestrictRemoteSAM": "O:BAG:BAD:(A;;RC;;;BA)",
	   "NoLMHash": 1,
	   "LmCompatibilityLevel": 5
	  },
	  "HKLM\\SYSTEM\\CurrentControlSet\\Services\\Netlogon\\Parameters": {
	   "RequireSignOrSeal": 1,
	   "SealSecureChannel": 1,
	   "SignSecureChannel": 1,
	   "DisablePasswordChange": 0,
	   "MaximumPasswordAge": 30,
	   "RequireStrongKey": 1
	  },
	  "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon": {
	   "CachedLogonsCount": "10 (or less)",
	   "SCRemoveOption": "1 (Lock Workstation) or 2 (Force Logoff)"
	  },
	  "HKLM\\SYSTEM\\CurrentControlSet\\Services\\LanmanWorkstation\\Parameters": {
	   "RequireSecuritySignature": 1,
	   "EnablePlainTextPassword": 0
	  },
	  "HKLM\\SYSTEM\\CurrentControlSet\\Services\\LanManServer\\Parameters": {
	   "RequireSecuritySignature": 1,
	   "RestrictNullSessAccess": 1
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
	  "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager": {
	   "ProtectionMode": 1
	  }
	 }
	}

test_generated_registry_rules_pass_on_green_fixture if {
	report := windows_11.stig_assessment with input as green_fixture
	open_reg := [f | some f in report.findings;
		f.status == "Open"
		startswith(f.stig_id, "WN11-")
		registry_rule_ids[f.stig_id]
	]
	count(open_reg) == 0
}

registry_rule_ids := {
	"WN11-CC-000005",
	"WN11-CC-000010",
	"WN11-CC-000020",
	"WN11-CC-000025",
	"WN11-CC-000030",
	"WN11-CC-000035",
	"WN11-CC-000038",
	"WN11-CC-000040",
	"WN11-CC-000044",
	"WN11-CC-000050",
	"WN11-CC-000060",
	"WN11-CC-000066",
	"WN11-CC-000068",
	"WN11-CC-000070",
	"WN11-CC-000075",
	"WN11-CC-000080",
	"WN11-CC-000090",
	"WN11-CC-000100",
	"WN11-CC-000105",
	"WN11-CC-000110",
	"WN11-CC-000120",
	"WN11-CC-000130",
	"WN11-CC-000145",
	"WN11-CC-000150",
	"WN11-CC-000155",
	"WN11-CC-000165",
	"WN11-CC-000170",
	"WN11-CC-000175",
	"WN11-CC-000180",
	"WN11-CC-000185",
	"WN11-CC-000190",
	"WN11-CC-000200",
	"WN11-CC-000204",
	"WN11-CC-000210",
	"WN11-CC-000220",
	"WN11-CC-000255",
	"WN11-CC-000270",
	"WN11-CC-000275",
	"WN11-CC-000280",
	"WN11-CC-000285",
	"WN11-CC-000290",
	"WN11-CC-000295",
	"WN11-CC-000310",
	"WN11-CC-000315",
	"WN11-CC-000325",
	"WN11-CC-000326",
	"WN11-CC-000327",
	"WN11-CC-000330",
	"WN11-CC-000335",
	"WN11-CC-000345",
	"WN11-CC-000350",
	"WN11-CC-000355",
	"WN11-CC-000360",
	"WN11-CC-000390",
	"WN11-00-000032",
	"WN11-00-000150",
	"WN11-00-000165",
	"WN11-00-000170",
	"WN11-00-000210",
	"WN11-00-000126",
	"WN11-AU-000500",
	"WN11-AU-000505",
	"WN11-AU-000510",
	"WN11-EP-000310",
	"WN11-UC-000015",
	"WN11-UC-000020",
	"WN11-SO-000015",
	"WN11-SO-000030",
	"WN11-SO-000035",
	"WN11-SO-000040",
	"WN11-SO-000045",
	"WN11-SO-000050",
	"WN11-SO-000055",
	"WN11-SO-000060",
	"WN11-SO-000070",
	"WN11-SO-000075",
	"WN11-SO-000080",
	"WN11-SO-000085",
	"WN11-SO-000095",
	"WN11-SO-000100",
	"WN11-SO-000110",
	"WN11-SO-000120",
	"WN11-SO-000145",
	"WN11-SO-000150",
	"WN11-SO-000160",
	"WN11-SO-000165",
	"WN11-SO-000167",
	"WN11-SO-000180",
	"WN11-SO-000185",
	"WN11-SO-000190",
	"WN11-SO-000195",
	"WN11-SO-000205",
	"WN11-SO-000210",
	"WN11-SO-000215",
	"WN11-SO-000220",
	"WN11-SO-000240",
	"WN11-SO-000245",
	"WN11-SO-000255",
	"WN11-SO-000260",
	"WN11-SO-000265",
	"WN11-SO-000270",
	"WN11-SO-000275",
}
