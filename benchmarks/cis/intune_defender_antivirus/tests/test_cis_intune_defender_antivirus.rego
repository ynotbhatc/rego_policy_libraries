package cis.intune_defender_antivirus_test

import rego.v1

import data.cis.intune_defender_antivirus as b
import data.cis.intune_defender_antivirus.main as m

green := {
	 "intune_defender": {
	  "settings": {
	   "Spynet_LocalSettingOverrideSpynetReporting": "disabled",
	   "DisableBlockAtFirstSeen": "enabled",
	   "RealtimeProtection_DisableScanOnRealtimeEnable": "enabled",
	   "Reporting_DisablegenericrePorts": "disabled",
	   "DisableRoutinelyTakingAction": "disabled",
	   "AllowArchiveScanning": 1,
	   "AllowBehaviorMonitoring": 1,
	   "AllowCloudProtection": 1,
	   "AllowEmailScanning": 1,
	   "AllowFullScanRemovableDriveScanning": 1,
	   "AllowOnAccessProtection": 1,
	   "AllowRealtimeMonitoring": 1,
	   "AllowIOAVProtection": 1,
	   "AllowScriptScanning": 1,
	   "CheckForSignaturesBeforeRunningScan": 1,
	   "CloudBlockLevel": 2,
	   "CloudExtendedTimeout": 50,
	   "DaysUntilAggressiveCatchupQuickScan": 7,
	   "EnableConvertWarnToBlock": 1,
	   "EnableDynamicSignatureDroppedEventReporting": 1,
	   "EnableFileHashComputation": 1,
	   "EnableNetworkProtection": 1,
	   "HideExclusionsFromLocalUsers": 1,
	   "OobeEnableRtpAndSigUpdate": 1,
	   "PUAProtection": 1,
	   "QuickScanIncludeExclusions": 1,
	   "RealTimeScanDirection": 0,
	   "RemoteEncryptionProtectionAggressiveness": 1,
	   "RemoteEncryptionProtectionConfiguredState": 1,
	   "ScanParameter": 1,
	   "ScheduleQuickScanTime": 120,
	   "ScheduleScanTime": 120,
	   "ScheduleScanDay": 0,
	   "SignatureUpdateInterval": 4,
	   "SubmitSamplesConsent": 1,
	   "AttackSurfaceReductionRules": "56a863a9-875e-4185-98a7-b882c64b5ce5=1|7674BA52-37EB-4A4F-A9A1-F0F9A1619A2C=1|d4f940ab-401b-4efc-aadc-ad5f3c50688a=1|9E6C4E1F-7D60-472F-BA1A-A39EF669E4B2=1|be9ba2d9-53ea-4cdc-84e5-9b1eeee46550=1|01443614-CD74-433A-B99E-2ECDC07BFC25=1|5beb7efe-fd9a-4556-801d-275e5ffc04cc=1|D3E037E1-3EB8-44C8-A917-57927947596D=1|3b576869-a4ec-4529-8536-b80a7769e899=1|75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84=1|26190899-1602-49e8-8b27-eb1d0a1ce869=1|E6DB77E5-3DF2-4CF1-B95A-636979351E5B=1|d1e49aac-8f56-4280-b9ba-993a6d77406c=1|33DDEDF1-C6E0-47CB-833E-DE6133960387=1|b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4=1|92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B=1|c1db55ab-c21a-4637-bb3f-a12568109d35=1",
	   "ThreatSeverityDefaultAction": "2=2|4=2|5=3"
	  }
	 }
	}

test_green_policy_is_compliant if {
	r := b.compliance_report with input as green
	r.compliant == true
	count(r.violations) == 0
	r.total_controls == 55
	r.standard_total == 55
}

test_main_alias_matches if {
	r := m.compliance_report with input as green
	r.compliant == true
	r.facts_supplied == true
	m.compliant with input as green
}

test_fail_closed_on_empty_input if {
	r := b.compliance_report with input as {}
	r.compliant == false
	count(r.violations) > 0
	m.compliance_report.facts_supplied == false with input as {}
}

test_every_recommendation_fires_without_facts if {
	v := b.violations with input as {"intune_defender": {"settings": {}}}
	ids := {id | some msg in v; id := split(msg, ":")[0]}
	count(ids) == 55
}

test_recommendations_cover_the_workbook if {
	count(b.recommendations) == 55
	count([r | some r in b.recommendations; r.level == 2]) == 3
}

test_level_1_scope if {
	count(b.in_scope) == 52 with input as object.union(green, {"cis_profile": {"level": 1}})
	b.compliant with input as object.union(json.patch(green, [{"op": "remove", "path": "/intune_defender/settings/EnableConvertWarnToBlock"}]), {"cis_profile": {"level": 1}})
}

test_numeric_strings_and_key_case_are_accepted if {
	ok := json.patch(green, [{"op": "remove", "path": "/intune_defender/settings/CloudBlockLevel"}, {"op": "add", "path": "/intune_defender/settings/cloudblocklevel", "value": " 4 "}])
	b.compliant with input as ok
}

test_non_numeric_value_fails if {
	bad := json.patch(green, [{"op": "replace", "path": "/intune_defender/settings/AllowArchiveScanning", "value": "allowed"}])
	"2.1: Ensure 'Allow Archive Scanning' is set to 'Allowed'" in b.violations with input as bad
}

test_audit_or_higher_rule_accepts_audit if {
	ok := json.patch(green, [{"op": "replace", "path": "/intune_defender/settings/AttackSurfaceReductionRules", "value": "56a863a9-875e-4185-98a7-b882c64b5ce5=1|7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c=1|d4f940ab-401b-4efc-aadc-ad5f3c50688a=2|9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2=1|be9ba2d9-53ea-4cdc-84e5-9b1eeee46550=1|01443614-cd74-433a-b99e-2ecdc07bfc25=1|5beb7efe-fd9a-4556-801d-275e5ffc04cc=1|d3e037e1-3eb8-44c8-a917-57927947596d=1|3b576869-a4ec-4529-8536-b80a7769e899=1|75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84=1|26190899-1602-49e8-8b27-eb1d0a1ce869=1|e6db77e5-3df2-4cf1-b95a-636979351e5b=1|d1e49aac-8f56-4280-b9ba-993a6d77406c=1|33ddedf1-c6e0-47cb-833e-de6133960387=1|b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4=1|92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b=1|c1db55ab-c21a-4637-bb3f-a12568109d35=1"}])
	b.compliant with input as ok
}

test_2_3_absent_is_in_effect if {
	ok := json.patch(green, [{"op": "remove", "path": "/intune_defender/settings/AllowCloudProtection"}])
	b.compliant with input as ok
}

test_admx_state_is_case_insensitive if {
	ok := json.patch(green, [{"op": "replace", "path": "/intune_defender/settings/DisableBlockAtFirstSeen", "value": "Enabled"}])
	b.compliant with input as ok
}

test_admx_syncml_state_is_accepted if {
	ok := json.patch(green, [{"op": "replace", "path": "/intune_defender/settings/DisableBlockAtFirstSeen", "value": "<enabled/>"}, {"op": "replace", "path": "/intune_defender/settings/DisableRoutinelyTakingAction", "value": "<disabled/>"}])
	b.compliant with input as ok
}

test_admx_syncml_wrong_state_fails if {
	bad := json.patch(green, [{"op": "replace", "path": "/intune_defender/settings/DisableBlockAtFirstSeen", "value": "<disabled/>"}])
	"1.3.2: Ensure 'Configure the 'Block at First Sight' feature' is set to 'Enabled'" in b.violations with input as bad
}

# 1.3.1
test_1_3_1_pass if {
	v := b.violations with input as green
	count([msg | some msg in v; startswith(msg, "1.3.1:")]) == 0
}

test_1_3_1_fail_1 if {
	bad := json.patch(green, [{"op": "replace", "path": "/intune_defender/settings/Spynet_LocalSettingOverrideSpynetReporting", "value": "enabled"}])
	"1.3.1: Ensure 'Configure local setting override for reporting to Microsoft MAPS' is set to 'Disabled'" in b.violations with input as bad
}

test_1_3_1_fail_2 if {
	bad := json.patch(green, [{"op": "replace", "path": "/intune_defender/settings/Spynet_LocalSettingOverrideSpynetReporting", "value": 0}])
	"1.3.1: Ensure 'Configure local setting override for reporting to Microsoft MAPS' is set to 'Disabled'" in b.violations with input as bad
}

test_1_3_1_fail_3 if {
	bad := json.patch(green, [{"op": "replace", "path": "/intune_defender/settings/Spynet_LocalSettingOverrideSpynetReporting", "value": 1}])
	"1.3.1: Ensure 'Configure local setting override for reporting to Microsoft MAPS' is set to 'Disabled'" in b.violations with input as bad
}

test_1_3_1_evidence_missing if {
	bad := json.patch(green, [{"op": "remove", "path": "/intune_defender/settings/Spynet_LocalSettingOverrideSpynetReporting"}])
	"1.3.1: evidence missing — intune_defender.settings.Spynet_LocalSettingOverrideSpynetReporting not collected" in b.violations with input as bad
}

# 1.3.2
test_1_3_2_pass if {
	v := b.violations with input as green
	count([msg | some msg in v; startswith(msg, "1.3.2:")]) == 0
}

test_1_3_2_fail_1 if {
	bad := json.patch(green, [{"op": "replace", "path": "/intune_defender/settings/DisableBlockAtFirstSeen", "value": "disabled"}])
	"1.3.2: Ensure 'Configure the 'Block at First Sight' feature' is set to 'Enabled'" in b.violations with input as bad
}

test_1_3_2_fail_2 if {
	bad := json.patch(green, [{"op": "replace", "path": "/intune_defender/settings/DisableBlockAtFirstSeen", "value": 0}])
	"1.3.2: Ensure 'Configure the 'Block at First Sight' feature' is set to 'Enabled'" in b.violations with input as bad
}

test_1_3_2_fail_3 if {
	bad := json.patch(green, [{"op": "replace", "path": "/intune_defender/settings/DisableBlockAtFirstSeen", "value": 1}])
	"1.3.2: Ensure 'Configure the 'Block at First Sight' feature' is set to 'Enabled'" in b.violations with input as bad
}

test_1_3_2_evidence_missing if {
	bad := json.patch(green, [{"op": "remove", "path": "/intune_defender/settings/DisableBlockAtFirstSeen"}])
	"1.3.2: evidence missing — intune_defender.settings.DisableBlockAtFirstSeen not collected" in b.violations with input as bad
}

# 1.8.1
test_1_8_1_pass if {
	v := b.violations with input as green
	count([msg | some msg in v; startswith(msg, "1.8.1:")]) == 0
}

test_1_8_1_fail_1 if {
	bad := json.patch(green, [{"op": "replace", "path": "/intune_defender/settings/RealtimeProtection_DisableScanOnRealtimeEnable", "value": "disabled"}])
	"1.8.1: Ensure 'Turn on process scanning whenever real-time protection is enabled' is set to 'Enabled'" in b.violations with input as bad
}

test_1_8_1_fail_2 if {
	bad := json.patch(green, [{"op": "replace", "path": "/intune_defender/settings/RealtimeProtection_DisableScanOnRealtimeEnable", "value": 0}])
	"1.8.1: Ensure 'Turn on process scanning whenever real-time protection is enabled' is set to 'Enabled'" in b.violations with input as bad
}

test_1_8_1_fail_3 if {
	bad := json.patch(green, [{"op": "replace", "path": "/intune_defender/settings/RealtimeProtection_DisableScanOnRealtimeEnable", "value": 1}])
	"1.8.1: Ensure 'Turn on process scanning whenever real-time protection is enabled' is set to 'Enabled'" in b.violations with input as bad
}

test_1_8_1_evidence_missing if {
	bad := json.patch(green, [{"op": "remove", "path": "/intune_defender/settings/RealtimeProtection_DisableScanOnRealtimeEnable"}])
	"1.8.1: evidence missing — intune_defender.settings.RealtimeProtection_DisableScanOnRealtimeEnable not collected" in b.violations with input as bad
}

# 1.10.1
test_1_10_1_pass if {
	v := b.violations with input as green
	count([msg | some msg in v; startswith(msg, "1.10.1:")]) == 0
}

test_1_10_1_fail_1 if {
	bad := json.patch(green, [{"op": "replace", "path": "/intune_defender/settings/Reporting_DisablegenericrePorts", "value": "enabled"}])
	"1.10.1: Ensure 'Configure Watson events' is set to 'Disabled'" in b.violations with input as bad
}

test_1_10_1_fail_2 if {
	bad := json.patch(green, [{"op": "replace", "path": "/intune_defender/settings/Reporting_DisablegenericrePorts", "value": 0}])
	"1.10.1: Ensure 'Configure Watson events' is set to 'Disabled'" in b.violations with input as bad
}

test_1_10_1_fail_3 if {
	bad := json.patch(green, [{"op": "replace", "path": "/intune_defender/settings/Reporting_DisablegenericrePorts", "value": 1}])
	"1.10.1: Ensure 'Configure Watson events' is set to 'Disabled'" in b.violations with input as bad
}

test_1_10_1_evidence_missing if {
	bad := json.patch(green, [{"op": "remove", "path": "/intune_defender/settings/Reporting_DisablegenericrePorts"}])
	"1.10.1: evidence missing — intune_defender.settings.Reporting_DisablegenericrePorts not collected" in b.violations with input as bad
}

# 1.14
test_1_14_pass if {
	v := b.violations with input as green
	count([msg | some msg in v; startswith(msg, "1.14:")]) == 0
}

test_1_14_fail_1 if {
	bad := json.patch(green, [{"op": "replace", "path": "/intune_defender/settings/DisableRoutinelyTakingAction", "value": "enabled"}])
	"1.14: Ensure 'Turn off routine remediation' is set to 'Disabled'" in b.violations with input as bad
}

test_1_14_fail_2 if {
	bad := json.patch(green, [{"op": "replace", "path": "/intune_defender/settings/DisableRoutinelyTakingAction", "value": 0}])
	"1.14: Ensure 'Turn off routine remediation' is set to 'Disabled'" in b.violations with input as bad
}

test_1_14_fail_3 if {
	bad := json.patch(green, [{"op": "replace", "path": "/intune_defender/settings/DisableRoutinelyTakingAction", "value": 1}])
	"1.14: Ensure 'Turn off routine remediation' is set to 'Disabled'" in b.violations with input as bad
}

test_1_14_evidence_missing if {
	bad := json.patch(green, [{"op": "remove", "path": "/intune_defender/settings/DisableRoutinelyTakingAction"}])
	"1.14: evidence missing — intune_defender.settings.DisableRoutinelyTakingAction not collected" in b.violations with input as bad
}

# 2.1
test_2_1_pass if {
	v := b.violations with input as green
	count([msg | some msg in v; startswith(msg, "2.1:")]) == 0
}

test_2_1_fail if {
	bad := json.patch(green, [{"op": "replace", "path": "/intune_defender/settings/AllowArchiveScanning", "value": 0}])
	"2.1: Ensure 'Allow Archive Scanning' is set to 'Allowed'" in b.violations with input as bad
}

test_2_1_evidence_missing if {
	bad := json.patch(green, [{"op": "remove", "path": "/intune_defender/settings/AllowArchiveScanning"}])
	"2.1: evidence missing — intune_defender.settings.AllowArchiveScanning not collected" in b.violations with input as bad
}

# 2.2
test_2_2_pass if {
	v := b.violations with input as green
	count([msg | some msg in v; startswith(msg, "2.2:")]) == 0
}

test_2_2_fail if {
	bad := json.patch(green, [{"op": "replace", "path": "/intune_defender/settings/AllowBehaviorMonitoring", "value": 0}])
	"2.2: Ensure 'Allow Behavior Monitoring' is set to 'Allowed'" in b.violations with input as bad
}

test_2_2_evidence_missing if {
	bad := json.patch(green, [{"op": "remove", "path": "/intune_defender/settings/AllowBehaviorMonitoring"}])
	"2.2: evidence missing — intune_defender.settings.AllowBehaviorMonitoring not collected" in b.violations with input as bad
}

# 2.3
test_2_3_pass if {
	v := b.violations with input as green
	count([msg | some msg in v; startswith(msg, "2.3:")]) == 0
}

test_2_3_fail if {
	bad := json.patch(green, [{"op": "replace", "path": "/intune_defender/settings/AllowCloudProtection", "value": 0}])
	"2.3: Ensure 'Allow Cloud Protection' is set to 'Allowed'" in b.violations with input as bad
}

test_2_3_evidence_missing if {
	bad := json.patch(green, [{"op": "replace", "path": "/intune_defender/settings", "value": {}}])
	"2.3: evidence missing — intune_defender.settings not collected" in b.violations with input as bad
}

# 2.4
test_2_4_pass if {
	v := b.violations with input as green
	count([msg | some msg in v; startswith(msg, "2.4:")]) == 0
}

test_2_4_fail if {
	bad := json.patch(green, [{"op": "replace", "path": "/intune_defender/settings/AllowEmailScanning", "value": 0}])
	"2.4: Ensure 'Allow Email Scanning' is set to 'Allowed'" in b.violations with input as bad
}

test_2_4_evidence_missing if {
	bad := json.patch(green, [{"op": "remove", "path": "/intune_defender/settings/AllowEmailScanning"}])
	"2.4: evidence missing — intune_defender.settings.AllowEmailScanning not collected" in b.violations with input as bad
}

# 2.5
test_2_5_pass if {
	v := b.violations with input as green
	count([msg | some msg in v; startswith(msg, "2.5:")]) == 0
}

test_2_5_fail if {
	bad := json.patch(green, [{"op": "replace", "path": "/intune_defender/settings/AllowFullScanRemovableDriveScanning", "value": 0}])
	"2.5: Ensure 'Allow Full Scan Removable Drive Scanning' is set to 'Allowed'" in b.violations with input as bad
}

test_2_5_evidence_missing if {
	bad := json.patch(green, [{"op": "remove", "path": "/intune_defender/settings/AllowFullScanRemovableDriveScanning"}])
	"2.5: evidence missing — intune_defender.settings.AllowFullScanRemovableDriveScanning not collected" in b.violations with input as bad
}

# 2.6
test_2_6_pass if {
	v := b.violations with input as green
	count([msg | some msg in v; startswith(msg, "2.6:")]) == 0
}

test_2_6_fail if {
	bad := json.patch(green, [{"op": "replace", "path": "/intune_defender/settings/AllowOnAccessProtection", "value": 0}])
	"2.6: Ensure 'Allow On Access Protection' is set to 'Allow'" in b.violations with input as bad
}

test_2_6_evidence_missing if {
	bad := json.patch(green, [{"op": "remove", "path": "/intune_defender/settings/AllowOnAccessProtection"}])
	"2.6: evidence missing — intune_defender.settings.AllowOnAccessProtection not collected" in b.violations with input as bad
}

# 2.7
test_2_7_pass if {
	v := b.violations with input as green
	count([msg | some msg in v; startswith(msg, "2.7:")]) == 0
}

test_2_7_fail if {
	bad := json.patch(green, [{"op": "replace", "path": "/intune_defender/settings/AllowRealtimeMonitoring", "value": 0}])
	"2.7: Ensure 'Allow Realtime Monitoring' is set to 'Allowed'" in b.violations with input as bad
}

test_2_7_evidence_missing if {
	bad := json.patch(green, [{"op": "remove", "path": "/intune_defender/settings/AllowRealtimeMonitoring"}])
	"2.7: evidence missing — intune_defender.settings.AllowRealtimeMonitoring not collected" in b.violations with input as bad
}

# 2.8
test_2_8_pass if {
	v := b.violations with input as green
	count([msg | some msg in v; startswith(msg, "2.8:")]) == 0
}

test_2_8_fail if {
	bad := json.patch(green, [{"op": "replace", "path": "/intune_defender/settings/AllowIOAVProtection", "value": 0}])
	"2.8: Ensure 'Allow scanning of all downloaded files and attachments' is set to 'Allowed'" in b.violations with input as bad
}

test_2_8_evidence_missing if {
	bad := json.patch(green, [{"op": "remove", "path": "/intune_defender/settings/AllowIOAVProtection"}])
	"2.8: evidence missing — intune_defender.settings.AllowIOAVProtection not collected" in b.violations with input as bad
}

# 2.9
test_2_9_pass if {
	v := b.violations with input as green
	count([msg | some msg in v; startswith(msg, "2.9:")]) == 0
}

test_2_9_fail if {
	bad := json.patch(green, [{"op": "replace", "path": "/intune_defender/settings/AllowScriptScanning", "value": 0}])
	"2.9: Ensure 'Allow Script Scanning' is set to 'Allowed'" in b.violations with input as bad
}

test_2_9_evidence_missing if {
	bad := json.patch(green, [{"op": "remove", "path": "/intune_defender/settings/AllowScriptScanning"}])
	"2.9: evidence missing — intune_defender.settings.AllowScriptScanning not collected" in b.violations with input as bad
}

# 2.10
test_2_10_pass if {
	v := b.violations with input as green
	count([msg | some msg in v; startswith(msg, "2.10:")]) == 0
}

test_2_10_fail_1 if {
	bad := json.patch(green, [{"op": "replace", "path": "/intune_defender/settings/AttackSurfaceReductionRules", "value": "56a863a9-875e-4185-98a7-b882c64b5ce5=2|7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c=1|d4f940ab-401b-4efc-aadc-ad5f3c50688a=1|9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2=1|be9ba2d9-53ea-4cdc-84e5-9b1eeee46550=1|01443614-cd74-433a-b99e-2ecdc07bfc25=1|5beb7efe-fd9a-4556-801d-275e5ffc04cc=1|d3e037e1-3eb8-44c8-a917-57927947596d=1|3b576869-a4ec-4529-8536-b80a7769e899=1|75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84=1|26190899-1602-49e8-8b27-eb1d0a1ce869=1|e6db77e5-3df2-4cf1-b95a-636979351e5b=1|d1e49aac-8f56-4280-b9ba-993a6d77406c=1|33ddedf1-c6e0-47cb-833e-de6133960387=1|b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4=1|92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b=1|c1db55ab-c21a-4637-bb3f-a12568109d35=1"}])
	"2.10: Ensure 'ASR: Block abuse of exploited vulnerable signed drivers' is set to 'Block'" in b.violations with input as bad
}

test_2_10_fail_2 if {
	bad := json.patch(green, [{"op": "replace", "path": "/intune_defender/settings/AttackSurfaceReductionRules", "value": "7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c=1|d4f940ab-401b-4efc-aadc-ad5f3c50688a=1|9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2=1|be9ba2d9-53ea-4cdc-84e5-9b1eeee46550=1|01443614-cd74-433a-b99e-2ecdc07bfc25=1|5beb7efe-fd9a-4556-801d-275e5ffc04cc=1|d3e037e1-3eb8-44c8-a917-57927947596d=1|3b576869-a4ec-4529-8536-b80a7769e899=1|75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84=1|26190899-1602-49e8-8b27-eb1d0a1ce869=1|e6db77e5-3df2-4cf1-b95a-636979351e5b=1|d1e49aac-8f56-4280-b9ba-993a6d77406c=1|33ddedf1-c6e0-47cb-833e-de6133960387=1|b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4=1|92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b=1|c1db55ab-c21a-4637-bb3f-a12568109d35=1"}])
	"2.10: Ensure 'ASR: Block abuse of exploited vulnerable signed drivers' is set to 'Block'" in b.violations with input as bad
}

test_2_10_fail_3 if {
	bad := json.patch(green, [{"op": "replace", "path": "/intune_defender/settings/AttackSurfaceReductionRules", "value": "56a863a9-875e-4185-98a7-b882c64b5ce5=1|7674BA52-37EB-4A4F-A9A1-F0F9A1619A2C=1|d4f940ab-401b-4efc-aadc-ad5f3c50688a=1|9E6C4E1F-7D60-472F-BA1A-A39EF669E4B2=1|be9ba2d9-53ea-4cdc-84e5-9b1eeee46550=1|01443614-CD74-433A-B99E-2ECDC07BFC25=1|5beb7efe-fd9a-4556-801d-275e5ffc04cc=1|D3E037E1-3EB8-44C8-A917-57927947596D=1|3b576869-a4ec-4529-8536-b80a7769e899=1|75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84=1|26190899-1602-49e8-8b27-eb1d0a1ce869=1|E6DB77E5-3DF2-4CF1-B95A-636979351E5B=1|d1e49aac-8f56-4280-b9ba-993a6d77406c=1|33DDEDF1-C6E0-47CB-833E-DE6133960387=1|b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4=1|92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B=1|c1db55ab-c21a-4637-bb3f-a12568109d35=1|56a863a9-875e-4185-98a7-b882c64b5ce5=6"}])
	"2.10: Ensure 'ASR: Block abuse of exploited vulnerable signed drivers' is set to 'Block'" in b.violations with input as bad
}

test_2_10_evidence_missing if {
	bad := json.patch(green, [{"op": "remove", "path": "/intune_defender/settings/AttackSurfaceReductionRules"}])
	"2.10: evidence missing — intune_defender.settings.AttackSurfaceReductionRules not collected" in b.violations with input as bad
}

# 2.11
test_2_11_pass if {
	v := b.violations with input as green
	count([msg | some msg in v; startswith(msg, "2.11:")]) == 0
}

test_2_11_fail_1 if {
	bad := json.patch(green, [{"op": "replace", "path": "/intune_defender/settings/AttackSurfaceReductionRules", "value": "56a863a9-875e-4185-98a7-b882c64b5ce5=1|7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c=2|d4f940ab-401b-4efc-aadc-ad5f3c50688a=1|9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2=1|be9ba2d9-53ea-4cdc-84e5-9b1eeee46550=1|01443614-cd74-433a-b99e-2ecdc07bfc25=1|5beb7efe-fd9a-4556-801d-275e5ffc04cc=1|d3e037e1-3eb8-44c8-a917-57927947596d=1|3b576869-a4ec-4529-8536-b80a7769e899=1|75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84=1|26190899-1602-49e8-8b27-eb1d0a1ce869=1|e6db77e5-3df2-4cf1-b95a-636979351e5b=1|d1e49aac-8f56-4280-b9ba-993a6d77406c=1|33ddedf1-c6e0-47cb-833e-de6133960387=1|b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4=1|92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b=1|c1db55ab-c21a-4637-bb3f-a12568109d35=1"}])
	"2.11: Ensure 'ASR: Block Adobe Reader from creating child processes' is set to 'Block'" in b.violations with input as bad
}

test_2_11_fail_2 if {
	bad := json.patch(green, [{"op": "replace", "path": "/intune_defender/settings/AttackSurfaceReductionRules", "value": "56a863a9-875e-4185-98a7-b882c64b5ce5=1|d4f940ab-401b-4efc-aadc-ad5f3c50688a=1|9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2=1|be9ba2d9-53ea-4cdc-84e5-9b1eeee46550=1|01443614-cd74-433a-b99e-2ecdc07bfc25=1|5beb7efe-fd9a-4556-801d-275e5ffc04cc=1|d3e037e1-3eb8-44c8-a917-57927947596d=1|3b576869-a4ec-4529-8536-b80a7769e899=1|75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84=1|26190899-1602-49e8-8b27-eb1d0a1ce869=1|e6db77e5-3df2-4cf1-b95a-636979351e5b=1|d1e49aac-8f56-4280-b9ba-993a6d77406c=1|33ddedf1-c6e0-47cb-833e-de6133960387=1|b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4=1|92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b=1|c1db55ab-c21a-4637-bb3f-a12568109d35=1"}])
	"2.11: Ensure 'ASR: Block Adobe Reader from creating child processes' is set to 'Block'" in b.violations with input as bad
}

test_2_11_fail_3 if {
	bad := json.patch(green, [{"op": "replace", "path": "/intune_defender/settings/AttackSurfaceReductionRules", "value": "56a863a9-875e-4185-98a7-b882c64b5ce5=1|7674BA52-37EB-4A4F-A9A1-F0F9A1619A2C=1|d4f940ab-401b-4efc-aadc-ad5f3c50688a=1|9E6C4E1F-7D60-472F-BA1A-A39EF669E4B2=1|be9ba2d9-53ea-4cdc-84e5-9b1eeee46550=1|01443614-CD74-433A-B99E-2ECDC07BFC25=1|5beb7efe-fd9a-4556-801d-275e5ffc04cc=1|D3E037E1-3EB8-44C8-A917-57927947596D=1|3b576869-a4ec-4529-8536-b80a7769e899=1|75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84=1|26190899-1602-49e8-8b27-eb1d0a1ce869=1|E6DB77E5-3DF2-4CF1-B95A-636979351E5B=1|d1e49aac-8f56-4280-b9ba-993a6d77406c=1|33DDEDF1-C6E0-47CB-833E-DE6133960387=1|b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4=1|92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B=1|c1db55ab-c21a-4637-bb3f-a12568109d35=1|7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c=6"}])
	"2.11: Ensure 'ASR: Block Adobe Reader from creating child processes' is set to 'Block'" in b.violations with input as bad
}

test_2_11_evidence_missing if {
	bad := json.patch(green, [{"op": "remove", "path": "/intune_defender/settings/AttackSurfaceReductionRules"}])
	"2.11: evidence missing — intune_defender.settings.AttackSurfaceReductionRules not collected" in b.violations with input as bad
}

# 2.12
test_2_12_pass if {
	v := b.violations with input as green
	count([msg | some msg in v; startswith(msg, "2.12:")]) == 0
}

test_2_12_fail_1 if {
	bad := json.patch(green, [{"op": "replace", "path": "/intune_defender/settings/AttackSurfaceReductionRules", "value": "56a863a9-875e-4185-98a7-b882c64b5ce5=1|7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c=1|d4f940ab-401b-4efc-aadc-ad5f3c50688a=0|9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2=1|be9ba2d9-53ea-4cdc-84e5-9b1eeee46550=1|01443614-cd74-433a-b99e-2ecdc07bfc25=1|5beb7efe-fd9a-4556-801d-275e5ffc04cc=1|d3e037e1-3eb8-44c8-a917-57927947596d=1|3b576869-a4ec-4529-8536-b80a7769e899=1|75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84=1|26190899-1602-49e8-8b27-eb1d0a1ce869=1|e6db77e5-3df2-4cf1-b95a-636979351e5b=1|d1e49aac-8f56-4280-b9ba-993a6d77406c=1|33ddedf1-c6e0-47cb-833e-de6133960387=1|b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4=1|92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b=1|c1db55ab-c21a-4637-bb3f-a12568109d35=1"}])
	"2.12: Ensure 'ASR: Block all Office applications from creating child processes' is set to 'Audit' or higher" in b.violations with input as bad
}

test_2_12_fail_2 if {
	bad := json.patch(green, [{"op": "replace", "path": "/intune_defender/settings/AttackSurfaceReductionRules", "value": "56a863a9-875e-4185-98a7-b882c64b5ce5=1|7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c=1|9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2=1|be9ba2d9-53ea-4cdc-84e5-9b1eeee46550=1|01443614-cd74-433a-b99e-2ecdc07bfc25=1|5beb7efe-fd9a-4556-801d-275e5ffc04cc=1|d3e037e1-3eb8-44c8-a917-57927947596d=1|3b576869-a4ec-4529-8536-b80a7769e899=1|75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84=1|26190899-1602-49e8-8b27-eb1d0a1ce869=1|e6db77e5-3df2-4cf1-b95a-636979351e5b=1|d1e49aac-8f56-4280-b9ba-993a6d77406c=1|33ddedf1-c6e0-47cb-833e-de6133960387=1|b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4=1|92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b=1|c1db55ab-c21a-4637-bb3f-a12568109d35=1"}])
	"2.12: Ensure 'ASR: Block all Office applications from creating child processes' is set to 'Audit' or higher" in b.violations with input as bad
}

test_2_12_fail_3 if {
	bad := json.patch(green, [{"op": "replace", "path": "/intune_defender/settings/AttackSurfaceReductionRules", "value": "56a863a9-875e-4185-98a7-b882c64b5ce5=1|7674BA52-37EB-4A4F-A9A1-F0F9A1619A2C=1|d4f940ab-401b-4efc-aadc-ad5f3c50688a=1|9E6C4E1F-7D60-472F-BA1A-A39EF669E4B2=1|be9ba2d9-53ea-4cdc-84e5-9b1eeee46550=1|01443614-CD74-433A-B99E-2ECDC07BFC25=1|5beb7efe-fd9a-4556-801d-275e5ffc04cc=1|D3E037E1-3EB8-44C8-A917-57927947596D=1|3b576869-a4ec-4529-8536-b80a7769e899=1|75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84=1|26190899-1602-49e8-8b27-eb1d0a1ce869=1|E6DB77E5-3DF2-4CF1-B95A-636979351E5B=1|d1e49aac-8f56-4280-b9ba-993a6d77406c=1|33DDEDF1-C6E0-47CB-833E-DE6133960387=1|b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4=1|92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B=1|c1db55ab-c21a-4637-bb3f-a12568109d35=1|d4f940ab-401b-4efc-aadc-ad5f3c50688a=6"}])
	"2.12: Ensure 'ASR: Block all Office applications from creating child processes' is set to 'Audit' or higher" in b.violations with input as bad
}

test_2_12_evidence_missing if {
	bad := json.patch(green, [{"op": "remove", "path": "/intune_defender/settings/AttackSurfaceReductionRules"}])
	"2.12: evidence missing — intune_defender.settings.AttackSurfaceReductionRules not collected" in b.violations with input as bad
}

# 2.13
test_2_13_pass if {
	v := b.violations with input as green
	count([msg | some msg in v; startswith(msg, "2.13:")]) == 0
}

test_2_13_fail_1 if {
	bad := json.patch(green, [{"op": "replace", "path": "/intune_defender/settings/AttackSurfaceReductionRules", "value": "56a863a9-875e-4185-98a7-b882c64b5ce5=1|7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c=1|d4f940ab-401b-4efc-aadc-ad5f3c50688a=1|9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2=2|be9ba2d9-53ea-4cdc-84e5-9b1eeee46550=1|01443614-cd74-433a-b99e-2ecdc07bfc25=1|5beb7efe-fd9a-4556-801d-275e5ffc04cc=1|d3e037e1-3eb8-44c8-a917-57927947596d=1|3b576869-a4ec-4529-8536-b80a7769e899=1|75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84=1|26190899-1602-49e8-8b27-eb1d0a1ce869=1|e6db77e5-3df2-4cf1-b95a-636979351e5b=1|d1e49aac-8f56-4280-b9ba-993a6d77406c=1|33ddedf1-c6e0-47cb-833e-de6133960387=1|b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4=1|92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b=1|c1db55ab-c21a-4637-bb3f-a12568109d35=1"}])
	"2.13: Ensure 'ASR: Block credential stealing from the Windows local security authority subsystem' is set to 'Block'" in b.violations with input as bad
}

test_2_13_fail_2 if {
	bad := json.patch(green, [{"op": "replace", "path": "/intune_defender/settings/AttackSurfaceReductionRules", "value": "56a863a9-875e-4185-98a7-b882c64b5ce5=1|7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c=1|d4f940ab-401b-4efc-aadc-ad5f3c50688a=1|be9ba2d9-53ea-4cdc-84e5-9b1eeee46550=1|01443614-cd74-433a-b99e-2ecdc07bfc25=1|5beb7efe-fd9a-4556-801d-275e5ffc04cc=1|d3e037e1-3eb8-44c8-a917-57927947596d=1|3b576869-a4ec-4529-8536-b80a7769e899=1|75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84=1|26190899-1602-49e8-8b27-eb1d0a1ce869=1|e6db77e5-3df2-4cf1-b95a-636979351e5b=1|d1e49aac-8f56-4280-b9ba-993a6d77406c=1|33ddedf1-c6e0-47cb-833e-de6133960387=1|b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4=1|92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b=1|c1db55ab-c21a-4637-bb3f-a12568109d35=1"}])
	"2.13: Ensure 'ASR: Block credential stealing from the Windows local security authority subsystem' is set to 'Block'" in b.violations with input as bad
}

test_2_13_fail_3 if {
	bad := json.patch(green, [{"op": "replace", "path": "/intune_defender/settings/AttackSurfaceReductionRules", "value": "56a863a9-875e-4185-98a7-b882c64b5ce5=1|7674BA52-37EB-4A4F-A9A1-F0F9A1619A2C=1|d4f940ab-401b-4efc-aadc-ad5f3c50688a=1|9E6C4E1F-7D60-472F-BA1A-A39EF669E4B2=1|be9ba2d9-53ea-4cdc-84e5-9b1eeee46550=1|01443614-CD74-433A-B99E-2ECDC07BFC25=1|5beb7efe-fd9a-4556-801d-275e5ffc04cc=1|D3E037E1-3EB8-44C8-A917-57927947596D=1|3b576869-a4ec-4529-8536-b80a7769e899=1|75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84=1|26190899-1602-49e8-8b27-eb1d0a1ce869=1|E6DB77E5-3DF2-4CF1-B95A-636979351E5B=1|d1e49aac-8f56-4280-b9ba-993a6d77406c=1|33DDEDF1-C6E0-47CB-833E-DE6133960387=1|b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4=1|92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B=1|c1db55ab-c21a-4637-bb3f-a12568109d35=1|9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2=6"}])
	"2.13: Ensure 'ASR: Block credential stealing from the Windows local security authority subsystem' is set to 'Block'" in b.violations with input as bad
}

test_2_13_evidence_missing if {
	bad := json.patch(green, [{"op": "remove", "path": "/intune_defender/settings/AttackSurfaceReductionRules"}])
	"2.13: evidence missing — intune_defender.settings.AttackSurfaceReductionRules not collected" in b.violations with input as bad
}

# 2.14
test_2_14_pass if {
	v := b.violations with input as green
	count([msg | some msg in v; startswith(msg, "2.14:")]) == 0
}

test_2_14_fail_1 if {
	bad := json.patch(green, [{"op": "replace", "path": "/intune_defender/settings/AttackSurfaceReductionRules", "value": "56a863a9-875e-4185-98a7-b882c64b5ce5=1|7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c=1|d4f940ab-401b-4efc-aadc-ad5f3c50688a=1|9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2=1|be9ba2d9-53ea-4cdc-84e5-9b1eeee46550=2|01443614-cd74-433a-b99e-2ecdc07bfc25=1|5beb7efe-fd9a-4556-801d-275e5ffc04cc=1|d3e037e1-3eb8-44c8-a917-57927947596d=1|3b576869-a4ec-4529-8536-b80a7769e899=1|75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84=1|26190899-1602-49e8-8b27-eb1d0a1ce869=1|e6db77e5-3df2-4cf1-b95a-636979351e5b=1|d1e49aac-8f56-4280-b9ba-993a6d77406c=1|33ddedf1-c6e0-47cb-833e-de6133960387=1|b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4=1|92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b=1|c1db55ab-c21a-4637-bb3f-a12568109d35=1"}])
	"2.14: Ensure 'ASR: Block executable content from email client and webmail' is set to 'Block'" in b.violations with input as bad
}

test_2_14_fail_2 if {
	bad := json.patch(green, [{"op": "replace", "path": "/intune_defender/settings/AttackSurfaceReductionRules", "value": "56a863a9-875e-4185-98a7-b882c64b5ce5=1|7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c=1|d4f940ab-401b-4efc-aadc-ad5f3c50688a=1|9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2=1|01443614-cd74-433a-b99e-2ecdc07bfc25=1|5beb7efe-fd9a-4556-801d-275e5ffc04cc=1|d3e037e1-3eb8-44c8-a917-57927947596d=1|3b576869-a4ec-4529-8536-b80a7769e899=1|75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84=1|26190899-1602-49e8-8b27-eb1d0a1ce869=1|e6db77e5-3df2-4cf1-b95a-636979351e5b=1|d1e49aac-8f56-4280-b9ba-993a6d77406c=1|33ddedf1-c6e0-47cb-833e-de6133960387=1|b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4=1|92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b=1|c1db55ab-c21a-4637-bb3f-a12568109d35=1"}])
	"2.14: Ensure 'ASR: Block executable content from email client and webmail' is set to 'Block'" in b.violations with input as bad
}

test_2_14_fail_3 if {
	bad := json.patch(green, [{"op": "replace", "path": "/intune_defender/settings/AttackSurfaceReductionRules", "value": "56a863a9-875e-4185-98a7-b882c64b5ce5=1|7674BA52-37EB-4A4F-A9A1-F0F9A1619A2C=1|d4f940ab-401b-4efc-aadc-ad5f3c50688a=1|9E6C4E1F-7D60-472F-BA1A-A39EF669E4B2=1|be9ba2d9-53ea-4cdc-84e5-9b1eeee46550=1|01443614-CD74-433A-B99E-2ECDC07BFC25=1|5beb7efe-fd9a-4556-801d-275e5ffc04cc=1|D3E037E1-3EB8-44C8-A917-57927947596D=1|3b576869-a4ec-4529-8536-b80a7769e899=1|75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84=1|26190899-1602-49e8-8b27-eb1d0a1ce869=1|E6DB77E5-3DF2-4CF1-B95A-636979351E5B=1|d1e49aac-8f56-4280-b9ba-993a6d77406c=1|33DDEDF1-C6E0-47CB-833E-DE6133960387=1|b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4=1|92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B=1|c1db55ab-c21a-4637-bb3f-a12568109d35=1|be9ba2d9-53ea-4cdc-84e5-9b1eeee46550=6"}])
	"2.14: Ensure 'ASR: Block executable content from email client and webmail' is set to 'Block'" in b.violations with input as bad
}

test_2_14_evidence_missing if {
	bad := json.patch(green, [{"op": "remove", "path": "/intune_defender/settings/AttackSurfaceReductionRules"}])
	"2.14: evidence missing — intune_defender.settings.AttackSurfaceReductionRules not collected" in b.violations with input as bad
}

# 2.15
test_2_15_pass if {
	v := b.violations with input as green
	count([msg | some msg in v; startswith(msg, "2.15:")]) == 0
}

test_2_15_fail_1 if {
	bad := json.patch(green, [{"op": "replace", "path": "/intune_defender/settings/AttackSurfaceReductionRules", "value": "56a863a9-875e-4185-98a7-b882c64b5ce5=1|7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c=1|d4f940ab-401b-4efc-aadc-ad5f3c50688a=1|9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2=1|be9ba2d9-53ea-4cdc-84e5-9b1eeee46550=1|01443614-cd74-433a-b99e-2ecdc07bfc25=0|5beb7efe-fd9a-4556-801d-275e5ffc04cc=1|d3e037e1-3eb8-44c8-a917-57927947596d=1|3b576869-a4ec-4529-8536-b80a7769e899=1|75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84=1|26190899-1602-49e8-8b27-eb1d0a1ce869=1|e6db77e5-3df2-4cf1-b95a-636979351e5b=1|d1e49aac-8f56-4280-b9ba-993a6d77406c=1|33ddedf1-c6e0-47cb-833e-de6133960387=1|b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4=1|92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b=1|c1db55ab-c21a-4637-bb3f-a12568109d35=1"}])
	"2.15: Ensure 'ASR: Block executable files from running unless they meet a prevalence, age, or trusted list criterion' is set to 'Audit' or higher" in b.violations with input as bad
}

test_2_15_fail_2 if {
	bad := json.patch(green, [{"op": "replace", "path": "/intune_defender/settings/AttackSurfaceReductionRules", "value": "56a863a9-875e-4185-98a7-b882c64b5ce5=1|7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c=1|d4f940ab-401b-4efc-aadc-ad5f3c50688a=1|9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2=1|be9ba2d9-53ea-4cdc-84e5-9b1eeee46550=1|5beb7efe-fd9a-4556-801d-275e5ffc04cc=1|d3e037e1-3eb8-44c8-a917-57927947596d=1|3b576869-a4ec-4529-8536-b80a7769e899=1|75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84=1|26190899-1602-49e8-8b27-eb1d0a1ce869=1|e6db77e5-3df2-4cf1-b95a-636979351e5b=1|d1e49aac-8f56-4280-b9ba-993a6d77406c=1|33ddedf1-c6e0-47cb-833e-de6133960387=1|b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4=1|92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b=1|c1db55ab-c21a-4637-bb3f-a12568109d35=1"}])
	"2.15: Ensure 'ASR: Block executable files from running unless they meet a prevalence, age, or trusted list criterion' is set to 'Audit' or higher" in b.violations with input as bad
}

test_2_15_fail_3 if {
	bad := json.patch(green, [{"op": "replace", "path": "/intune_defender/settings/AttackSurfaceReductionRules", "value": "56a863a9-875e-4185-98a7-b882c64b5ce5=1|7674BA52-37EB-4A4F-A9A1-F0F9A1619A2C=1|d4f940ab-401b-4efc-aadc-ad5f3c50688a=1|9E6C4E1F-7D60-472F-BA1A-A39EF669E4B2=1|be9ba2d9-53ea-4cdc-84e5-9b1eeee46550=1|01443614-CD74-433A-B99E-2ECDC07BFC25=1|5beb7efe-fd9a-4556-801d-275e5ffc04cc=1|D3E037E1-3EB8-44C8-A917-57927947596D=1|3b576869-a4ec-4529-8536-b80a7769e899=1|75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84=1|26190899-1602-49e8-8b27-eb1d0a1ce869=1|E6DB77E5-3DF2-4CF1-B95A-636979351E5B=1|d1e49aac-8f56-4280-b9ba-993a6d77406c=1|33DDEDF1-C6E0-47CB-833E-DE6133960387=1|b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4=1|92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B=1|c1db55ab-c21a-4637-bb3f-a12568109d35=1|01443614-cd74-433a-b99e-2ecdc07bfc25=6"}])
	"2.15: Ensure 'ASR: Block executable files from running unless they meet a prevalence, age, or trusted list criterion' is set to 'Audit' or higher" in b.violations with input as bad
}

test_2_15_evidence_missing if {
	bad := json.patch(green, [{"op": "remove", "path": "/intune_defender/settings/AttackSurfaceReductionRules"}])
	"2.15: evidence missing — intune_defender.settings.AttackSurfaceReductionRules not collected" in b.violations with input as bad
}

# 2.16
test_2_16_pass if {
	v := b.violations with input as green
	count([msg | some msg in v; startswith(msg, "2.16:")]) == 0
}

test_2_16_fail_1 if {
	bad := json.patch(green, [{"op": "replace", "path": "/intune_defender/settings/AttackSurfaceReductionRules", "value": "56a863a9-875e-4185-98a7-b882c64b5ce5=1|7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c=1|d4f940ab-401b-4efc-aadc-ad5f3c50688a=1|9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2=1|be9ba2d9-53ea-4cdc-84e5-9b1eeee46550=1|01443614-cd74-433a-b99e-2ecdc07bfc25=1|5beb7efe-fd9a-4556-801d-275e5ffc04cc=0|d3e037e1-3eb8-44c8-a917-57927947596d=1|3b576869-a4ec-4529-8536-b80a7769e899=1|75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84=1|26190899-1602-49e8-8b27-eb1d0a1ce869=1|e6db77e5-3df2-4cf1-b95a-636979351e5b=1|d1e49aac-8f56-4280-b9ba-993a6d77406c=1|33ddedf1-c6e0-47cb-833e-de6133960387=1|b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4=1|92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b=1|c1db55ab-c21a-4637-bb3f-a12568109d35=1"}])
	"2.16: Ensure 'ASR: Block execution of potentially obfuscated scripts' is set to 'Audit' or higher" in b.violations with input as bad
}

test_2_16_fail_2 if {
	bad := json.patch(green, [{"op": "replace", "path": "/intune_defender/settings/AttackSurfaceReductionRules", "value": "56a863a9-875e-4185-98a7-b882c64b5ce5=1|7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c=1|d4f940ab-401b-4efc-aadc-ad5f3c50688a=1|9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2=1|be9ba2d9-53ea-4cdc-84e5-9b1eeee46550=1|01443614-cd74-433a-b99e-2ecdc07bfc25=1|d3e037e1-3eb8-44c8-a917-57927947596d=1|3b576869-a4ec-4529-8536-b80a7769e899=1|75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84=1|26190899-1602-49e8-8b27-eb1d0a1ce869=1|e6db77e5-3df2-4cf1-b95a-636979351e5b=1|d1e49aac-8f56-4280-b9ba-993a6d77406c=1|33ddedf1-c6e0-47cb-833e-de6133960387=1|b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4=1|92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b=1|c1db55ab-c21a-4637-bb3f-a12568109d35=1"}])
	"2.16: Ensure 'ASR: Block execution of potentially obfuscated scripts' is set to 'Audit' or higher" in b.violations with input as bad
}

test_2_16_fail_3 if {
	bad := json.patch(green, [{"op": "replace", "path": "/intune_defender/settings/AttackSurfaceReductionRules", "value": "56a863a9-875e-4185-98a7-b882c64b5ce5=1|7674BA52-37EB-4A4F-A9A1-F0F9A1619A2C=1|d4f940ab-401b-4efc-aadc-ad5f3c50688a=1|9E6C4E1F-7D60-472F-BA1A-A39EF669E4B2=1|be9ba2d9-53ea-4cdc-84e5-9b1eeee46550=1|01443614-CD74-433A-B99E-2ECDC07BFC25=1|5beb7efe-fd9a-4556-801d-275e5ffc04cc=1|D3E037E1-3EB8-44C8-A917-57927947596D=1|3b576869-a4ec-4529-8536-b80a7769e899=1|75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84=1|26190899-1602-49e8-8b27-eb1d0a1ce869=1|E6DB77E5-3DF2-4CF1-B95A-636979351E5B=1|d1e49aac-8f56-4280-b9ba-993a6d77406c=1|33DDEDF1-C6E0-47CB-833E-DE6133960387=1|b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4=1|92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B=1|c1db55ab-c21a-4637-bb3f-a12568109d35=1|5beb7efe-fd9a-4556-801d-275e5ffc04cc=6"}])
	"2.16: Ensure 'ASR: Block execution of potentially obfuscated scripts' is set to 'Audit' or higher" in b.violations with input as bad
}

test_2_16_evidence_missing if {
	bad := json.patch(green, [{"op": "remove", "path": "/intune_defender/settings/AttackSurfaceReductionRules"}])
	"2.16: evidence missing — intune_defender.settings.AttackSurfaceReductionRules not collected" in b.violations with input as bad
}

# 2.17
test_2_17_pass if {
	v := b.violations with input as green
	count([msg | some msg in v; startswith(msg, "2.17:")]) == 0
}

test_2_17_fail_1 if {
	bad := json.patch(green, [{"op": "replace", "path": "/intune_defender/settings/AttackSurfaceReductionRules", "value": "56a863a9-875e-4185-98a7-b882c64b5ce5=1|7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c=1|d4f940ab-401b-4efc-aadc-ad5f3c50688a=1|9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2=1|be9ba2d9-53ea-4cdc-84e5-9b1eeee46550=1|01443614-cd74-433a-b99e-2ecdc07bfc25=1|5beb7efe-fd9a-4556-801d-275e5ffc04cc=1|d3e037e1-3eb8-44c8-a917-57927947596d=2|3b576869-a4ec-4529-8536-b80a7769e899=1|75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84=1|26190899-1602-49e8-8b27-eb1d0a1ce869=1|e6db77e5-3df2-4cf1-b95a-636979351e5b=1|d1e49aac-8f56-4280-b9ba-993a6d77406c=1|33ddedf1-c6e0-47cb-833e-de6133960387=1|b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4=1|92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b=1|c1db55ab-c21a-4637-bb3f-a12568109d35=1"}])
	"2.17: Ensure 'ASR: Block JavaScript or VBScript from launching downloaded executable content' is set to 'Block'" in b.violations with input as bad
}

test_2_17_fail_2 if {
	bad := json.patch(green, [{"op": "replace", "path": "/intune_defender/settings/AttackSurfaceReductionRules", "value": "56a863a9-875e-4185-98a7-b882c64b5ce5=1|7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c=1|d4f940ab-401b-4efc-aadc-ad5f3c50688a=1|9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2=1|be9ba2d9-53ea-4cdc-84e5-9b1eeee46550=1|01443614-cd74-433a-b99e-2ecdc07bfc25=1|5beb7efe-fd9a-4556-801d-275e5ffc04cc=1|3b576869-a4ec-4529-8536-b80a7769e899=1|75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84=1|26190899-1602-49e8-8b27-eb1d0a1ce869=1|e6db77e5-3df2-4cf1-b95a-636979351e5b=1|d1e49aac-8f56-4280-b9ba-993a6d77406c=1|33ddedf1-c6e0-47cb-833e-de6133960387=1|b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4=1|92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b=1|c1db55ab-c21a-4637-bb3f-a12568109d35=1"}])
	"2.17: Ensure 'ASR: Block JavaScript or VBScript from launching downloaded executable content' is set to 'Block'" in b.violations with input as bad
}

test_2_17_fail_3 if {
	bad := json.patch(green, [{"op": "replace", "path": "/intune_defender/settings/AttackSurfaceReductionRules", "value": "56a863a9-875e-4185-98a7-b882c64b5ce5=1|7674BA52-37EB-4A4F-A9A1-F0F9A1619A2C=1|d4f940ab-401b-4efc-aadc-ad5f3c50688a=1|9E6C4E1F-7D60-472F-BA1A-A39EF669E4B2=1|be9ba2d9-53ea-4cdc-84e5-9b1eeee46550=1|01443614-CD74-433A-B99E-2ECDC07BFC25=1|5beb7efe-fd9a-4556-801d-275e5ffc04cc=1|D3E037E1-3EB8-44C8-A917-57927947596D=1|3b576869-a4ec-4529-8536-b80a7769e899=1|75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84=1|26190899-1602-49e8-8b27-eb1d0a1ce869=1|E6DB77E5-3DF2-4CF1-B95A-636979351E5B=1|d1e49aac-8f56-4280-b9ba-993a6d77406c=1|33DDEDF1-C6E0-47CB-833E-DE6133960387=1|b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4=1|92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B=1|c1db55ab-c21a-4637-bb3f-a12568109d35=1|d3e037e1-3eb8-44c8-a917-57927947596d=6"}])
	"2.17: Ensure 'ASR: Block JavaScript or VBScript from launching downloaded executable content' is set to 'Block'" in b.violations with input as bad
}

test_2_17_evidence_missing if {
	bad := json.patch(green, [{"op": "remove", "path": "/intune_defender/settings/AttackSurfaceReductionRules"}])
	"2.17: evidence missing — intune_defender.settings.AttackSurfaceReductionRules not collected" in b.violations with input as bad
}

# 2.18
test_2_18_pass if {
	v := b.violations with input as green
	count([msg | some msg in v; startswith(msg, "2.18:")]) == 0
}

test_2_18_fail_1 if {
	bad := json.patch(green, [{"op": "replace", "path": "/intune_defender/settings/AttackSurfaceReductionRules", "value": "56a863a9-875e-4185-98a7-b882c64b5ce5=1|7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c=1|d4f940ab-401b-4efc-aadc-ad5f3c50688a=1|9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2=1|be9ba2d9-53ea-4cdc-84e5-9b1eeee46550=1|01443614-cd74-433a-b99e-2ecdc07bfc25=1|5beb7efe-fd9a-4556-801d-275e5ffc04cc=1|d3e037e1-3eb8-44c8-a917-57927947596d=1|3b576869-a4ec-4529-8536-b80a7769e899=2|75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84=1|26190899-1602-49e8-8b27-eb1d0a1ce869=1|e6db77e5-3df2-4cf1-b95a-636979351e5b=1|d1e49aac-8f56-4280-b9ba-993a6d77406c=1|33ddedf1-c6e0-47cb-833e-de6133960387=1|b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4=1|92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b=1|c1db55ab-c21a-4637-bb3f-a12568109d35=1"}])
	"2.18: Ensure 'ASR: Block Office applications from creating executable content' is set to 'Block'" in b.violations with input as bad
}

test_2_18_fail_2 if {
	bad := json.patch(green, [{"op": "replace", "path": "/intune_defender/settings/AttackSurfaceReductionRules", "value": "56a863a9-875e-4185-98a7-b882c64b5ce5=1|7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c=1|d4f940ab-401b-4efc-aadc-ad5f3c50688a=1|9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2=1|be9ba2d9-53ea-4cdc-84e5-9b1eeee46550=1|01443614-cd74-433a-b99e-2ecdc07bfc25=1|5beb7efe-fd9a-4556-801d-275e5ffc04cc=1|d3e037e1-3eb8-44c8-a917-57927947596d=1|75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84=1|26190899-1602-49e8-8b27-eb1d0a1ce869=1|e6db77e5-3df2-4cf1-b95a-636979351e5b=1|d1e49aac-8f56-4280-b9ba-993a6d77406c=1|33ddedf1-c6e0-47cb-833e-de6133960387=1|b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4=1|92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b=1|c1db55ab-c21a-4637-bb3f-a12568109d35=1"}])
	"2.18: Ensure 'ASR: Block Office applications from creating executable content' is set to 'Block'" in b.violations with input as bad
}

test_2_18_fail_3 if {
	bad := json.patch(green, [{"op": "replace", "path": "/intune_defender/settings/AttackSurfaceReductionRules", "value": "56a863a9-875e-4185-98a7-b882c64b5ce5=1|7674BA52-37EB-4A4F-A9A1-F0F9A1619A2C=1|d4f940ab-401b-4efc-aadc-ad5f3c50688a=1|9E6C4E1F-7D60-472F-BA1A-A39EF669E4B2=1|be9ba2d9-53ea-4cdc-84e5-9b1eeee46550=1|01443614-CD74-433A-B99E-2ECDC07BFC25=1|5beb7efe-fd9a-4556-801d-275e5ffc04cc=1|D3E037E1-3EB8-44C8-A917-57927947596D=1|3b576869-a4ec-4529-8536-b80a7769e899=1|75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84=1|26190899-1602-49e8-8b27-eb1d0a1ce869=1|E6DB77E5-3DF2-4CF1-B95A-636979351E5B=1|d1e49aac-8f56-4280-b9ba-993a6d77406c=1|33DDEDF1-C6E0-47CB-833E-DE6133960387=1|b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4=1|92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B=1|c1db55ab-c21a-4637-bb3f-a12568109d35=1|3b576869-a4ec-4529-8536-b80a7769e899=6"}])
	"2.18: Ensure 'ASR: Block Office applications from creating executable content' is set to 'Block'" in b.violations with input as bad
}

test_2_18_evidence_missing if {
	bad := json.patch(green, [{"op": "remove", "path": "/intune_defender/settings/AttackSurfaceReductionRules"}])
	"2.18: evidence missing — intune_defender.settings.AttackSurfaceReductionRules not collected" in b.violations with input as bad
}

# 2.19
test_2_19_pass if {
	v := b.violations with input as green
	count([msg | some msg in v; startswith(msg, "2.19:")]) == 0
}

test_2_19_fail_1 if {
	bad := json.patch(green, [{"op": "replace", "path": "/intune_defender/settings/AttackSurfaceReductionRules", "value": "56a863a9-875e-4185-98a7-b882c64b5ce5=1|7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c=1|d4f940ab-401b-4efc-aadc-ad5f3c50688a=1|9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2=1|be9ba2d9-53ea-4cdc-84e5-9b1eeee46550=1|01443614-cd74-433a-b99e-2ecdc07bfc25=1|5beb7efe-fd9a-4556-801d-275e5ffc04cc=1|d3e037e1-3eb8-44c8-a917-57927947596d=1|3b576869-a4ec-4529-8536-b80a7769e899=1|75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84=2|26190899-1602-49e8-8b27-eb1d0a1ce869=1|e6db77e5-3df2-4cf1-b95a-636979351e5b=1|d1e49aac-8f56-4280-b9ba-993a6d77406c=1|33ddedf1-c6e0-47cb-833e-de6133960387=1|b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4=1|92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b=1|c1db55ab-c21a-4637-bb3f-a12568109d35=1"}])
	"2.19: Ensure 'ASR: Block Office applications from injecting code into other processes' is set to 'Block'" in b.violations with input as bad
}

test_2_19_fail_2 if {
	bad := json.patch(green, [{"op": "replace", "path": "/intune_defender/settings/AttackSurfaceReductionRules", "value": "56a863a9-875e-4185-98a7-b882c64b5ce5=1|7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c=1|d4f940ab-401b-4efc-aadc-ad5f3c50688a=1|9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2=1|be9ba2d9-53ea-4cdc-84e5-9b1eeee46550=1|01443614-cd74-433a-b99e-2ecdc07bfc25=1|5beb7efe-fd9a-4556-801d-275e5ffc04cc=1|d3e037e1-3eb8-44c8-a917-57927947596d=1|3b576869-a4ec-4529-8536-b80a7769e899=1|26190899-1602-49e8-8b27-eb1d0a1ce869=1|e6db77e5-3df2-4cf1-b95a-636979351e5b=1|d1e49aac-8f56-4280-b9ba-993a6d77406c=1|33ddedf1-c6e0-47cb-833e-de6133960387=1|b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4=1|92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b=1|c1db55ab-c21a-4637-bb3f-a12568109d35=1"}])
	"2.19: Ensure 'ASR: Block Office applications from injecting code into other processes' is set to 'Block'" in b.violations with input as bad
}

test_2_19_fail_3 if {
	bad := json.patch(green, [{"op": "replace", "path": "/intune_defender/settings/AttackSurfaceReductionRules", "value": "56a863a9-875e-4185-98a7-b882c64b5ce5=1|7674BA52-37EB-4A4F-A9A1-F0F9A1619A2C=1|d4f940ab-401b-4efc-aadc-ad5f3c50688a=1|9E6C4E1F-7D60-472F-BA1A-A39EF669E4B2=1|be9ba2d9-53ea-4cdc-84e5-9b1eeee46550=1|01443614-CD74-433A-B99E-2ECDC07BFC25=1|5beb7efe-fd9a-4556-801d-275e5ffc04cc=1|D3E037E1-3EB8-44C8-A917-57927947596D=1|3b576869-a4ec-4529-8536-b80a7769e899=1|75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84=1|26190899-1602-49e8-8b27-eb1d0a1ce869=1|E6DB77E5-3DF2-4CF1-B95A-636979351E5B=1|d1e49aac-8f56-4280-b9ba-993a6d77406c=1|33DDEDF1-C6E0-47CB-833E-DE6133960387=1|b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4=1|92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B=1|c1db55ab-c21a-4637-bb3f-a12568109d35=1|75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84=6"}])
	"2.19: Ensure 'ASR: Block Office applications from injecting code into other processes' is set to 'Block'" in b.violations with input as bad
}

test_2_19_evidence_missing if {
	bad := json.patch(green, [{"op": "remove", "path": "/intune_defender/settings/AttackSurfaceReductionRules"}])
	"2.19: evidence missing — intune_defender.settings.AttackSurfaceReductionRules not collected" in b.violations with input as bad
}

# 2.20
test_2_20_pass if {
	v := b.violations with input as green
	count([msg | some msg in v; startswith(msg, "2.20:")]) == 0
}

test_2_20_fail_1 if {
	bad := json.patch(green, [{"op": "replace", "path": "/intune_defender/settings/AttackSurfaceReductionRules", "value": "56a863a9-875e-4185-98a7-b882c64b5ce5=1|7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c=1|d4f940ab-401b-4efc-aadc-ad5f3c50688a=1|9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2=1|be9ba2d9-53ea-4cdc-84e5-9b1eeee46550=1|01443614-cd74-433a-b99e-2ecdc07bfc25=1|5beb7efe-fd9a-4556-801d-275e5ffc04cc=1|d3e037e1-3eb8-44c8-a917-57927947596d=1|3b576869-a4ec-4529-8536-b80a7769e899=1|75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84=1|26190899-1602-49e8-8b27-eb1d0a1ce869=0|e6db77e5-3df2-4cf1-b95a-636979351e5b=1|d1e49aac-8f56-4280-b9ba-993a6d77406c=1|33ddedf1-c6e0-47cb-833e-de6133960387=1|b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4=1|92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b=1|c1db55ab-c21a-4637-bb3f-a12568109d35=1"}])
	"2.20: Ensure 'ASR: Block Office communication application from creating child processes' is set to 'Audit' or higher" in b.violations with input as bad
}

test_2_20_fail_2 if {
	bad := json.patch(green, [{"op": "replace", "path": "/intune_defender/settings/AttackSurfaceReductionRules", "value": "56a863a9-875e-4185-98a7-b882c64b5ce5=1|7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c=1|d4f940ab-401b-4efc-aadc-ad5f3c50688a=1|9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2=1|be9ba2d9-53ea-4cdc-84e5-9b1eeee46550=1|01443614-cd74-433a-b99e-2ecdc07bfc25=1|5beb7efe-fd9a-4556-801d-275e5ffc04cc=1|d3e037e1-3eb8-44c8-a917-57927947596d=1|3b576869-a4ec-4529-8536-b80a7769e899=1|75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84=1|e6db77e5-3df2-4cf1-b95a-636979351e5b=1|d1e49aac-8f56-4280-b9ba-993a6d77406c=1|33ddedf1-c6e0-47cb-833e-de6133960387=1|b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4=1|92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b=1|c1db55ab-c21a-4637-bb3f-a12568109d35=1"}])
	"2.20: Ensure 'ASR: Block Office communication application from creating child processes' is set to 'Audit' or higher" in b.violations with input as bad
}

test_2_20_fail_3 if {
	bad := json.patch(green, [{"op": "replace", "path": "/intune_defender/settings/AttackSurfaceReductionRules", "value": "56a863a9-875e-4185-98a7-b882c64b5ce5=1|7674BA52-37EB-4A4F-A9A1-F0F9A1619A2C=1|d4f940ab-401b-4efc-aadc-ad5f3c50688a=1|9E6C4E1F-7D60-472F-BA1A-A39EF669E4B2=1|be9ba2d9-53ea-4cdc-84e5-9b1eeee46550=1|01443614-CD74-433A-B99E-2ECDC07BFC25=1|5beb7efe-fd9a-4556-801d-275e5ffc04cc=1|D3E037E1-3EB8-44C8-A917-57927947596D=1|3b576869-a4ec-4529-8536-b80a7769e899=1|75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84=1|26190899-1602-49e8-8b27-eb1d0a1ce869=1|E6DB77E5-3DF2-4CF1-B95A-636979351E5B=1|d1e49aac-8f56-4280-b9ba-993a6d77406c=1|33DDEDF1-C6E0-47CB-833E-DE6133960387=1|b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4=1|92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B=1|c1db55ab-c21a-4637-bb3f-a12568109d35=1|26190899-1602-49e8-8b27-eb1d0a1ce869=6"}])
	"2.20: Ensure 'ASR: Block Office communication application from creating child processes' is set to 'Audit' or higher" in b.violations with input as bad
}

test_2_20_evidence_missing if {
	bad := json.patch(green, [{"op": "remove", "path": "/intune_defender/settings/AttackSurfaceReductionRules"}])
	"2.20: evidence missing — intune_defender.settings.AttackSurfaceReductionRules not collected" in b.violations with input as bad
}

# 2.21
test_2_21_pass if {
	v := b.violations with input as green
	count([msg | some msg in v; startswith(msg, "2.21:")]) == 0
}

test_2_21_fail_1 if {
	bad := json.patch(green, [{"op": "replace", "path": "/intune_defender/settings/AttackSurfaceReductionRules", "value": "56a863a9-875e-4185-98a7-b882c64b5ce5=1|7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c=1|d4f940ab-401b-4efc-aadc-ad5f3c50688a=1|9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2=1|be9ba2d9-53ea-4cdc-84e5-9b1eeee46550=1|01443614-cd74-433a-b99e-2ecdc07bfc25=1|5beb7efe-fd9a-4556-801d-275e5ffc04cc=1|d3e037e1-3eb8-44c8-a917-57927947596d=1|3b576869-a4ec-4529-8536-b80a7769e899=1|75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84=1|26190899-1602-49e8-8b27-eb1d0a1ce869=1|e6db77e5-3df2-4cf1-b95a-636979351e5b=2|d1e49aac-8f56-4280-b9ba-993a6d77406c=1|33ddedf1-c6e0-47cb-833e-de6133960387=1|b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4=1|92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b=1|c1db55ab-c21a-4637-bb3f-a12568109d35=1"}])
	"2.21: Ensure 'ASR: Block persistence through WMI event subscription' is set to 'Block'" in b.violations with input as bad
}

test_2_21_fail_2 if {
	bad := json.patch(green, [{"op": "replace", "path": "/intune_defender/settings/AttackSurfaceReductionRules", "value": "56a863a9-875e-4185-98a7-b882c64b5ce5=1|7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c=1|d4f940ab-401b-4efc-aadc-ad5f3c50688a=1|9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2=1|be9ba2d9-53ea-4cdc-84e5-9b1eeee46550=1|01443614-cd74-433a-b99e-2ecdc07bfc25=1|5beb7efe-fd9a-4556-801d-275e5ffc04cc=1|d3e037e1-3eb8-44c8-a917-57927947596d=1|3b576869-a4ec-4529-8536-b80a7769e899=1|75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84=1|26190899-1602-49e8-8b27-eb1d0a1ce869=1|d1e49aac-8f56-4280-b9ba-993a6d77406c=1|33ddedf1-c6e0-47cb-833e-de6133960387=1|b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4=1|92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b=1|c1db55ab-c21a-4637-bb3f-a12568109d35=1"}])
	"2.21: Ensure 'ASR: Block persistence through WMI event subscription' is set to 'Block'" in b.violations with input as bad
}

test_2_21_fail_3 if {
	bad := json.patch(green, [{"op": "replace", "path": "/intune_defender/settings/AttackSurfaceReductionRules", "value": "56a863a9-875e-4185-98a7-b882c64b5ce5=1|7674BA52-37EB-4A4F-A9A1-F0F9A1619A2C=1|d4f940ab-401b-4efc-aadc-ad5f3c50688a=1|9E6C4E1F-7D60-472F-BA1A-A39EF669E4B2=1|be9ba2d9-53ea-4cdc-84e5-9b1eeee46550=1|01443614-CD74-433A-B99E-2ECDC07BFC25=1|5beb7efe-fd9a-4556-801d-275e5ffc04cc=1|D3E037E1-3EB8-44C8-A917-57927947596D=1|3b576869-a4ec-4529-8536-b80a7769e899=1|75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84=1|26190899-1602-49e8-8b27-eb1d0a1ce869=1|E6DB77E5-3DF2-4CF1-B95A-636979351E5B=1|d1e49aac-8f56-4280-b9ba-993a6d77406c=1|33DDEDF1-C6E0-47CB-833E-DE6133960387=1|b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4=1|92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B=1|c1db55ab-c21a-4637-bb3f-a12568109d35=1|e6db77e5-3df2-4cf1-b95a-636979351e5b=6"}])
	"2.21: Ensure 'ASR: Block persistence through WMI event subscription' is set to 'Block'" in b.violations with input as bad
}

test_2_21_evidence_missing if {
	bad := json.patch(green, [{"op": "remove", "path": "/intune_defender/settings/AttackSurfaceReductionRules"}])
	"2.21: evidence missing — intune_defender.settings.AttackSurfaceReductionRules not collected" in b.violations with input as bad
}

# 2.22
test_2_22_pass if {
	v := b.violations with input as green
	count([msg | some msg in v; startswith(msg, "2.22:")]) == 0
}

test_2_22_fail_1 if {
	bad := json.patch(green, [{"op": "replace", "path": "/intune_defender/settings/AttackSurfaceReductionRules", "value": "56a863a9-875e-4185-98a7-b882c64b5ce5=1|7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c=1|d4f940ab-401b-4efc-aadc-ad5f3c50688a=1|9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2=1|be9ba2d9-53ea-4cdc-84e5-9b1eeee46550=1|01443614-cd74-433a-b99e-2ecdc07bfc25=1|5beb7efe-fd9a-4556-801d-275e5ffc04cc=1|d3e037e1-3eb8-44c8-a917-57927947596d=1|3b576869-a4ec-4529-8536-b80a7769e899=1|75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84=1|26190899-1602-49e8-8b27-eb1d0a1ce869=1|e6db77e5-3df2-4cf1-b95a-636979351e5b=1|d1e49aac-8f56-4280-b9ba-993a6d77406c=0|33ddedf1-c6e0-47cb-833e-de6133960387=1|b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4=1|92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b=1|c1db55ab-c21a-4637-bb3f-a12568109d35=1"}])
	"2.22: Ensure 'ASR: Block process creations originating from PSExec and WMI commands' is set to 'Audit' or higher" in b.violations with input as bad
}

test_2_22_fail_2 if {
	bad := json.patch(green, [{"op": "replace", "path": "/intune_defender/settings/AttackSurfaceReductionRules", "value": "56a863a9-875e-4185-98a7-b882c64b5ce5=1|7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c=1|d4f940ab-401b-4efc-aadc-ad5f3c50688a=1|9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2=1|be9ba2d9-53ea-4cdc-84e5-9b1eeee46550=1|01443614-cd74-433a-b99e-2ecdc07bfc25=1|5beb7efe-fd9a-4556-801d-275e5ffc04cc=1|d3e037e1-3eb8-44c8-a917-57927947596d=1|3b576869-a4ec-4529-8536-b80a7769e899=1|75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84=1|26190899-1602-49e8-8b27-eb1d0a1ce869=1|e6db77e5-3df2-4cf1-b95a-636979351e5b=1|33ddedf1-c6e0-47cb-833e-de6133960387=1|b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4=1|92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b=1|c1db55ab-c21a-4637-bb3f-a12568109d35=1"}])
	"2.22: Ensure 'ASR: Block process creations originating from PSExec and WMI commands' is set to 'Audit' or higher" in b.violations with input as bad
}

test_2_22_fail_3 if {
	bad := json.patch(green, [{"op": "replace", "path": "/intune_defender/settings/AttackSurfaceReductionRules", "value": "56a863a9-875e-4185-98a7-b882c64b5ce5=1|7674BA52-37EB-4A4F-A9A1-F0F9A1619A2C=1|d4f940ab-401b-4efc-aadc-ad5f3c50688a=1|9E6C4E1F-7D60-472F-BA1A-A39EF669E4B2=1|be9ba2d9-53ea-4cdc-84e5-9b1eeee46550=1|01443614-CD74-433A-B99E-2ECDC07BFC25=1|5beb7efe-fd9a-4556-801d-275e5ffc04cc=1|D3E037E1-3EB8-44C8-A917-57927947596D=1|3b576869-a4ec-4529-8536-b80a7769e899=1|75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84=1|26190899-1602-49e8-8b27-eb1d0a1ce869=1|E6DB77E5-3DF2-4CF1-B95A-636979351E5B=1|d1e49aac-8f56-4280-b9ba-993a6d77406c=1|33DDEDF1-C6E0-47CB-833E-DE6133960387=1|b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4=1|92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B=1|c1db55ab-c21a-4637-bb3f-a12568109d35=1|d1e49aac-8f56-4280-b9ba-993a6d77406c=6"}])
	"2.22: Ensure 'ASR: Block process creations originating from PSExec and WMI commands' is set to 'Audit' or higher" in b.violations with input as bad
}

test_2_22_evidence_missing if {
	bad := json.patch(green, [{"op": "remove", "path": "/intune_defender/settings/AttackSurfaceReductionRules"}])
	"2.22: evidence missing — intune_defender.settings.AttackSurfaceReductionRules not collected" in b.violations with input as bad
}

# 2.23
test_2_23_pass if {
	v := b.violations with input as green
	count([msg | some msg in v; startswith(msg, "2.23:")]) == 0
}

test_2_23_fail_1 if {
	bad := json.patch(green, [{"op": "replace", "path": "/intune_defender/settings/AttackSurfaceReductionRules", "value": "56a863a9-875e-4185-98a7-b882c64b5ce5=1|7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c=1|d4f940ab-401b-4efc-aadc-ad5f3c50688a=1|9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2=1|be9ba2d9-53ea-4cdc-84e5-9b1eeee46550=1|01443614-cd74-433a-b99e-2ecdc07bfc25=1|5beb7efe-fd9a-4556-801d-275e5ffc04cc=1|d3e037e1-3eb8-44c8-a917-57927947596d=1|3b576869-a4ec-4529-8536-b80a7769e899=1|75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84=1|26190899-1602-49e8-8b27-eb1d0a1ce869=1|e6db77e5-3df2-4cf1-b95a-636979351e5b=1|d1e49aac-8f56-4280-b9ba-993a6d77406c=1|33ddedf1-c6e0-47cb-833e-de6133960387=2|b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4=1|92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b=1|c1db55ab-c21a-4637-bb3f-a12568109d35=1"}])
	"2.23: Ensure 'ASR: Block rebooting machine in Safe Mode' is set to 'Block'" in b.violations with input as bad
}

test_2_23_fail_2 if {
	bad := json.patch(green, [{"op": "replace", "path": "/intune_defender/settings/AttackSurfaceReductionRules", "value": "56a863a9-875e-4185-98a7-b882c64b5ce5=1|7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c=1|d4f940ab-401b-4efc-aadc-ad5f3c50688a=1|9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2=1|be9ba2d9-53ea-4cdc-84e5-9b1eeee46550=1|01443614-cd74-433a-b99e-2ecdc07bfc25=1|5beb7efe-fd9a-4556-801d-275e5ffc04cc=1|d3e037e1-3eb8-44c8-a917-57927947596d=1|3b576869-a4ec-4529-8536-b80a7769e899=1|75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84=1|26190899-1602-49e8-8b27-eb1d0a1ce869=1|e6db77e5-3df2-4cf1-b95a-636979351e5b=1|d1e49aac-8f56-4280-b9ba-993a6d77406c=1|b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4=1|92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b=1|c1db55ab-c21a-4637-bb3f-a12568109d35=1"}])
	"2.23: Ensure 'ASR: Block rebooting machine in Safe Mode' is set to 'Block'" in b.violations with input as bad
}

test_2_23_fail_3 if {
	bad := json.patch(green, [{"op": "replace", "path": "/intune_defender/settings/AttackSurfaceReductionRules", "value": "56a863a9-875e-4185-98a7-b882c64b5ce5=1|7674BA52-37EB-4A4F-A9A1-F0F9A1619A2C=1|d4f940ab-401b-4efc-aadc-ad5f3c50688a=1|9E6C4E1F-7D60-472F-BA1A-A39EF669E4B2=1|be9ba2d9-53ea-4cdc-84e5-9b1eeee46550=1|01443614-CD74-433A-B99E-2ECDC07BFC25=1|5beb7efe-fd9a-4556-801d-275e5ffc04cc=1|D3E037E1-3EB8-44C8-A917-57927947596D=1|3b576869-a4ec-4529-8536-b80a7769e899=1|75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84=1|26190899-1602-49e8-8b27-eb1d0a1ce869=1|E6DB77E5-3DF2-4CF1-B95A-636979351E5B=1|d1e49aac-8f56-4280-b9ba-993a6d77406c=1|33DDEDF1-C6E0-47CB-833E-DE6133960387=1|b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4=1|92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B=1|c1db55ab-c21a-4637-bb3f-a12568109d35=1|33ddedf1-c6e0-47cb-833e-de6133960387=6"}])
	"2.23: Ensure 'ASR: Block rebooting machine in Safe Mode' is set to 'Block'" in b.violations with input as bad
}

test_2_23_evidence_missing if {
	bad := json.patch(green, [{"op": "remove", "path": "/intune_defender/settings/AttackSurfaceReductionRules"}])
	"2.23: evidence missing — intune_defender.settings.AttackSurfaceReductionRules not collected" in b.violations with input as bad
}

# 2.24
test_2_24_pass if {
	v := b.violations with input as green
	count([msg | some msg in v; startswith(msg, "2.24:")]) == 0
}

test_2_24_fail_1 if {
	bad := json.patch(green, [{"op": "replace", "path": "/intune_defender/settings/AttackSurfaceReductionRules", "value": "56a863a9-875e-4185-98a7-b882c64b5ce5=1|7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c=1|d4f940ab-401b-4efc-aadc-ad5f3c50688a=1|9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2=1|be9ba2d9-53ea-4cdc-84e5-9b1eeee46550=1|01443614-cd74-433a-b99e-2ecdc07bfc25=1|5beb7efe-fd9a-4556-801d-275e5ffc04cc=1|d3e037e1-3eb8-44c8-a917-57927947596d=1|3b576869-a4ec-4529-8536-b80a7769e899=1|75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84=1|26190899-1602-49e8-8b27-eb1d0a1ce869=1|e6db77e5-3df2-4cf1-b95a-636979351e5b=1|d1e49aac-8f56-4280-b9ba-993a6d77406c=1|33ddedf1-c6e0-47cb-833e-de6133960387=1|b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4=2|92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b=1|c1db55ab-c21a-4637-bb3f-a12568109d35=1"}])
	"2.24: Ensure 'ASR: Block untrusted and unsigned processes that run from USB' is set to 'Block'" in b.violations with input as bad
}

test_2_24_fail_2 if {
	bad := json.patch(green, [{"op": "replace", "path": "/intune_defender/settings/AttackSurfaceReductionRules", "value": "56a863a9-875e-4185-98a7-b882c64b5ce5=1|7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c=1|d4f940ab-401b-4efc-aadc-ad5f3c50688a=1|9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2=1|be9ba2d9-53ea-4cdc-84e5-9b1eeee46550=1|01443614-cd74-433a-b99e-2ecdc07bfc25=1|5beb7efe-fd9a-4556-801d-275e5ffc04cc=1|d3e037e1-3eb8-44c8-a917-57927947596d=1|3b576869-a4ec-4529-8536-b80a7769e899=1|75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84=1|26190899-1602-49e8-8b27-eb1d0a1ce869=1|e6db77e5-3df2-4cf1-b95a-636979351e5b=1|d1e49aac-8f56-4280-b9ba-993a6d77406c=1|33ddedf1-c6e0-47cb-833e-de6133960387=1|92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b=1|c1db55ab-c21a-4637-bb3f-a12568109d35=1"}])
	"2.24: Ensure 'ASR: Block untrusted and unsigned processes that run from USB' is set to 'Block'" in b.violations with input as bad
}

test_2_24_fail_3 if {
	bad := json.patch(green, [{"op": "replace", "path": "/intune_defender/settings/AttackSurfaceReductionRules", "value": "56a863a9-875e-4185-98a7-b882c64b5ce5=1|7674BA52-37EB-4A4F-A9A1-F0F9A1619A2C=1|d4f940ab-401b-4efc-aadc-ad5f3c50688a=1|9E6C4E1F-7D60-472F-BA1A-A39EF669E4B2=1|be9ba2d9-53ea-4cdc-84e5-9b1eeee46550=1|01443614-CD74-433A-B99E-2ECDC07BFC25=1|5beb7efe-fd9a-4556-801d-275e5ffc04cc=1|D3E037E1-3EB8-44C8-A917-57927947596D=1|3b576869-a4ec-4529-8536-b80a7769e899=1|75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84=1|26190899-1602-49e8-8b27-eb1d0a1ce869=1|E6DB77E5-3DF2-4CF1-B95A-636979351E5B=1|d1e49aac-8f56-4280-b9ba-993a6d77406c=1|33DDEDF1-C6E0-47CB-833E-DE6133960387=1|b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4=1|92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B=1|c1db55ab-c21a-4637-bb3f-a12568109d35=1|b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4=6"}])
	"2.24: Ensure 'ASR: Block untrusted and unsigned processes that run from USB' is set to 'Block'" in b.violations with input as bad
}

test_2_24_evidence_missing if {
	bad := json.patch(green, [{"op": "remove", "path": "/intune_defender/settings/AttackSurfaceReductionRules"}])
	"2.24: evidence missing — intune_defender.settings.AttackSurfaceReductionRules not collected" in b.violations with input as bad
}

# 2.25
test_2_25_pass if {
	v := b.violations with input as green
	count([msg | some msg in v; startswith(msg, "2.25:")]) == 0
}

test_2_25_fail_1 if {
	bad := json.patch(green, [{"op": "replace", "path": "/intune_defender/settings/AttackSurfaceReductionRules", "value": "56a863a9-875e-4185-98a7-b882c64b5ce5=1|7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c=1|d4f940ab-401b-4efc-aadc-ad5f3c50688a=1|9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2=1|be9ba2d9-53ea-4cdc-84e5-9b1eeee46550=1|01443614-cd74-433a-b99e-2ecdc07bfc25=1|5beb7efe-fd9a-4556-801d-275e5ffc04cc=1|d3e037e1-3eb8-44c8-a917-57927947596d=1|3b576869-a4ec-4529-8536-b80a7769e899=1|75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84=1|26190899-1602-49e8-8b27-eb1d0a1ce869=1|e6db77e5-3df2-4cf1-b95a-636979351e5b=1|d1e49aac-8f56-4280-b9ba-993a6d77406c=1|33ddedf1-c6e0-47cb-833e-de6133960387=1|b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4=1|92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b=2|c1db55ab-c21a-4637-bb3f-a12568109d35=1"}])
	"2.25: Ensure 'ASR: Block Win32 API calls from Office macros' is set to 'Block'" in b.violations with input as bad
}

test_2_25_fail_2 if {
	bad := json.patch(green, [{"op": "replace", "path": "/intune_defender/settings/AttackSurfaceReductionRules", "value": "56a863a9-875e-4185-98a7-b882c64b5ce5=1|7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c=1|d4f940ab-401b-4efc-aadc-ad5f3c50688a=1|9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2=1|be9ba2d9-53ea-4cdc-84e5-9b1eeee46550=1|01443614-cd74-433a-b99e-2ecdc07bfc25=1|5beb7efe-fd9a-4556-801d-275e5ffc04cc=1|d3e037e1-3eb8-44c8-a917-57927947596d=1|3b576869-a4ec-4529-8536-b80a7769e899=1|75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84=1|26190899-1602-49e8-8b27-eb1d0a1ce869=1|e6db77e5-3df2-4cf1-b95a-636979351e5b=1|d1e49aac-8f56-4280-b9ba-993a6d77406c=1|33ddedf1-c6e0-47cb-833e-de6133960387=1|b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4=1|c1db55ab-c21a-4637-bb3f-a12568109d35=1"}])
	"2.25: Ensure 'ASR: Block Win32 API calls from Office macros' is set to 'Block'" in b.violations with input as bad
}

test_2_25_fail_3 if {
	bad := json.patch(green, [{"op": "replace", "path": "/intune_defender/settings/AttackSurfaceReductionRules", "value": "56a863a9-875e-4185-98a7-b882c64b5ce5=1|7674BA52-37EB-4A4F-A9A1-F0F9A1619A2C=1|d4f940ab-401b-4efc-aadc-ad5f3c50688a=1|9E6C4E1F-7D60-472F-BA1A-A39EF669E4B2=1|be9ba2d9-53ea-4cdc-84e5-9b1eeee46550=1|01443614-CD74-433A-B99E-2ECDC07BFC25=1|5beb7efe-fd9a-4556-801d-275e5ffc04cc=1|D3E037E1-3EB8-44C8-A917-57927947596D=1|3b576869-a4ec-4529-8536-b80a7769e899=1|75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84=1|26190899-1602-49e8-8b27-eb1d0a1ce869=1|E6DB77E5-3DF2-4CF1-B95A-636979351E5B=1|d1e49aac-8f56-4280-b9ba-993a6d77406c=1|33DDEDF1-C6E0-47CB-833E-DE6133960387=1|b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4=1|92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B=1|c1db55ab-c21a-4637-bb3f-a12568109d35=1|92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b=6"}])
	"2.25: Ensure 'ASR: Block Win32 API calls from Office macros' is set to 'Block'" in b.violations with input as bad
}

test_2_25_evidence_missing if {
	bad := json.patch(green, [{"op": "remove", "path": "/intune_defender/settings/AttackSurfaceReductionRules"}])
	"2.25: evidence missing — intune_defender.settings.AttackSurfaceReductionRules not collected" in b.violations with input as bad
}

# 2.26
test_2_26_pass if {
	v := b.violations with input as green
	count([msg | some msg in v; startswith(msg, "2.26:")]) == 0
}

test_2_26_fail_1 if {
	bad := json.patch(green, [{"op": "replace", "path": "/intune_defender/settings/AttackSurfaceReductionRules", "value": "56a863a9-875e-4185-98a7-b882c64b5ce5=1|7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c=1|d4f940ab-401b-4efc-aadc-ad5f3c50688a=1|9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2=1|be9ba2d9-53ea-4cdc-84e5-9b1eeee46550=1|01443614-cd74-433a-b99e-2ecdc07bfc25=1|5beb7efe-fd9a-4556-801d-275e5ffc04cc=1|d3e037e1-3eb8-44c8-a917-57927947596d=1|3b576869-a4ec-4529-8536-b80a7769e899=1|75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84=1|26190899-1602-49e8-8b27-eb1d0a1ce869=1|e6db77e5-3df2-4cf1-b95a-636979351e5b=1|d1e49aac-8f56-4280-b9ba-993a6d77406c=1|33ddedf1-c6e0-47cb-833e-de6133960387=1|b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4=1|92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b=1|c1db55ab-c21a-4637-bb3f-a12568109d35=0"}])
	"2.26: Ensure 'ASR: Use advanced protection against ransomware' is set to 'Audit' or higher" in b.violations with input as bad
}

test_2_26_fail_2 if {
	bad := json.patch(green, [{"op": "replace", "path": "/intune_defender/settings/AttackSurfaceReductionRules", "value": "56a863a9-875e-4185-98a7-b882c64b5ce5=1|7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c=1|d4f940ab-401b-4efc-aadc-ad5f3c50688a=1|9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2=1|be9ba2d9-53ea-4cdc-84e5-9b1eeee46550=1|01443614-cd74-433a-b99e-2ecdc07bfc25=1|5beb7efe-fd9a-4556-801d-275e5ffc04cc=1|d3e037e1-3eb8-44c8-a917-57927947596d=1|3b576869-a4ec-4529-8536-b80a7769e899=1|75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84=1|26190899-1602-49e8-8b27-eb1d0a1ce869=1|e6db77e5-3df2-4cf1-b95a-636979351e5b=1|d1e49aac-8f56-4280-b9ba-993a6d77406c=1|33ddedf1-c6e0-47cb-833e-de6133960387=1|b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4=1|92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b=1"}])
	"2.26: Ensure 'ASR: Use advanced protection against ransomware' is set to 'Audit' or higher" in b.violations with input as bad
}

test_2_26_fail_3 if {
	bad := json.patch(green, [{"op": "replace", "path": "/intune_defender/settings/AttackSurfaceReductionRules", "value": "56a863a9-875e-4185-98a7-b882c64b5ce5=1|7674BA52-37EB-4A4F-A9A1-F0F9A1619A2C=1|d4f940ab-401b-4efc-aadc-ad5f3c50688a=1|9E6C4E1F-7D60-472F-BA1A-A39EF669E4B2=1|be9ba2d9-53ea-4cdc-84e5-9b1eeee46550=1|01443614-CD74-433A-B99E-2ECDC07BFC25=1|5beb7efe-fd9a-4556-801d-275e5ffc04cc=1|D3E037E1-3EB8-44C8-A917-57927947596D=1|3b576869-a4ec-4529-8536-b80a7769e899=1|75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84=1|26190899-1602-49e8-8b27-eb1d0a1ce869=1|E6DB77E5-3DF2-4CF1-B95A-636979351E5B=1|d1e49aac-8f56-4280-b9ba-993a6d77406c=1|33DDEDF1-C6E0-47CB-833E-DE6133960387=1|b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4=1|92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B=1|c1db55ab-c21a-4637-bb3f-a12568109d35=1|c1db55ab-c21a-4637-bb3f-a12568109d35=6"}])
	"2.26: Ensure 'ASR: Use advanced protection against ransomware' is set to 'Audit' or higher" in b.violations with input as bad
}

test_2_26_evidence_missing if {
	bad := json.patch(green, [{"op": "remove", "path": "/intune_defender/settings/AttackSurfaceReductionRules"}])
	"2.26: evidence missing — intune_defender.settings.AttackSurfaceReductionRules not collected" in b.violations with input as bad
}

# 2.27
test_2_27_pass if {
	v := b.violations with input as green
	count([msg | some msg in v; startswith(msg, "2.27:")]) == 0
}

test_2_27_fail if {
	bad := json.patch(green, [{"op": "replace", "path": "/intune_defender/settings/CheckForSignaturesBeforeRunningScan", "value": 0}])
	"2.27: Ensure 'Check For Signatures Before Running Scan' is set to 'Enabled'" in b.violations with input as bad
}

test_2_27_evidence_missing if {
	bad := json.patch(green, [{"op": "remove", "path": "/intune_defender/settings/CheckForSignaturesBeforeRunningScan"}])
	"2.27: evidence missing — intune_defender.settings.CheckForSignaturesBeforeRunningScan not collected" in b.violations with input as bad
}

# 2.28
test_2_28_pass if {
	v := b.violations with input as green
	count([msg | some msg in v; startswith(msg, "2.28:")]) == 0
}

test_2_28_fail_1 if {
	bad := json.patch(green, [{"op": "replace", "path": "/intune_defender/settings/CloudBlockLevel", "value": 0}])
	"2.28: Ensure 'Cloud Block Level' is set to Enabled: High blocking level' or higher" in b.violations with input as bad
}

test_2_28_fail_2 if {
	bad := json.patch(green, [{"op": "replace", "path": "/intune_defender/settings/CloudBlockLevel", "value": 1}])
	"2.28: Ensure 'Cloud Block Level' is set to Enabled: High blocking level' or higher" in b.violations with input as bad
}

test_2_28_evidence_missing if {
	bad := json.patch(green, [{"op": "remove", "path": "/intune_defender/settings/CloudBlockLevel"}])
	"2.28: evidence missing — intune_defender.settings.CloudBlockLevel not collected" in b.violations with input as bad
}

# 2.29
test_2_29_pass if {
	v := b.violations with input as green
	count([msg | some msg in v; startswith(msg, "2.29:")]) == 0
}

test_2_29_fail if {
	bad := json.patch(green, [{"op": "replace", "path": "/intune_defender/settings/CloudExtendedTimeout", "value": 0}])
	"2.29: Ensure ‘Cloud Extended Timeout’ is set to '1 or higher, but not 0'" in b.violations with input as bad
}

test_2_29_evidence_missing if {
	bad := json.patch(green, [{"op": "remove", "path": "/intune_defender/settings/CloudExtendedTimeout"}])
	"2.29: evidence missing — intune_defender.settings.CloudExtendedTimeout not collected" in b.violations with input as bad
}

# 2.30
test_2_30_pass if {
	v := b.violations with input as green
	count([msg | some msg in v; startswith(msg, "2.30:")]) == 0
}

test_2_30_fail_1 if {
	bad := json.patch(green, [{"op": "replace", "path": "/intune_defender/settings/DaysUntilAggressiveCatchupQuickScan", "value": 0}])
	"2.30: Ensure 'Days Until Aggressive Catchup Quick Scan' is set to '7' days" in b.violations with input as bad
}

test_2_30_fail_2 if {
	bad := json.patch(green, [{"op": "replace", "path": "/intune_defender/settings/DaysUntilAggressiveCatchupQuickScan", "value": 30}])
	"2.30: Ensure 'Days Until Aggressive Catchup Quick Scan' is set to '7' days" in b.violations with input as bad
}

test_2_30_evidence_missing if {
	bad := json.patch(green, [{"op": "remove", "path": "/intune_defender/settings/DaysUntilAggressiveCatchupQuickScan"}])
	"2.30: evidence missing — intune_defender.settings.DaysUntilAggressiveCatchupQuickScan not collected" in b.violations with input as bad
}

# 2.31
test_2_31_pass if {
	v := b.violations with input as green
	count([msg | some msg in v; startswith(msg, "2.31:")]) == 0
}

test_2_31_fail if {
	bad := json.patch(green, [{"op": "replace", "path": "/intune_defender/settings/EnableConvertWarnToBlock", "value": 0}])
	"2.31: Ensure 'Enable Convert Warn To Block' is set to 'Warn verdicts are converted to block'" in b.violations with input as bad
}

test_2_31_evidence_missing if {
	bad := json.patch(green, [{"op": "remove", "path": "/intune_defender/settings/EnableConvertWarnToBlock"}])
	"2.31: evidence missing — intune_defender.settings.EnableConvertWarnToBlock not collected" in b.violations with input as bad
}

# 2.32
test_2_32_pass if {
	v := b.violations with input as green
	count([msg | some msg in v; startswith(msg, "2.32:")]) == 0
}

test_2_32_fail if {
	bad := json.patch(green, [{"op": "replace", "path": "/intune_defender/settings/EnableDynamicSignatureDroppedEventReporting", "value": 0}])
	"2.32: Ensure 'Enable Dynamic Signature Dropped Event Reporting' is set to 'Dynamic Security intelligence update events will be reported.'" in b.violations with input as bad
}

test_2_32_evidence_missing if {
	bad := json.patch(green, [{"op": "remove", "path": "/intune_defender/settings/EnableDynamicSignatureDroppedEventReporting"}])
	"2.32: evidence missing — intune_defender.settings.EnableDynamicSignatureDroppedEventReporting not collected" in b.violations with input as bad
}

# 2.33
test_2_33_pass if {
	v := b.violations with input as green
	count([msg | some msg in v; startswith(msg, "2.33:")]) == 0
}

test_2_33_fail if {
	bad := json.patch(green, [{"op": "replace", "path": "/intune_defender/settings/EnableFileHashComputation", "value": 0}])
	"2.33: Ensure 'Enable File Hash Computation' is set to 'Enable'" in b.violations with input as bad
}

test_2_33_evidence_missing if {
	bad := json.patch(green, [{"op": "remove", "path": "/intune_defender/settings/EnableFileHashComputation"}])
	"2.33: evidence missing — intune_defender.settings.EnableFileHashComputation not collected" in b.violations with input as bad
}

# 2.34
test_2_34_pass if {
	v := b.violations with input as green
	count([msg | some msg in v; startswith(msg, "2.34:")]) == 0
}

test_2_34_fail_1 if {
	bad := json.patch(green, [{"op": "replace", "path": "/intune_defender/settings/EnableNetworkProtection", "value": 0}])
	"2.34: Ensure 'Enable Network Protection' is set to 'Enabled (block mode)'" in b.violations with input as bad
}

test_2_34_fail_2 if {
	bad := json.patch(green, [{"op": "replace", "path": "/intune_defender/settings/EnableNetworkProtection", "value": 2}])
	"2.34: Ensure 'Enable Network Protection' is set to 'Enabled (block mode)'" in b.violations with input as bad
}

test_2_34_evidence_missing if {
	bad := json.patch(green, [{"op": "remove", "path": "/intune_defender/settings/EnableNetworkProtection"}])
	"2.34: evidence missing — intune_defender.settings.EnableNetworkProtection not collected" in b.violations with input as bad
}

# 2.35
test_2_35_pass if {
	v := b.violations with input as green
	count([msg | some msg in v; startswith(msg, "2.35:")]) == 0
}

test_2_35_fail if {
	bad := json.patch(green, [{"op": "replace", "path": "/intune_defender/settings/HideExclusionsFromLocalUsers", "value": 0}])
	"2.35: Ensure 'Hide Exclusions From Local Users' is set to 'Enabled'" in b.violations with input as bad
}

test_2_35_evidence_missing if {
	bad := json.patch(green, [{"op": "remove", "path": "/intune_defender/settings/HideExclusionsFromLocalUsers"}])
	"2.35: evidence missing — intune_defender.settings.HideExclusionsFromLocalUsers not collected" in b.violations with input as bad
}

# 2.36
test_2_36_pass if {
	v := b.violations with input as green
	count([msg | some msg in v; startswith(msg, "2.36:")]) == 0
}

test_2_36_fail if {
	bad := json.patch(green, [{"op": "replace", "path": "/intune_defender/settings/OobeEnableRtpAndSigUpdate", "value": 0}])
	"2.36: Ensure 'Oobe Enable Rtp And Sig Update' is set to 'Enabled'" in b.violations with input as bad
}

test_2_36_evidence_missing if {
	bad := json.patch(green, [{"op": "remove", "path": "/intune_defender/settings/OobeEnableRtpAndSigUpdate"}])
	"2.36: evidence missing — intune_defender.settings.OobeEnableRtpAndSigUpdate not collected" in b.violations with input as bad
}

# 2.37
test_2_37_pass if {
	v := b.violations with input as green
	count([msg | some msg in v; startswith(msg, "2.37:")]) == 0
}

test_2_37_fail_1 if {
	bad := json.patch(green, [{"op": "replace", "path": "/intune_defender/settings/PUAProtection", "value": 0}])
	"2.37: Ensure 'PUA Protection' is set to 'PUA Protection on'" in b.violations with input as bad
}

test_2_37_fail_2 if {
	bad := json.patch(green, [{"op": "replace", "path": "/intune_defender/settings/PUAProtection", "value": 2}])
	"2.37: Ensure 'PUA Protection' is set to 'PUA Protection on'" in b.violations with input as bad
}

test_2_37_evidence_missing if {
	bad := json.patch(green, [{"op": "remove", "path": "/intune_defender/settings/PUAProtection"}])
	"2.37: evidence missing — intune_defender.settings.PUAProtection not collected" in b.violations with input as bad
}

# 2.38
test_2_38_pass if {
	v := b.violations with input as green
	count([msg | some msg in v; startswith(msg, "2.38:")]) == 0
}

test_2_38_fail if {
	bad := json.patch(green, [{"op": "replace", "path": "/intune_defender/settings/QuickScanIncludeExclusions", "value": 0}])
	"2.38: Ensure 'Quick Scan Include Exclusions' is set to '1'" in b.violations with input as bad
}

test_2_38_evidence_missing if {
	bad := json.patch(green, [{"op": "remove", "path": "/intune_defender/settings/QuickScanIncludeExclusions"}])
	"2.38: evidence missing — intune_defender.settings.QuickScanIncludeExclusions not collected" in b.violations with input as bad
}

# 2.39
test_2_39_pass if {
	v := b.violations with input as green
	count([msg | some msg in v; startswith(msg, "2.39:")]) == 0
}

test_2_39_fail_1 if {
	bad := json.patch(green, [{"op": "replace", "path": "/intune_defender/settings/RealTimeScanDirection", "value": 1}])
	"2.39: Ensure 'Real Time Scan Direction' is set to 'Monitor all files bi-directional'" in b.violations with input as bad
}

test_2_39_fail_2 if {
	bad := json.patch(green, [{"op": "replace", "path": "/intune_defender/settings/RealTimeScanDirection", "value": 2}])
	"2.39: Ensure 'Real Time Scan Direction' is set to 'Monitor all files bi-directional'" in b.violations with input as bad
}

test_2_39_evidence_missing if {
	bad := json.patch(green, [{"op": "remove", "path": "/intune_defender/settings/RealTimeScanDirection"}])
	"2.39: evidence missing — intune_defender.settings.RealTimeScanDirection not collected" in b.violations with input as bad
}

# 2.40
test_2_40_pass if {
	v := b.violations with input as green
	count([msg | some msg in v; startswith(msg, "2.40:")]) == 0
}

test_2_40_fail if {
	bad := json.patch(green, [{"op": "replace", "path": "/intune_defender/settings/RemoteEncryptionProtectionAggressiveness", "value": 0}])
	"2.40: Ensure 'Remote Encryption Protection Aggressiveness' is set to 'Medium' or higher" in b.violations with input as bad
}

test_2_40_evidence_missing if {
	bad := json.patch(green, [{"op": "remove", "path": "/intune_defender/settings/RemoteEncryptionProtectionAggressiveness"}])
	"2.40: evidence missing — intune_defender.settings.RemoteEncryptionProtectionAggressiveness not collected" in b.violations with input as bad
}

# 2.41
test_2_41_pass if {
	v := b.violations with input as green
	count([msg | some msg in v; startswith(msg, "2.41:")]) == 0
}

test_2_41_fail_1 if {
	bad := json.patch(green, [{"op": "replace", "path": "/intune_defender/settings/RemoteEncryptionProtectionConfiguredState", "value": 0}])
	"2.41: Ensure 'Remote Encryption Protection Configured State' is set to 'Audit: Generate EDR detections without blocking' or higher" in b.violations with input as bad
}

test_2_41_fail_2 if {
	bad := json.patch(green, [{"op": "replace", "path": "/intune_defender/settings/RemoteEncryptionProtectionConfiguredState", "value": 4}])
	"2.41: Ensure 'Remote Encryption Protection Configured State' is set to 'Audit: Generate EDR detections without blocking' or higher" in b.violations with input as bad
}

test_2_41_evidence_missing if {
	bad := json.patch(green, [{"op": "remove", "path": "/intune_defender/settings/RemoteEncryptionProtectionConfiguredState"}])
	"2.41: evidence missing — intune_defender.settings.RemoteEncryptionProtectionConfiguredState not collected" in b.violations with input as bad
}

# 2.42
test_2_42_pass if {
	v := b.violations with input as green
	count([msg | some msg in v; startswith(msg, "2.42:")]) == 0
}

test_2_42_fail if {
	bad := json.patch(green, [{"op": "replace", "path": "/intune_defender/settings/ScanParameter", "value": 0}])
	"2.42: Ensure 'Scan Parameter' is set to 'Quick Scan' or higher" in b.violations with input as bad
}

test_2_42_evidence_missing if {
	bad := json.patch(green, [{"op": "remove", "path": "/intune_defender/settings/ScanParameter"}])
	"2.42: evidence missing — intune_defender.settings.ScanParameter not collected" in b.violations with input as bad
}

# 2.43
test_2_43_pass if {
	v := b.violations with input as green
	count([msg | some msg in v; startswith(msg, "2.43:")]) == 0
}

test_2_43_fail if {
	bad := json.patch(green, [{"op": "replace", "path": "/intune_defender/settings/ScheduleQuickScanTime", "value": 0}])
	"2.43: Ensure 'Schedule Quick Scan Time' is set to '1' or higher" in b.violations with input as bad
}

test_2_43_evidence_missing if {
	bad := json.patch(green, [{"op": "remove", "path": "/intune_defender/settings/ScheduleQuickScanTime"}])
	"2.43: evidence missing — intune_defender.settings.ScheduleQuickScanTime not collected" in b.violations with input as bad
}

# 2.44
test_2_44_pass if {
	v := b.violations with input as green
	count([msg | some msg in v; startswith(msg, "2.44:")]) == 0
}

test_2_44_fail if {
	bad := json.patch(green, [{"op": "replace", "path": "/intune_defender/settings/ScheduleScanTime", "value": 0}])
	"2.44: Ensure 'Schedule Scan Time' is set to '1' or higher" in b.violations with input as bad
}

test_2_44_evidence_missing if {
	bad := json.patch(green, [{"op": "remove", "path": "/intune_defender/settings/ScheduleScanTime"}])
	"2.44: evidence missing — intune_defender.settings.ScheduleScanTime not collected" in b.violations with input as bad
}

# 2.45
test_2_45_pass if {
	v := b.violations with input as green
	count([msg | some msg in v; startswith(msg, "2.45:")]) == 0
}

test_2_45_fail_1 if {
	bad := json.patch(green, [{"op": "replace", "path": "/intune_defender/settings/ScheduleScanDay", "value": 8}])
	"2.45: Ensure 'Schedule Scan Day' is set to 'Enabled: 0' or higher, but not '8'" in b.violations with input as bad
}

test_2_45_fail_2 if {
	bad := json.patch(green, [{"op": "replace", "path": "/intune_defender/settings/ScheduleScanDay", "value": -1}])
	"2.45: Ensure 'Schedule Scan Day' is set to 'Enabled: 0' or higher, but not '8'" in b.violations with input as bad
}

test_2_45_evidence_missing if {
	bad := json.patch(green, [{"op": "remove", "path": "/intune_defender/settings/ScheduleScanDay"}])
	"2.45: evidence missing — intune_defender.settings.ScheduleScanDay not collected" in b.violations with input as bad
}

# 2.46
test_2_46_pass if {
	v := b.violations with input as green
	count([msg | some msg in v; startswith(msg, "2.46:")]) == 0
}

test_2_46_fail_1 if {
	bad := json.patch(green, [{"op": "replace", "path": "/intune_defender/settings/SignatureUpdateInterval", "value": 0}])
	"2.46: Ensure 'Signature Update Interval' is set to '4' or fewer, but not '0'" in b.violations with input as bad
}

test_2_46_fail_2 if {
	bad := json.patch(green, [{"op": "replace", "path": "/intune_defender/settings/SignatureUpdateInterval", "value": 5}])
	"2.46: Ensure 'Signature Update Interval' is set to '4' or fewer, but not '0'" in b.violations with input as bad
}

test_2_46_fail_3 if {
	bad := json.patch(green, [{"op": "replace", "path": "/intune_defender/settings/SignatureUpdateInterval", "value": 24}])
	"2.46: Ensure 'Signature Update Interval' is set to '4' or fewer, but not '0'" in b.violations with input as bad
}

test_2_46_evidence_missing if {
	bad := json.patch(green, [{"op": "remove", "path": "/intune_defender/settings/SignatureUpdateInterval"}])
	"2.46: evidence missing — intune_defender.settings.SignatureUpdateInterval not collected" in b.violations with input as bad
}

# 2.47
test_2_47_pass if {
	v := b.violations with input as green
	count([msg | some msg in v; startswith(msg, "2.47:")]) == 0
}

test_2_47_fail_1 if {
	bad := json.patch(green, [{"op": "replace", "path": "/intune_defender/settings/SubmitSamplesConsent", "value": 0}])
	"2.47: Ensure 'Submit Samples Consent' is set to 'Enabled: Send safe samples automatically' or higher" in b.violations with input as bad
}

test_2_47_fail_2 if {
	bad := json.patch(green, [{"op": "replace", "path": "/intune_defender/settings/SubmitSamplesConsent", "value": 2}])
	"2.47: Ensure 'Submit Samples Consent' is set to 'Enabled: Send safe samples automatically' or higher" in b.violations with input as bad
}

test_2_47_evidence_missing if {
	bad := json.patch(green, [{"op": "remove", "path": "/intune_defender/settings/SubmitSamplesConsent"}])
	"2.47: evidence missing — intune_defender.settings.SubmitSamplesConsent not collected" in b.violations with input as bad
}

# 2.48
test_2_48_pass if {
	v := b.violations with input as green
	count([msg | some msg in v; startswith(msg, "2.48:")]) == 0
}

test_2_48_fail_1 if {
	bad := json.patch(green, [{"op": "replace", "path": "/intune_defender/settings/ThreatSeverityDefaultAction", "value": "2=6|4=2|5=3"}])
	"2.48: Ensure 'Remediation action for Moderate severity threats' is set to 'Quarantine or Remove'" in b.violations with input as bad
}

test_2_48_fail_2 if {
	bad := json.patch(green, [{"op": "replace", "path": "/intune_defender/settings/ThreatSeverityDefaultAction", "value": "4=2|5=3"}])
	"2.48: Ensure 'Remediation action for Moderate severity threats' is set to 'Quarantine or Remove'" in b.violations with input as bad
}

test_2_48_evidence_missing if {
	bad := json.patch(green, [{"op": "remove", "path": "/intune_defender/settings/ThreatSeverityDefaultAction"}])
	"2.48: evidence missing — intune_defender.settings.ThreatSeverityDefaultAction not collected" in b.violations with input as bad
}

# 2.49
test_2_49_pass if {
	v := b.violations with input as green
	count([msg | some msg in v; startswith(msg, "2.49:")]) == 0
}

test_2_49_fail_1 if {
	bad := json.patch(green, [{"op": "replace", "path": "/intune_defender/settings/ThreatSeverityDefaultAction", "value": "2=2|4=6|5=3"}])
	"2.49: Ensure 'Remediation action for High severity threats' is set to 'Quarantine or Remove'" in b.violations with input as bad
}

test_2_49_fail_2 if {
	bad := json.patch(green, [{"op": "replace", "path": "/intune_defender/settings/ThreatSeverityDefaultAction", "value": "2=2|5=3"}])
	"2.49: Ensure 'Remediation action for High severity threats' is set to 'Quarantine or Remove'" in b.violations with input as bad
}

test_2_49_evidence_missing if {
	bad := json.patch(green, [{"op": "remove", "path": "/intune_defender/settings/ThreatSeverityDefaultAction"}])
	"2.49: evidence missing — intune_defender.settings.ThreatSeverityDefaultAction not collected" in b.violations with input as bad
}

# 2.50
test_2_50_pass if {
	v := b.violations with input as green
	count([msg | some msg in v; startswith(msg, "2.50:")]) == 0
}

test_2_50_fail_1 if {
	bad := json.patch(green, [{"op": "replace", "path": "/intune_defender/settings/ThreatSeverityDefaultAction", "value": "2=2|4=2|5=6"}])
	"2.50: Ensure 'Remediation action for Severe threats' is set to 'Quarantine or Remove'" in b.violations with input as bad
}

test_2_50_fail_2 if {
	bad := json.patch(green, [{"op": "replace", "path": "/intune_defender/settings/ThreatSeverityDefaultAction", "value": "2=2|4=2"}])
	"2.50: Ensure 'Remediation action for Severe threats' is set to 'Quarantine or Remove'" in b.violations with input as bad
}

test_2_50_evidence_missing if {
	bad := json.patch(green, [{"op": "remove", "path": "/intune_defender/settings/ThreatSeverityDefaultAction"}])
	"2.50: evidence missing — intune_defender.settings.ThreatSeverityDefaultAction not collected" in b.violations with input as bad
}
