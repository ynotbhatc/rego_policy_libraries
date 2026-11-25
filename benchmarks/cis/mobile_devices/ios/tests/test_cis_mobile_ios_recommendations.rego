package cis.mobile.ios_test

import rego.v1

import data.cis.mobile.ios as b
import data.cis.mobile.ios.main as m

# Generated per-recommendation tests for CIS Apple iOS 27 Benchmark v1.0.0 (tools/cis_generators/gen_ios_27.py): a pass, a fail and, for configuration checks,
# an evidence-missing case per recommendation; attestations fail when false or absent.

green_end_user := {
	"ios_profile": {
		"restrictions": {
			"allowAssistantWhileLocked": false,
			"allowManagedAppsCloudSync": false,
			"forceEncryptedBackup": true,
			"allowApplePersonalizedAdvertising": false,
			"allowUntrustedTLSPrompt": false,
			"forceAutomaticDateAndTime": true,
			"allowOpenFromManagedToUnmanaged": false,
			"allowOpenFromUnmanagedToManaged": false,
			"forceAirDropUnmanaged": true,
			"allowActivityContinuation": false,
			"allowDiagnosticSubmission": false,
			"forceWatchWristDetection": true,
			"allowLockScreenControlCenter": false,
			"allowLockScreenNotificationsView": false,
			"safariForceFraudWarning": true,
			"safariAcceptCookies": 1,
			"allowExternalIntelligenceIntegrations": false,
			"allowExternalIntelligenceIntegrationsSignIn": false,
			"allowNotesTranscription": false,
			"allowNotesTranscriptionSummary": false,
			"allowMailSummary": false,
			"allowWritingTools": false,
			"allowSafariSummary": false,
			"allowMailSmartReplies": false,
		},
		"passcode": {
			"allowSimple": false,
			"requireAlphanumeric": true,
			"minLength": 6,
			"maxInactivity": 2,
			"maxGracePeriod": 0,
			"maxFailedAttempts": 6,
		},
		"profile": {
			"removal": "always",
			"consent_message": "Authorised use only",
		},
		"mail_accounts": [{"PreventMove": true}],
		"attest": {
			"managed_safari_domains": true,
			"mac_randomization_reviewed": true,
			"vpn_configured": true,
			"managed_app_notifications": true,
			"sharing_access_reviewed": true,
			"emergency_reset_reviewed": true,
			"lockdown_mode_reviewed": true,
			"app_privacy_report_enabled": true,
			"airprint_reviewed": true,
			"stolen_device_protection_enabled": true,
			"not_jailbroken": true,
			"auto_update_install_enabled": true,
			"software_up_to_date": true,
			"private_relay_reviewed": true,
			"mail_privacy_reviewed": true,
			"auto_app_updates_enabled": true,
			"find_my_enabled": true,
			"latest_hardware_for_high_value": true,
			"iphone_mirroring_reviewed": true,
			"rcs_messaging_enabled": true,
		},
	},
	"cis_profile": {
		"level": 2,
		"ownership": "end_user",
	},
}

green_institutional := {
	"ios_profile": {
		"restrictions": {
			"allowScreenShot": false,
			"allowAssistantWhileLocked": false,
			"allowCloudBackup": false,
			"allowCloudDocumentSync": false,
			"allowCloudKeychainSync": false,
			"allowManagedAppsCloudSync": false,
			"allowFilesUSBDriveAccess": false,
			"allowFilesNetworkDriveAccess": false,
			"forceEncryptedBackup": true,
			"allowApplePersonalizedAdvertising": false,
			"allowEraseContentAndSettings": false,
			"allowUntrustedTLSPrompt": false,
			"allowEnterpriseAppTrust": false,
			"allowUIConfigurationProfileInstallation": false,
			"allowVPNCreation": false,
			"forceAutomaticDateAndTime": true,
			"allowAppCellularDataModification": false,
			"allowUSBRestrictedMode": true,
			"allowHostPairing": false,
			"allowOpenFromManagedToUnmanaged": false,
			"allowOpenFromUnmanagedToManaged": false,
			"forceAirDropUnmanaged": true,
			"allowActivityContinuation": false,
			"allowDiagnosticSubmission": false,
			"forceAuthenticationBeforeAutoFill": true,
			"forceWatchWristDetection": true,
			"allowProximitySetupToNewDevice": false,
			"allowPasswordProximityRequests": false,
			"allowPasswordSharing": false,
			"allowLockScreenControlCenter": false,
			"allowLockScreenNotificationsView": false,
			"safariForceFraudWarning": true,
			"safariAcceptCookies": 1,
			"allowExternalIntelligenceIntegrations": false,
			"allowExternalIntelligenceIntegrationsSignIn": false,
			"allowNotesTranscription": false,
			"allowNotesTranscriptionSummary": false,
			"allowMailSummary": false,
			"allowWritingTools": false,
			"allowSafariSummary": false,
			"allowMailSmartReplies": false,
		},
		"passcode": {
			"requireAlphanumeric": true,
			"allowSimple": false,
			"minLength": 6,
			"maxInactivity": 2,
			"maxGracePeriod": 0,
			"maxFailedAttempts": 6,
		},
		"profile": {"removal": "never"},
		"mail_accounts": [{
			"allowMailDrop": false,
			"PreventMove": true,
		}],
		"attest": {
			"managed_safari_domains": true,
			"mac_randomization_reviewed": true,
			"vpn_configured": true,
			"managed_app_notifications": true,
			"lost_message_configured": true,
			"sharing_access_reviewed": true,
			"emergency_reset_reviewed": true,
			"lockdown_mode_reviewed": true,
			"app_privacy_report_enabled": true,
			"airprint_reviewed": true,
			"not_jailbroken": true,
			"auto_update_install_enabled": true,
			"software_up_to_date": true,
			"private_relay_reviewed": true,
			"mail_privacy_reviewed": true,
			"auto_app_updates_enabled": true,
			"latest_hardware_for_high_value": true,
			"iphone_mirroring_reviewed": true,
			"rcs_messaging_enabled": true,
		},
	},
	"cis_profile": {
		"level": 2,
		"ownership": "institutional",
	},
}

_has_id(vs, id) if {
	some v in vs
	startswith(v, concat("", [id, ":"]))
}

test_green_end_user_is_compliant if {
	vs := b.violations with input as green_end_user
	count(vs) == 0
	b.compliant with input as green_end_user
	r := m.compliance_report with input as green_end_user
	r.total_controls == 53
	r.failed_controls == 0
}

test_empty_input_fails_every_end_user_level_1_recommendation if {
	r := m.compliance_report with input as {"cis_profile": {"ownership": "end_user", "level": 1}}
	r.total_controls == 45
	r.failed_controls == 45
	r.compliant == false
}

test_empty_input_fails_every_end_user_level_2_recommendation if {
	r := m.compliance_report with input as {"cis_profile": {"ownership": "end_user", "level": 2}}
	r.total_controls == 53
	r.failed_controls == 53
	r.compliant == false
}

test_green_institutional_is_compliant if {
	vs := b.violations with input as green_institutional
	count(vs) == 0
	b.compliant with input as green_institutional
	r := m.compliance_report with input as green_institutional
	r.total_controls == 69
	r.failed_controls == 0
}

test_empty_input_fails_every_institutional_level_1_recommendation if {
	r := m.compliance_report with input as {"cis_profile": {"ownership": "institutional", "level": 1}}
	r.total_controls == 56
	r.failed_controls == 56
	r.compliant == false
}

test_empty_input_fails_every_institutional_level_2_recommendation if {
	r := m.compliance_report with input as {"cis_profile": {"ownership": "institutional", "level": 2}}
	r.total_controls == 69
	r.failed_controls == 69
	r.compliant == false
}

test_empty_object_input_contract if {
	r := m.compliance_report with input as {}
	r.compliant == false
	r.total_controls == 69
	r.failed_controls == r.total_controls
	r.violation_count > 0
}

test_recommendation_counts_match_workbook if {
	count(b.recommendations) == 105
	count([id | some id, r in b.recommendations; r.assessment == "Automated"]) == 70
	count([id | some id, r in b.recommendations; r.check == "attestation"]) == 25
}

test_ownership_scopes_the_ids if {
	vs := b.violations with input as {"cis_profile": {"ownership": "end_user", "level": 2}}
	_has_id(vs, "2.4.3")
	not _has_id(vs, "3.4.3")
}

test_level_1_skips_level_2_ids if {
	vs := b.violations with input as {"cis_profile": {"ownership": "institutional", "level": 1}}
	not _has_id(vs, "3.2.1.1")
	_has_id(vs, "3.2.1.2")
}

# 2.1.1
test_2_1_1_pass if {
	vs := b.violations with input as green_end_user
	not _has_id(vs, "2.1.1")
}

test_2_1_1_fail if {
	inp := json.patch(green_end_user, [{"op": "replace", "path": "/ios_profile/profile/consent_message", "value": "  "}])
	vs := b.violations with input as inp
	"2.1.1: the profile must carry a consent message" in vs
}

test_2_1_1_evidence_missing if {
	inp := json.patch(green_end_user, [{"op": "remove", "path": "/ios_profile/profile/consent_message"}])
	vs := b.violations with input as inp
	"2.1.1: evidence missing — ios_profile.profile.consent_message not collected" in vs
	not "2.1.1: the profile must carry a consent message" in vs
}

# 2.1.2
test_2_1_2_pass if {
	vs := b.violations with input as green_end_user
	not _has_id(vs, "2.1.2")
}

test_2_1_2_fail if {
	inp := json.patch(green_end_user, [{"op": "replace", "path": "/ios_profile/profile/removal", "value": "never"}])
	vs := b.violations with input as inp
	"2.1.2: end-user profile removal must stay allowed" in vs
}

test_2_1_2_evidence_missing if {
	inp := json.patch(green_end_user, [{"op": "remove", "path": "/ios_profile/profile/removal"}])
	vs := b.violations with input as inp
	"2.1.2: evidence missing — ios_profile.profile.removal not collected" in vs
	not "2.1.2: end-user profile removal must stay allowed" in vs
}

# 2.2.1.1
test_2_2_1_1_pass if {
	vs := b.violations with input as green_end_user
	not _has_id(vs, "2.2.1.1")
}

test_2_2_1_1_fail if {
	inp := json.patch(green_end_user, [{"op": "replace", "path": "/ios_profile/restrictions/allowAssistantWhileLocked", "value": true}])
	vs := b.violations with input as inp
	"2.2.1.1: Siri must be blocked on the lock screen" in vs
}

test_2_2_1_1_evidence_missing if {
	inp := json.patch(green_end_user, [{"op": "remove", "path": "/ios_profile/restrictions/allowAssistantWhileLocked"}])
	vs := b.violations with input as inp
	"2.2.1.1: evidence missing — ios_profile.restrictions.allowAssistantWhileLocked not collected" in vs
	not "2.2.1.1: Siri must be blocked on the lock screen" in vs
}

# 2.2.1.2
test_2_2_1_2_pass if {
	vs := b.violations with input as green_end_user
	not _has_id(vs, "2.2.1.2")
}

test_2_2_1_2_fail if {
	inp := json.patch(green_end_user, [{"op": "replace", "path": "/ios_profile/restrictions/allowManagedAppsCloudSync", "value": true}])
	vs := b.violations with input as inp
	"2.2.1.2: managed apps must not sync data to iCloud" in vs
}

test_2_2_1_2_evidence_missing if {
	inp := json.patch(green_end_user, [{"op": "remove", "path": "/ios_profile/restrictions/allowManagedAppsCloudSync"}])
	vs := b.violations with input as inp
	"2.2.1.2: evidence missing — ios_profile.restrictions.allowManagedAppsCloudSync not collected" in vs
	not "2.2.1.2: managed apps must not sync data to iCloud" in vs
}

# 2.2.1.3
test_2_2_1_3_pass if {
	vs := b.violations with input as green_end_user
	not _has_id(vs, "2.2.1.3")
}

test_2_2_1_3_fail if {
	inp := json.patch(green_end_user, [{"op": "replace", "path": "/ios_profile/restrictions/forceEncryptedBackup", "value": false}])
	vs := b.violations with input as inp
	"2.2.1.3: backups must be forced to encrypt" in vs
}

test_2_2_1_3_evidence_missing if {
	inp := json.patch(green_end_user, [{"op": "remove", "path": "/ios_profile/restrictions/forceEncryptedBackup"}])
	vs := b.violations with input as inp
	"2.2.1.3: evidence missing — ios_profile.restrictions.forceEncryptedBackup not collected" in vs
	not "2.2.1.3: backups must be forced to encrypt" in vs
}

# 2.2.1.4
test_2_2_1_4_pass if {
	vs := b.violations with input as green_end_user
	not _has_id(vs, "2.2.1.4")
}

test_2_2_1_4_fail if {
	inp := json.patch(green_end_user, [{"op": "replace", "path": "/ios_profile/restrictions/allowApplePersonalizedAdvertising", "value": true}])
	vs := b.violations with input as inp
	"2.2.1.4: Apple personalized advertising must be blocked" in vs
}

test_2_2_1_4_evidence_missing if {
	inp := json.patch(green_end_user, [{"op": "remove", "path": "/ios_profile/restrictions/allowApplePersonalizedAdvertising"}])
	vs := b.violations with input as inp
	"2.2.1.4: evidence missing — ios_profile.restrictions.allowApplePersonalizedAdvertising not collected" in vs
	not "2.2.1.4: Apple personalized advertising must be blocked" in vs
}

# 2.2.1.5
test_2_2_1_5_pass if {
	vs := b.violations with input as green_end_user
	not _has_id(vs, "2.2.1.5")
}

test_2_2_1_5_fail if {
	inp := json.patch(green_end_user, [{"op": "replace", "path": "/ios_profile/restrictions/allowUntrustedTLSPrompt", "value": true}])
	vs := b.violations with input as inp
	"2.2.1.5: the user must not be able to accept untrusted TLS certificates" in vs
}

test_2_2_1_5_evidence_missing if {
	inp := json.patch(green_end_user, [{"op": "remove", "path": "/ios_profile/restrictions/allowUntrustedTLSPrompt"}])
	vs := b.violations with input as inp
	"2.2.1.5: evidence missing — ios_profile.restrictions.allowUntrustedTLSPrompt not collected" in vs
	not "2.2.1.5: the user must not be able to accept untrusted TLS certificates" in vs
}

# 2.2.1.6
test_2_2_1_6_pass if {
	vs := b.violations with input as green_end_user
	not _has_id(vs, "2.2.1.6")
}

test_2_2_1_6_fail if {
	inp := json.patch(green_end_user, [{"op": "replace", "path": "/ios_profile/restrictions/forceAutomaticDateAndTime", "value": false}])
	vs := b.violations with input as inp
	"2.2.1.6: automatic date and time must be forced" in vs
}

test_2_2_1_6_evidence_missing if {
	inp := json.patch(green_end_user, [{"op": "remove", "path": "/ios_profile/restrictions/forceAutomaticDateAndTime"}])
	vs := b.violations with input as inp
	"2.2.1.6: evidence missing — ios_profile.restrictions.forceAutomaticDateAndTime not collected" in vs
	not "2.2.1.6: automatic date and time must be forced" in vs
}

# 2.2.1.7
test_2_2_1_7_pass if {
	vs := b.violations with input as green_end_user
	not _has_id(vs, "2.2.1.7")
}

test_2_2_1_7_fail if {
	inp := json.patch(green_end_user, [{"op": "replace", "path": "/ios_profile/restrictions/allowOpenFromManagedToUnmanaged", "value": true}])
	vs := b.violations with input as inp
	"2.2.1.7: documents must not open from managed into unmanaged destinations" in vs
}

test_2_2_1_7_evidence_missing if {
	inp := json.patch(green_end_user, [{"op": "remove", "path": "/ios_profile/restrictions/allowOpenFromManagedToUnmanaged"}])
	vs := b.violations with input as inp
	"2.2.1.7: evidence missing — ios_profile.restrictions.allowOpenFromManagedToUnmanaged not collected" in vs
	not "2.2.1.7: documents must not open from managed into unmanaged destinations" in vs
}

# 2.2.1.8
test_2_2_1_8_pass if {
	vs := b.violations with input as green_end_user
	not _has_id(vs, "2.2.1.8")
}

test_2_2_1_8_fail if {
	inp := json.patch(green_end_user, [{"op": "replace", "path": "/ios_profile/restrictions/allowOpenFromUnmanagedToManaged", "value": true}])
	vs := b.violations with input as inp
	"2.2.1.8: documents must not open from unmanaged into managed destinations" in vs
}

test_2_2_1_8_evidence_missing if {
	inp := json.patch(green_end_user, [{"op": "remove", "path": "/ios_profile/restrictions/allowOpenFromUnmanagedToManaged"}])
	vs := b.violations with input as inp
	"2.2.1.8: evidence missing — ios_profile.restrictions.allowOpenFromUnmanagedToManaged not collected" in vs
	not "2.2.1.8: documents must not open from unmanaged into managed destinations" in vs
}

# 2.2.1.9
test_2_2_1_9_pass if {
	vs := b.violations with input as green_end_user
	not _has_id(vs, "2.2.1.9")
}

test_2_2_1_9_fail if {
	inp := json.patch(green_end_user, [{"op": "replace", "path": "/ios_profile/restrictions/forceAirDropUnmanaged", "value": false}])
	vs := b.violations with input as inp
	"2.2.1.9: AirDrop must be treated as an unmanaged destination" in vs
}

test_2_2_1_9_evidence_missing if {
	inp := json.patch(green_end_user, [{"op": "remove", "path": "/ios_profile/restrictions/forceAirDropUnmanaged"}])
	vs := b.violations with input as inp
	"2.2.1.9: evidence missing — ios_profile.restrictions.forceAirDropUnmanaged not collected" in vs
	not "2.2.1.9: AirDrop must be treated as an unmanaged destination" in vs
}

# 2.2.1.10
test_2_2_1_10_pass if {
	vs := b.violations with input as green_end_user
	not _has_id(vs, "2.2.1.10")
}

test_2_2_1_10_fail if {
	inp := json.patch(green_end_user, [{"op": "replace", "path": "/ios_profile/restrictions/allowActivityContinuation", "value": true}])
	vs := b.violations with input as inp
	"2.2.1.10: Handoff must be blocked" in vs
}

test_2_2_1_10_evidence_missing if {
	inp := json.patch(green_end_user, [{"op": "remove", "path": "/ios_profile/restrictions/allowActivityContinuation"}])
	vs := b.violations with input as inp
	"2.2.1.10: evidence missing — ios_profile.restrictions.allowActivityContinuation not collected" in vs
	not "2.2.1.10: Handoff must be blocked" in vs
}

# 2.2.1.11
test_2_2_1_11_pass if {
	vs := b.violations with input as green_end_user
	not _has_id(vs, "2.2.1.11")
}

test_2_2_1_11_fail if {
	inp := json.patch(green_end_user, [{"op": "replace", "path": "/ios_profile/restrictions/allowDiagnosticSubmission", "value": true}])
	vs := b.violations with input as inp
	"2.2.1.11: diagnostic and usage data must not be sent to Apple" in vs
}

test_2_2_1_11_evidence_missing if {
	inp := json.patch(green_end_user, [{"op": "remove", "path": "/ios_profile/restrictions/allowDiagnosticSubmission"}])
	vs := b.violations with input as inp
	"2.2.1.11: evidence missing — ios_profile.restrictions.allowDiagnosticSubmission not collected" in vs
	not "2.2.1.11: diagnostic and usage data must not be sent to Apple" in vs
}

# 2.2.1.12
test_2_2_1_12_pass if {
	vs := b.violations with input as green_end_user
	not _has_id(vs, "2.2.1.12")
}

test_2_2_1_12_fail if {
	inp := json.patch(green_end_user, [{"op": "replace", "path": "/ios_profile/restrictions/forceWatchWristDetection", "value": false}])
	vs := b.violations with input as inp
	"2.2.1.12: Apple Watch wrist detection must be forced" in vs
}

test_2_2_1_12_evidence_missing if {
	inp := json.patch(green_end_user, [{"op": "remove", "path": "/ios_profile/restrictions/forceWatchWristDetection"}])
	vs := b.violations with input as inp
	"2.2.1.12: evidence missing — ios_profile.restrictions.forceWatchWristDetection not collected" in vs
	not "2.2.1.12: Apple Watch wrist detection must be forced" in vs
}

# 2.2.1.13
test_2_2_1_13_pass if {
	vs := b.violations with input as green_end_user
	not _has_id(vs, "2.2.1.13")
}

test_2_2_1_13_fail if {
	inp := json.patch(green_end_user, [{"op": "replace", "path": "/ios_profile/restrictions/allowLockScreenControlCenter", "value": true}])
	vs := b.violations with input as inp
	"2.2.1.13: Control Center must be hidden on the lock screen" in vs
}

test_2_2_1_13_evidence_missing if {
	inp := json.patch(green_end_user, [{"op": "remove", "path": "/ios_profile/restrictions/allowLockScreenControlCenter"}])
	vs := b.violations with input as inp
	"2.2.1.13: evidence missing — ios_profile.restrictions.allowLockScreenControlCenter not collected" in vs
	not "2.2.1.13: Control Center must be hidden on the lock screen" in vs
}

# 2.2.1.14
test_2_2_1_14_pass if {
	vs := b.violations with input as green_end_user
	not _has_id(vs, "2.2.1.14")
}

test_2_2_1_14_fail if {
	inp := json.patch(green_end_user, [{"op": "replace", "path": "/ios_profile/restrictions/allowLockScreenNotificationsView", "value": true}])
	vs := b.violations with input as inp
	"2.2.1.14: Notification Center must be hidden on the lock screen" in vs
}

test_2_2_1_14_evidence_missing if {
	inp := json.patch(green_end_user, [{"op": "remove", "path": "/ios_profile/restrictions/allowLockScreenNotificationsView"}])
	vs := b.violations with input as inp
	"2.2.1.14: evidence missing — ios_profile.restrictions.allowLockScreenNotificationsView not collected" in vs
	not "2.2.1.14: Notification Center must be hidden on the lock screen" in vs
}

# 2.2.2.1
test_2_2_2_1_pass if {
	vs := b.violations with input as green_end_user
	not _has_id(vs, "2.2.2.1")
}

test_2_2_2_1_fail if {
	inp := json.patch(green_end_user, [{"op": "replace", "path": "/ios_profile/restrictions/safariForceFraudWarning", "value": false}])
	vs := b.violations with input as inp
	"2.2.2.1: Safari fraud warning must be forced" in vs
}

test_2_2_2_1_evidence_missing if {
	inp := json.patch(green_end_user, [{"op": "remove", "path": "/ios_profile/restrictions/safariForceFraudWarning"}])
	vs := b.violations with input as inp
	"2.2.2.1: evidence missing — ios_profile.restrictions.safariForceFraudWarning not collected" in vs
	not "2.2.2.1: Safari fraud warning must be forced" in vs
}

# 2.2.2.2
test_2_2_2_2_pass if {
	vs := b.violations with input as green_end_user
	not _has_id(vs, "2.2.2.2")
}

test_2_2_2_2_fail if {
	inp := json.patch(green_end_user, [{"op": "replace", "path": "/ios_profile/restrictions/safariAcceptCookies", "value": 2}])
	vs := b.violations with input as inp
	"2.2.2.2: Safari must accept cookies only from visited or the current site" in vs
}

test_2_2_2_2_evidence_missing if {
	inp := json.patch(green_end_user, [{"op": "remove", "path": "/ios_profile/restrictions/safariAcceptCookies"}])
	vs := b.violations with input as inp
	"2.2.2.2: evidence missing — ios_profile.restrictions.safariAcceptCookies not collected" in vs
	not "2.2.2.2: Safari must accept cookies only from visited or the current site" in vs
}

# 2.3.1
test_2_3_1_pass if {
	vs := b.violations with input as green_end_user
	not _has_id(vs, "2.3.1")
}

test_2_3_1_fail if {
	inp := json.patch(green_end_user, [{"op": "replace", "path": "/ios_profile/attest/managed_safari_domains", "value": false}])
	vs := b.violations with input as inp
	"2.3.1: managed Safari web domains must be configured for the organisation (manual review not attested)" in vs
}

test_2_3_1_not_attested_when_absent if {
	inp := json.patch(green_end_user, [{"op": "remove", "path": "/ios_profile/attest/managed_safari_domains"}])
	vs := b.violations with input as inp
	"2.3.1: managed Safari web domains must be configured for the organisation (manual review not attested)" in vs
}

# 2.4.1
test_2_4_1_pass if {
	vs := b.violations with input as green_end_user
	not _has_id(vs, "2.4.1")
}

test_2_4_1_fail if {
	inp := json.patch(green_end_user, [{"op": "replace", "path": "/ios_profile/passcode/allowSimple", "value": true}])
	vs := b.violations with input as inp
	"2.4.1: simple passcodes must be blocked" in vs
}

test_2_4_1_evidence_missing if {
	inp := json.patch(green_end_user, [{"op": "remove", "path": "/ios_profile/passcode/allowSimple"}])
	vs := b.violations with input as inp
	"2.4.1: evidence missing — ios_profile.passcode.allowSimple not collected" in vs
	not "2.4.1: simple passcodes must be blocked" in vs
}

# 2.4.2
test_2_4_2_pass if {
	vs := b.violations with input as green_end_user
	not _has_id(vs, "2.4.2")
}

test_2_4_2_fail if {
	inp := json.patch(green_end_user, [{"op": "replace", "path": "/ios_profile/passcode/requireAlphanumeric", "value": false}])
	vs := b.violations with input as inp
	"2.4.2: an alphanumeric passcode must be required" in vs
}

test_2_4_2_evidence_missing if {
	inp := json.patch(green_end_user, [{"op": "remove", "path": "/ios_profile/passcode/requireAlphanumeric"}])
	vs := b.violations with input as inp
	"2.4.2: evidence missing — ios_profile.passcode.requireAlphanumeric not collected" in vs
	not "2.4.2: an alphanumeric passcode must be required" in vs
}

# 2.4.3
test_2_4_3_pass if {
	vs := b.violations with input as green_end_user
	not _has_id(vs, "2.4.3")
}

test_2_4_3_fail if {
	inp := json.patch(green_end_user, [{"op": "replace", "path": "/ios_profile/passcode/minLength", "value": 4}])
	vs := b.violations with input as inp
	"2.4.3: the passcode must be at least 6 characters" in vs
}

test_2_4_3_evidence_missing if {
	inp := json.patch(green_end_user, [{"op": "remove", "path": "/ios_profile/passcode/minLength"}])
	vs := b.violations with input as inp
	"2.4.3: evidence missing — ios_profile.passcode.minLength not collected" in vs
	not "2.4.3: the passcode must be at least 6 characters" in vs
}

# 2.4.4
test_2_4_4_pass if {
	vs := b.violations with input as green_end_user
	not _has_id(vs, "2.4.4")
}

test_2_4_4_fail if {
	inp := json.patch(green_end_user, [{"op": "replace", "path": "/ios_profile/passcode/maxInactivity", "value": 5}])
	vs := b.violations with input as inp
	"2.4.4: auto-lock must be set and no longer than 2 minutes" in vs
}

test_2_4_4_evidence_missing if {
	inp := json.patch(green_end_user, [{"op": "remove", "path": "/ios_profile/passcode/maxInactivity"}])
	vs := b.violations with input as inp
	"2.4.4: evidence missing — ios_profile.passcode.maxInactivity not collected" in vs
	not "2.4.4: auto-lock must be set and no longer than 2 minutes" in vs
}

# 2.4.5
test_2_4_5_pass if {
	vs := b.violations with input as green_end_user
	not _has_id(vs, "2.4.5")
}

test_2_4_5_fail if {
	inp := json.patch(green_end_user, [{"op": "replace", "path": "/ios_profile/passcode/maxGracePeriod", "value": 5}])
	vs := b.violations with input as inp
	"2.4.5: the device lock grace period must be immediate" in vs
}

test_2_4_5_evidence_missing if {
	inp := json.patch(green_end_user, [{"op": "remove", "path": "/ios_profile/passcode/maxGracePeriod"}])
	vs := b.violations with input as inp
	"2.4.5: evidence missing — ios_profile.passcode.maxGracePeriod not collected" in vs
	not "2.4.5: the device lock grace period must be immediate" in vs
}

# 2.4.6
test_2_4_6_pass if {
	vs := b.violations with input as green_end_user
	not _has_id(vs, "2.4.6")
}

test_2_4_6_fail if {
	inp := json.patch(green_end_user, [{"op": "replace", "path": "/ios_profile/passcode/maxFailedAttempts", "value": 10}])
	vs := b.violations with input as inp
	"2.4.6: failed passcode attempts must be limited to 6" in vs
}

test_2_4_6_evidence_missing if {
	inp := json.patch(green_end_user, [{"op": "remove", "path": "/ios_profile/passcode/maxFailedAttempts"}])
	vs := b.violations with input as inp
	"2.4.6: evidence missing — ios_profile.passcode.maxFailedAttempts not collected" in vs
	not "2.4.6: failed passcode attempts must be limited to 6" in vs
}

# 2.5.1
test_2_5_1_pass if {
	vs := b.violations with input as green_end_user
	not _has_id(vs, "2.5.1")
}

test_2_5_1_fail if {
	inp := json.patch(green_end_user, [{"op": "replace", "path": "/ios_profile/attest/mac_randomization_reviewed", "value": false}])
	vs := b.violations with input as inp
	"2.5.1: Wi-Fi MAC randomization must be disabled where the network needs it (manual review not attested)" in vs
}

test_2_5_1_not_attested_when_absent if {
	inp := json.patch(green_end_user, [{"op": "remove", "path": "/ios_profile/attest/mac_randomization_reviewed"}])
	vs := b.violations with input as inp
	"2.5.1: Wi-Fi MAC randomization must be disabled where the network needs it (manual review not attested)" in vs
}

# 2.6.1
test_2_6_1_pass if {
	vs := b.violations with input as green_end_user
	not _has_id(vs, "2.6.1")
}

test_2_6_1_fail if {
	inp := json.patch(green_end_user, [{"op": "replace", "path": "/ios_profile/attest/vpn_configured", "value": false}])
	vs := b.violations with input as inp
	"2.6.1: a VPN (per-app or system-wide) must be configured (manual review not attested)" in vs
}

test_2_6_1_not_attested_when_absent if {
	inp := json.patch(green_end_user, [{"op": "remove", "path": "/ios_profile/attest/vpn_configured"}])
	vs := b.violations with input as inp
	"2.6.1: a VPN (per-app or system-wide) must be configured (manual review not attested)" in vs
}

# 2.7.1
test_2_7_1_pass if {
	vs := b.violations with input as green_end_user
	not _has_id(vs, "2.7.1")
}

test_2_7_1_fail if {
	inp := json.patch(green_end_user, [{"op": "add", "path": "/ios_profile/mail_accounts/0/PreventMove", "value": false}])
	vs := b.violations with input as inp
	"2.7.1: mail messages must not be movable out of the managed account" in vs
}

test_2_7_1_evidence_missing if {
	inp := json.patch(green_end_user, [{"op": "remove", "path": "/ios_profile/mail_accounts"}])
	vs := b.violations with input as inp
	"2.7.1: evidence missing — ios_profile.mail_accounts not collected" in vs
	not "2.7.1: mail messages must not be movable out of the managed account" in vs
}

# 2.7.2
test_2_7_2_pass if {
	vs := b.violations with input as green_institutional
	not _has_id(vs, "2.7.2")
}

test_2_7_2_fail if {
	inp := json.patch(green_institutional, [{"op": "add", "path": "/ios_profile/mail_accounts/0/allowMailDrop", "value": true}])
	vs := b.violations with input as inp
	"2.7.2: Mail Drop must be blocked" in vs
}

test_2_7_2_evidence_missing if {
	inp := json.patch(green_institutional, [{"op": "remove", "path": "/ios_profile/mail_accounts"}])
	vs := b.violations with input as inp
	"2.7.2: evidence missing — ios_profile.mail_accounts not collected" in vs
	not "2.7.2: Mail Drop must be blocked" in vs
}

# 2.8.1
test_2_8_1_pass if {
	vs := b.violations with input as green_end_user
	not _has_id(vs, "2.8.1")
}

test_2_8_1_fail if {
	inp := json.patch(green_end_user, [{"op": "replace", "path": "/ios_profile/attest/managed_app_notifications", "value": false}])
	vs := b.violations with input as inp
	"2.8.1: every managed app must have a notification setting (manual review not attested)" in vs
}

test_2_8_1_not_attested_when_absent if {
	inp := json.patch(green_end_user, [{"op": "remove", "path": "/ios_profile/attest/managed_app_notifications"}])
	vs := b.violations with input as inp
	"2.8.1: every managed app must have a notification setting (manual review not attested)" in vs
}

# 2.9.1
test_2_9_1_pass if {
	vs := b.violations with input as green_end_user
	not _has_id(vs, "2.9.1")
}

test_2_9_1_fail if {
	inp := json.patch(green_end_user, [{"op": "replace", "path": "/ios_profile/restrictions/allowExternalIntelligenceIntegrations", "value": true}])
	vs := b.violations with input as inp
	"2.9.1: external intelligence integrations and their sign-in must be blocked" in vs
}

test_2_9_1_evidence_missing if {
	inp := json.patch(green_end_user, [{"op": "remove", "path": "/ios_profile/restrictions/allowExternalIntelligenceIntegrations"}])
	vs := b.violations with input as inp
	"2.9.1: evidence missing — ios_profile.restrictions.allowExternalIntelligenceIntegrations and ios_profile.restrictions.allowExternalIntelligenceIntegrationsSignIn not collected" in vs
	not "2.9.1: external intelligence integrations and their sign-in must be blocked" in vs
}

# 2.9.2
test_2_9_2_pass if {
	vs := b.violations with input as green_end_user
	not _has_id(vs, "2.9.2")
}

test_2_9_2_fail if {
	inp := json.patch(green_end_user, [{"op": "replace", "path": "/ios_profile/restrictions/allowNotesTranscription", "value": true}])
	vs := b.violations with input as inp
	"2.9.2: Notes transcription and summaries must be blocked" in vs
}

test_2_9_2_evidence_missing if {
	inp := json.patch(green_end_user, [{"op": "remove", "path": "/ios_profile/restrictions/allowNotesTranscription"}])
	vs := b.violations with input as inp
	"2.9.2: evidence missing — ios_profile.restrictions.allowNotesTranscription and ios_profile.restrictions.allowNotesTranscriptionSummary not collected" in vs
	not "2.9.2: Notes transcription and summaries must be blocked" in vs
}

# 2.9.3
test_2_9_3_pass if {
	vs := b.violations with input as green_end_user
	not _has_id(vs, "2.9.3")
}

test_2_9_3_fail if {
	inp := json.patch(green_end_user, [{"op": "replace", "path": "/ios_profile/restrictions/allowMailSummary", "value": true}])
	vs := b.violations with input as inp
	"2.9.3: Mail summaries must be blocked" in vs
}

test_2_9_3_evidence_missing if {
	inp := json.patch(green_end_user, [{"op": "remove", "path": "/ios_profile/restrictions/allowMailSummary"}])
	vs := b.violations with input as inp
	"2.9.3: evidence missing — ios_profile.restrictions.allowMailSummary not collected" in vs
	not "2.9.3: Mail summaries must be blocked" in vs
}

# 2.9.4
test_2_9_4_pass if {
	vs := b.violations with input as green_end_user
	not _has_id(vs, "2.9.4")
}

test_2_9_4_fail if {
	inp := json.patch(green_end_user, [{"op": "replace", "path": "/ios_profile/restrictions/allowWritingTools", "value": true}])
	vs := b.violations with input as inp
	"2.9.4: Writing Tools must be blocked" in vs
}

test_2_9_4_evidence_missing if {
	inp := json.patch(green_end_user, [{"op": "remove", "path": "/ios_profile/restrictions/allowWritingTools"}])
	vs := b.violations with input as inp
	"2.9.4: evidence missing — ios_profile.restrictions.allowWritingTools not collected" in vs
	not "2.9.4: Writing Tools must be blocked" in vs
}

# 2.9.5
test_2_9_5_pass if {
	vs := b.violations with input as green_end_user
	not _has_id(vs, "2.9.5")
}

test_2_9_5_fail if {
	inp := json.patch(green_end_user, [{"op": "replace", "path": "/ios_profile/restrictions/allowSafariSummary", "value": true}])
	vs := b.violations with input as inp
	"2.9.5: Safari summaries must be blocked" in vs
}

test_2_9_5_evidence_missing if {
	inp := json.patch(green_end_user, [{"op": "remove", "path": "/ios_profile/restrictions/allowSafariSummary"}])
	vs := b.violations with input as inp
	"2.9.5: evidence missing — ios_profile.restrictions.allowSafariSummary not collected" in vs
	not "2.9.5: Safari summaries must be blocked" in vs
}

# 2.9.6
test_2_9_6_pass if {
	vs := b.violations with input as green_end_user
	not _has_id(vs, "2.9.6")
}

test_2_9_6_fail if {
	inp := json.patch(green_end_user, [{"op": "replace", "path": "/ios_profile/restrictions/allowMailSmartReplies", "value": true}])
	vs := b.violations with input as inp
	"2.9.6: Mail smart replies must be blocked" in vs
}

test_2_9_6_evidence_missing if {
	inp := json.patch(green_end_user, [{"op": "remove", "path": "/ios_profile/restrictions/allowMailSmartReplies"}])
	vs := b.violations with input as inp
	"2.9.6: evidence missing — ios_profile.restrictions.allowMailSmartReplies not collected" in vs
	not "2.9.6: Mail smart replies must be blocked" in vs
}

# 3.1.1
test_3_1_1_pass if {
	vs := b.violations with input as green_institutional
	not _has_id(vs, "3.1.1")
}

test_3_1_1_fail if {
	inp := json.patch(green_institutional, [{"op": "replace", "path": "/ios_profile/profile/removal", "value": "always"}])
	vs := b.violations with input as inp
	"3.1.1: the profile must not be removable by the user" in vs
}

test_3_1_1_evidence_missing if {
	inp := json.patch(green_institutional, [{"op": "remove", "path": "/ios_profile/profile/removal"}])
	vs := b.violations with input as inp
	"3.1.1: evidence missing — ios_profile.profile.removal not collected" in vs
	not "3.1.1: the profile must not be removable by the user" in vs
}

# 3.2.1.1
test_3_2_1_1_pass if {
	vs := b.violations with input as green_institutional
	not _has_id(vs, "3.2.1.1")
}

test_3_2_1_1_fail if {
	inp := json.patch(green_institutional, [{"op": "replace", "path": "/ios_profile/restrictions/allowScreenShot", "value": true}])
	vs := b.violations with input as inp
	"3.2.1.1: screenshots and screen recording must be blocked" in vs
}

test_3_2_1_1_evidence_missing if {
	inp := json.patch(green_institutional, [{"op": "remove", "path": "/ios_profile/restrictions/allowScreenShot"}])
	vs := b.violations with input as inp
	"3.2.1.1: evidence missing — ios_profile.restrictions.allowScreenShot not collected" in vs
	not "3.2.1.1: screenshots and screen recording must be blocked" in vs
}

# 3.2.1.2
test_3_2_1_2_pass if {
	vs := b.violations with input as green_institutional
	not _has_id(vs, "3.2.1.2")
}

test_3_2_1_2_fail if {
	inp := json.patch(green_institutional, [{"op": "replace", "path": "/ios_profile/restrictions/allowAssistantWhileLocked", "value": true}])
	vs := b.violations with input as inp
	"3.2.1.2: Siri must be blocked on the lock screen" in vs
}

test_3_2_1_2_evidence_missing if {
	inp := json.patch(green_institutional, [{"op": "remove", "path": "/ios_profile/restrictions/allowAssistantWhileLocked"}])
	vs := b.violations with input as inp
	"3.2.1.2: evidence missing — ios_profile.restrictions.allowAssistantWhileLocked not collected" in vs
	not "3.2.1.2: Siri must be blocked on the lock screen" in vs
}

# 3.2.1.3
test_3_2_1_3_pass if {
	vs := b.violations with input as green_institutional
	not _has_id(vs, "3.2.1.3")
}

test_3_2_1_3_fail if {
	inp := json.patch(green_institutional, [{"op": "replace", "path": "/ios_profile/restrictions/allowCloudBackup", "value": true}])
	vs := b.violations with input as inp
	"3.2.1.3: iCloud backup must be blocked" in vs
}

test_3_2_1_3_evidence_missing if {
	inp := json.patch(green_institutional, [{"op": "remove", "path": "/ios_profile/restrictions/allowCloudBackup"}])
	vs := b.violations with input as inp
	"3.2.1.3: evidence missing — ios_profile.restrictions.allowCloudBackup not collected" in vs
	not "3.2.1.3: iCloud backup must be blocked" in vs
}

# 3.2.1.4
test_3_2_1_4_pass if {
	vs := b.violations with input as green_institutional
	not _has_id(vs, "3.2.1.4")
}

test_3_2_1_4_fail if {
	inp := json.patch(green_institutional, [{"op": "replace", "path": "/ios_profile/restrictions/allowCloudDocumentSync", "value": true}])
	vs := b.violations with input as inp
	"3.2.1.4: iCloud documents and data must be blocked" in vs
}

test_3_2_1_4_evidence_missing if {
	inp := json.patch(green_institutional, [{"op": "remove", "path": "/ios_profile/restrictions/allowCloudDocumentSync"}])
	vs := b.violations with input as inp
	"3.2.1.4: evidence missing — ios_profile.restrictions.allowCloudDocumentSync not collected" in vs
	not "3.2.1.4: iCloud documents and data must be blocked" in vs
}

# 3.2.1.5
test_3_2_1_5_pass if {
	vs := b.violations with input as green_institutional
	not _has_id(vs, "3.2.1.5")
}

test_3_2_1_5_fail if {
	inp := json.patch(green_institutional, [{"op": "replace", "path": "/ios_profile/restrictions/allowCloudKeychainSync", "value": true}])
	vs := b.violations with input as inp
	"3.2.1.5: iCloud Keychain must be blocked" in vs
}

test_3_2_1_5_evidence_missing if {
	inp := json.patch(green_institutional, [{"op": "remove", "path": "/ios_profile/restrictions/allowCloudKeychainSync"}])
	vs := b.violations with input as inp
	"3.2.1.5: evidence missing — ios_profile.restrictions.allowCloudKeychainSync not collected" in vs
	not "3.2.1.5: iCloud Keychain must be blocked" in vs
}

# 3.2.1.6
test_3_2_1_6_pass if {
	vs := b.violations with input as green_institutional
	not _has_id(vs, "3.2.1.6")
}

test_3_2_1_6_fail if {
	inp := json.patch(green_institutional, [{"op": "replace", "path": "/ios_profile/restrictions/allowManagedAppsCloudSync", "value": true}])
	vs := b.violations with input as inp
	"3.2.1.6: managed apps must not sync data to iCloud" in vs
}

test_3_2_1_6_evidence_missing if {
	inp := json.patch(green_institutional, [{"op": "remove", "path": "/ios_profile/restrictions/allowManagedAppsCloudSync"}])
	vs := b.violations with input as inp
	"3.2.1.6: evidence missing — ios_profile.restrictions.allowManagedAppsCloudSync not collected" in vs
	not "3.2.1.6: managed apps must not sync data to iCloud" in vs
}

# 3.2.1.7
test_3_2_1_7_pass if {
	vs := b.violations with input as green_institutional
	not _has_id(vs, "3.2.1.7")
}

test_3_2_1_7_fail if {
	inp := json.patch(green_institutional, [{"op": "replace", "path": "/ios_profile/restrictions/allowFilesUSBDriveAccess", "value": true}])
	vs := b.violations with input as inp
	"3.2.1.7: USB drive access in Files must be blocked" in vs
}

test_3_2_1_7_evidence_missing if {
	inp := json.patch(green_institutional, [{"op": "remove", "path": "/ios_profile/restrictions/allowFilesUSBDriveAccess"}])
	vs := b.violations with input as inp
	"3.2.1.7: evidence missing — ios_profile.restrictions.allowFilesUSBDriveAccess not collected" in vs
	not "3.2.1.7: USB drive access in Files must be blocked" in vs
}

# 3.2.1.8
test_3_2_1_8_pass if {
	vs := b.violations with input as green_institutional
	not _has_id(vs, "3.2.1.8")
}

test_3_2_1_8_fail if {
	inp := json.patch(green_institutional, [{"op": "replace", "path": "/ios_profile/restrictions/allowFilesNetworkDriveAccess", "value": true}])
	vs := b.violations with input as inp
	"3.2.1.8: network drive access in Files must be blocked" in vs
}

test_3_2_1_8_evidence_missing if {
	inp := json.patch(green_institutional, [{"op": "remove", "path": "/ios_profile/restrictions/allowFilesNetworkDriveAccess"}])
	vs := b.violations with input as inp
	"3.2.1.8: evidence missing — ios_profile.restrictions.allowFilesNetworkDriveAccess not collected" in vs
	not "3.2.1.8: network drive access in Files must be blocked" in vs
}

# 3.2.1.9
test_3_2_1_9_pass if {
	vs := b.violations with input as green_institutional
	not _has_id(vs, "3.2.1.9")
}

test_3_2_1_9_fail if {
	inp := json.patch(green_institutional, [{"op": "replace", "path": "/ios_profile/restrictions/forceEncryptedBackup", "value": false}])
	vs := b.violations with input as inp
	"3.2.1.9: backups must be forced to encrypt" in vs
}

test_3_2_1_9_evidence_missing if {
	inp := json.patch(green_institutional, [{"op": "remove", "path": "/ios_profile/restrictions/forceEncryptedBackup"}])
	vs := b.violations with input as inp
	"3.2.1.9: evidence missing — ios_profile.restrictions.forceEncryptedBackup not collected" in vs
	not "3.2.1.9: backups must be forced to encrypt" in vs
}

# 3.2.1.10
test_3_2_1_10_pass if {
	vs := b.violations with input as green_institutional
	not _has_id(vs, "3.2.1.10")
}

test_3_2_1_10_fail if {
	inp := json.patch(green_institutional, [{"op": "replace", "path": "/ios_profile/restrictions/allowApplePersonalizedAdvertising", "value": true}])
	vs := b.violations with input as inp
	"3.2.1.10: Apple personalized advertising must be blocked" in vs
}

test_3_2_1_10_evidence_missing if {
	inp := json.patch(green_institutional, [{"op": "remove", "path": "/ios_profile/restrictions/allowApplePersonalizedAdvertising"}])
	vs := b.violations with input as inp
	"3.2.1.10: evidence missing — ios_profile.restrictions.allowApplePersonalizedAdvertising not collected" in vs
	not "3.2.1.10: Apple personalized advertising must be blocked" in vs
}

# 3.2.1.11
test_3_2_1_11_pass if {
	vs := b.violations with input as green_institutional
	not _has_id(vs, "3.2.1.11")
}

test_3_2_1_11_fail if {
	inp := json.patch(green_institutional, [{"op": "replace", "path": "/ios_profile/restrictions/allowEraseContentAndSettings", "value": true}])
	vs := b.violations with input as inp
	"3.2.1.11: Erase All Content and Settings must be blocked" in vs
}

test_3_2_1_11_evidence_missing if {
	inp := json.patch(green_institutional, [{"op": "remove", "path": "/ios_profile/restrictions/allowEraseContentAndSettings"}])
	vs := b.violations with input as inp
	"3.2.1.11: evidence missing — ios_profile.restrictions.allowEraseContentAndSettings not collected" in vs
	not "3.2.1.11: Erase All Content and Settings must be blocked" in vs
}

# 3.2.1.12
test_3_2_1_12_pass if {
	vs := b.violations with input as green_institutional
	not _has_id(vs, "3.2.1.12")
}

test_3_2_1_12_fail if {
	inp := json.patch(green_institutional, [{"op": "replace", "path": "/ios_profile/restrictions/allowUntrustedTLSPrompt", "value": true}])
	vs := b.violations with input as inp
	"3.2.1.12: the user must not be able to accept untrusted TLS certificates" in vs
}

test_3_2_1_12_evidence_missing if {
	inp := json.patch(green_institutional, [{"op": "remove", "path": "/ios_profile/restrictions/allowUntrustedTLSPrompt"}])
	vs := b.violations with input as inp
	"3.2.1.12: evidence missing — ios_profile.restrictions.allowUntrustedTLSPrompt not collected" in vs
	not "3.2.1.12: the user must not be able to accept untrusted TLS certificates" in vs
}

# 3.2.1.13
test_3_2_1_13_pass if {
	vs := b.violations with input as green_institutional
	not _has_id(vs, "3.2.1.13")
}

test_3_2_1_13_fail if {
	inp := json.patch(green_institutional, [{"op": "replace", "path": "/ios_profile/restrictions/allowEnterpriseAppTrust", "value": true}])
	vs := b.violations with input as inp
	"3.2.1.13: trusting new enterprise app authors must be blocked" in vs
}

test_3_2_1_13_evidence_missing if {
	inp := json.patch(green_institutional, [{"op": "remove", "path": "/ios_profile/restrictions/allowEnterpriseAppTrust"}])
	vs := b.violations with input as inp
	"3.2.1.13: evidence missing — ios_profile.restrictions.allowEnterpriseAppTrust not collected" in vs
	not "3.2.1.13: trusting new enterprise app authors must be blocked" in vs
}

# 3.2.1.14
test_3_2_1_14_pass if {
	vs := b.violations with input as green_institutional
	not _has_id(vs, "3.2.1.14")
}

test_3_2_1_14_fail if {
	inp := json.patch(green_institutional, [{"op": "replace", "path": "/ios_profile/restrictions/allowUIConfigurationProfileInstallation", "value": true}])
	vs := b.violations with input as inp
	"3.2.1.14: installing configuration profiles must be blocked" in vs
}

test_3_2_1_14_evidence_missing if {
	inp := json.patch(green_institutional, [{"op": "remove", "path": "/ios_profile/restrictions/allowUIConfigurationProfileInstallation"}])
	vs := b.violations with input as inp
	"3.2.1.14: evidence missing — ios_profile.restrictions.allowUIConfigurationProfileInstallation not collected" in vs
	not "3.2.1.14: installing configuration profiles must be blocked" in vs
}

# 3.2.1.15
test_3_2_1_15_pass if {
	vs := b.violations with input as green_institutional
	not _has_id(vs, "3.2.1.15")
}

test_3_2_1_15_fail if {
	inp := json.patch(green_institutional, [{"op": "replace", "path": "/ios_profile/restrictions/allowVPNCreation", "value": true}])
	vs := b.violations with input as inp
	"3.2.1.15: adding VPN configurations must be blocked" in vs
}

test_3_2_1_15_evidence_missing if {
	inp := json.patch(green_institutional, [{"op": "remove", "path": "/ios_profile/restrictions/allowVPNCreation"}])
	vs := b.violations with input as inp
	"3.2.1.15: evidence missing — ios_profile.restrictions.allowVPNCreation not collected" in vs
	not "3.2.1.15: adding VPN configurations must be blocked" in vs
}

# 3.2.1.16
test_3_2_1_16_pass if {
	vs := b.violations with input as green_institutional
	not _has_id(vs, "3.2.1.16")
}

test_3_2_1_16_fail if {
	inp := json.patch(green_institutional, [{"op": "replace", "path": "/ios_profile/restrictions/forceAutomaticDateAndTime", "value": false}])
	vs := b.violations with input as inp
	"3.2.1.16: automatic date and time must be forced" in vs
}

test_3_2_1_16_evidence_missing if {
	inp := json.patch(green_institutional, [{"op": "remove", "path": "/ios_profile/restrictions/forceAutomaticDateAndTime"}])
	vs := b.violations with input as inp
	"3.2.1.16: evidence missing — ios_profile.restrictions.forceAutomaticDateAndTime not collected" in vs
	not "3.2.1.16: automatic date and time must be forced" in vs
}

# 3.2.1.17
test_3_2_1_17_pass if {
	vs := b.violations with input as green_institutional
	not _has_id(vs, "3.2.1.17")
}

test_3_2_1_17_fail if {
	inp := json.patch(green_institutional, [{"op": "replace", "path": "/ios_profile/restrictions/allowAppCellularDataModification", "value": true}])
	vs := b.violations with input as inp
	"3.2.1.17: changing per-app cellular data settings must be blocked" in vs
}

test_3_2_1_17_evidence_missing if {
	inp := json.patch(green_institutional, [{"op": "remove", "path": "/ios_profile/restrictions/allowAppCellularDataModification"}])
	vs := b.violations with input as inp
	"3.2.1.17: evidence missing — ios_profile.restrictions.allowAppCellularDataModification not collected" in vs
	not "3.2.1.17: changing per-app cellular data settings must be blocked" in vs
}

# 3.2.1.18
test_3_2_1_18_pass if {
	vs := b.violations with input as green_institutional
	not _has_id(vs, "3.2.1.18")
}

test_3_2_1_18_fail if {
	inp := json.patch(green_institutional, [{"op": "replace", "path": "/ios_profile/restrictions/allowUSBRestrictedMode", "value": false}])
	vs := b.violations with input as inp
	"3.2.1.18: USB accessories must be blocked while the device is locked (USB restricted mode kept on)" in vs
}

test_3_2_1_18_evidence_missing if {
	inp := json.patch(green_institutional, [{"op": "remove", "path": "/ios_profile/restrictions/allowUSBRestrictedMode"}])
	vs := b.violations with input as inp
	"3.2.1.18: evidence missing — ios_profile.restrictions.allowUSBRestrictedMode not collected" in vs
	not "3.2.1.18: USB accessories must be blocked while the device is locked (USB restricted mode kept on)" in vs
}

# 3.2.1.19
test_3_2_1_19_pass if {
	vs := b.violations with input as green_institutional
	not _has_id(vs, "3.2.1.19")
}

test_3_2_1_19_fail if {
	inp := json.patch(green_institutional, [{"op": "replace", "path": "/ios_profile/restrictions/allowHostPairing", "value": true}])
	vs := b.violations with input as inp
	"3.2.1.19: pairing with hosts other than Configurator must be blocked" in vs
}

test_3_2_1_19_evidence_missing if {
	inp := json.patch(green_institutional, [{"op": "remove", "path": "/ios_profile/restrictions/allowHostPairing"}])
	vs := b.violations with input as inp
	"3.2.1.19: evidence missing — ios_profile.restrictions.allowHostPairing not collected" in vs
	not "3.2.1.19: pairing with hosts other than Configurator must be blocked" in vs
}

# 3.2.1.20
test_3_2_1_20_pass if {
	vs := b.violations with input as green_institutional
	not _has_id(vs, "3.2.1.20")
}

test_3_2_1_20_fail if {
	inp := json.patch(green_institutional, [{"op": "replace", "path": "/ios_profile/restrictions/allowOpenFromManagedToUnmanaged", "value": true}])
	vs := b.violations with input as inp
	"3.2.1.20: documents must not open from managed into unmanaged destinations" in vs
}

test_3_2_1_20_evidence_missing if {
	inp := json.patch(green_institutional, [{"op": "remove", "path": "/ios_profile/restrictions/allowOpenFromManagedToUnmanaged"}])
	vs := b.violations with input as inp
	"3.2.1.20: evidence missing — ios_profile.restrictions.allowOpenFromManagedToUnmanaged not collected" in vs
	not "3.2.1.20: documents must not open from managed into unmanaged destinations" in vs
}

# 3.2.1.21
test_3_2_1_21_pass if {
	vs := b.violations with input as green_institutional
	not _has_id(vs, "3.2.1.21")
}

test_3_2_1_21_fail if {
	inp := json.patch(green_institutional, [{"op": "replace", "path": "/ios_profile/restrictions/allowOpenFromUnmanagedToManaged", "value": true}])
	vs := b.violations with input as inp
	"3.2.1.21: documents must not open from unmanaged into managed destinations" in vs
}

test_3_2_1_21_evidence_missing if {
	inp := json.patch(green_institutional, [{"op": "remove", "path": "/ios_profile/restrictions/allowOpenFromUnmanagedToManaged"}])
	vs := b.violations with input as inp
	"3.2.1.21: evidence missing — ios_profile.restrictions.allowOpenFromUnmanagedToManaged not collected" in vs
	not "3.2.1.21: documents must not open from unmanaged into managed destinations" in vs
}

# 3.2.1.22
test_3_2_1_22_pass if {
	vs := b.violations with input as green_institutional
	not _has_id(vs, "3.2.1.22")
}

test_3_2_1_22_fail if {
	inp := json.patch(green_institutional, [{"op": "replace", "path": "/ios_profile/restrictions/forceAirDropUnmanaged", "value": false}])
	vs := b.violations with input as inp
	"3.2.1.22: AirDrop must be treated as an unmanaged destination" in vs
}

test_3_2_1_22_evidence_missing if {
	inp := json.patch(green_institutional, [{"op": "remove", "path": "/ios_profile/restrictions/forceAirDropUnmanaged"}])
	vs := b.violations with input as inp
	"3.2.1.22: evidence missing — ios_profile.restrictions.forceAirDropUnmanaged not collected" in vs
	not "3.2.1.22: AirDrop must be treated as an unmanaged destination" in vs
}

# 3.2.1.23
test_3_2_1_23_pass if {
	vs := b.violations with input as green_institutional
	not _has_id(vs, "3.2.1.23")
}

test_3_2_1_23_fail if {
	inp := json.patch(green_institutional, [{"op": "replace", "path": "/ios_profile/restrictions/allowActivityContinuation", "value": true}])
	vs := b.violations with input as inp
	"3.2.1.23: Handoff must be blocked" in vs
}

test_3_2_1_23_evidence_missing if {
	inp := json.patch(green_institutional, [{"op": "remove", "path": "/ios_profile/restrictions/allowActivityContinuation"}])
	vs := b.violations with input as inp
	"3.2.1.23: evidence missing — ios_profile.restrictions.allowActivityContinuation not collected" in vs
	not "3.2.1.23: Handoff must be blocked" in vs
}

# 3.2.1.24
test_3_2_1_24_pass if {
	vs := b.violations with input as green_institutional
	not _has_id(vs, "3.2.1.24")
}

test_3_2_1_24_fail if {
	inp := json.patch(green_institutional, [{"op": "replace", "path": "/ios_profile/restrictions/allowDiagnosticSubmission", "value": true}])
	vs := b.violations with input as inp
	"3.2.1.24: diagnostic and usage data must not be sent to Apple" in vs
}

test_3_2_1_24_evidence_missing if {
	inp := json.patch(green_institutional, [{"op": "remove", "path": "/ios_profile/restrictions/allowDiagnosticSubmission"}])
	vs := b.violations with input as inp
	"3.2.1.24: evidence missing — ios_profile.restrictions.allowDiagnosticSubmission not collected" in vs
	not "3.2.1.24: diagnostic and usage data must not be sent to Apple" in vs
}

# 3.2.1.25
test_3_2_1_25_pass if {
	vs := b.violations with input as green_institutional
	not _has_id(vs, "3.2.1.25")
}

test_3_2_1_25_fail if {
	inp := json.patch(green_institutional, [{"op": "replace", "path": "/ios_profile/restrictions/forceAuthenticationBeforeAutoFill", "value": false}])
	vs := b.violations with input as inp
	"3.2.1.25: biometric authentication must be required before AutoFill" in vs
}

test_3_2_1_25_evidence_missing if {
	inp := json.patch(green_institutional, [{"op": "remove", "path": "/ios_profile/restrictions/forceAuthenticationBeforeAutoFill"}])
	vs := b.violations with input as inp
	"3.2.1.25: evidence missing — ios_profile.restrictions.forceAuthenticationBeforeAutoFill not collected" in vs
	not "3.2.1.25: biometric authentication must be required before AutoFill" in vs
}

# 3.2.1.26
test_3_2_1_26_pass if {
	vs := b.violations with input as green_institutional
	not _has_id(vs, "3.2.1.26")
}

test_3_2_1_26_fail if {
	inp := json.patch(green_institutional, [{"op": "replace", "path": "/ios_profile/restrictions/forceWatchWristDetection", "value": false}])
	vs := b.violations with input as inp
	"3.2.1.26: Apple Watch wrist detection must be forced" in vs
}

test_3_2_1_26_evidence_missing if {
	inp := json.patch(green_institutional, [{"op": "remove", "path": "/ios_profile/restrictions/forceWatchWristDetection"}])
	vs := b.violations with input as inp
	"3.2.1.26: evidence missing — ios_profile.restrictions.forceWatchWristDetection not collected" in vs
	not "3.2.1.26: Apple Watch wrist detection must be forced" in vs
}

# 3.2.1.27
test_3_2_1_27_pass if {
	vs := b.violations with input as green_institutional
	not _has_id(vs, "3.2.1.27")
}

test_3_2_1_27_fail if {
	inp := json.patch(green_institutional, [{"op": "replace", "path": "/ios_profile/restrictions/allowProximitySetupToNewDevice", "value": true}])
	vs := b.violations with input as inp
	"3.2.1.27: setting up new nearby devices must be blocked" in vs
}

test_3_2_1_27_evidence_missing if {
	inp := json.patch(green_institutional, [{"op": "remove", "path": "/ios_profile/restrictions/allowProximitySetupToNewDevice"}])
	vs := b.violations with input as inp
	"3.2.1.27: evidence missing — ios_profile.restrictions.allowProximitySetupToNewDevice not collected" in vs
	not "3.2.1.27: setting up new nearby devices must be blocked" in vs
}

# 3.2.1.28
test_3_2_1_28_pass if {
	vs := b.violations with input as green_institutional
	not _has_id(vs, "3.2.1.28")
}

test_3_2_1_28_fail if {
	inp := json.patch(green_institutional, [{"op": "replace", "path": "/ios_profile/restrictions/allowPasswordProximityRequests", "value": true}])
	vs := b.violations with input as inp
	"3.2.1.28: proximity password sharing requests must be blocked" in vs
}

test_3_2_1_28_evidence_missing if {
	inp := json.patch(green_institutional, [{"op": "remove", "path": "/ios_profile/restrictions/allowPasswordProximityRequests"}])
	vs := b.violations with input as inp
	"3.2.1.28: evidence missing — ios_profile.restrictions.allowPasswordProximityRequests not collected" in vs
	not "3.2.1.28: proximity password sharing requests must be blocked" in vs
}

# 3.2.1.29
test_3_2_1_29_pass if {
	vs := b.violations with input as green_institutional
	not _has_id(vs, "3.2.1.29")
}

test_3_2_1_29_fail if {
	inp := json.patch(green_institutional, [{"op": "replace", "path": "/ios_profile/restrictions/allowPasswordSharing", "value": true}])
	vs := b.violations with input as inp
	"3.2.1.29: password sharing must be blocked" in vs
}

test_3_2_1_29_evidence_missing if {
	inp := json.patch(green_institutional, [{"op": "remove", "path": "/ios_profile/restrictions/allowPasswordSharing"}])
	vs := b.violations with input as inp
	"3.2.1.29: evidence missing — ios_profile.restrictions.allowPasswordSharing not collected" in vs
	not "3.2.1.29: password sharing must be blocked" in vs
}

# 3.2.1.30
test_3_2_1_30_pass if {
	vs := b.violations with input as green_institutional
	not _has_id(vs, "3.2.1.30")
}

test_3_2_1_30_fail if {
	inp := json.patch(green_institutional, [{"op": "replace", "path": "/ios_profile/restrictions/allowLockScreenControlCenter", "value": true}])
	vs := b.violations with input as inp
	"3.2.1.30: Control Center must be hidden on the lock screen" in vs
}

test_3_2_1_30_evidence_missing if {
	inp := json.patch(green_institutional, [{"op": "remove", "path": "/ios_profile/restrictions/allowLockScreenControlCenter"}])
	vs := b.violations with input as inp
	"3.2.1.30: evidence missing — ios_profile.restrictions.allowLockScreenControlCenter not collected" in vs
	not "3.2.1.30: Control Center must be hidden on the lock screen" in vs
}

# 3.2.1.31
test_3_2_1_31_pass if {
	vs := b.violations with input as green_institutional
	not _has_id(vs, "3.2.1.31")
}

test_3_2_1_31_fail if {
	inp := json.patch(green_institutional, [{"op": "replace", "path": "/ios_profile/restrictions/allowLockScreenNotificationsView", "value": true}])
	vs := b.violations with input as inp
	"3.2.1.31: Notification Center must be hidden on the lock screen" in vs
}

test_3_2_1_31_evidence_missing if {
	inp := json.patch(green_institutional, [{"op": "remove", "path": "/ios_profile/restrictions/allowLockScreenNotificationsView"}])
	vs := b.violations with input as inp
	"3.2.1.31: evidence missing — ios_profile.restrictions.allowLockScreenNotificationsView not collected" in vs
	not "3.2.1.31: Notification Center must be hidden on the lock screen" in vs
}

# 3.2.2.1
test_3_2_2_1_pass if {
	vs := b.violations with input as green_institutional
	not _has_id(vs, "3.2.2.1")
}

test_3_2_2_1_fail if {
	inp := json.patch(green_institutional, [{"op": "replace", "path": "/ios_profile/restrictions/safariForceFraudWarning", "value": false}])
	vs := b.violations with input as inp
	"3.2.2.1: Safari fraud warning must be forced" in vs
}

test_3_2_2_1_evidence_missing if {
	inp := json.patch(green_institutional, [{"op": "remove", "path": "/ios_profile/restrictions/safariForceFraudWarning"}])
	vs := b.violations with input as inp
	"3.2.2.1: evidence missing — ios_profile.restrictions.safariForceFraudWarning not collected" in vs
	not "3.2.2.1: Safari fraud warning must be forced" in vs
}

# 3.2.2.2
test_3_2_2_2_pass if {
	vs := b.violations with input as green_institutional
	not _has_id(vs, "3.2.2.2")
}

test_3_2_2_2_fail if {
	inp := json.patch(green_institutional, [{"op": "replace", "path": "/ios_profile/restrictions/safariAcceptCookies", "value": 2}])
	vs := b.violations with input as inp
	"3.2.2.2: Safari must accept cookies only from visited or the current site" in vs
}

test_3_2_2_2_evidence_missing if {
	inp := json.patch(green_institutional, [{"op": "remove", "path": "/ios_profile/restrictions/safariAcceptCookies"}])
	vs := b.violations with input as inp
	"3.2.2.2: evidence missing — ios_profile.restrictions.safariAcceptCookies not collected" in vs
	not "3.2.2.2: Safari must accept cookies only from visited or the current site" in vs
}

# 3.3.1
test_3_3_1_pass if {
	vs := b.violations with input as green_institutional
	not _has_id(vs, "3.3.1")
}

test_3_3_1_fail if {
	inp := json.patch(green_institutional, [{"op": "replace", "path": "/ios_profile/attest/managed_safari_domains", "value": false}])
	vs := b.violations with input as inp
	"3.3.1: managed Safari web domains must be configured for the organisation (manual review not attested)" in vs
}

test_3_3_1_not_attested_when_absent if {
	inp := json.patch(green_institutional, [{"op": "remove", "path": "/ios_profile/attest/managed_safari_domains"}])
	vs := b.violations with input as inp
	"3.3.1: managed Safari web domains must be configured for the organisation (manual review not attested)" in vs
}

# 3.4.1
test_3_4_1_pass if {
	vs := b.violations with input as green_institutional
	not _has_id(vs, "3.4.1")
}

test_3_4_1_fail if {
	inp := json.patch(green_institutional, [{"op": "replace", "path": "/ios_profile/passcode/allowSimple", "value": true}])
	vs := b.violations with input as inp
	"3.4.1: simple passcodes must be blocked" in vs
}

test_3_4_1_evidence_missing if {
	inp := json.patch(green_institutional, [{"op": "remove", "path": "/ios_profile/passcode/allowSimple"}])
	vs := b.violations with input as inp
	"3.4.1: evidence missing — ios_profile.passcode.allowSimple not collected" in vs
	not "3.4.1: simple passcodes must be blocked" in vs
}

# 3.4.2
test_3_4_2_pass if {
	vs := b.violations with input as green_end_user
	not _has_id(vs, "3.4.2")
}

test_3_4_2_fail if {
	inp := json.patch(green_end_user, [{"op": "replace", "path": "/ios_profile/passcode/requireAlphanumeric", "value": false}])
	vs := b.violations with input as inp
	"3.4.2: an alphanumeric passcode must be required" in vs
}

test_3_4_2_evidence_missing if {
	inp := json.patch(green_end_user, [{"op": "remove", "path": "/ios_profile/passcode/requireAlphanumeric"}])
	vs := b.violations with input as inp
	"3.4.2: evidence missing — ios_profile.passcode.requireAlphanumeric not collected" in vs
	not "3.4.2: an alphanumeric passcode must be required" in vs
}

# 3.4.3
test_3_4_3_pass if {
	vs := b.violations with input as green_institutional
	not _has_id(vs, "3.4.3")
}

test_3_4_3_fail if {
	inp := json.patch(green_institutional, [{"op": "replace", "path": "/ios_profile/passcode/minLength", "value": 4}])
	vs := b.violations with input as inp
	"3.4.3: the passcode must be at least 6 characters" in vs
}

test_3_4_3_evidence_missing if {
	inp := json.patch(green_institutional, [{"op": "remove", "path": "/ios_profile/passcode/minLength"}])
	vs := b.violations with input as inp
	"3.4.3: evidence missing — ios_profile.passcode.minLength not collected" in vs
	not "3.4.3: the passcode must be at least 6 characters" in vs
}

# 3.4.4
test_3_4_4_pass if {
	vs := b.violations with input as green_institutional
	not _has_id(vs, "3.4.4")
}

test_3_4_4_fail if {
	inp := json.patch(green_institutional, [{"op": "replace", "path": "/ios_profile/passcode/maxInactivity", "value": 5}])
	vs := b.violations with input as inp
	"3.4.4: auto-lock must be set and no longer than 2 minutes" in vs
}

test_3_4_4_evidence_missing if {
	inp := json.patch(green_institutional, [{"op": "remove", "path": "/ios_profile/passcode/maxInactivity"}])
	vs := b.violations with input as inp
	"3.4.4: evidence missing — ios_profile.passcode.maxInactivity not collected" in vs
	not "3.4.4: auto-lock must be set and no longer than 2 minutes" in vs
}

# 3.4.5
test_3_4_5_pass if {
	vs := b.violations with input as green_institutional
	not _has_id(vs, "3.4.5")
}

test_3_4_5_fail if {
	inp := json.patch(green_institutional, [{"op": "replace", "path": "/ios_profile/passcode/maxGracePeriod", "value": 5}])
	vs := b.violations with input as inp
	"3.4.5: the device lock grace period must be immediate" in vs
}

test_3_4_5_evidence_missing if {
	inp := json.patch(green_institutional, [{"op": "remove", "path": "/ios_profile/passcode/maxGracePeriod"}])
	vs := b.violations with input as inp
	"3.4.5: evidence missing — ios_profile.passcode.maxGracePeriod not collected" in vs
	not "3.4.5: the device lock grace period must be immediate" in vs
}

# 3.4.6
test_3_4_6_pass if {
	vs := b.violations with input as green_institutional
	not _has_id(vs, "3.4.6")
}

test_3_4_6_fail if {
	inp := json.patch(green_institutional, [{"op": "replace", "path": "/ios_profile/passcode/maxFailedAttempts", "value": 10}])
	vs := b.violations with input as inp
	"3.4.6: failed passcode attempts must be limited to 6" in vs
}

test_3_4_6_evidence_missing if {
	inp := json.patch(green_institutional, [{"op": "remove", "path": "/ios_profile/passcode/maxFailedAttempts"}])
	vs := b.violations with input as inp
	"3.4.6: evidence missing — ios_profile.passcode.maxFailedAttempts not collected" in vs
	not "3.4.6: failed passcode attempts must be limited to 6" in vs
}

# 3.5.1
test_3_5_1_pass if {
	vs := b.violations with input as green_end_user
	not _has_id(vs, "3.5.1")
}

test_3_5_1_fail if {
	inp := json.patch(green_end_user, [{"op": "replace", "path": "/ios_profile/attest/mac_randomization_reviewed", "value": false}])
	vs := b.violations with input as inp
	"3.5.1: Wi-Fi MAC randomization must be disabled where the network needs it (manual review not attested)" in vs
}

test_3_5_1_not_attested_when_absent if {
	inp := json.patch(green_end_user, [{"op": "remove", "path": "/ios_profile/attest/mac_randomization_reviewed"}])
	vs := b.violations with input as inp
	"3.5.1: Wi-Fi MAC randomization must be disabled where the network needs it (manual review not attested)" in vs
}

# 3.6.1
test_3_6_1_pass if {
	vs := b.violations with input as green_institutional
	not _has_id(vs, "3.6.1")
}

test_3_6_1_fail if {
	inp := json.patch(green_institutional, [{"op": "replace", "path": "/ios_profile/attest/vpn_configured", "value": false}])
	vs := b.violations with input as inp
	"3.6.1: a VPN (per-app or system-wide) must be configured (manual review not attested)" in vs
}

test_3_6_1_not_attested_when_absent if {
	inp := json.patch(green_institutional, [{"op": "remove", "path": "/ios_profile/attest/vpn_configured"}])
	vs := b.violations with input as inp
	"3.6.1: a VPN (per-app or system-wide) must be configured (manual review not attested)" in vs
}

# 3.7.1
test_3_7_1_pass if {
	vs := b.violations with input as green_institutional
	not _has_id(vs, "3.7.1")
}

test_3_7_1_fail if {
	inp := json.patch(green_institutional, [{"op": "add", "path": "/ios_profile/mail_accounts/0/PreventMove", "value": false}])
	vs := b.violations with input as inp
	"3.7.1: mail messages must not be movable out of the managed account" in vs
}

test_3_7_1_evidence_missing if {
	inp := json.patch(green_institutional, [{"op": "remove", "path": "/ios_profile/mail_accounts"}])
	vs := b.violations with input as inp
	"3.7.1: evidence missing — ios_profile.mail_accounts not collected" in vs
	not "3.7.1: mail messages must not be movable out of the managed account" in vs
}

# 3.7.2
test_3_7_2_pass if {
	vs := b.violations with input as green_institutional
	not _has_id(vs, "3.7.2")
}

test_3_7_2_fail if {
	inp := json.patch(green_institutional, [{"op": "add", "path": "/ios_profile/mail_accounts/0/allowMailDrop", "value": true}])
	vs := b.violations with input as inp
	"3.7.2: Mail Drop must be blocked" in vs
}

test_3_7_2_evidence_missing if {
	inp := json.patch(green_institutional, [{"op": "remove", "path": "/ios_profile/mail_accounts"}])
	vs := b.violations with input as inp
	"3.7.2: evidence missing — ios_profile.mail_accounts not collected" in vs
	not "3.7.2: Mail Drop must be blocked" in vs
}

# 3.8.1
test_3_8_1_pass if {
	vs := b.violations with input as green_institutional
	not _has_id(vs, "3.8.1")
}

test_3_8_1_fail if {
	inp := json.patch(green_institutional, [{"op": "replace", "path": "/ios_profile/attest/managed_app_notifications", "value": false}])
	vs := b.violations with input as inp
	"3.8.1: every managed app must have a notification setting (manual review not attested)" in vs
}

test_3_8_1_not_attested_when_absent if {
	inp := json.patch(green_institutional, [{"op": "remove", "path": "/ios_profile/attest/managed_app_notifications"}])
	vs := b.violations with input as inp
	"3.8.1: every managed app must have a notification setting (manual review not attested)" in vs
}

# 3.9.1
test_3_9_1_pass if {
	vs := b.violations with input as green_institutional
	not _has_id(vs, "3.9.1")
}

test_3_9_1_fail if {
	inp := json.patch(green_institutional, [{"op": "replace", "path": "/ios_profile/attest/lost_message_configured", "value": false}])
	vs := b.violations with input as inp
	"3.9.1: a return-if-found lock screen message must be configured (manual review not attested)" in vs
}

test_3_9_1_not_attested_when_absent if {
	inp := json.patch(green_institutional, [{"op": "remove", "path": "/ios_profile/attest/lost_message_configured"}])
	vs := b.violations with input as inp
	"3.9.1: a return-if-found lock screen message must be configured (manual review not attested)" in vs
}

# 3.10.1
test_3_10_1_pass if {
	vs := b.violations with input as green_institutional
	not _has_id(vs, "3.10.1")
}

test_3_10_1_fail if {
	inp := json.patch(green_institutional, [{"op": "replace", "path": "/ios_profile/restrictions/allowExternalIntelligenceIntegrations", "value": true}])
	vs := b.violations with input as inp
	"3.10.1: external intelligence integrations and their sign-in must be blocked" in vs
}

test_3_10_1_evidence_missing if {
	inp := json.patch(green_institutional, [{"op": "remove", "path": "/ios_profile/restrictions/allowExternalIntelligenceIntegrations"}])
	vs := b.violations with input as inp
	"3.10.1: evidence missing — ios_profile.restrictions.allowExternalIntelligenceIntegrations and ios_profile.restrictions.allowExternalIntelligenceIntegrationsSignIn not collected" in vs
	not "3.10.1: external intelligence integrations and their sign-in must be blocked" in vs
}

# 3.10.2
test_3_10_2_pass if {
	vs := b.violations with input as green_institutional
	not _has_id(vs, "3.10.2")
}

test_3_10_2_fail if {
	inp := json.patch(green_institutional, [{"op": "replace", "path": "/ios_profile/restrictions/allowNotesTranscription", "value": true}])
	vs := b.violations with input as inp
	"3.10.2: Notes transcription and summaries must be blocked" in vs
}

test_3_10_2_evidence_missing if {
	inp := json.patch(green_institutional, [{"op": "remove", "path": "/ios_profile/restrictions/allowNotesTranscription"}])
	vs := b.violations with input as inp
	"3.10.2: evidence missing — ios_profile.restrictions.allowNotesTranscription and ios_profile.restrictions.allowNotesTranscriptionSummary not collected" in vs
	not "3.10.2: Notes transcription and summaries must be blocked" in vs
}

# 3.10.3
test_3_10_3_pass if {
	vs := b.violations with input as green_institutional
	not _has_id(vs, "3.10.3")
}

test_3_10_3_fail if {
	inp := json.patch(green_institutional, [{"op": "replace", "path": "/ios_profile/restrictions/allowMailSummary", "value": true}])
	vs := b.violations with input as inp
	"3.10.3: Mail summaries must be blocked" in vs
}

test_3_10_3_evidence_missing if {
	inp := json.patch(green_institutional, [{"op": "remove", "path": "/ios_profile/restrictions/allowMailSummary"}])
	vs := b.violations with input as inp
	"3.10.3: evidence missing — ios_profile.restrictions.allowMailSummary not collected" in vs
	not "3.10.3: Mail summaries must be blocked" in vs
}

# 3.10.4
test_3_10_4_pass if {
	vs := b.violations with input as green_institutional
	not _has_id(vs, "3.10.4")
}

test_3_10_4_fail if {
	inp := json.patch(green_institutional, [{"op": "replace", "path": "/ios_profile/restrictions/allowWritingTools", "value": true}])
	vs := b.violations with input as inp
	"3.10.4: Writing Tools must be blocked" in vs
}

test_3_10_4_evidence_missing if {
	inp := json.patch(green_institutional, [{"op": "remove", "path": "/ios_profile/restrictions/allowWritingTools"}])
	vs := b.violations with input as inp
	"3.10.4: evidence missing — ios_profile.restrictions.allowWritingTools not collected" in vs
	not "3.10.4: Writing Tools must be blocked" in vs
}

# 3.10.5
test_3_10_5_pass if {
	vs := b.violations with input as green_institutional
	not _has_id(vs, "3.10.5")
}

test_3_10_5_fail if {
	inp := json.patch(green_institutional, [{"op": "replace", "path": "/ios_profile/restrictions/allowSafariSummary", "value": true}])
	vs := b.violations with input as inp
	"3.10.5: Safari summaries must be blocked" in vs
}

test_3_10_5_evidence_missing if {
	inp := json.patch(green_institutional, [{"op": "remove", "path": "/ios_profile/restrictions/allowSafariSummary"}])
	vs := b.violations with input as inp
	"3.10.5: evidence missing — ios_profile.restrictions.allowSafariSummary not collected" in vs
	not "3.10.5: Safari summaries must be blocked" in vs
}

# 3.10.6
test_3_10_6_pass if {
	vs := b.violations with input as green_institutional
	not _has_id(vs, "3.10.6")
}

test_3_10_6_fail if {
	inp := json.patch(green_institutional, [{"op": "replace", "path": "/ios_profile/restrictions/allowMailSmartReplies", "value": true}])
	vs := b.violations with input as inp
	"3.10.6: Mail smart replies must be blocked" in vs
}

test_3_10_6_evidence_missing if {
	inp := json.patch(green_institutional, [{"op": "remove", "path": "/ios_profile/restrictions/allowMailSmartReplies"}])
	vs := b.violations with input as inp
	"3.10.6: evidence missing — ios_profile.restrictions.allowMailSmartReplies not collected" in vs
	not "3.10.6: Mail smart replies must be blocked" in vs
}

# 4.1.1
test_4_1_1_pass if {
	vs := b.violations with input as green_end_user
	not _has_id(vs, "4.1.1")
}

test_4_1_1_fail if {
	inp := json.patch(green_end_user, [{"op": "replace", "path": "/ios_profile/attest/sharing_access_reviewed", "value": false}])
	vs := b.violations with input as inp
	"4.1.1: Manage Sharing and Access must be reviewed on the device (manual review not attested)" in vs
}

test_4_1_1_not_attested_when_absent if {
	inp := json.patch(green_end_user, [{"op": "remove", "path": "/ios_profile/attest/sharing_access_reviewed"}])
	vs := b.violations with input as inp
	"4.1.1: Manage Sharing and Access must be reviewed on the device (manual review not attested)" in vs
}

# 4.1.2
test_4_1_2_pass if {
	vs := b.violations with input as green_end_user
	not _has_id(vs, "4.1.2")
}

test_4_1_2_fail if {
	inp := json.patch(green_end_user, [{"op": "replace", "path": "/ios_profile/attest/emergency_reset_reviewed", "value": false}])
	vs := b.violations with input as inp
	"4.1.2: Emergency Reset must be reviewed on the device (manual review not attested)" in vs
}

test_4_1_2_not_attested_when_absent if {
	inp := json.patch(green_end_user, [{"op": "remove", "path": "/ios_profile/attest/emergency_reset_reviewed"}])
	vs := b.violations with input as inp
	"4.1.2: Emergency Reset must be reviewed on the device (manual review not attested)" in vs
}

# 4.1.3
test_4_1_3_pass if {
	vs := b.violations with input as green_end_user
	not _has_id(vs, "4.1.3")
}

test_4_1_3_fail if {
	inp := json.patch(green_end_user, [{"op": "replace", "path": "/ios_profile/attest/lockdown_mode_reviewed", "value": false}])
	vs := b.violations with input as inp
	"4.1.3: Lockdown Mode must be reviewed for the user (manual review not attested)" in vs
}

test_4_1_3_not_attested_when_absent if {
	inp := json.patch(green_end_user, [{"op": "remove", "path": "/ios_profile/attest/lockdown_mode_reviewed"}])
	vs := b.violations with input as inp
	"4.1.3: Lockdown Mode must be reviewed for the user (manual review not attested)" in vs
}

# 4.1.4
test_4_1_4_pass if {
	vs := b.violations with input as green_end_user
	not _has_id(vs, "4.1.4")
}

test_4_1_4_fail if {
	inp := json.patch(green_end_user, [{"op": "replace", "path": "/ios_profile/attest/app_privacy_report_enabled", "value": false}])
	vs := b.violations with input as inp
	"4.1.4: App Privacy Report must be turned on (manual review not attested)" in vs
}

test_4_1_4_not_attested_when_absent if {
	inp := json.patch(green_end_user, [{"op": "remove", "path": "/ios_profile/attest/app_privacy_report_enabled"}])
	vs := b.violations with input as inp
	"4.1.4: App Privacy Report must be turned on (manual review not attested)" in vs
}

# 4.1.5
test_4_1_5_pass if {
	vs := b.violations with input as green_end_user
	not _has_id(vs, "4.1.5")
}

test_4_1_5_fail if {
	inp := json.patch(green_end_user, [{"op": "replace", "path": "/ios_profile/attest/airprint_reviewed", "value": false}])
	vs := b.violations with input as inp
	"4.1.5: AirPrint use must be reviewed on the device (manual review not attested)" in vs
}

test_4_1_5_not_attested_when_absent if {
	inp := json.patch(green_end_user, [{"op": "remove", "path": "/ios_profile/attest/airprint_reviewed"}])
	vs := b.violations with input as inp
	"4.1.5: AirPrint use must be reviewed on the device (manual review not attested)" in vs
}

# 4.1.6
test_4_1_6_pass if {
	vs := b.violations with input as green_end_user
	not _has_id(vs, "4.1.6")
}

test_4_1_6_fail if {
	inp := json.patch(green_end_user, [{"op": "replace", "path": "/ios_profile/attest/stolen_device_protection_enabled", "value": false}])
	vs := b.violations with input as inp
	"4.1.6: Stolen Device Protection must be turned on (manual review not attested)" in vs
}

test_4_1_6_not_attested_when_absent if {
	inp := json.patch(green_end_user, [{"op": "remove", "path": "/ios_profile/attest/stolen_device_protection_enabled"}])
	vs := b.violations with input as inp
	"4.1.6: Stolen Device Protection must be turned on (manual review not attested)" in vs
}

# 4.2
test_4_2_pass if {
	vs := b.violations with input as green_end_user
	not _has_id(vs, "4.2")
}

test_4_2_fail if {
	inp := json.patch(green_end_user, [{"op": "replace", "path": "/ios_profile/attest/not_jailbroken", "value": false}])
	vs := b.violations with input as inp
	"4.2: the device must show no sign of jailbreak or compromise (manual review not attested)" in vs
}

test_4_2_not_attested_when_absent if {
	inp := json.patch(green_end_user, [{"op": "remove", "path": "/ios_profile/attest/not_jailbroken"}])
	vs := b.violations with input as inp
	"4.2: the device must show no sign of jailbreak or compromise (manual review not attested)" in vs
}

# 4.3
test_4_3_pass if {
	vs := b.violations with input as green_end_user
	not _has_id(vs, "4.3")
}

test_4_3_fail if {
	inp := json.patch(green_end_user, [{"op": "replace", "path": "/ios_profile/attest/auto_update_install_enabled", "value": false}])
	vs := b.violations with input as inp
	"4.3: automatic iOS update installation must be turned on (manual review not attested)" in vs
}

test_4_3_not_attested_when_absent if {
	inp := json.patch(green_end_user, [{"op": "remove", "path": "/ios_profile/attest/auto_update_install_enabled"}])
	vs := b.violations with input as inp
	"4.3: automatic iOS update installation must be turned on (manual review not attested)" in vs
}

# 4.4
test_4_4_pass if {
	vs := b.violations with input as green_end_user
	not _has_id(vs, "4.4")
}

test_4_4_fail if {
	inp := json.patch(green_end_user, [{"op": "replace", "path": "/ios_profile/attest/software_up_to_date", "value": false}])
	vs := b.violations with input as inp
	"4.4: the device must be on the current iOS release (manual review not attested)" in vs
}

test_4_4_not_attested_when_absent if {
	inp := json.patch(green_end_user, [{"op": "remove", "path": "/ios_profile/attest/software_up_to_date"}])
	vs := b.violations with input as inp
	"4.4: the device must be on the current iOS release (manual review not attested)" in vs
}

# 4.5
test_4_5_pass if {
	vs := b.violations with input as green_end_user
	not _has_id(vs, "4.5")
}

test_4_5_fail if {
	inp := json.patch(green_end_user, [{"op": "replace", "path": "/ios_profile/attest/private_relay_reviewed", "value": false}])
	vs := b.violations with input as inp
	"4.5: iCloud Private Relay must be reviewed on the device (manual review not attested)" in vs
}

test_4_5_not_attested_when_absent if {
	inp := json.patch(green_end_user, [{"op": "remove", "path": "/ios_profile/attest/private_relay_reviewed"}])
	vs := b.violations with input as inp
	"4.5: iCloud Private Relay must be reviewed on the device (manual review not attested)" in vs
}

# 4.6
test_4_6_pass if {
	vs := b.violations with input as green_end_user
	not _has_id(vs, "4.6")
}

test_4_6_fail if {
	inp := json.patch(green_end_user, [{"op": "replace", "path": "/ios_profile/attest/mail_privacy_reviewed", "value": false}])
	vs := b.violations with input as inp
	"4.6: Mail Privacy Protection must be reviewed on the device (manual review not attested)" in vs
}

test_4_6_not_attested_when_absent if {
	inp := json.patch(green_end_user, [{"op": "remove", "path": "/ios_profile/attest/mail_privacy_reviewed"}])
	vs := b.violations with input as inp
	"4.6: Mail Privacy Protection must be reviewed on the device (manual review not attested)" in vs
}

# 4.7
test_4_7_pass if {
	vs := b.violations with input as green_end_user
	not _has_id(vs, "4.7")
}

test_4_7_fail if {
	inp := json.patch(green_end_user, [{"op": "replace", "path": "/ios_profile/attest/auto_app_updates_enabled", "value": false}])
	vs := b.violations with input as inp
	"4.7: automatic app update downloads must be turned on (manual review not attested)" in vs
}

test_4_7_not_attested_when_absent if {
	inp := json.patch(green_end_user, [{"op": "remove", "path": "/ios_profile/attest/auto_app_updates_enabled"}])
	vs := b.violations with input as inp
	"4.7: automatic app update downloads must be turned on (manual review not attested)" in vs
}

# 4.8
test_4_8_pass if {
	vs := b.violations with input as green_end_user
	not _has_id(vs, "4.8")
}

test_4_8_fail if {
	inp := json.patch(green_end_user, [{"op": "replace", "path": "/ios_profile/attest/find_my_enabled", "value": false}])
	vs := b.violations with input as inp
	"4.8: Find My iPhone, Find My network and Send Last Location must be turned on (manual review not attested)" in vs
}

test_4_8_not_attested_when_absent if {
	inp := json.patch(green_end_user, [{"op": "remove", "path": "/ios_profile/attest/find_my_enabled"}])
	vs := b.violations with input as inp
	"4.8: Find My iPhone, Find My network and Send Last Location must be turned on (manual review not attested)" in vs
}

# 4.9
test_4_9_pass if {
	vs := b.violations with input as green_end_user
	not _has_id(vs, "4.9")
}

test_4_9_fail if {
	inp := json.patch(green_end_user, [{"op": "replace", "path": "/ios_profile/attest/latest_hardware_for_high_value", "value": false}])
	vs := b.violations with input as inp
	"4.9: high-value targets must use the latest device hardware generation (manual review not attested)" in vs
}

test_4_9_not_attested_when_absent if {
	inp := json.patch(green_end_user, [{"op": "remove", "path": "/ios_profile/attest/latest_hardware_for_high_value"}])
	vs := b.violations with input as inp
	"4.9: high-value targets must use the latest device hardware generation (manual review not attested)" in vs
}

# 4.10
test_4_10_pass if {
	vs := b.violations with input as green_end_user
	not _has_id(vs, "4.10")
}

test_4_10_fail if {
	inp := json.patch(green_end_user, [{"op": "replace", "path": "/ios_profile/attest/iphone_mirroring_reviewed", "value": false}])
	vs := b.violations with input as inp
	"4.10: iPhone Mirroring must be reviewed on the device (manual review not attested)" in vs
}

test_4_10_not_attested_when_absent if {
	inp := json.patch(green_end_user, [{"op": "remove", "path": "/ios_profile/attest/iphone_mirroring_reviewed"}])
	vs := b.violations with input as inp
	"4.10: iPhone Mirroring must be reviewed on the device (manual review not attested)" in vs
}

# 4.11
test_4_11_pass if {
	vs := b.violations with input as green_end_user
	not _has_id(vs, "4.11")
}

test_4_11_fail if {
	inp := json.patch(green_end_user, [{"op": "replace", "path": "/ios_profile/attest/rcs_messaging_enabled", "value": false}])
	vs := b.violations with input as inp
	"4.11: RCS messaging must be turned on where available (manual review not attested)" in vs
}

test_4_11_not_attested_when_absent if {
	inp := json.patch(green_end_user, [{"op": "remove", "path": "/ios_profile/attest/rcs_messaging_enabled"}])
	vs := b.violations with input as inp
	"4.11: RCS messaging must be turned on where available (manual review not attested)" in vs
}

# #300 type traps: a non-number must not pass r_2_4_4.
test_r_2_4_4_number_type_traps if {
	data.cis.mobile.ios.r_2_4_4 with input as {"ios_profile": {"passcode": {"maxInactivity": 2}}}
	not data.cis.mobile.ios.r_2_4_4 with input as {"ios_profile": {"passcode": {"maxInactivity": "1"}}}
	not data.cis.mobile.ios.r_2_4_4 with input as {"ios_profile": {"passcode": {"maxInactivity": null}}}
	not data.cis.mobile.ios.r_2_4_4 with input as {"ios_profile": {"passcode": {"maxInactivity": "not-a-number"}}}
}
