# METADATA
# title: "CIS Apple iOS 27 Benchmark v1.0.0"
# custom:
#   class: security
#   framework: cis_mobile_devices
#   source: cis
#   domains: [mobile, ios]
#   coverage:
#     checks: 105
#     cited: 105
#     expected: 105
#     found: 105
#     scope: module
#     density: full
#     basis: declared-total
#     tested: true
#     entrypoint: compliance_report
#     guard: self
#     as_of: v2.5.0
package cis.mobile.ios

# CIS Apple iOS 27 Benchmark v1.0.0.
# Rebuilt from the CIS workbook by tools/cis_generators/gen_ios_27.py; it replaces the earlier hand-written module (24 checks, old numbering,
# input.device_config) in place. Messages use our own wording, not CIS text.
# 105 recommendations (70 Automated, 35 Manual) over four profiles: Level 1 / Level 2 for
# end-user owned and institutionally owned devices. input.cis_profile.ownership (end_user | institutional, default
# institutional) and input.cis_profile.level (the number 1 | 2, default 2, includes Level 1) select the recommendations in scope:
# end_user 45 / 53, institutional 56 / 69 at Level 1 / Level 2.
# 80 are decided from configuration-profile keys and fail closed ('<id>: evidence missing — <path> not collected');
# 25 are attestation booleans under input.ios_profile.attest (false or absent => violation): on-device settings and judgement
# items. 4.8 and 4.11 are Automated in the workbook but are on-device settings with no profile key, so they are attested.
# Manual recommendations that map to one profile key (for example 2.2.1.4, 2.4.2, 3.2.1.1) are checked like Automated ones.
#
# Input contract (input.ios_profile): the EFFECTIVE configuration-profile values, payload key names as in the Apple payloads:
#   restrictions   : com.apple.applicationaccess keys (allowAssistantWhileLocked, forceEncryptedBackup, allowUntrustedTLSPrompt,
#                    allowOpenFromManagedToUnmanaged, forceAirDropUnmanaged, safariForceFraudWarning, safariAcceptCookies, ...) as booleans/numbers
#   passcode       : com.apple.mobiledevice.passwordpolicy keys (allowSimple, requireAlphanumeric, minLength, maxInactivity in minutes,
#                    maxGracePeriod, maxFailedAttempts)
#   profile        : {removal: always | with_authorization | never, consent_message: string}
#   mail_accounts  : list of com.apple.mail.managed payloads {PreventMove, allowMailDrop}; an empty list passes
#   attest         : attestation booleans
# A key that is absent is evidence missing, never a pass (the Apple defaults are not assumed).

import rego.v1

default _cis_profile := {}

_cis_profile := p if {
	p := input.cis_profile
	is_object(p)
}

default level := 2

level := 1 if _cis_profile.level == 1

default _ownership := "institutional"

_ownership := o if {
	o := _cis_profile.ownership
	o in {"end_user", "institutional"}
}

_applies(id) if {
	some p in recommendations[id].profiles
	p.ownership == _ownership
	p.level <= level
}

# A profile selector that is present and not one of its values is invalid evidence, never a default. A bad level is
# scoped at Level 2 and fails every Level 2 recommendation of the ownership; a bad ownership is scoped as institutional
# and fails every recommendation, because the set that applies could not be chosen.
default _level_invalid := false

_level_invalid if {
	cp := input.cis_profile
	not is_object(cp)
}

_level_invalid if {
	lv := input.cis_profile.level
	not lv in {1, 2}
}

default _ownership_invalid := false

_ownership_invalid if {
	cp := input.cis_profile
	not is_object(cp)
}

_ownership_invalid if {
	o := input.cis_profile.ownership
	not o in {"end_user", "institutional"}
}

_selector_got(k) := json.marshal(input.cis_profile[k]) if is_object(input.cis_profile)

_selector_got(_) := json.marshal(cp) if {
	cp := input.cis_profile
	not is_object(cp)
}

_level_finding := sprintf("evidence invalid — cis_profile.level must be the number 1 or 2, got %s", [_selector_got("level")])

_ownership_finding := sprintf("evidence invalid — cis_profile.ownership must be \"end_user\" or \"institutional\", got %s", [_selector_got("ownership")])

_v_profile contains sprintf("cis_profile.level: %s; the report is scoped at Level 2", [_level_finding]) if _level_invalid

_v_profile contains sprintf("%s: %s, so this Level 2 recommendation could not be scoped", [id, _level_finding]) if {
	_level_invalid
	some id, r in recommendations
	some p in r.profiles
	p.ownership == _ownership
	p.level == 2
}

_v_profile contains sprintf("cis_profile.ownership: %s; the report is scoped as institutional", [_ownership_finding]) if _ownership_invalid

_v_profile contains sprintf("%s: %s, so this recommendation could not be scoped", [id, _ownership_finding]) if {
	_ownership_invalid
	some id in in_scope
}

default compliant := false

compliant if {
	input.ios_profile
	count(violations) == 0
}

violations := ((_v_2 | _v_3) | _v_4) | _v_profile

# section 2
# 2.1.1 (Automated, Level 1 - End-User Owned Devices)
default r_2_1_1 := false

r_2_1_1 if {
	trim_space(input.ios_profile.profile.consent_message) != ""
}

default e_2_1_1 := false

e_2_1_1 if {
	is_string(input.ios_profile.profile.consent_message)
}

_v_2 contains "2.1.1: evidence missing — ios_profile.profile.consent_message not collected" if {
	_applies("2.1.1")
	not e_2_1_1
}

_v_2 contains "2.1.1: the profile must carry a consent message" if {
	_applies("2.1.1")
	e_2_1_1
	not r_2_1_1
}

# 2.1.2 (Manual, Level 1 - End-User Owned Devices) -- Manual in the workbook; decidable from configuration, so checked like Automated
default r_2_1_2 := false

r_2_1_2 if {
	lower(input.ios_profile.profile.removal) == "always"
}

default e_2_1_2 := false

e_2_1_2 if {
	is_string(input.ios_profile.profile.removal)
}

_v_2 contains "2.1.2: evidence missing — ios_profile.profile.removal not collected" if {
	_applies("2.1.2")
	not e_2_1_2
}

_v_2 contains "2.1.2: end-user profile removal must stay allowed" if {
	_applies("2.1.2")
	e_2_1_2
	not r_2_1_2
}

# 2.2.1.1 (Automated, Level 1 - End-User Owned Devices)
default r_2_2_1_1 := false

r_2_2_1_1 if {
	input.ios_profile.restrictions.allowAssistantWhileLocked == false
}

default e_2_2_1_1 := false

e_2_2_1_1 if {
	is_boolean(input.ios_profile.restrictions.allowAssistantWhileLocked)
}

_v_2 contains "2.2.1.1: evidence missing — ios_profile.restrictions.allowAssistantWhileLocked not collected" if {
	_applies("2.2.1.1")
	not e_2_2_1_1
}

_v_2 contains "2.2.1.1: Siri must be blocked on the lock screen" if {
	_applies("2.2.1.1")
	e_2_2_1_1
	not r_2_2_1_1
}

# 2.2.1.2 (Automated, Level 1 - End-User Owned Devices)
default r_2_2_1_2 := false

r_2_2_1_2 if {
	input.ios_profile.restrictions.allowManagedAppsCloudSync == false
}

default e_2_2_1_2 := false

e_2_2_1_2 if {
	is_boolean(input.ios_profile.restrictions.allowManagedAppsCloudSync)
}

_v_2 contains "2.2.1.2: evidence missing — ios_profile.restrictions.allowManagedAppsCloudSync not collected" if {
	_applies("2.2.1.2")
	not e_2_2_1_2
}

_v_2 contains "2.2.1.2: managed apps must not sync data to iCloud" if {
	_applies("2.2.1.2")
	e_2_2_1_2
	not r_2_2_1_2
}

# 2.2.1.3 (Automated, Level 1 - End-User Owned Devices)
default r_2_2_1_3 := false

r_2_2_1_3 if {
	input.ios_profile.restrictions.forceEncryptedBackup == true
}

default e_2_2_1_3 := false

e_2_2_1_3 if {
	is_boolean(input.ios_profile.restrictions.forceEncryptedBackup)
}

_v_2 contains "2.2.1.3: evidence missing — ios_profile.restrictions.forceEncryptedBackup not collected" if {
	_applies("2.2.1.3")
	not e_2_2_1_3
}

_v_2 contains "2.2.1.3: backups must be forced to encrypt" if {
	_applies("2.2.1.3")
	e_2_2_1_3
	not r_2_2_1_3
}

# 2.2.1.4 (Manual, Level 1 - End-User Owned Devices) -- Manual in the workbook; decidable from configuration, so checked like Automated
default r_2_2_1_4 := false

r_2_2_1_4 if {
	input.ios_profile.restrictions.allowApplePersonalizedAdvertising == false
}

default e_2_2_1_4 := false

e_2_2_1_4 if {
	is_boolean(input.ios_profile.restrictions.allowApplePersonalizedAdvertising)
}

_v_2 contains "2.2.1.4: evidence missing — ios_profile.restrictions.allowApplePersonalizedAdvertising not collected" if {
	_applies("2.2.1.4")
	not e_2_2_1_4
}

_v_2 contains "2.2.1.4: Apple personalized advertising must be blocked" if {
	_applies("2.2.1.4")
	e_2_2_1_4
	not r_2_2_1_4
}

# 2.2.1.5 (Automated, Level 2 - End-User Owned Devices)
default r_2_2_1_5 := false

r_2_2_1_5 if {
	input.ios_profile.restrictions.allowUntrustedTLSPrompt == false
}

default e_2_2_1_5 := false

e_2_2_1_5 if {
	is_boolean(input.ios_profile.restrictions.allowUntrustedTLSPrompt)
}

_v_2 contains "2.2.1.5: evidence missing — ios_profile.restrictions.allowUntrustedTLSPrompt not collected" if {
	_applies("2.2.1.5")
	not e_2_2_1_5
}

_v_2 contains "2.2.1.5: the user must not be able to accept untrusted TLS certificates" if {
	_applies("2.2.1.5")
	e_2_2_1_5
	not r_2_2_1_5
}

# 2.2.1.6 (Manual, Level 1 - End-User Owned Devices) -- Manual in the workbook; decidable from configuration, so checked like Automated
default r_2_2_1_6 := false

r_2_2_1_6 if {
	input.ios_profile.restrictions.forceAutomaticDateAndTime == true
}

default e_2_2_1_6 := false

e_2_2_1_6 if {
	is_boolean(input.ios_profile.restrictions.forceAutomaticDateAndTime)
}

_v_2 contains "2.2.1.6: evidence missing — ios_profile.restrictions.forceAutomaticDateAndTime not collected" if {
	_applies("2.2.1.6")
	not e_2_2_1_6
}

_v_2 contains "2.2.1.6: automatic date and time must be forced" if {
	_applies("2.2.1.6")
	e_2_2_1_6
	not r_2_2_1_6
}

# 2.2.1.7 (Automated, Level 1 - End-User Owned Devices)
default r_2_2_1_7 := false

r_2_2_1_7 if {
	input.ios_profile.restrictions.allowOpenFromManagedToUnmanaged == false
}

default e_2_2_1_7 := false

e_2_2_1_7 if {
	is_boolean(input.ios_profile.restrictions.allowOpenFromManagedToUnmanaged)
}

_v_2 contains "2.2.1.7: evidence missing — ios_profile.restrictions.allowOpenFromManagedToUnmanaged not collected" if {
	_applies("2.2.1.7")
	not e_2_2_1_7
}

_v_2 contains "2.2.1.7: documents must not open from managed into unmanaged destinations" if {
	_applies("2.2.1.7")
	e_2_2_1_7
	not r_2_2_1_7
}

# 2.2.1.8 (Automated, Level 1 - End-User Owned Devices)
default r_2_2_1_8 := false

r_2_2_1_8 if {
	input.ios_profile.restrictions.allowOpenFromUnmanagedToManaged == false
}

default e_2_2_1_8 := false

e_2_2_1_8 if {
	is_boolean(input.ios_profile.restrictions.allowOpenFromUnmanagedToManaged)
}

_v_2 contains "2.2.1.8: evidence missing — ios_profile.restrictions.allowOpenFromUnmanagedToManaged not collected" if {
	_applies("2.2.1.8")
	not e_2_2_1_8
}

_v_2 contains "2.2.1.8: documents must not open from unmanaged into managed destinations" if {
	_applies("2.2.1.8")
	e_2_2_1_8
	not r_2_2_1_8
}

# 2.2.1.9 (Automated, Level 1 - End-User Owned Devices)
default r_2_2_1_9 := false

r_2_2_1_9 if {
	input.ios_profile.restrictions.forceAirDropUnmanaged == true
}

default e_2_2_1_9 := false

e_2_2_1_9 if {
	is_boolean(input.ios_profile.restrictions.forceAirDropUnmanaged)
}

_v_2 contains "2.2.1.9: evidence missing — ios_profile.restrictions.forceAirDropUnmanaged not collected" if {
	_applies("2.2.1.9")
	not e_2_2_1_9
}

_v_2 contains "2.2.1.9: AirDrop must be treated as an unmanaged destination" if {
	_applies("2.2.1.9")
	e_2_2_1_9
	not r_2_2_1_9
}

# 2.2.1.10 (Automated, Level 2 - End-User Owned Devices)
default r_2_2_1_10 := false

r_2_2_1_10 if {
	input.ios_profile.restrictions.allowActivityContinuation == false
}

default e_2_2_1_10 := false

e_2_2_1_10 if {
	is_boolean(input.ios_profile.restrictions.allowActivityContinuation)
}

_v_2 contains "2.2.1.10: evidence missing — ios_profile.restrictions.allowActivityContinuation not collected" if {
	_applies("2.2.1.10")
	not e_2_2_1_10
}

_v_2 contains "2.2.1.10: Handoff must be blocked" if {
	_applies("2.2.1.10")
	e_2_2_1_10
	not r_2_2_1_10
}

# 2.2.1.11 (Manual, Level 1 - End-User Owned Devices) -- Manual in the workbook; decidable from configuration, so checked like Automated
default r_2_2_1_11 := false

r_2_2_1_11 if {
	input.ios_profile.restrictions.allowDiagnosticSubmission == false
}

default e_2_2_1_11 := false

e_2_2_1_11 if {
	is_boolean(input.ios_profile.restrictions.allowDiagnosticSubmission)
}

_v_2 contains "2.2.1.11: evidence missing — ios_profile.restrictions.allowDiagnosticSubmission not collected" if {
	_applies("2.2.1.11")
	not e_2_2_1_11
}

_v_2 contains "2.2.1.11: diagnostic and usage data must not be sent to Apple" if {
	_applies("2.2.1.11")
	e_2_2_1_11
	not r_2_2_1_11
}

# 2.2.1.12 (Automated, Level 1 - End-User Owned Devices)
default r_2_2_1_12 := false

r_2_2_1_12 if {
	input.ios_profile.restrictions.forceWatchWristDetection == true
}

default e_2_2_1_12 := false

e_2_2_1_12 if {
	is_boolean(input.ios_profile.restrictions.forceWatchWristDetection)
}

_v_2 contains "2.2.1.12: evidence missing — ios_profile.restrictions.forceWatchWristDetection not collected" if {
	_applies("2.2.1.12")
	not e_2_2_1_12
}

_v_2 contains "2.2.1.12: Apple Watch wrist detection must be forced" if {
	_applies("2.2.1.12")
	e_2_2_1_12
	not r_2_2_1_12
}

# 2.2.1.13 (Automated, Level 1 - End-User Owned Devices)
default r_2_2_1_13 := false

r_2_2_1_13 if {
	input.ios_profile.restrictions.allowLockScreenControlCenter == false
}

default e_2_2_1_13 := false

e_2_2_1_13 if {
	is_boolean(input.ios_profile.restrictions.allowLockScreenControlCenter)
}

_v_2 contains "2.2.1.13: evidence missing — ios_profile.restrictions.allowLockScreenControlCenter not collected" if {
	_applies("2.2.1.13")
	not e_2_2_1_13
}

_v_2 contains "2.2.1.13: Control Center must be hidden on the lock screen" if {
	_applies("2.2.1.13")
	e_2_2_1_13
	not r_2_2_1_13
}

# 2.2.1.14 (Automated, Level 1 - End-User Owned Devices)
default r_2_2_1_14 := false

r_2_2_1_14 if {
	input.ios_profile.restrictions.allowLockScreenNotificationsView == false
}

default e_2_2_1_14 := false

e_2_2_1_14 if {
	is_boolean(input.ios_profile.restrictions.allowLockScreenNotificationsView)
}

_v_2 contains "2.2.1.14: evidence missing — ios_profile.restrictions.allowLockScreenNotificationsView not collected" if {
	_applies("2.2.1.14")
	not e_2_2_1_14
}

_v_2 contains "2.2.1.14: Notification Center must be hidden on the lock screen" if {
	_applies("2.2.1.14")
	e_2_2_1_14
	not r_2_2_1_14
}

# 2.2.2.1 (Automated, Level 1 - End-User Owned Devices)
default r_2_2_2_1 := false

r_2_2_2_1 if {
	input.ios_profile.restrictions.safariForceFraudWarning == true
}

default e_2_2_2_1 := false

e_2_2_2_1 if {
	is_boolean(input.ios_profile.restrictions.safariForceFraudWarning)
}

_v_2 contains "2.2.2.1: evidence missing — ios_profile.restrictions.safariForceFraudWarning not collected" if {
	_applies("2.2.2.1")
	not e_2_2_2_1
}

_v_2 contains "2.2.2.1: Safari fraud warning must be forced" if {
	_applies("2.2.2.1")
	e_2_2_2_1
	not r_2_2_2_1
}

# 2.2.2.2 (Automated, Level 1 - End-User Owned Devices)
default r_2_2_2_2 := false

r_2_2_2_2 if {
	input.ios_profile.restrictions.safariAcceptCookies in {1, 1.5}
}

default e_2_2_2_2 := false

e_2_2_2_2 if {
	is_number(input.ios_profile.restrictions.safariAcceptCookies)
}

_v_2 contains "2.2.2.2: evidence missing — ios_profile.restrictions.safariAcceptCookies not collected" if {
	_applies("2.2.2.2")
	not e_2_2_2_2
}

_v_2 contains "2.2.2.2: Safari must accept cookies only from visited or the current site" if {
	_applies("2.2.2.2")
	e_2_2_2_2
	not r_2_2_2_2
}

# 2.3.1 (Manual, Level 1 - End-User Owned Devices)
default r_2_3_1 := false

r_2_3_1 if {
	input.ios_profile.attest.managed_safari_domains == true
}

_v_2 contains "2.3.1: managed Safari web domains must be configured for the organisation (manual review not attested)" if {
	_applies("2.3.1")
	not r_2_3_1
}

# 2.4.1 (Automated, Level 1 - End-User Owned Devices)
default r_2_4_1 := false

r_2_4_1 if {
	input.ios_profile.passcode.allowSimple == false
}

default e_2_4_1 := false

e_2_4_1 if {
	is_boolean(input.ios_profile.passcode.allowSimple)
}

_v_2 contains "2.4.1: evidence missing — ios_profile.passcode.allowSimple not collected" if {
	_applies("2.4.1")
	not e_2_4_1
}

_v_2 contains "2.4.1: simple passcodes must be blocked" if {
	_applies("2.4.1")
	e_2_4_1
	not r_2_4_1
}

# 2.4.2 (Manual, Level 2 - End-User Owned Devices; Level 2 - Institutionally-Owned Devices) -- Manual in the workbook; decidable from configuration, so checked like Automated
default r_2_4_2 := false

r_2_4_2 if {
	input.ios_profile.passcode.requireAlphanumeric == true
}

default e_2_4_2 := false

e_2_4_2 if {
	is_boolean(input.ios_profile.passcode.requireAlphanumeric)
}

_v_2 contains "2.4.2: evidence missing — ios_profile.passcode.requireAlphanumeric not collected" if {
	_applies("2.4.2")
	not e_2_4_2
}

_v_2 contains "2.4.2: an alphanumeric passcode must be required" if {
	_applies("2.4.2")
	e_2_4_2
	not r_2_4_2
}

# 2.4.3 (Automated, Level 1 - End-User Owned Devices)
default r_2_4_3 := false

r_2_4_3 if {
	is_number(input.ios_profile.passcode.minLength)
	input.ios_profile.passcode.minLength >= 6
}

default e_2_4_3 := false

e_2_4_3 if {
	is_number(input.ios_profile.passcode.minLength)
}

_v_2 contains "2.4.3: evidence missing — ios_profile.passcode.minLength not collected" if {
	_applies("2.4.3")
	not e_2_4_3
}

_v_2 contains "2.4.3: the passcode must be at least 6 characters" if {
	_applies("2.4.3")
	e_2_4_3
	not r_2_4_3
}

# 2.4.4 (Automated, Level 1 - End-User Owned Devices)
default r_2_4_4 := false

r_2_4_4 if {
	is_number(input.ios_profile.passcode.maxInactivity)
	input.ios_profile.passcode.maxInactivity >= 1
	input.ios_profile.passcode.maxInactivity <= 2
}

default e_2_4_4 := false

e_2_4_4 if {
	is_number(input.ios_profile.passcode.maxInactivity)
}

_v_2 contains "2.4.4: evidence missing — ios_profile.passcode.maxInactivity not collected" if {
	_applies("2.4.4")
	not e_2_4_4
}

_v_2 contains "2.4.4: auto-lock must be set and no longer than 2 minutes" if {
	_applies("2.4.4")
	e_2_4_4
	not r_2_4_4
}

# 2.4.5 (Automated, Level 1 - End-User Owned Devices)
default r_2_4_5 := false

r_2_4_5 if {
	input.ios_profile.passcode.maxGracePeriod == 0
}

default e_2_4_5 := false

e_2_4_5 if {
	is_number(input.ios_profile.passcode.maxGracePeriod)
}

_v_2 contains "2.4.5: evidence missing — ios_profile.passcode.maxGracePeriod not collected" if {
	_applies("2.4.5")
	not e_2_4_5
}

_v_2 contains "2.4.5: the device lock grace period must be immediate" if {
	_applies("2.4.5")
	e_2_4_5
	not r_2_4_5
}

# 2.4.6 (Automated, Level 1 - End-User Owned Devices)
default r_2_4_6 := false

r_2_4_6 if {
	input.ios_profile.passcode.maxFailedAttempts == 6
}

default e_2_4_6 := false

e_2_4_6 if {
	is_number(input.ios_profile.passcode.maxFailedAttempts)
}

_v_2 contains "2.4.6: evidence missing — ios_profile.passcode.maxFailedAttempts not collected" if {
	_applies("2.4.6")
	not e_2_4_6
}

_v_2 contains "2.4.6: failed passcode attempts must be limited to 6" if {
	_applies("2.4.6")
	e_2_4_6
	not r_2_4_6
}

# 2.5.1 (Manual, Level 1 - End-User Owned Devices)
default r_2_5_1 := false

r_2_5_1 if {
	input.ios_profile.attest.mac_randomization_reviewed == true
}

_v_2 contains "2.5.1: Wi-Fi MAC randomization must be disabled where the network needs it (manual review not attested)" if {
	_applies("2.5.1")
	not r_2_5_1
}

# 2.6.1 (Manual, Level 1 - End-User Owned Devices)
default r_2_6_1 := false

r_2_6_1 if {
	input.ios_profile.attest.vpn_configured == true
}

_v_2 contains "2.6.1: a VPN (per-app or system-wide) must be configured (manual review not attested)" if {
	_applies("2.6.1")
	not r_2_6_1
}

# 2.7.1 (Automated, Level 1 - End-User Owned Devices)
default r_2_7_1 := false

r_2_7_1 if {
	every acct in input.ios_profile.mail_accounts { object.get(acct, "PreventMove", null) == true }
}

default e_2_7_1 := false

e_2_7_1 if {
	is_array(input.ios_profile.mail_accounts)
}

_v_2 contains "2.7.1: evidence missing — ios_profile.mail_accounts not collected" if {
	_applies("2.7.1")
	not e_2_7_1
}

_v_2 contains "2.7.1: mail messages must not be movable out of the managed account" if {
	_applies("2.7.1")
	e_2_7_1
	not r_2_7_1
}

# 2.7.2 (Automated, Level 2 - Institutionally-Owned Devices)
default r_2_7_2 := false

r_2_7_2 if {
	every acct in input.ios_profile.mail_accounts { object.get(acct, "allowMailDrop", null) == false }
}

default e_2_7_2 := false

e_2_7_2 if {
	is_array(input.ios_profile.mail_accounts)
}

_v_2 contains "2.7.2: evidence missing — ios_profile.mail_accounts not collected" if {
	_applies("2.7.2")
	not e_2_7_2
}

_v_2 contains "2.7.2: Mail Drop must be blocked" if {
	_applies("2.7.2")
	e_2_7_2
	not r_2_7_2
}

# 2.8.1 (Manual, Level 1 - End-User Owned Devices)
default r_2_8_1 := false

r_2_8_1 if {
	input.ios_profile.attest.managed_app_notifications == true
}

_v_2 contains "2.8.1: every managed app must have a notification setting (manual review not attested)" if {
	_applies("2.8.1")
	not r_2_8_1
}

# 2.9.1 (Automated, Level 1 - End-User Owned Devices)
default r_2_9_1 := false

r_2_9_1 if {
	input.ios_profile.restrictions.allowExternalIntelligenceIntegrations == false
	input.ios_profile.restrictions.allowExternalIntelligenceIntegrationsSignIn == false
}

default e_2_9_1 := false

e_2_9_1 if {
	is_boolean(input.ios_profile.restrictions.allowExternalIntelligenceIntegrations)
	is_boolean(input.ios_profile.restrictions.allowExternalIntelligenceIntegrationsSignIn)
}

_v_2 contains "2.9.1: evidence missing — ios_profile.restrictions.allowExternalIntelligenceIntegrations and ios_profile.restrictions.allowExternalIntelligenceIntegrationsSignIn not collected" if {
	_applies("2.9.1")
	not e_2_9_1
}

_v_2 contains "2.9.1: external intelligence integrations and their sign-in must be blocked" if {
	_applies("2.9.1")
	e_2_9_1
	not r_2_9_1
}

# 2.9.2 (Automated, Level 1 - End-User Owned Devices)
default r_2_9_2 := false

r_2_9_2 if {
	input.ios_profile.restrictions.allowNotesTranscription == false
	input.ios_profile.restrictions.allowNotesTranscriptionSummary == false
}

default e_2_9_2 := false

e_2_9_2 if {
	is_boolean(input.ios_profile.restrictions.allowNotesTranscription)
	is_boolean(input.ios_profile.restrictions.allowNotesTranscriptionSummary)
}

_v_2 contains "2.9.2: evidence missing — ios_profile.restrictions.allowNotesTranscription and ios_profile.restrictions.allowNotesTranscriptionSummary not collected" if {
	_applies("2.9.2")
	not e_2_9_2
}

_v_2 contains "2.9.2: Notes transcription and summaries must be blocked" if {
	_applies("2.9.2")
	e_2_9_2
	not r_2_9_2
}

# 2.9.3 (Automated, Level 1 - End-User Owned Devices)
default r_2_9_3 := false

r_2_9_3 if {
	input.ios_profile.restrictions.allowMailSummary == false
}

default e_2_9_3 := false

e_2_9_3 if {
	is_boolean(input.ios_profile.restrictions.allowMailSummary)
}

_v_2 contains "2.9.3: evidence missing — ios_profile.restrictions.allowMailSummary not collected" if {
	_applies("2.9.3")
	not e_2_9_3
}

_v_2 contains "2.9.3: Mail summaries must be blocked" if {
	_applies("2.9.3")
	e_2_9_3
	not r_2_9_3
}

# 2.9.4 (Automated, Level 1 - End-User Owned Devices)
default r_2_9_4 := false

r_2_9_4 if {
	input.ios_profile.restrictions.allowWritingTools == false
}

default e_2_9_4 := false

e_2_9_4 if {
	is_boolean(input.ios_profile.restrictions.allowWritingTools)
}

_v_2 contains "2.9.4: evidence missing — ios_profile.restrictions.allowWritingTools not collected" if {
	_applies("2.9.4")
	not e_2_9_4
}

_v_2 contains "2.9.4: Writing Tools must be blocked" if {
	_applies("2.9.4")
	e_2_9_4
	not r_2_9_4
}

# 2.9.5 (Automated, Level 1 - End-User Owned Devices)
default r_2_9_5 := false

r_2_9_5 if {
	input.ios_profile.restrictions.allowSafariSummary == false
}

default e_2_9_5 := false

e_2_9_5 if {
	is_boolean(input.ios_profile.restrictions.allowSafariSummary)
}

_v_2 contains "2.9.5: evidence missing — ios_profile.restrictions.allowSafariSummary not collected" if {
	_applies("2.9.5")
	not e_2_9_5
}

_v_2 contains "2.9.5: Safari summaries must be blocked" if {
	_applies("2.9.5")
	e_2_9_5
	not r_2_9_5
}

# 2.9.6 (Automated, Level 1 - End-User Owned Devices)
default r_2_9_6 := false

r_2_9_6 if {
	input.ios_profile.restrictions.allowMailSmartReplies == false
}

default e_2_9_6 := false

e_2_9_6 if {
	is_boolean(input.ios_profile.restrictions.allowMailSmartReplies)
}

_v_2 contains "2.9.6: evidence missing — ios_profile.restrictions.allowMailSmartReplies not collected" if {
	_applies("2.9.6")
	not e_2_9_6
}

_v_2 contains "2.9.6: Mail smart replies must be blocked" if {
	_applies("2.9.6")
	e_2_9_6
	not r_2_9_6
}

# section 3
# 3.1.1 (Automated, Level 1 - Institutionally-Owned Devices)
default r_3_1_1 := false

r_3_1_1 if {
	lower(input.ios_profile.profile.removal) == "never"
}

default e_3_1_1 := false

e_3_1_1 if {
	is_string(input.ios_profile.profile.removal)
}

_v_3 contains "3.1.1: evidence missing — ios_profile.profile.removal not collected" if {
	_applies("3.1.1")
	not e_3_1_1
}

_v_3 contains "3.1.1: the profile must not be removable by the user" if {
	_applies("3.1.1")
	e_3_1_1
	not r_3_1_1
}

# 3.2.1.1 (Manual, Level 2 - Institutionally-Owned Devices) -- Manual in the workbook; decidable from configuration, so checked like Automated
default r_3_2_1_1 := false

r_3_2_1_1 if {
	input.ios_profile.restrictions.allowScreenShot == false
}

default e_3_2_1_1 := false

e_3_2_1_1 if {
	is_boolean(input.ios_profile.restrictions.allowScreenShot)
}

_v_3 contains "3.2.1.1: evidence missing — ios_profile.restrictions.allowScreenShot not collected" if {
	_applies("3.2.1.1")
	not e_3_2_1_1
}

_v_3 contains "3.2.1.1: screenshots and screen recording must be blocked" if {
	_applies("3.2.1.1")
	e_3_2_1_1
	not r_3_2_1_1
}

# 3.2.1.2 (Automated, Level 1 - Institutionally-Owned Devices)
default r_3_2_1_2 := false

r_3_2_1_2 if {
	input.ios_profile.restrictions.allowAssistantWhileLocked == false
}

default e_3_2_1_2 := false

e_3_2_1_2 if {
	is_boolean(input.ios_profile.restrictions.allowAssistantWhileLocked)
}

_v_3 contains "3.2.1.2: evidence missing — ios_profile.restrictions.allowAssistantWhileLocked not collected" if {
	_applies("3.2.1.2")
	not e_3_2_1_2
}

_v_3 contains "3.2.1.2: Siri must be blocked on the lock screen" if {
	_applies("3.2.1.2")
	e_3_2_1_2
	not r_3_2_1_2
}

# 3.2.1.3 (Automated, Level 1 - Institutionally-Owned Devices)
default r_3_2_1_3 := false

r_3_2_1_3 if {
	input.ios_profile.restrictions.allowCloudBackup == false
}

default e_3_2_1_3 := false

e_3_2_1_3 if {
	is_boolean(input.ios_profile.restrictions.allowCloudBackup)
}

_v_3 contains "3.2.1.3: evidence missing — ios_profile.restrictions.allowCloudBackup not collected" if {
	_applies("3.2.1.3")
	not e_3_2_1_3
}

_v_3 contains "3.2.1.3: iCloud backup must be blocked" if {
	_applies("3.2.1.3")
	e_3_2_1_3
	not r_3_2_1_3
}

# 3.2.1.4 (Automated, Level 1 - Institutionally-Owned Devices)
default r_3_2_1_4 := false

r_3_2_1_4 if {
	input.ios_profile.restrictions.allowCloudDocumentSync == false
}

default e_3_2_1_4 := false

e_3_2_1_4 if {
	is_boolean(input.ios_profile.restrictions.allowCloudDocumentSync)
}

_v_3 contains "3.2.1.4: evidence missing — ios_profile.restrictions.allowCloudDocumentSync not collected" if {
	_applies("3.2.1.4")
	not e_3_2_1_4
}

_v_3 contains "3.2.1.4: iCloud documents and data must be blocked" if {
	_applies("3.2.1.4")
	e_3_2_1_4
	not r_3_2_1_4
}

# 3.2.1.5 (Automated, Level 1 - Institutionally-Owned Devices)
default r_3_2_1_5 := false

r_3_2_1_5 if {
	input.ios_profile.restrictions.allowCloudKeychainSync == false
}

default e_3_2_1_5 := false

e_3_2_1_5 if {
	is_boolean(input.ios_profile.restrictions.allowCloudKeychainSync)
}

_v_3 contains "3.2.1.5: evidence missing — ios_profile.restrictions.allowCloudKeychainSync not collected" if {
	_applies("3.2.1.5")
	not e_3_2_1_5
}

_v_3 contains "3.2.1.5: iCloud Keychain must be blocked" if {
	_applies("3.2.1.5")
	e_3_2_1_5
	not r_3_2_1_5
}

# 3.2.1.6 (Automated, Level 1 - Institutionally-Owned Devices)
default r_3_2_1_6 := false

r_3_2_1_6 if {
	input.ios_profile.restrictions.allowManagedAppsCloudSync == false
}

default e_3_2_1_6 := false

e_3_2_1_6 if {
	is_boolean(input.ios_profile.restrictions.allowManagedAppsCloudSync)
}

_v_3 contains "3.2.1.6: evidence missing — ios_profile.restrictions.allowManagedAppsCloudSync not collected" if {
	_applies("3.2.1.6")
	not e_3_2_1_6
}

_v_3 contains "3.2.1.6: managed apps must not sync data to iCloud" if {
	_applies("3.2.1.6")
	e_3_2_1_6
	not r_3_2_1_6
}

# 3.2.1.7 (Automated, Level 2 - Institutionally-Owned Devices)
default r_3_2_1_7 := false

r_3_2_1_7 if {
	input.ios_profile.restrictions.allowFilesUSBDriveAccess == false
}

default e_3_2_1_7 := false

e_3_2_1_7 if {
	is_boolean(input.ios_profile.restrictions.allowFilesUSBDriveAccess)
}

_v_3 contains "3.2.1.7: evidence missing — ios_profile.restrictions.allowFilesUSBDriveAccess not collected" if {
	_applies("3.2.1.7")
	not e_3_2_1_7
}

_v_3 contains "3.2.1.7: USB drive access in Files must be blocked" if {
	_applies("3.2.1.7")
	e_3_2_1_7
	not r_3_2_1_7
}

# 3.2.1.8 (Automated, Level 2 - Institutionally-Owned Devices)
default r_3_2_1_8 := false

r_3_2_1_8 if {
	input.ios_profile.restrictions.allowFilesNetworkDriveAccess == false
}

default e_3_2_1_8 := false

e_3_2_1_8 if {
	is_boolean(input.ios_profile.restrictions.allowFilesNetworkDriveAccess)
}

_v_3 contains "3.2.1.8: evidence missing — ios_profile.restrictions.allowFilesNetworkDriveAccess not collected" if {
	_applies("3.2.1.8")
	not e_3_2_1_8
}

_v_3 contains "3.2.1.8: network drive access in Files must be blocked" if {
	_applies("3.2.1.8")
	e_3_2_1_8
	not r_3_2_1_8
}

# 3.2.1.9 (Automated, Level 1 - Institutionally-Owned Devices)
default r_3_2_1_9 := false

r_3_2_1_9 if {
	input.ios_profile.restrictions.forceEncryptedBackup == true
}

default e_3_2_1_9 := false

e_3_2_1_9 if {
	is_boolean(input.ios_profile.restrictions.forceEncryptedBackup)
}

_v_3 contains "3.2.1.9: evidence missing — ios_profile.restrictions.forceEncryptedBackup not collected" if {
	_applies("3.2.1.9")
	not e_3_2_1_9
}

_v_3 contains "3.2.1.9: backups must be forced to encrypt" if {
	_applies("3.2.1.9")
	e_3_2_1_9
	not r_3_2_1_9
}

# 3.2.1.10 (Manual, Level 1 - Institutionally-Owned Devices) -- Manual in the workbook; decidable from configuration, so checked like Automated
default r_3_2_1_10 := false

r_3_2_1_10 if {
	input.ios_profile.restrictions.allowApplePersonalizedAdvertising == false
}

default e_3_2_1_10 := false

e_3_2_1_10 if {
	is_boolean(input.ios_profile.restrictions.allowApplePersonalizedAdvertising)
}

_v_3 contains "3.2.1.10: evidence missing — ios_profile.restrictions.allowApplePersonalizedAdvertising not collected" if {
	_applies("3.2.1.10")
	not e_3_2_1_10
}

_v_3 contains "3.2.1.10: Apple personalized advertising must be blocked" if {
	_applies("3.2.1.10")
	e_3_2_1_10
	not r_3_2_1_10
}

# 3.2.1.11 (Automated, Level 1 - Institutionally-Owned Devices)
default r_3_2_1_11 := false

r_3_2_1_11 if {
	input.ios_profile.restrictions.allowEraseContentAndSettings == false
}

default e_3_2_1_11 := false

e_3_2_1_11 if {
	is_boolean(input.ios_profile.restrictions.allowEraseContentAndSettings)
}

_v_3 contains "3.2.1.11: evidence missing — ios_profile.restrictions.allowEraseContentAndSettings not collected" if {
	_applies("3.2.1.11")
	not e_3_2_1_11
}

_v_3 contains "3.2.1.11: Erase All Content and Settings must be blocked" if {
	_applies("3.2.1.11")
	e_3_2_1_11
	not r_3_2_1_11
}

# 3.2.1.12 (Automated, Level 2 - Institutionally-Owned Devices)
default r_3_2_1_12 := false

r_3_2_1_12 if {
	input.ios_profile.restrictions.allowUntrustedTLSPrompt == false
}

default e_3_2_1_12 := false

e_3_2_1_12 if {
	is_boolean(input.ios_profile.restrictions.allowUntrustedTLSPrompt)
}

_v_3 contains "3.2.1.12: evidence missing — ios_profile.restrictions.allowUntrustedTLSPrompt not collected" if {
	_applies("3.2.1.12")
	not e_3_2_1_12
}

_v_3 contains "3.2.1.12: the user must not be able to accept untrusted TLS certificates" if {
	_applies("3.2.1.12")
	e_3_2_1_12
	not r_3_2_1_12
}

# 3.2.1.13 (Manual, Level 1 - Institutionally-Owned Devices) -- Manual in the workbook; decidable from configuration, so checked like Automated
default r_3_2_1_13 := false

r_3_2_1_13 if {
	input.ios_profile.restrictions.allowEnterpriseAppTrust == false
}

default e_3_2_1_13 := false

e_3_2_1_13 if {
	is_boolean(input.ios_profile.restrictions.allowEnterpriseAppTrust)
}

_v_3 contains "3.2.1.13: evidence missing — ios_profile.restrictions.allowEnterpriseAppTrust not collected" if {
	_applies("3.2.1.13")
	not e_3_2_1_13
}

_v_3 contains "3.2.1.13: trusting new enterprise app authors must be blocked" if {
	_applies("3.2.1.13")
	e_3_2_1_13
	not r_3_2_1_13
}

# 3.2.1.14 (Automated, Level 1 - Institutionally-Owned Devices)
default r_3_2_1_14 := false

r_3_2_1_14 if {
	input.ios_profile.restrictions.allowUIConfigurationProfileInstallation == false
}

default e_3_2_1_14 := false

e_3_2_1_14 if {
	is_boolean(input.ios_profile.restrictions.allowUIConfigurationProfileInstallation)
}

_v_3 contains "3.2.1.14: evidence missing — ios_profile.restrictions.allowUIConfigurationProfileInstallation not collected" if {
	_applies("3.2.1.14")
	not e_3_2_1_14
}

_v_3 contains "3.2.1.14: installing configuration profiles must be blocked" if {
	_applies("3.2.1.14")
	e_3_2_1_14
	not r_3_2_1_14
}

# 3.2.1.15 (Automated, Level 1 - Institutionally-Owned Devices)
default r_3_2_1_15 := false

r_3_2_1_15 if {
	input.ios_profile.restrictions.allowVPNCreation == false
}

default e_3_2_1_15 := false

e_3_2_1_15 if {
	is_boolean(input.ios_profile.restrictions.allowVPNCreation)
}

_v_3 contains "3.2.1.15: evidence missing — ios_profile.restrictions.allowVPNCreation not collected" if {
	_applies("3.2.1.15")
	not e_3_2_1_15
}

_v_3 contains "3.2.1.15: adding VPN configurations must be blocked" if {
	_applies("3.2.1.15")
	e_3_2_1_15
	not r_3_2_1_15
}

# 3.2.1.16 (Manual, Level 1 - Institutionally-Owned Devices) -- Manual in the workbook; decidable from configuration, so checked like Automated
default r_3_2_1_16 := false

r_3_2_1_16 if {
	input.ios_profile.restrictions.forceAutomaticDateAndTime == true
}

default e_3_2_1_16 := false

e_3_2_1_16 if {
	is_boolean(input.ios_profile.restrictions.forceAutomaticDateAndTime)
}

_v_3 contains "3.2.1.16: evidence missing — ios_profile.restrictions.forceAutomaticDateAndTime not collected" if {
	_applies("3.2.1.16")
	not e_3_2_1_16
}

_v_3 contains "3.2.1.16: automatic date and time must be forced" if {
	_applies("3.2.1.16")
	e_3_2_1_16
	not r_3_2_1_16
}

# 3.2.1.17 (Automated, Level 2 - Institutionally-Owned Devices)
default r_3_2_1_17 := false

r_3_2_1_17 if {
	input.ios_profile.restrictions.allowAppCellularDataModification == false
}

default e_3_2_1_17 := false

e_3_2_1_17 if {
	is_boolean(input.ios_profile.restrictions.allowAppCellularDataModification)
}

_v_3 contains "3.2.1.17: evidence missing — ios_profile.restrictions.allowAppCellularDataModification not collected" if {
	_applies("3.2.1.17")
	not e_3_2_1_17
}

_v_3 contains "3.2.1.17: changing per-app cellular data settings must be blocked" if {
	_applies("3.2.1.17")
	e_3_2_1_17
	not r_3_2_1_17
}

# 3.2.1.18 (Automated, Level 1 - Institutionally-Owned Devices)
default r_3_2_1_18 := false

r_3_2_1_18 if {
	input.ios_profile.restrictions.allowUSBRestrictedMode == true
}

default e_3_2_1_18 := false

e_3_2_1_18 if {
	is_boolean(input.ios_profile.restrictions.allowUSBRestrictedMode)
}

_v_3 contains "3.2.1.18: evidence missing — ios_profile.restrictions.allowUSBRestrictedMode not collected" if {
	_applies("3.2.1.18")
	not e_3_2_1_18
}

_v_3 contains "3.2.1.18: USB accessories must be blocked while the device is locked (USB restricted mode kept on)" if {
	_applies("3.2.1.18")
	e_3_2_1_18
	not r_3_2_1_18
}

# 3.2.1.19 (Automated, Level 2 - Institutionally-Owned Devices)
default r_3_2_1_19 := false

r_3_2_1_19 if {
	input.ios_profile.restrictions.allowHostPairing == false
}

default e_3_2_1_19 := false

e_3_2_1_19 if {
	is_boolean(input.ios_profile.restrictions.allowHostPairing)
}

_v_3 contains "3.2.1.19: evidence missing — ios_profile.restrictions.allowHostPairing not collected" if {
	_applies("3.2.1.19")
	not e_3_2_1_19
}

_v_3 contains "3.2.1.19: pairing with hosts other than Configurator must be blocked" if {
	_applies("3.2.1.19")
	e_3_2_1_19
	not r_3_2_1_19
}

# 3.2.1.20 (Automated, Level 1 - Institutionally-Owned Devices)
default r_3_2_1_20 := false

r_3_2_1_20 if {
	input.ios_profile.restrictions.allowOpenFromManagedToUnmanaged == false
}

default e_3_2_1_20 := false

e_3_2_1_20 if {
	is_boolean(input.ios_profile.restrictions.allowOpenFromManagedToUnmanaged)
}

_v_3 contains "3.2.1.20: evidence missing — ios_profile.restrictions.allowOpenFromManagedToUnmanaged not collected" if {
	_applies("3.2.1.20")
	not e_3_2_1_20
}

_v_3 contains "3.2.1.20: documents must not open from managed into unmanaged destinations" if {
	_applies("3.2.1.20")
	e_3_2_1_20
	not r_3_2_1_20
}

# 3.2.1.21 (Automated, Level 1 - Institutionally-Owned Devices)
default r_3_2_1_21 := false

r_3_2_1_21 if {
	input.ios_profile.restrictions.allowOpenFromUnmanagedToManaged == false
}

default e_3_2_1_21 := false

e_3_2_1_21 if {
	is_boolean(input.ios_profile.restrictions.allowOpenFromUnmanagedToManaged)
}

_v_3 contains "3.2.1.21: evidence missing — ios_profile.restrictions.allowOpenFromUnmanagedToManaged not collected" if {
	_applies("3.2.1.21")
	not e_3_2_1_21
}

_v_3 contains "3.2.1.21: documents must not open from unmanaged into managed destinations" if {
	_applies("3.2.1.21")
	e_3_2_1_21
	not r_3_2_1_21
}

# 3.2.1.22 (Automated, Level 1 - Institutionally-Owned Devices)
default r_3_2_1_22 := false

r_3_2_1_22 if {
	input.ios_profile.restrictions.forceAirDropUnmanaged == true
}

default e_3_2_1_22 := false

e_3_2_1_22 if {
	is_boolean(input.ios_profile.restrictions.forceAirDropUnmanaged)
}

_v_3 contains "3.2.1.22: evidence missing — ios_profile.restrictions.forceAirDropUnmanaged not collected" if {
	_applies("3.2.1.22")
	not e_3_2_1_22
}

_v_3 contains "3.2.1.22: AirDrop must be treated as an unmanaged destination" if {
	_applies("3.2.1.22")
	e_3_2_1_22
	not r_3_2_1_22
}

# 3.2.1.23 (Automated, Level 1 - Institutionally-Owned Devices)
default r_3_2_1_23 := false

r_3_2_1_23 if {
	input.ios_profile.restrictions.allowActivityContinuation == false
}

default e_3_2_1_23 := false

e_3_2_1_23 if {
	is_boolean(input.ios_profile.restrictions.allowActivityContinuation)
}

_v_3 contains "3.2.1.23: evidence missing — ios_profile.restrictions.allowActivityContinuation not collected" if {
	_applies("3.2.1.23")
	not e_3_2_1_23
}

_v_3 contains "3.2.1.23: Handoff must be blocked" if {
	_applies("3.2.1.23")
	e_3_2_1_23
	not r_3_2_1_23
}

# 3.2.1.24 (Manual, Level 1 - Institutionally-Owned Devices) -- Manual in the workbook; decidable from configuration, so checked like Automated
default r_3_2_1_24 := false

r_3_2_1_24 if {
	input.ios_profile.restrictions.allowDiagnosticSubmission == false
}

default e_3_2_1_24 := false

e_3_2_1_24 if {
	is_boolean(input.ios_profile.restrictions.allowDiagnosticSubmission)
}

_v_3 contains "3.2.1.24: evidence missing — ios_profile.restrictions.allowDiagnosticSubmission not collected" if {
	_applies("3.2.1.24")
	not e_3_2_1_24
}

_v_3 contains "3.2.1.24: diagnostic and usage data must not be sent to Apple" if {
	_applies("3.2.1.24")
	e_3_2_1_24
	not r_3_2_1_24
}

# 3.2.1.25 (Automated, Level 1 - Institutionally-Owned Devices)
default r_3_2_1_25 := false

r_3_2_1_25 if {
	input.ios_profile.restrictions.forceAuthenticationBeforeAutoFill == true
}

default e_3_2_1_25 := false

e_3_2_1_25 if {
	is_boolean(input.ios_profile.restrictions.forceAuthenticationBeforeAutoFill)
}

_v_3 contains "3.2.1.25: evidence missing — ios_profile.restrictions.forceAuthenticationBeforeAutoFill not collected" if {
	_applies("3.2.1.25")
	not e_3_2_1_25
}

_v_3 contains "3.2.1.25: biometric authentication must be required before AutoFill" if {
	_applies("3.2.1.25")
	e_3_2_1_25
	not r_3_2_1_25
}

# 3.2.1.26 (Automated, Level 1 - Institutionally-Owned Devices)
default r_3_2_1_26 := false

r_3_2_1_26 if {
	input.ios_profile.restrictions.forceWatchWristDetection == true
}

default e_3_2_1_26 := false

e_3_2_1_26 if {
	is_boolean(input.ios_profile.restrictions.forceWatchWristDetection)
}

_v_3 contains "3.2.1.26: evidence missing — ios_profile.restrictions.forceWatchWristDetection not collected" if {
	_applies("3.2.1.26")
	not e_3_2_1_26
}

_v_3 contains "3.2.1.26: Apple Watch wrist detection must be forced" if {
	_applies("3.2.1.26")
	e_3_2_1_26
	not r_3_2_1_26
}

# 3.2.1.27 (Automated, Level 1 - Institutionally-Owned Devices)
default r_3_2_1_27 := false

r_3_2_1_27 if {
	input.ios_profile.restrictions.allowProximitySetupToNewDevice == false
}

default e_3_2_1_27 := false

e_3_2_1_27 if {
	is_boolean(input.ios_profile.restrictions.allowProximitySetupToNewDevice)
}

_v_3 contains "3.2.1.27: evidence missing — ios_profile.restrictions.allowProximitySetupToNewDevice not collected" if {
	_applies("3.2.1.27")
	not e_3_2_1_27
}

_v_3 contains "3.2.1.27: setting up new nearby devices must be blocked" if {
	_applies("3.2.1.27")
	e_3_2_1_27
	not r_3_2_1_27
}

# 3.2.1.28 (Automated, Level 1 - Institutionally-Owned Devices)
default r_3_2_1_28 := false

r_3_2_1_28 if {
	input.ios_profile.restrictions.allowPasswordProximityRequests == false
}

default e_3_2_1_28 := false

e_3_2_1_28 if {
	is_boolean(input.ios_profile.restrictions.allowPasswordProximityRequests)
}

_v_3 contains "3.2.1.28: evidence missing — ios_profile.restrictions.allowPasswordProximityRequests not collected" if {
	_applies("3.2.1.28")
	not e_3_2_1_28
}

_v_3 contains "3.2.1.28: proximity password sharing requests must be blocked" if {
	_applies("3.2.1.28")
	e_3_2_1_28
	not r_3_2_1_28
}

# 3.2.1.29 (Manual, Level 1 - Institutionally-Owned Devices) -- Manual in the workbook; decidable from configuration, so checked like Automated
default r_3_2_1_29 := false

r_3_2_1_29 if {
	input.ios_profile.restrictions.allowPasswordSharing == false
}

default e_3_2_1_29 := false

e_3_2_1_29 if {
	is_boolean(input.ios_profile.restrictions.allowPasswordSharing)
}

_v_3 contains "3.2.1.29: evidence missing — ios_profile.restrictions.allowPasswordSharing not collected" if {
	_applies("3.2.1.29")
	not e_3_2_1_29
}

_v_3 contains "3.2.1.29: password sharing must be blocked" if {
	_applies("3.2.1.29")
	e_3_2_1_29
	not r_3_2_1_29
}

# 3.2.1.30 (Automated, Level 1 - Institutionally-Owned Devices)
default r_3_2_1_30 := false

r_3_2_1_30 if {
	input.ios_profile.restrictions.allowLockScreenControlCenter == false
}

default e_3_2_1_30 := false

e_3_2_1_30 if {
	is_boolean(input.ios_profile.restrictions.allowLockScreenControlCenter)
}

_v_3 contains "3.2.1.30: evidence missing — ios_profile.restrictions.allowLockScreenControlCenter not collected" if {
	_applies("3.2.1.30")
	not e_3_2_1_30
}

_v_3 contains "3.2.1.30: Control Center must be hidden on the lock screen" if {
	_applies("3.2.1.30")
	e_3_2_1_30
	not r_3_2_1_30
}

# 3.2.1.31 (Automated, Level 1 - Institutionally-Owned Devices)
default r_3_2_1_31 := false

r_3_2_1_31 if {
	input.ios_profile.restrictions.allowLockScreenNotificationsView == false
}

default e_3_2_1_31 := false

e_3_2_1_31 if {
	is_boolean(input.ios_profile.restrictions.allowLockScreenNotificationsView)
}

_v_3 contains "3.2.1.31: evidence missing — ios_profile.restrictions.allowLockScreenNotificationsView not collected" if {
	_applies("3.2.1.31")
	not e_3_2_1_31
}

_v_3 contains "3.2.1.31: Notification Center must be hidden on the lock screen" if {
	_applies("3.2.1.31")
	e_3_2_1_31
	not r_3_2_1_31
}

# 3.2.2.1 (Automated, Level 1 - Institutionally-Owned Devices)
default r_3_2_2_1 := false

r_3_2_2_1 if {
	input.ios_profile.restrictions.safariForceFraudWarning == true
}

default e_3_2_2_1 := false

e_3_2_2_1 if {
	is_boolean(input.ios_profile.restrictions.safariForceFraudWarning)
}

_v_3 contains "3.2.2.1: evidence missing — ios_profile.restrictions.safariForceFraudWarning not collected" if {
	_applies("3.2.2.1")
	not e_3_2_2_1
}

_v_3 contains "3.2.2.1: Safari fraud warning must be forced" if {
	_applies("3.2.2.1")
	e_3_2_2_1
	not r_3_2_2_1
}

# 3.2.2.2 (Automated, Level 1 - Institutionally-Owned Devices)
default r_3_2_2_2 := false

r_3_2_2_2 if {
	input.ios_profile.restrictions.safariAcceptCookies in {1, 1.5}
}

default e_3_2_2_2 := false

e_3_2_2_2 if {
	is_number(input.ios_profile.restrictions.safariAcceptCookies)
}

_v_3 contains "3.2.2.2: evidence missing — ios_profile.restrictions.safariAcceptCookies not collected" if {
	_applies("3.2.2.2")
	not e_3_2_2_2
}

_v_3 contains "3.2.2.2: Safari must accept cookies only from visited or the current site" if {
	_applies("3.2.2.2")
	e_3_2_2_2
	not r_3_2_2_2
}

# 3.3.1 (Manual, Level 1 - Institutionally-Owned Devices)
default r_3_3_1 := false

r_3_3_1 if {
	input.ios_profile.attest.managed_safari_domains == true
}

_v_3 contains "3.3.1: managed Safari web domains must be configured for the organisation (manual review not attested)" if {
	_applies("3.3.1")
	not r_3_3_1
}

# 3.4.1 (Automated, Level 1 - Institutionally-Owned Devices)
default r_3_4_1 := false

r_3_4_1 if {
	input.ios_profile.passcode.allowSimple == false
}

default e_3_4_1 := false

e_3_4_1 if {
	is_boolean(input.ios_profile.passcode.allowSimple)
}

_v_3 contains "3.4.1: evidence missing — ios_profile.passcode.allowSimple not collected" if {
	_applies("3.4.1")
	not e_3_4_1
}

_v_3 contains "3.4.1: simple passcodes must be blocked" if {
	_applies("3.4.1")
	e_3_4_1
	not r_3_4_1
}

# 3.4.2 (Manual, Level 2 - End-User Owned Devices; Level 2 - Institutionally-Owned Devices) -- Manual in the workbook; decidable from configuration, so checked like Automated
default r_3_4_2 := false

r_3_4_2 if {
	input.ios_profile.passcode.requireAlphanumeric == true
}

default e_3_4_2 := false

e_3_4_2 if {
	is_boolean(input.ios_profile.passcode.requireAlphanumeric)
}

_v_3 contains "3.4.2: evidence missing — ios_profile.passcode.requireAlphanumeric not collected" if {
	_applies("3.4.2")
	not e_3_4_2
}

_v_3 contains "3.4.2: an alphanumeric passcode must be required" if {
	_applies("3.4.2")
	e_3_4_2
	not r_3_4_2
}

# 3.4.3 (Automated, Level 1 - Institutionally-Owned Devices)
default r_3_4_3 := false

r_3_4_3 if {
	is_number(input.ios_profile.passcode.minLength)
	input.ios_profile.passcode.minLength >= 6
}

default e_3_4_3 := false

e_3_4_3 if {
	is_number(input.ios_profile.passcode.minLength)
}

_v_3 contains "3.4.3: evidence missing — ios_profile.passcode.minLength not collected" if {
	_applies("3.4.3")
	not e_3_4_3
}

_v_3 contains "3.4.3: the passcode must be at least 6 characters" if {
	_applies("3.4.3")
	e_3_4_3
	not r_3_4_3
}

# 3.4.4 (Automated, Level 1 - Institutionally-Owned Devices)
default r_3_4_4 := false

r_3_4_4 if {
	is_number(input.ios_profile.passcode.maxInactivity)
	input.ios_profile.passcode.maxInactivity >= 1
	input.ios_profile.passcode.maxInactivity <= 2
}

default e_3_4_4 := false

e_3_4_4 if {
	is_number(input.ios_profile.passcode.maxInactivity)
}

_v_3 contains "3.4.4: evidence missing — ios_profile.passcode.maxInactivity not collected" if {
	_applies("3.4.4")
	not e_3_4_4
}

_v_3 contains "3.4.4: auto-lock must be set and no longer than 2 minutes" if {
	_applies("3.4.4")
	e_3_4_4
	not r_3_4_4
}

# 3.4.5 (Automated, Level 1 - Institutionally-Owned Devices)
default r_3_4_5 := false

r_3_4_5 if {
	input.ios_profile.passcode.maxGracePeriod == 0
}

default e_3_4_5 := false

e_3_4_5 if {
	is_number(input.ios_profile.passcode.maxGracePeriod)
}

_v_3 contains "3.4.5: evidence missing — ios_profile.passcode.maxGracePeriod not collected" if {
	_applies("3.4.5")
	not e_3_4_5
}

_v_3 contains "3.4.5: the device lock grace period must be immediate" if {
	_applies("3.4.5")
	e_3_4_5
	not r_3_4_5
}

# 3.4.6 (Automated, Level 1 - Institutionally-Owned Devices)
default r_3_4_6 := false

r_3_4_6 if {
	input.ios_profile.passcode.maxFailedAttempts == 6
}

default e_3_4_6 := false

e_3_4_6 if {
	is_number(input.ios_profile.passcode.maxFailedAttempts)
}

_v_3 contains "3.4.6: evidence missing — ios_profile.passcode.maxFailedAttempts not collected" if {
	_applies("3.4.6")
	not e_3_4_6
}

_v_3 contains "3.4.6: failed passcode attempts must be limited to 6" if {
	_applies("3.4.6")
	e_3_4_6
	not r_3_4_6
}

# 3.5.1 (Manual, Level 1 - End-User Owned Devices; Level 1 - Institutionally-Owned Devices)
default r_3_5_1 := false

r_3_5_1 if {
	input.ios_profile.attest.mac_randomization_reviewed == true
}

_v_3 contains "3.5.1: Wi-Fi MAC randomization must be disabled where the network needs it (manual review not attested)" if {
	_applies("3.5.1")
	not r_3_5_1
}

# 3.6.1 (Manual, Level 1 - Institutionally-Owned Devices)
default r_3_6_1 := false

r_3_6_1 if {
	input.ios_profile.attest.vpn_configured == true
}

_v_3 contains "3.6.1: a VPN (per-app or system-wide) must be configured (manual review not attested)" if {
	_applies("3.6.1")
	not r_3_6_1
}

# 3.7.1 (Automated, Level 1 - Institutionally-Owned Devices)
default r_3_7_1 := false

r_3_7_1 if {
	every acct in input.ios_profile.mail_accounts { object.get(acct, "PreventMove", null) == true }
}

default e_3_7_1 := false

e_3_7_1 if {
	is_array(input.ios_profile.mail_accounts)
}

_v_3 contains "3.7.1: evidence missing — ios_profile.mail_accounts not collected" if {
	_applies("3.7.1")
	not e_3_7_1
}

_v_3 contains "3.7.1: mail messages must not be movable out of the managed account" if {
	_applies("3.7.1")
	e_3_7_1
	not r_3_7_1
}

# 3.7.2 (Automated, Level 2 - Institutionally-Owned Devices)
default r_3_7_2 := false

r_3_7_2 if {
	every acct in input.ios_profile.mail_accounts { object.get(acct, "allowMailDrop", null) == false }
}

default e_3_7_2 := false

e_3_7_2 if {
	is_array(input.ios_profile.mail_accounts)
}

_v_3 contains "3.7.2: evidence missing — ios_profile.mail_accounts not collected" if {
	_applies("3.7.2")
	not e_3_7_2
}

_v_3 contains "3.7.2: Mail Drop must be blocked" if {
	_applies("3.7.2")
	e_3_7_2
	not r_3_7_2
}

# 3.8.1 (Manual, Level 1 - Institutionally-Owned Devices)
default r_3_8_1 := false

r_3_8_1 if {
	input.ios_profile.attest.managed_app_notifications == true
}

_v_3 contains "3.8.1: every managed app must have a notification setting (manual review not attested)" if {
	_applies("3.8.1")
	not r_3_8_1
}

# 3.9.1 (Manual, Level 1 - Institutionally-Owned Devices)
default r_3_9_1 := false

r_3_9_1 if {
	input.ios_profile.attest.lost_message_configured == true
}

_v_3 contains "3.9.1: a return-if-found lock screen message must be configured (manual review not attested)" if {
	_applies("3.9.1")
	not r_3_9_1
}

# 3.10.1 (Automated, Level 1 - Institutionally-Owned Devices)
default r_3_10_1 := false

r_3_10_1 if {
	input.ios_profile.restrictions.allowExternalIntelligenceIntegrations == false
	input.ios_profile.restrictions.allowExternalIntelligenceIntegrationsSignIn == false
}

default e_3_10_1 := false

e_3_10_1 if {
	is_boolean(input.ios_profile.restrictions.allowExternalIntelligenceIntegrations)
	is_boolean(input.ios_profile.restrictions.allowExternalIntelligenceIntegrationsSignIn)
}

_v_3 contains "3.10.1: evidence missing — ios_profile.restrictions.allowExternalIntelligenceIntegrations and ios_profile.restrictions.allowExternalIntelligenceIntegrationsSignIn not collected" if {
	_applies("3.10.1")
	not e_3_10_1
}

_v_3 contains "3.10.1: external intelligence integrations and their sign-in must be blocked" if {
	_applies("3.10.1")
	e_3_10_1
	not r_3_10_1
}

# 3.10.2 (Automated, Level 1 - Institutionally-Owned Devices)
default r_3_10_2 := false

r_3_10_2 if {
	input.ios_profile.restrictions.allowNotesTranscription == false
	input.ios_profile.restrictions.allowNotesTranscriptionSummary == false
}

default e_3_10_2 := false

e_3_10_2 if {
	is_boolean(input.ios_profile.restrictions.allowNotesTranscription)
	is_boolean(input.ios_profile.restrictions.allowNotesTranscriptionSummary)
}

_v_3 contains "3.10.2: evidence missing — ios_profile.restrictions.allowNotesTranscription and ios_profile.restrictions.allowNotesTranscriptionSummary not collected" if {
	_applies("3.10.2")
	not e_3_10_2
}

_v_3 contains "3.10.2: Notes transcription and summaries must be blocked" if {
	_applies("3.10.2")
	e_3_10_2
	not r_3_10_2
}

# 3.10.3 (Automated, Level 1 - Institutionally-Owned Devices)
default r_3_10_3 := false

r_3_10_3 if {
	input.ios_profile.restrictions.allowMailSummary == false
}

default e_3_10_3 := false

e_3_10_3 if {
	is_boolean(input.ios_profile.restrictions.allowMailSummary)
}

_v_3 contains "3.10.3: evidence missing — ios_profile.restrictions.allowMailSummary not collected" if {
	_applies("3.10.3")
	not e_3_10_3
}

_v_3 contains "3.10.3: Mail summaries must be blocked" if {
	_applies("3.10.3")
	e_3_10_3
	not r_3_10_3
}

# 3.10.4 (Automated, Level 1 - Institutionally-Owned Devices)
default r_3_10_4 := false

r_3_10_4 if {
	input.ios_profile.restrictions.allowWritingTools == false
}

default e_3_10_4 := false

e_3_10_4 if {
	is_boolean(input.ios_profile.restrictions.allowWritingTools)
}

_v_3 contains "3.10.4: evidence missing — ios_profile.restrictions.allowWritingTools not collected" if {
	_applies("3.10.4")
	not e_3_10_4
}

_v_3 contains "3.10.4: Writing Tools must be blocked" if {
	_applies("3.10.4")
	e_3_10_4
	not r_3_10_4
}

# 3.10.5 (Automated, Level 1 - Institutionally-Owned Devices)
default r_3_10_5 := false

r_3_10_5 if {
	input.ios_profile.restrictions.allowSafariSummary == false
}

default e_3_10_5 := false

e_3_10_5 if {
	is_boolean(input.ios_profile.restrictions.allowSafariSummary)
}

_v_3 contains "3.10.5: evidence missing — ios_profile.restrictions.allowSafariSummary not collected" if {
	_applies("3.10.5")
	not e_3_10_5
}

_v_3 contains "3.10.5: Safari summaries must be blocked" if {
	_applies("3.10.5")
	e_3_10_5
	not r_3_10_5
}

# 3.10.6 (Automated, Level 1 - Institutionally-Owned Devices)
default r_3_10_6 := false

r_3_10_6 if {
	input.ios_profile.restrictions.allowMailSmartReplies == false
}

default e_3_10_6 := false

e_3_10_6 if {
	is_boolean(input.ios_profile.restrictions.allowMailSmartReplies)
}

_v_3 contains "3.10.6: evidence missing — ios_profile.restrictions.allowMailSmartReplies not collected" if {
	_applies("3.10.6")
	not e_3_10_6
}

_v_3 contains "3.10.6: Mail smart replies must be blocked" if {
	_applies("3.10.6")
	e_3_10_6
	not r_3_10_6
}

# section 4
# 4.1.1 (Manual, Level 1 - End-User Owned Devices; Level 1 - Institutionally-Owned Devices)
default r_4_1_1 := false

r_4_1_1 if {
	input.ios_profile.attest.sharing_access_reviewed == true
}

_v_4 contains "4.1.1: Manage Sharing and Access must be reviewed on the device (manual review not attested)" if {
	_applies("4.1.1")
	not r_4_1_1
}

# 4.1.2 (Manual, Level 1 - End-User Owned Devices; Level 1 - Institutionally-Owned Devices)
default r_4_1_2 := false

r_4_1_2 if {
	input.ios_profile.attest.emergency_reset_reviewed == true
}

_v_4 contains "4.1.2: Emergency Reset must be reviewed on the device (manual review not attested)" if {
	_applies("4.1.2")
	not r_4_1_2
}

# 4.1.3 (Manual, Level 2 - End-User Owned Devices; Level 2 - Institutionally-Owned Devices)
default r_4_1_3 := false

r_4_1_3 if {
	input.ios_profile.attest.lockdown_mode_reviewed == true
}

_v_4 contains "4.1.3: Lockdown Mode must be reviewed for the user (manual review not attested)" if {
	_applies("4.1.3")
	not r_4_1_3
}

# 4.1.4 (Manual, Level 1 - End-User Owned Devices; Level 1 - Institutionally-Owned Devices)
default r_4_1_4 := false

r_4_1_4 if {
	input.ios_profile.attest.app_privacy_report_enabled == true
}

_v_4 contains "4.1.4: App Privacy Report must be turned on (manual review not attested)" if {
	_applies("4.1.4")
	not r_4_1_4
}

# 4.1.5 (Manual, Level 2 - End-User Owned Devices; Level 2 - Institutionally-Owned Devices)
default r_4_1_5 := false

r_4_1_5 if {
	input.ios_profile.attest.airprint_reviewed == true
}

_v_4 contains "4.1.5: AirPrint use must be reviewed on the device (manual review not attested)" if {
	_applies("4.1.5")
	not r_4_1_5
}

# 4.1.6 (Manual, Level 2 - End-User Owned Devices)
default r_4_1_6 := false

r_4_1_6 if {
	input.ios_profile.attest.stolen_device_protection_enabled == true
}

_v_4 contains "4.1.6: Stolen Device Protection must be turned on (manual review not attested)" if {
	_applies("4.1.6")
	not r_4_1_6
}

# 4.2 (Manual, Level 1 - End-User Owned Devices; Level 1 - Institutionally-Owned Devices)
default r_4_2 := false

r_4_2 if {
	input.ios_profile.attest.not_jailbroken == true
}

_v_4 contains "4.2: the device must show no sign of jailbreak or compromise (manual review not attested)" if {
	_applies("4.2")
	not r_4_2
}

# 4.3 (Manual, Level 1 - End-User Owned Devices; Level 1 - Institutionally-Owned Devices)
default r_4_3 := false

r_4_3 if {
	input.ios_profile.attest.auto_update_install_enabled == true
}

_v_4 contains "4.3: automatic iOS update installation must be turned on (manual review not attested)" if {
	_applies("4.3")
	not r_4_3
}

# 4.4 (Manual, Level 1 - End-User Owned Devices; Level 1 - Institutionally-Owned Devices)
default r_4_4 := false

r_4_4 if {
	input.ios_profile.attest.software_up_to_date == true
}

_v_4 contains "4.4: the device must be on the current iOS release (manual review not attested)" if {
	_applies("4.4")
	not r_4_4
}

# 4.5 (Manual, Level 1 - End-User Owned Devices; Level 1 - Institutionally-Owned Devices)
default r_4_5 := false

r_4_5 if {
	input.ios_profile.attest.private_relay_reviewed == true
}

_v_4 contains "4.5: iCloud Private Relay must be reviewed on the device (manual review not attested)" if {
	_applies("4.5")
	not r_4_5
}

# 4.6 (Manual, Level 1 - End-User Owned Devices; Level 1 - Institutionally-Owned Devices)
default r_4_6 := false

r_4_6 if {
	input.ios_profile.attest.mail_privacy_reviewed == true
}

_v_4 contains "4.6: Mail Privacy Protection must be reviewed on the device (manual review not attested)" if {
	_applies("4.6")
	not r_4_6
}

# 4.7 (Manual, Level 1 - End-User Owned Devices; Level 1 - Institutionally-Owned Devices)
default r_4_7 := false

r_4_7 if {
	input.ios_profile.attest.auto_app_updates_enabled == true
}

_v_4 contains "4.7: automatic app update downloads must be turned on (manual review not attested)" if {
	_applies("4.7")
	not r_4_7
}

# 4.8 (Automated, Level 1 - End-User Owned Devices)
default r_4_8 := false

r_4_8 if {
	input.ios_profile.attest.find_my_enabled == true
}

_v_4 contains "4.8: Find My iPhone, Find My network and Send Last Location must be turned on (manual review not attested)" if {
	_applies("4.8")
	not r_4_8
}

# 4.9 (Manual, Level 2 - End-User Owned Devices; Level 2 - Institutionally-Owned Devices)
default r_4_9 := false

r_4_9 if {
	input.ios_profile.attest.latest_hardware_for_high_value == true
}

_v_4 contains "4.9: high-value targets must use the latest device hardware generation (manual review not attested)" if {
	_applies("4.9")
	not r_4_9
}

# 4.10 (Manual, Level 1 - End-User Owned Devices; Level 1 - Institutionally-Owned Devices)
default r_4_10 := false

r_4_10 if {
	input.ios_profile.attest.iphone_mirroring_reviewed == true
}

_v_4 contains "4.10: iPhone Mirroring must be reviewed on the device (manual review not attested)" if {
	_applies("4.10")
	not r_4_10
}

# 4.11 (Automated, Level 1 - End-User Owned Devices; Level 1 - Institutionally-Owned Devices)
default r_4_11 := false

r_4_11 if {
	input.ios_profile.attest.rcs_messaging_enabled == true
}

_v_4 contains "4.11: RCS messaging must be turned on where available (manual review not attested)" if {
	_applies("4.11")
	not r_4_11
}

# Every recommendation: our title, workbook status, how it is checked, and the (ownership, level) profiles it belongs to.
recommendations := {
	"2.1.1": {
		"title": "the profile must carry a consent message",
		"assessment": "Automated",
		"check": "configuration",
		"profiles": [{
			"ownership": "end_user",
			"level": 1,
		}],
	},
	"2.1.2": {
		"title": "end-user profile removal must stay allowed",
		"assessment": "Manual",
		"check": "configuration",
		"profiles": [{
			"ownership": "end_user",
			"level": 1,
		}],
	},
	"2.2.1.1": {
		"title": "Siri must be blocked on the lock screen",
		"assessment": "Automated",
		"check": "configuration",
		"profiles": [{
			"ownership": "end_user",
			"level": 1,
		}],
	},
	"2.2.1.2": {
		"title": "managed apps must not sync data to iCloud",
		"assessment": "Automated",
		"check": "configuration",
		"profiles": [{
			"ownership": "end_user",
			"level": 1,
		}],
	},
	"2.2.1.3": {
		"title": "backups must be forced to encrypt",
		"assessment": "Automated",
		"check": "configuration",
		"profiles": [{
			"ownership": "end_user",
			"level": 1,
		}],
	},
	"2.2.1.4": {
		"title": "Apple personalized advertising must be blocked",
		"assessment": "Manual",
		"check": "configuration",
		"profiles": [{
			"ownership": "end_user",
			"level": 1,
		}],
	},
	"2.2.1.5": {
		"title": "the user must not be able to accept untrusted TLS certificates",
		"assessment": "Automated",
		"check": "configuration",
		"profiles": [{
			"ownership": "end_user",
			"level": 2,
		}],
	},
	"2.2.1.6": {
		"title": "automatic date and time must be forced",
		"assessment": "Manual",
		"check": "configuration",
		"profiles": [{
			"ownership": "end_user",
			"level": 1,
		}],
	},
	"2.2.1.7": {
		"title": "documents must not open from managed into unmanaged destinations",
		"assessment": "Automated",
		"check": "configuration",
		"profiles": [{
			"ownership": "end_user",
			"level": 1,
		}],
	},
	"2.2.1.8": {
		"title": "documents must not open from unmanaged into managed destinations",
		"assessment": "Automated",
		"check": "configuration",
		"profiles": [{
			"ownership": "end_user",
			"level": 1,
		}],
	},
	"2.2.1.9": {
		"title": "AirDrop must be treated as an unmanaged destination",
		"assessment": "Automated",
		"check": "configuration",
		"profiles": [{
			"ownership": "end_user",
			"level": 1,
		}],
	},
	"2.2.1.10": {
		"title": "Handoff must be blocked",
		"assessment": "Automated",
		"check": "configuration",
		"profiles": [{
			"ownership": "end_user",
			"level": 2,
		}],
	},
	"2.2.1.11": {
		"title": "diagnostic and usage data must not be sent to Apple",
		"assessment": "Manual",
		"check": "configuration",
		"profiles": [{
			"ownership": "end_user",
			"level": 1,
		}],
	},
	"2.2.1.12": {
		"title": "Apple Watch wrist detection must be forced",
		"assessment": "Automated",
		"check": "configuration",
		"profiles": [{
			"ownership": "end_user",
			"level": 1,
		}],
	},
	"2.2.1.13": {
		"title": "Control Center must be hidden on the lock screen",
		"assessment": "Automated",
		"check": "configuration",
		"profiles": [{
			"ownership": "end_user",
			"level": 1,
		}],
	},
	"2.2.1.14": {
		"title": "Notification Center must be hidden on the lock screen",
		"assessment": "Automated",
		"check": "configuration",
		"profiles": [{
			"ownership": "end_user",
			"level": 1,
		}],
	},
	"2.2.2.1": {
		"title": "Safari fraud warning must be forced",
		"assessment": "Automated",
		"check": "configuration",
		"profiles": [{
			"ownership": "end_user",
			"level": 1,
		}],
	},
	"2.2.2.2": {
		"title": "Safari must accept cookies only from visited or the current site",
		"assessment": "Automated",
		"check": "configuration",
		"profiles": [{
			"ownership": "end_user",
			"level": 1,
		}],
	},
	"2.3.1": {
		"title": "managed Safari web domains must be configured for the organisation",
		"assessment": "Manual",
		"check": "attestation",
		"profiles": [{
			"ownership": "end_user",
			"level": 1,
		}],
	},
	"2.4.1": {
		"title": "simple passcodes must be blocked",
		"assessment": "Automated",
		"check": "configuration",
		"profiles": [{
			"ownership": "end_user",
			"level": 1,
		}],
	},
	"2.4.2": {
		"title": "an alphanumeric passcode must be required",
		"assessment": "Manual",
		"check": "configuration",
		"profiles": [
			{
				"ownership": "end_user",
				"level": 2,
			},
			{
				"ownership": "institutional",
				"level": 2,
			},
		],
	},
	"2.4.3": {
		"title": "the passcode must be at least 6 characters",
		"assessment": "Automated",
		"check": "configuration",
		"profiles": [{
			"ownership": "end_user",
			"level": 1,
		}],
	},
	"2.4.4": {
		"title": "auto-lock must be set and no longer than 2 minutes",
		"assessment": "Automated",
		"check": "configuration",
		"profiles": [{
			"ownership": "end_user",
			"level": 1,
		}],
	},
	"2.4.5": {
		"title": "the device lock grace period must be immediate",
		"assessment": "Automated",
		"check": "configuration",
		"profiles": [{
			"ownership": "end_user",
			"level": 1,
		}],
	},
	"2.4.6": {
		"title": "failed passcode attempts must be limited to 6",
		"assessment": "Automated",
		"check": "configuration",
		"profiles": [{
			"ownership": "end_user",
			"level": 1,
		}],
	},
	"2.5.1": {
		"title": "Wi-Fi MAC randomization must be disabled where the network needs it",
		"assessment": "Manual",
		"check": "attestation",
		"profiles": [{
			"ownership": "end_user",
			"level": 1,
		}],
	},
	"2.6.1": {
		"title": "a VPN (per-app or system-wide) must be configured",
		"assessment": "Manual",
		"check": "attestation",
		"profiles": [{
			"ownership": "end_user",
			"level": 1,
		}],
	},
	"2.7.1": {
		"title": "mail messages must not be movable out of the managed account",
		"assessment": "Automated",
		"check": "configuration",
		"profiles": [{
			"ownership": "end_user",
			"level": 1,
		}],
	},
	"2.7.2": {
		"title": "Mail Drop must be blocked",
		"assessment": "Automated",
		"check": "configuration",
		"profiles": [{
			"ownership": "institutional",
			"level": 2,
		}],
	},
	"2.8.1": {
		"title": "every managed app must have a notification setting",
		"assessment": "Manual",
		"check": "attestation",
		"profiles": [{
			"ownership": "end_user",
			"level": 1,
		}],
	},
	"2.9.1": {
		"title": "external intelligence integrations and their sign-in must be blocked",
		"assessment": "Automated",
		"check": "configuration",
		"profiles": [{
			"ownership": "end_user",
			"level": 1,
		}],
	},
	"2.9.2": {
		"title": "Notes transcription and summaries must be blocked",
		"assessment": "Automated",
		"check": "configuration",
		"profiles": [{
			"ownership": "end_user",
			"level": 1,
		}],
	},
	"2.9.3": {
		"title": "Mail summaries must be blocked",
		"assessment": "Automated",
		"check": "configuration",
		"profiles": [{
			"ownership": "end_user",
			"level": 1,
		}],
	},
	"2.9.4": {
		"title": "Writing Tools must be blocked",
		"assessment": "Automated",
		"check": "configuration",
		"profiles": [{
			"ownership": "end_user",
			"level": 1,
		}],
	},
	"2.9.5": {
		"title": "Safari summaries must be blocked",
		"assessment": "Automated",
		"check": "configuration",
		"profiles": [{
			"ownership": "end_user",
			"level": 1,
		}],
	},
	"2.9.6": {
		"title": "Mail smart replies must be blocked",
		"assessment": "Automated",
		"check": "configuration",
		"profiles": [{
			"ownership": "end_user",
			"level": 1,
		}],
	},
	"3.1.1": {
		"title": "the profile must not be removable by the user",
		"assessment": "Automated",
		"check": "configuration",
		"profiles": [{
			"ownership": "institutional",
			"level": 1,
		}],
	},
	"3.2.1.1": {
		"title": "screenshots and screen recording must be blocked",
		"assessment": "Manual",
		"check": "configuration",
		"profiles": [{
			"ownership": "institutional",
			"level": 2,
		}],
	},
	"3.2.1.2": {
		"title": "Siri must be blocked on the lock screen",
		"assessment": "Automated",
		"check": "configuration",
		"profiles": [{
			"ownership": "institutional",
			"level": 1,
		}],
	},
	"3.2.1.3": {
		"title": "iCloud backup must be blocked",
		"assessment": "Automated",
		"check": "configuration",
		"profiles": [{
			"ownership": "institutional",
			"level": 1,
		}],
	},
	"3.2.1.4": {
		"title": "iCloud documents and data must be blocked",
		"assessment": "Automated",
		"check": "configuration",
		"profiles": [{
			"ownership": "institutional",
			"level": 1,
		}],
	},
	"3.2.1.5": {
		"title": "iCloud Keychain must be blocked",
		"assessment": "Automated",
		"check": "configuration",
		"profiles": [{
			"ownership": "institutional",
			"level": 1,
		}],
	},
	"3.2.1.6": {
		"title": "managed apps must not sync data to iCloud",
		"assessment": "Automated",
		"check": "configuration",
		"profiles": [{
			"ownership": "institutional",
			"level": 1,
		}],
	},
	"3.2.1.7": {
		"title": "USB drive access in Files must be blocked",
		"assessment": "Automated",
		"check": "configuration",
		"profiles": [{
			"ownership": "institutional",
			"level": 2,
		}],
	},
	"3.2.1.8": {
		"title": "network drive access in Files must be blocked",
		"assessment": "Automated",
		"check": "configuration",
		"profiles": [{
			"ownership": "institutional",
			"level": 2,
		}],
	},
	"3.2.1.9": {
		"title": "backups must be forced to encrypt",
		"assessment": "Automated",
		"check": "configuration",
		"profiles": [{
			"ownership": "institutional",
			"level": 1,
		}],
	},
	"3.2.1.10": {
		"title": "Apple personalized advertising must be blocked",
		"assessment": "Manual",
		"check": "configuration",
		"profiles": [{
			"ownership": "institutional",
			"level": 1,
		}],
	},
	"3.2.1.11": {
		"title": "Erase All Content and Settings must be blocked",
		"assessment": "Automated",
		"check": "configuration",
		"profiles": [{
			"ownership": "institutional",
			"level": 1,
		}],
	},
	"3.2.1.12": {
		"title": "the user must not be able to accept untrusted TLS certificates",
		"assessment": "Automated",
		"check": "configuration",
		"profiles": [{
			"ownership": "institutional",
			"level": 2,
		}],
	},
	"3.2.1.13": {
		"title": "trusting new enterprise app authors must be blocked",
		"assessment": "Manual",
		"check": "configuration",
		"profiles": [{
			"ownership": "institutional",
			"level": 1,
		}],
	},
	"3.2.1.14": {
		"title": "installing configuration profiles must be blocked",
		"assessment": "Automated",
		"check": "configuration",
		"profiles": [{
			"ownership": "institutional",
			"level": 1,
		}],
	},
	"3.2.1.15": {
		"title": "adding VPN configurations must be blocked",
		"assessment": "Automated",
		"check": "configuration",
		"profiles": [{
			"ownership": "institutional",
			"level": 1,
		}],
	},
	"3.2.1.16": {
		"title": "automatic date and time must be forced",
		"assessment": "Manual",
		"check": "configuration",
		"profiles": [{
			"ownership": "institutional",
			"level": 1,
		}],
	},
	"3.2.1.17": {
		"title": "changing per-app cellular data settings must be blocked",
		"assessment": "Automated",
		"check": "configuration",
		"profiles": [{
			"ownership": "institutional",
			"level": 2,
		}],
	},
	"3.2.1.18": {
		"title": "USB accessories must be blocked while the device is locked (USB restricted mode kept on)",
		"assessment": "Automated",
		"check": "configuration",
		"profiles": [{
			"ownership": "institutional",
			"level": 1,
		}],
	},
	"3.2.1.19": {
		"title": "pairing with hosts other than Configurator must be blocked",
		"assessment": "Automated",
		"check": "configuration",
		"profiles": [{
			"ownership": "institutional",
			"level": 2,
		}],
	},
	"3.2.1.20": {
		"title": "documents must not open from managed into unmanaged destinations",
		"assessment": "Automated",
		"check": "configuration",
		"profiles": [{
			"ownership": "institutional",
			"level": 1,
		}],
	},
	"3.2.1.21": {
		"title": "documents must not open from unmanaged into managed destinations",
		"assessment": "Automated",
		"check": "configuration",
		"profiles": [{
			"ownership": "institutional",
			"level": 1,
		}],
	},
	"3.2.1.22": {
		"title": "AirDrop must be treated as an unmanaged destination",
		"assessment": "Automated",
		"check": "configuration",
		"profiles": [{
			"ownership": "institutional",
			"level": 1,
		}],
	},
	"3.2.1.23": {
		"title": "Handoff must be blocked",
		"assessment": "Automated",
		"check": "configuration",
		"profiles": [{
			"ownership": "institutional",
			"level": 1,
		}],
	},
	"3.2.1.24": {
		"title": "diagnostic and usage data must not be sent to Apple",
		"assessment": "Manual",
		"check": "configuration",
		"profiles": [{
			"ownership": "institutional",
			"level": 1,
		}],
	},
	"3.2.1.25": {
		"title": "biometric authentication must be required before AutoFill",
		"assessment": "Automated",
		"check": "configuration",
		"profiles": [{
			"ownership": "institutional",
			"level": 1,
		}],
	},
	"3.2.1.26": {
		"title": "Apple Watch wrist detection must be forced",
		"assessment": "Automated",
		"check": "configuration",
		"profiles": [{
			"ownership": "institutional",
			"level": 1,
		}],
	},
	"3.2.1.27": {
		"title": "setting up new nearby devices must be blocked",
		"assessment": "Automated",
		"check": "configuration",
		"profiles": [{
			"ownership": "institutional",
			"level": 1,
		}],
	},
	"3.2.1.28": {
		"title": "proximity password sharing requests must be blocked",
		"assessment": "Automated",
		"check": "configuration",
		"profiles": [{
			"ownership": "institutional",
			"level": 1,
		}],
	},
	"3.2.1.29": {
		"title": "password sharing must be blocked",
		"assessment": "Manual",
		"check": "configuration",
		"profiles": [{
			"ownership": "institutional",
			"level": 1,
		}],
	},
	"3.2.1.30": {
		"title": "Control Center must be hidden on the lock screen",
		"assessment": "Automated",
		"check": "configuration",
		"profiles": [{
			"ownership": "institutional",
			"level": 1,
		}],
	},
	"3.2.1.31": {
		"title": "Notification Center must be hidden on the lock screen",
		"assessment": "Automated",
		"check": "configuration",
		"profiles": [{
			"ownership": "institutional",
			"level": 1,
		}],
	},
	"3.2.2.1": {
		"title": "Safari fraud warning must be forced",
		"assessment": "Automated",
		"check": "configuration",
		"profiles": [{
			"ownership": "institutional",
			"level": 1,
		}],
	},
	"3.2.2.2": {
		"title": "Safari must accept cookies only from visited or the current site",
		"assessment": "Automated",
		"check": "configuration",
		"profiles": [{
			"ownership": "institutional",
			"level": 1,
		}],
	},
	"3.3.1": {
		"title": "managed Safari web domains must be configured for the organisation",
		"assessment": "Manual",
		"check": "attestation",
		"profiles": [{
			"ownership": "institutional",
			"level": 1,
		}],
	},
	"3.4.1": {
		"title": "simple passcodes must be blocked",
		"assessment": "Automated",
		"check": "configuration",
		"profiles": [{
			"ownership": "institutional",
			"level": 1,
		}],
	},
	"3.4.2": {
		"title": "an alphanumeric passcode must be required",
		"assessment": "Manual",
		"check": "configuration",
		"profiles": [
			{
				"ownership": "end_user",
				"level": 2,
			},
			{
				"ownership": "institutional",
				"level": 2,
			},
		],
	},
	"3.4.3": {
		"title": "the passcode must be at least 6 characters",
		"assessment": "Automated",
		"check": "configuration",
		"profiles": [{
			"ownership": "institutional",
			"level": 1,
		}],
	},
	"3.4.4": {
		"title": "auto-lock must be set and no longer than 2 minutes",
		"assessment": "Automated",
		"check": "configuration",
		"profiles": [{
			"ownership": "institutional",
			"level": 1,
		}],
	},
	"3.4.5": {
		"title": "the device lock grace period must be immediate",
		"assessment": "Automated",
		"check": "configuration",
		"profiles": [{
			"ownership": "institutional",
			"level": 1,
		}],
	},
	"3.4.6": {
		"title": "failed passcode attempts must be limited to 6",
		"assessment": "Automated",
		"check": "configuration",
		"profiles": [{
			"ownership": "institutional",
			"level": 1,
		}],
	},
	"3.5.1": {
		"title": "Wi-Fi MAC randomization must be disabled where the network needs it",
		"assessment": "Manual",
		"check": "attestation",
		"profiles": [
			{
				"ownership": "end_user",
				"level": 1,
			},
			{
				"ownership": "institutional",
				"level": 1,
			},
		],
	},
	"3.6.1": {
		"title": "a VPN (per-app or system-wide) must be configured",
		"assessment": "Manual",
		"check": "attestation",
		"profiles": [{
			"ownership": "institutional",
			"level": 1,
		}],
	},
	"3.7.1": {
		"title": "mail messages must not be movable out of the managed account",
		"assessment": "Automated",
		"check": "configuration",
		"profiles": [{
			"ownership": "institutional",
			"level": 1,
		}],
	},
	"3.7.2": {
		"title": "Mail Drop must be blocked",
		"assessment": "Automated",
		"check": "configuration",
		"profiles": [{
			"ownership": "institutional",
			"level": 2,
		}],
	},
	"3.8.1": {
		"title": "every managed app must have a notification setting",
		"assessment": "Manual",
		"check": "attestation",
		"profiles": [{
			"ownership": "institutional",
			"level": 1,
		}],
	},
	"3.9.1": {
		"title": "a return-if-found lock screen message must be configured",
		"assessment": "Manual",
		"check": "attestation",
		"profiles": [{
			"ownership": "institutional",
			"level": 1,
		}],
	},
	"3.10.1": {
		"title": "external intelligence integrations and their sign-in must be blocked",
		"assessment": "Automated",
		"check": "configuration",
		"profiles": [{
			"ownership": "institutional",
			"level": 1,
		}],
	},
	"3.10.2": {
		"title": "Notes transcription and summaries must be blocked",
		"assessment": "Automated",
		"check": "configuration",
		"profiles": [{
			"ownership": "institutional",
			"level": 1,
		}],
	},
	"3.10.3": {
		"title": "Mail summaries must be blocked",
		"assessment": "Automated",
		"check": "configuration",
		"profiles": [{
			"ownership": "institutional",
			"level": 1,
		}],
	},
	"3.10.4": {
		"title": "Writing Tools must be blocked",
		"assessment": "Automated",
		"check": "configuration",
		"profiles": [{
			"ownership": "institutional",
			"level": 1,
		}],
	},
	"3.10.5": {
		"title": "Safari summaries must be blocked",
		"assessment": "Automated",
		"check": "configuration",
		"profiles": [{
			"ownership": "institutional",
			"level": 1,
		}],
	},
	"3.10.6": {
		"title": "Mail smart replies must be blocked",
		"assessment": "Automated",
		"check": "configuration",
		"profiles": [{
			"ownership": "institutional",
			"level": 1,
		}],
	},
	"4.1.1": {
		"title": "Manage Sharing and Access must be reviewed on the device",
		"assessment": "Manual",
		"check": "attestation",
		"profiles": [
			{
				"ownership": "end_user",
				"level": 1,
			},
			{
				"ownership": "institutional",
				"level": 1,
			},
		],
	},
	"4.1.2": {
		"title": "Emergency Reset must be reviewed on the device",
		"assessment": "Manual",
		"check": "attestation",
		"profiles": [
			{
				"ownership": "end_user",
				"level": 1,
			},
			{
				"ownership": "institutional",
				"level": 1,
			},
		],
	},
	"4.1.3": {
		"title": "Lockdown Mode must be reviewed for the user",
		"assessment": "Manual",
		"check": "attestation",
		"profiles": [
			{
				"ownership": "end_user",
				"level": 2,
			},
			{
				"ownership": "institutional",
				"level": 2,
			},
		],
	},
	"4.1.4": {
		"title": "App Privacy Report must be turned on",
		"assessment": "Manual",
		"check": "attestation",
		"profiles": [
			{
				"ownership": "end_user",
				"level": 1,
			},
			{
				"ownership": "institutional",
				"level": 1,
			},
		],
	},
	"4.1.5": {
		"title": "AirPrint use must be reviewed on the device",
		"assessment": "Manual",
		"check": "attestation",
		"profiles": [
			{
				"ownership": "end_user",
				"level": 2,
			},
			{
				"ownership": "institutional",
				"level": 2,
			},
		],
	},
	"4.1.6": {
		"title": "Stolen Device Protection must be turned on",
		"assessment": "Manual",
		"check": "attestation",
		"profiles": [{
			"ownership": "end_user",
			"level": 2,
		}],
	},
	"4.2": {
		"title": "the device must show no sign of jailbreak or compromise",
		"assessment": "Manual",
		"check": "attestation",
		"profiles": [
			{
				"ownership": "end_user",
				"level": 1,
			},
			{
				"ownership": "institutional",
				"level": 1,
			},
		],
	},
	"4.3": {
		"title": "automatic iOS update installation must be turned on",
		"assessment": "Manual",
		"check": "attestation",
		"profiles": [
			{
				"ownership": "end_user",
				"level": 1,
			},
			{
				"ownership": "institutional",
				"level": 1,
			},
		],
	},
	"4.4": {
		"title": "the device must be on the current iOS release",
		"assessment": "Manual",
		"check": "attestation",
		"profiles": [
			{
				"ownership": "end_user",
				"level": 1,
			},
			{
				"ownership": "institutional",
				"level": 1,
			},
		],
	},
	"4.5": {
		"title": "iCloud Private Relay must be reviewed on the device",
		"assessment": "Manual",
		"check": "attestation",
		"profiles": [
			{
				"ownership": "end_user",
				"level": 1,
			},
			{
				"ownership": "institutional",
				"level": 1,
			},
		],
	},
	"4.6": {
		"title": "Mail Privacy Protection must be reviewed on the device",
		"assessment": "Manual",
		"check": "attestation",
		"profiles": [
			{
				"ownership": "end_user",
				"level": 1,
			},
			{
				"ownership": "institutional",
				"level": 1,
			},
		],
	},
	"4.7": {
		"title": "automatic app update downloads must be turned on",
		"assessment": "Manual",
		"check": "attestation",
		"profiles": [
			{
				"ownership": "end_user",
				"level": 1,
			},
			{
				"ownership": "institutional",
				"level": 1,
			},
		],
	},
	"4.8": {
		"title": "Find My iPhone, Find My network and Send Last Location must be turned on",
		"assessment": "Automated",
		"check": "attestation",
		"profiles": [{
			"ownership": "end_user",
			"level": 1,
		}],
	},
	"4.9": {
		"title": "high-value targets must use the latest device hardware generation",
		"assessment": "Manual",
		"check": "attestation",
		"profiles": [
			{
				"ownership": "end_user",
				"level": 2,
			},
			{
				"ownership": "institutional",
				"level": 2,
			},
		],
	},
	"4.10": {
		"title": "iPhone Mirroring must be reviewed on the device",
		"assessment": "Manual",
		"check": "attestation",
		"profiles": [
			{
				"ownership": "end_user",
				"level": 1,
			},
			{
				"ownership": "institutional",
				"level": 1,
			},
		],
	},
	"4.11": {
		"title": "RCS messaging must be turned on where available",
		"assessment": "Automated",
		"check": "attestation",
		"profiles": [
			{
				"ownership": "end_user",
				"level": 1,
			},
			{
				"ownership": "institutional",
				"level": 1,
			},
		],
	},
}

in_scope := {id | some id, _ in recommendations; _applies(id)}

_failed_ids := {id | some v in violations; id := split(v, ":")[0]; id in in_scope}

compliance_report := {
	"benchmark": "CIS Apple iOS 27 Benchmark v1.0.0",
	"profile": {"level": level, "ownership": _ownership},
	"total_controls": count(in_scope),
	"standard_total": 105,
	"standard_total_source": "CIS Apple iOS 27 Benchmark v1.0.0, recommendations counted from the CIS workbook",
	"failed_controls": count(_failed_ids),
	"passed_controls": count(in_scope) - count(_failed_ids),
	"compliant": compliant,
	"violation_count": count(violations),
	"violations": sort([v | some v in violations]),
}
