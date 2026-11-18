package pci_dss.access_control.requirement_8_test

import rego.v1

import data.pci_dss.access_control.requirement_8 as r8

# Parameter tests for requirement 8 (audit 2026-11-17, finding 4). Values per PCI DSS v4.0.1 as given in
# PCI SSC's public SAQ D and FAQs 1590/1591: 8.2.8 15 minutes, 8.3.4 not more than 10 attempts and 30
# minutes or until identity confirmed, 8.3.6 12 characters (8 where the system cannot support 12),
# 8.3.7 last four, 8.3.9 90 days or dynamic analysis, only where passwords are the sole factor.

_pw := {
	"minimum_length": 12,
	"numeric_and_alpha": {"required": true},
	"history": {"count": 4},
	"lockout": {"after_attempts": 10, "duration_minutes": 30},
}

_with_pw(patch) := {"pci": {"passwords": object.union(_pw, patch)}}

_without_pw(key) := {"pci": {"passwords": object.remove(_pw, [key])}}

# --- 8.3.4 lockout ---------------------------------------------------------

test_8_3_4_ten_attempts_passes if r8.password_requirements with input as _with_pw({})

test_8_3_4_eleven_attempts_fails if {
	not r8.password_requirements with input as _with_pw({"lockout": {"after_attempts": 11, "duration_minutes": 30}})
}

test_8_3_4_zero_attempts_never_locks_fails if {
	not r8.password_requirements with input as _with_pw({"lockout": {"after_attempts": 0, "duration_minutes": 30}})
}

test_8_3_4_string_attempts_fails if {
	not r8.password_requirements with input as _with_pw({"lockout": {"after_attempts": "5", "duration_minutes": 30}})
}

test_8_3_4_lockout_missing_fails if {
	not r8.password_requirements with input as _without_pw("lockout")
}

test_8_3_4_short_duration_fails if {
	not r8.password_requirements with input as _with_pw({"lockout": {"after_attempts": 6, "duration_minutes": 15}})
}

test_8_3_4_until_identity_confirmed_passes if {
	r8.password_requirements with input as _with_pw({"lockout": {"after_attempts": 6, "until_identity_confirmed": true}})
}

# --- 8.3.6 length and content -----------------------------------------------

test_8_3_6_eleven_characters_fails if {
	not r8.password_requirements with input as _with_pw({"minimum_length": 11})
}

test_8_3_6_eight_characters_where_system_cannot_support_12_passes if {
	r8.password_requirements with input as _with_pw({"minimum_length": 8, "system_supports_12_characters": false})
}

test_8_3_6_eight_characters_without_declared_limitation_fails if {
	not r8.password_requirements with input as _with_pw({"minimum_length": 8})
}

test_8_3_6_seven_characters_fails_even_with_limitation if {
	not r8.password_requirements with input as _with_pw({"minimum_length": 7, "system_supports_12_characters": false})
}

test_8_3_6_length_missing_fails if {
	not r8.password_requirements with input as _without_pw("minimum_length")
}

test_8_3_6_numeric_and_alpha_missing_fails if {
	not r8.password_requirements with input as _without_pw("numeric_and_alpha")
}

# --- 8.3.7 history ------------------------------------------------------------

test_8_3_7_three_fails if {
	not r8.password_requirements with input as _with_pw({"history": {"count": 3}})
}

test_8_3_7_missing_fails if {
	not r8.password_requirements with input as _without_pw("history")
}

# --- 8.3.9 password lifetime, single-factor only ------------------------------

test_8_3_9_mfa_everywhere_no_rotation_passes if {
	r8.single_factor_password_lifetime with input as {"pci": {"passwords": {"single_factor_only": false, "max_age_days": 365}}}
}

test_8_3_9_single_factor_365_days_fails if {
	not r8.single_factor_password_lifetime with input as {"pci": {"passwords": {"single_factor_only": true, "max_age_days": 365}}}
}

test_8_3_9_single_factor_90_days_passes if {
	r8.single_factor_password_lifetime with input as {"pci": {"passwords": {"single_factor_only": true, "max_age_days": 90}}}
}

test_8_3_9_single_factor_dynamic_analysis_passes if {
	r8.single_factor_password_lifetime with input as {"pci": {"passwords": {"single_factor_only": true, "dynamic_posture_analysis": {"implemented": true}}}}
}

test_8_3_9_single_factor_no_evidence_fails if {
	not r8.single_factor_password_lifetime with input as {"pci": {"passwords": {"single_factor_only": true}}}
}

test_8_3_9_factor_unknown_90_days_passes if {
	r8.single_factor_password_lifetime with input as {"pci": {"passwords": {"max_age_days": 90}}}
}

test_8_3_9_factor_unknown_365_days_fails if {
	not r8.single_factor_password_lifetime with input as {"pci": {"passwords": {"max_age_days": 365}}}
}

test_8_3_9_factor_unknown_dynamic_analysis_alone_fails if {
	not r8.single_factor_password_lifetime with input as {"pci": {"passwords": {"dynamic_posture_analysis": {"implemented": true}}}}
}

test_8_3_9_empty_input_fails if {
	not r8.single_factor_password_lifetime with input as {}
}

# --- 8.2.8 idle sessions --------------------------------------------------------

test_8_2_8_fifteen_minutes_passes if {
	r8.idle_session_reauthentication with input as {"pci": {"sessions": {"idle_timeout_minutes": 15, "reauthentication_required": true}}}
}

test_8_2_8_sixteen_minutes_fails if {
	not r8.idle_session_reauthentication with input as {"pci": {"sessions": {"idle_timeout_minutes": 16, "reauthentication_required": true}}}
}

test_8_2_8_zero_disabled_fails if {
	not r8.idle_session_reauthentication with input as {"pci": {"sessions": {"idle_timeout_minutes": 0, "reauthentication_required": true}}}
}

test_8_2_8_missing_fails if {
	not r8.idle_session_reauthentication with input as {"pci": {"sessions": {"reauthentication_required": true}}}
}

# --- 8.2.2, 8.2.3, 8.4.3, 8.5.1, 8.6.x alternatives --------------------------------

test_8_2_2_managed_exception_passes if {
	r8.unique_user_ids with input as {"pci": {"user_ids": {"unique_per_user": true, "shared_generic_group": {"exception_basis_managed": true}}}}
}

test_8_2_2_no_evidence_fails if {
	not r8.unique_user_ids with input as {"pci": {"user_ids": {"unique_per_user": true}}}
}

_factors := {"stored": {"encrypted": true}, "transmission": {"encrypted": true}}

test_8_2_3_merchant_passes if {
	r8.authentication_factors_protected with input as {"pci": {"auth_factors": _factors, "entity": {"service_provider": false}}}
}

test_8_2_3_service_provider_without_unique_factors_fails if {
	not r8.authentication_factors_protected with input as {"pci": {"auth_factors": _factors, "entity": {"service_provider": true}}}
}

test_8_2_3_entity_type_missing_fails if {
	not r8.authentication_factors_protected with input as {"pci": {"auth_factors": _factors}}
}

test_8_4_3_unused_vpn_and_rdp_pass if {
	r8.mfa_for_remote_access with input as {"pci": {"mfa": {"remote_access": {"required": true}, "vpn": {"in_use": false}, "remote_desktop": {"in_use": false}}}}
}

test_8_4_3_vpn_undeclared_fails if {
	not r8.mfa_for_remote_access with input as {"pci": {"mfa": {"remote_access": {"required": true}, "remote_desktop": {"mfa_enforced": true}}}}
}

test_8_5_1_all_factors_required_passes if {
	r8.mfa_not_susceptible_to_replay with input as {"pci": {"mfa": {"replay_attacks": {"prevented": true}, "all_factors_required": true}}}
}

test_8_5_1_missing_all_factors_fails if {
	not r8.mfa_not_susceptible_to_replay with input as {"pci": {"mfa": {"replay_attacks": {"prevented": true}}}}
}

_sys := {
	"interactive_use": {"prohibited_unless_exceptional": true},
	"authentication": {"managed": true},
	"review": {"performed_periodically": true},
}

test_8_6_not_hard_coded_and_tra_rotation_passes if {
	r8.system_application_accounts with input as {"pci": {"system_accounts": object.union(_sys, {"credentials": {"not_hard_coded": true, "rotation": {"tra_frequency_met": true}}})}}
}

test_8_6_no_rotation_evidence_fails if {
	not r8.system_application_accounts with input as {"pci": {"system_accounts": object.union(_sys, {"credentials": {"in_vault": true}})}}
}

# --- the auditor's case: MFA estate, lockout at 10, no 90-day rotation -----------

test_auditor_case_mfa_estate_lockout_10_meets_8_3 if {
	inp := {"pci": {"passwords": object.union(_pw, {"single_factor_only": false, "max_age_days": 365})}}
	r8.password_requirements with input as inp
	r8.single_factor_password_lifetime with input as inp
}
