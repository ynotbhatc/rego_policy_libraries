package nist.sp800_53.identification_authentication_logic_test

# IA family: one finding per base control and Moderate-baseline enhancement, fail closed, organization-defined
# lists. IA-5(1) is one enhancement: one finding naming whichever password protections are missing.

import data.nist.sp800_53.identification_authentication as ia
import rego.v1

# The ids that have a finding in a report ("NIST IA-2(8): ..." -> "IA-2(8)").
_ids(r) := {trim_prefix(split(v, ":")[0], "NIST ") | some v in r.violations}

_finding(r, id) := [v | some v in r.violations; startswith(v, concat("", ["NIST ", id, ":"]))]

_pass := {"ia_controls": {
	"policy": {"documented": true},
	"user_id_auth": {
		"uniquely_identified": true,
		"mfa_for_privileged": true,
		"mfa_for_non_privileged": true,
		"replay_resistance": {
			"odp": {"account_types": ["privileged", "non_privileged"]},
			"replay_resistant_account_types": ["non_privileged", "privileged"],
		},
		"piv": {"piv_accepted": true, "electronically_verified": true},
		"shared_accounts": {"reachable_without_individual_auth": 0},
		"separate_device": {
			"odp": {"access_types": ["network", "remote"], "account_types": ["privileged"]},
			"separate_device_access_types": ["local", "network", "remote"],
			"separate_device_account_types": ["privileged", "non_privileged"],
			"device_meets_strength_requirements": true,
		},
	},
	"device_identification": {"implemented": true},
	"identifier_management": {
		"unique_per_user": true,
		"user_status": {"odp": {"characteristics": ["contractor", "foreign_national"]}, "characteristics_indicated": ["contractor", "foreign_national", "employee"]},
	},
	"authenticator_management": {
		"complexity_enforced": true,
		"encrypted_in_transit": true,
		"encrypted_at_rest": true,
		"public_key": {
			"private_key_access_enforced": true,
			"identity_mapped_to_account": true,
			"pki_used": true,
			"certification_path_validated": true,
			"revocation_status_checked": true,
			"local_revocation_cache": true,
		},
		"authenticator_protection": {"plaintext_authenticators_found": 0, "protection_meets_security_category": true},
		"embedded_authenticators": {"unencrypted_static_found": 0},
		"multiple_system_accounts": {"odp": {"controls": ["single sign-on"]}, "controls_implemented": ["single sign-on", "distinct authenticators per system"]},
		"cached_authenticators": {"max_cache_hours": 24, "odp": {"max_hours": 72}},
	},
	"authenticator_feedback": {"obscured": true},
	"cryptographic_module_auth": {"odp": {"required_standards": ["FIPS 140-3"]}, "standards_met": ["FIPS 140-3"]},
	"non_organizational_users": {
		"identified": true,
		"piv_other_agencies": {"piv_accepted": true, "electronically_verified": true},
		"external_authenticators": {"list_maintained": true, "accepted": [{"name": "Login.gov", "nist_compliant": true}]},
		"identity_profiles": {"odp": {"profiles": ["SAML 2.0 Web SSO"]}, "conformed_profiles": ["SAML 2.0 Web SSO", "OIDC"]},
	},
	"reauthentication": {
		"odp": {"circumstances": ["role change", "privileged function"]},
		"enforced_circumstances": ["role change", "privileged function", "session timeout"],
	},
	"identity_proofing": {
		"accounts_without_proofing": 0,
		"assurance_level_meets_requirement": true,
		"resolved_to_unique_individual": true,
		"evidence_collected_validated_verified": true,
		"identity_evidence": {"presented_to_registration_authority": true},
		"validation": {"odp": {"methods": ["document authentication", "biometric comparison"]}, "methods_used": ["document authentication", "biometric comparison"]},
		"address_confirmation": {"odp": {"delivered_item": "registration code"}, "delivered_item": "registration code", "out_of_band": true},
		"in_person": {"required": true, "accounts_without_in_person_proofing": 0},
	},
	"service_authentication": {"odp": {"services": ["api-gateway", "billing"]}, "authenticated_services": ["api-gateway", "billing", "reports"]},
	"adaptive_authentication": {
		"odp": {"circumstances": ["new device", "unusual location"], "techniques": ["FIDO2 step-up"]},
		"enforced_circumstances": ["new device", "unusual location"],
		"techniques_configured": ["FIDO2 step-up"],
	},
	"identity_providers": {"applications_with_local_authentication": 0, "npe_and_device_identities_managed": true},
}}

test_all_pass_fixture_is_compliant if {
	fx := _pass
	r := ia.compliance_report with input as fx
	r.compliant == true
	r.violation_count == 0
}

test_evaluated_controls_match_the_catalog if {
	ia.evaluated_controls == {
		"IA-1", "IA-2", "IA-2(1)", "IA-2(2)", "IA-2(5)", "IA-2(6)", "IA-2(8)", "IA-2(12)", "IA-3", "IA-4", "IA-4(4)",
		"IA-5", "IA-5(1)", "IA-5(2)", "IA-5(6)", "IA-5(7)", "IA-5(8)", "IA-5(13)", "IA-6", "IA-7", "IA-8", "IA-8(1)",
		"IA-8(2)", "IA-8(4)", "IA-9", "IA-10", "IA-11", "IA-12", "IA-12(2)", "IA-12(3)", "IA-12(4)", "IA-12(5)", "IA-13",
	}
	count(ia.evaluated_controls) == 33
}

test_ia_one_finding_per_evaluated_id_on_empty_input if {
	r := ia.compliance_report with input as {}
	r.controls_evaluated == 33
	count(r.violations) == count(ia.evaluated_controls)
	_ids(r) == ia.evaluated_controls
	every v in r.violations {
		contains(v, "evidence missing")
	}
}

# --- original single-fact rules: absent is evidence missing, false keeps the original finding ----------------

test_original_rule_false_keeps_original_text if {
	fx := object.union(_pass, {"ia_controls": {"policy": {"documented": false}}})
	r := ia.compliance_report with input as fx
	_ids(r) == {"IA-1"}
	r.violations == {"NIST IA-1: Identification and authentication policy not documented"}
}

test_original_rule_absent_is_evidence_missing if {
	fx := json.remove(_pass, ["ia_controls/user_id_auth/mfa_for_privileged"])
	r := ia.compliance_report with input as fx
	_ids(r) == {"IA-2(1)"}
	r.violations == {"NIST IA-2(1): evidence missing — input.ia_controls.user_id_auth.mfa_for_privileged not collected"}
}

test_original_rule_parent_wrong_type_is_evidence_missing if {
	fx := object.union(_pass, {"ia_controls": {"device_identification": "yes"}})
	r := ia.compliance_report with input as fx
	_ids(r) == {"IA-3"}
	contains(concat("", r.violations), "evidence missing")
}

# Strict booleans: the original rules pass only on true; any other type is evidence missing.
test_original_rule_string_true_is_evidence_missing if {
	fx := object.union(_pass, {"ia_controls": {"authenticator_feedback": {"obscured": "true"}}})
	r := ia.compliance_report with input as fx
	r.violations == {"NIST IA-6: evidence missing — input.ia_controls.authenticator_feedback.obscured not collected"}
}

test_original_rule_number_one_is_evidence_missing if {
	fx := object.union(_pass, {"ia_controls": {"user_id_auth": {"mfa_for_non_privileged": 1}}})
	r := ia.compliance_report with input as fx
	r.violations == {"NIST IA-2(2): evidence missing — input.ia_controls.user_id_auth.mfa_for_non_privileged not collected"}
}

test_original_rule_null_is_evidence_missing if {
	fx := object.union(_pass, {"ia_controls": {"identifier_management": {"unique_per_user": null}}})
	r := ia.compliance_report with input as fx
	r.violations == {"NIST IA-4: evidence missing — input.ia_controls.identifier_management.unique_per_user not collected"}
}

test_original_rule_object_is_evidence_missing if {
	fx := object.union(_pass, {"ia_controls": {"non_organizational_users": {"identified": {"yes": true}}}})
	r := ia.compliance_report with input as fx
	_ids(r) == {"IA-8"}
	contains(concat("", r.violations), "evidence missing")
}

test_ia5_1_string_true_is_evidence_missing if {
	fx := object.union(_pass, {"ia_controls": {"authenticator_management": {"encrypted_in_transit": "yes"}}})
	r := ia.compliance_report with input as fx
	_ids(r) == {"IA-5(1)"}
	contains(concat("", r.violations), "evidence missing — input.ia_controls.authenticator_management.encrypted_in_transit")
}

# --- IA-5(1) ----------------------------------------------------------------------------------------------------

test_ia5_1_storage_gap_fails_once if {
	fx := object.union(_pass, {"ia_controls": {"authenticator_management": {"encrypted_at_rest": false}}})
	r := ia.compliance_report with input as fx
	_ids(r) == {"IA-5(1)"}
	f := _finding(r, "IA-5(1)")
	count(f) == 1
	contains(f[0], "encrypted_at_rest")
	not contains(f[0], "encrypted_in_transit")
	not contains(f[0], "evidence missing")
}

test_ia5_1_missing_evidence_one_finding if {
	fx := json.remove(_pass, ["ia_controls/authenticator_management/encrypted_in_transit", "ia_controls/authenticator_management/encrypted_at_rest"])
	r := ia.compliance_report with input as fx
	f := _finding(r, "IA-5(1)")
	count(f) == 1
	contains(f[0], "evidence missing")
	contains(f[0], "encrypted_in_transit")
	contains(f[0], "encrypted_at_rest")
}

# --- IA-7: applicable standard is the organisation's input; FIPS is not hard-required -------------------------

test_ia7_unmet_fails if {
	fx := object.union(_pass, {"ia_controls": {"cryptographic_module_auth": {"standards_met": []}}})
	r := ia.compliance_report with input as fx
	_ids(r) == {"IA-7"}
	not contains(concat("", r.violations), "evidence missing")
}

test_ia7_old_fips_boolean_is_missing_evidence if {
	fx := object.union(_pass, {"ia_controls": {"cryptographic_module_auth": {"fips_validated": true, "odp": null}}})
	r := ia.compliance_report with input as fx
	_ids(r) == {"IA-7"}
	contains(concat("", r.violations), "evidence missing")
}

test_ia7_empty_required_list_is_missing_evidence if {
	fx := object.union(_pass, {"ia_controls": {"cryptographic_module_auth": {"odp": {"required_standards": []}}}})
	r := ia.compliance_report with input as fx
	_ids(r) == {"IA-7"}
	contains(concat("", r.violations), "evidence missing")
}

test_ia7_wrong_type_is_missing_evidence if {
	fx := object.union(_pass, {"ia_controls": {"cryptographic_module_auth": "FIPS"}})
	r := ia.compliance_report with input as fx
	_ids(r) == {"IA-7"}
	contains(concat("", r.violations), "evidence missing")
}

# --- enhancements and new base controls: one failing case flips exactly that id, one evidence-missing case -----

test_ia2_8_non_privileged_not_replay_resistant_flips_only_ia2_8 if {
	fx := object.union(_pass, {"ia_controls": {"user_id_auth": {"replay_resistance": {"replay_resistant_account_types": ["privileged"]}}}})
	r := ia.compliance_report with input as fx
	_ids(r) == {"IA-2(8)"}
	contains(concat("", r.violations), "authentication for non_privileged accounts is not replay-resistant")
}

test_ia2_8_missing_odp_is_evidence_missing if {
	fx := json.remove(_pass, ["ia_controls/user_id_auth/replay_resistance/odp"])
	r := ia.compliance_report with input as fx
	_ids(r) == {"IA-2(8)"}
	contains(concat("", r.violations), "evidence missing — input.ia_controls.user_id_auth.replay_resistance.odp.account_types")
}

test_ia2_12_not_verified_flips_only_ia2_12 if {
	fx := object.union(_pass, {"ia_controls": {"user_id_auth": {"piv": {"electronically_verified": false}}}})
	r := ia.compliance_report with input as fx
	_ids(r) == {"IA-2(12)"}
}

test_ia2_12_boolean_as_string_true_is_a_finding if {
	fx := object.union(_pass, {"ia_controls": {"user_id_auth": {"piv": {"piv_accepted": "true"}}}})
	r := ia.compliance_report with input as fx
	_ids(r) == {"IA-2(12)"}
	contains(concat("", r.violations), "piv_accepted is not true")
}

test_ia2_12_missing_is_evidence_missing if {
	fx := json.remove(_pass, ["ia_controls/user_id_auth/piv"])
	r := ia.compliance_report with input as fx
	_ids(r) == {"IA-2(12)"}
	contains(concat("", r.violations), "evidence missing")
}

test_ia4_4_characteristic_not_indicated_flips_only_ia4_4 if {
	fx := object.union(_pass, {"ia_controls": {"identifier_management": {"user_status": {"characteristics_indicated": ["contractor"]}}}})
	r := ia.compliance_report with input as fx
	_ids(r) == {"IA-4(4)"}
	contains(concat("", r.violations), "characteristic foreign_national")
}

test_ia4_4_observed_not_a_list_is_evidence_missing if {
	fx := object.union(_pass, {"ia_controls": {"identifier_management": {"user_status": {"characteristics_indicated": "contractor"}}}})
	r := ia.compliance_report with input as fx
	_ids(r) == {"IA-4(4)"}
	contains(concat("", r.violations), "evidence missing")
}

test_ia5_2_no_revocation_cache_flips_only_ia5_2 if {
	fx := object.union(_pass, {"ia_controls": {"authenticator_management": {"public_key": {"local_revocation_cache": false}}}})
	r := ia.compliance_report with input as fx
	_ids(r) == {"IA-5(2)"}
	contains(concat("", r.violations), "no local cache of revocation data")
}

test_ia5_2_without_pki_needs_no_path_validation if {
	fx := json.remove(
		object.union(_pass, {"ia_controls": {"authenticator_management": {"public_key": {"pki_used": false}}}}),
		[
			"ia_controls/authenticator_management/public_key/certification_path_validated",
			"ia_controls/authenticator_management/public_key/revocation_status_checked",
			"ia_controls/authenticator_management/public_key/local_revocation_cache",
		],
	)
	r := ia.compliance_report with input as fx
	r.violation_count == 0
}

test_ia5_2_pki_flag_as_string_is_evidence_missing if {
	fx := object.union(_pass, {"ia_controls": {"authenticator_management": {"public_key": {"pki_used": "true"}}}})
	r := ia.compliance_report with input as fx
	_ids(r) == {"IA-5(2)"}
	contains(concat("", r.violations), "evidence missing — input.ia_controls.authenticator_management.public_key.pki_used")
}

test_ia5_6_plaintext_authenticators_flip_only_ia5_6 if {
	fx := object.union(_pass, {"ia_controls": {"authenticator_management": {"authenticator_protection": {"plaintext_authenticators_found": 2}}}})
	r := ia.compliance_report with input as fx
	_ids(r) == {"IA-5(6)"}
	contains(concat("", r.violations), "2 unprotected authenticators")
}

test_ia5_6_count_as_string_is_evidence_missing if {
	fx := object.union(_pass, {"ia_controls": {"authenticator_management": {"authenticator_protection": {"plaintext_authenticators_found": "1"}}}})
	r := ia.compliance_report with input as fx
	_ids(r) == {"IA-5(6)"}
	contains(concat("", r.violations), "evidence missing — input.ia_controls.authenticator_management.authenticator_protection.plaintext_authenticators_found")
}

test_ia5_6_count_as_null_is_evidence_missing if {
	fx := object.union(_pass, {"ia_controls": {"authenticator_management": {"authenticator_protection": {"plaintext_authenticators_found": null}}}})
	r := ia.compliance_report with input as fx
	_ids(r) == {"IA-5(6)"}
	contains(concat("", r.violations), "evidence missing")
}

test_ia8_1_not_accepted_flips_only_ia8_1 if {
	fx := object.union(_pass, {"ia_controls": {"non_organizational_users": {"piv_other_agencies": {"piv_accepted": false}}}})
	r := ia.compliance_report with input as fx
	_ids(r) == {"IA-8(1)"}
}

test_ia8_1_missing_is_evidence_missing if {
	fx := json.remove(_pass, ["ia_controls/non_organizational_users/piv_other_agencies"])
	r := ia.compliance_report with input as fx
	_ids(r) == {"IA-8(1)"}
	contains(concat("", r.violations), "evidence missing")
}

test_ia8_2_non_compliant_authenticator_flips_only_ia8_2 if {
	fx := object.union(_pass, {"ia_controls": {"non_organizational_users": {"external_authenticators": {"accepted": [{"name": "Login.gov", "nist_compliant": true}, {"name": "SocialID", "nist_compliant": false}]}}}})
	r := ia.compliance_report with input as fx
	_ids(r) == {"IA-8(2)"}
	contains(concat("", r.violations), "external authenticator SocialID")
}

test_ia8_2_no_external_authenticators_passes if {
	fx := object.union(_pass, {"ia_controls": {"non_organizational_users": {"external_authenticators": {"accepted": []}}}})
	r := ia.compliance_report with input as fx
	r.violation_count == 0
}

test_ia8_2_missing_list_is_evidence_missing if {
	fx := json.remove(_pass, ["ia_controls/non_organizational_users/external_authenticators/accepted"])
	r := ia.compliance_report with input as fx
	_ids(r) == {"IA-8(2)"}
	contains(concat("", r.violations), "evidence missing")
}

test_ia8_4_profile_not_conformed_flips_only_ia8_4 if {
	fx := object.union(_pass, {"ia_controls": {"non_organizational_users": {"identity_profiles": {"conformed_profiles": ["OIDC"]}}}})
	r := ia.compliance_report with input as fx
	_ids(r) == {"IA-8(4)"}
	contains(concat("", r.violations), "profile SAML 2.0 Web SSO")
}

test_ia8_4_empty_odp_is_evidence_missing if {
	fx := object.union(_pass, {"ia_controls": {"non_organizational_users": {"identity_profiles": {"odp": {"profiles": []}}}}})
	r := ia.compliance_report with input as fx
	_ids(r) == {"IA-8(4)"}
	contains(concat("", r.violations), "evidence missing")
}

test_ia11_circumstance_not_enforced_flips_only_ia11 if {
	fx := object.union(_pass, {"ia_controls": {"reauthentication": {"enforced_circumstances": ["session timeout"]}}})
	r := ia.compliance_report with input as fx
	_ids(r) == {"IA-11"}
	contains(concat("", r.violations), "re-authentication not required when privileged function")
	contains(concat("", r.violations), "re-authentication not required when role change")
}

test_ia11_missing_is_evidence_missing if {
	fx := json.remove(_pass, ["ia_controls/reauthentication"])
	r := ia.compliance_report with input as fx
	_ids(r) == {"IA-11"}
	contains(concat("", r.violations), "evidence missing")
}

test_ia12_unproofed_accounts_flip_only_ia12 if {
	fx := object.union(_pass, {"ia_controls": {"identity_proofing": {"accounts_without_proofing": 5}}})
	r := ia.compliance_report with input as fx
	_ids(r) == {"IA-12"}
	contains(concat("", r.violations), "5 accounts for logical access have no identity proofing record")
}

test_ia12_missing_is_evidence_missing if {
	fx := json.remove(_pass, ["ia_controls/identity_proofing/resolved_to_unique_individual"])
	r := ia.compliance_report with input as fx
	_ids(r) == {"IA-12"}
	contains(concat("", r.violations), "evidence missing — input.ia_controls.identity_proofing.resolved_to_unique_individual")
}

test_ia12_2_not_presented_flips_only_ia12_2 if {
	fx := object.union(_pass, {"ia_controls": {"identity_proofing": {"identity_evidence": {"presented_to_registration_authority": false}}}})
	r := ia.compliance_report with input as fx
	_ids(r) == {"IA-12(2)"}
}

test_ia12_2_missing_is_evidence_missing if {
	fx := json.remove(_pass, ["ia_controls/identity_proofing/identity_evidence"])
	r := ia.compliance_report with input as fx
	_ids(r) == {"IA-12(2)"}
	contains(concat("", r.violations), "evidence missing")
}

test_ia12_3_method_not_used_flips_only_ia12_3 if {
	fx := object.union(_pass, {"ia_controls": {"identity_proofing": {"validation": {"methods_used": ["document authentication"]}}}})
	r := ia.compliance_report with input as fx
	_ids(r) == {"IA-12(3)"}
	contains(concat("", r.violations), "through biometric comparison")
}

test_ia12_3_missing_is_evidence_missing if {
	fx := json.remove(_pass, ["ia_controls/identity_proofing/validation/methods_used"])
	r := ia.compliance_report with input as fx
	_ids(r) == {"IA-12(3)"}
	contains(concat("", r.violations), "evidence missing")
}

test_ia12_5_wrong_item_flips_only_ia12_5 if {
	fx := object.union(_pass, {"ia_controls": {"identity_proofing": {"address_confirmation": {"delivered_item": "notice of proofing"}}}})
	r := ia.compliance_report with input as fx
	_ids(r) == {"IA-12(5)"}
	contains(concat("", r.violations), "delivers notice of proofing; the organization-defined item is registration code")
}

test_ia12_5_in_band_flips_only_ia12_5 if {
	fx := object.union(_pass, {"ia_controls": {"identity_proofing": {"address_confirmation": {"out_of_band": false}}}})
	r := ia.compliance_report with input as fx
	_ids(r) == {"IA-12(5)"}
}

test_ia12_5_unknown_odp_is_evidence_missing if {
	fx := object.union(_pass, {"ia_controls": {"identity_proofing": {"address_confirmation": {"odp": {"delivered_item": "postcard"}}}}})
	r := ia.compliance_report with input as fx
	_ids(r) == {"IA-12(5)"}
	contains(concat("", r.violations), "evidence missing")
}

# A base control never fails for an enhancement: removing every enhancement fact fails only the enhancements
# (IA-12 still passes without the IA-12(2), (3) and (5) objects).
test_base_controls_ignore_enhancement_facts if {
	fx := json.remove(_pass, [
		"ia_controls/user_id_auth/replay_resistance", "ia_controls/user_id_auth/piv",
		"ia_controls/identifier_management/user_status", "ia_controls/authenticator_management/public_key",
		"ia_controls/authenticator_management/authenticator_protection",
		"ia_controls/non_organizational_users/piv_other_agencies",
		"ia_controls/non_organizational_users/external_authenticators",
		"ia_controls/non_organizational_users/identity_profiles", "ia_controls/identity_proofing/identity_evidence",
		"ia_controls/identity_proofing/validation", "ia_controls/identity_proofing/address_confirmation",
		"ia_controls/user_id_auth/shared_accounts", "ia_controls/user_id_auth/separate_device",
		"ia_controls/authenticator_management/embedded_authenticators",
		"ia_controls/authenticator_management/multiple_system_accounts",
		"ia_controls/authenticator_management/cached_authenticators", "ia_controls/identity_proofing/in_person",
	])
	r := ia.compliance_report with input as fx
	_ids(r) == {
		"IA-2(5)", "IA-2(6)", "IA-2(8)", "IA-2(12)", "IA-4(4)", "IA-5(2)", "IA-5(6)", "IA-5(7)", "IA-5(8)", "IA-5(13)",
		"IA-8(1)", "IA-8(2)", "IA-8(4)", "IA-12(2)", "IA-12(3)", "IA-12(4)", "IA-12(5)",
	}
}

# --- remaining base controls and High-baseline enhancements -------------------------------------------------------

test_ia2_5_shared_account_flips_only_ia2_5 if {
	fx := object.union(_pass, {"ia_controls": {"user_id_auth": {"shared_accounts": {"reachable_without_individual_auth": 2}}}})
	r := ia.compliance_report with input as fx
	r.violations == {"NIST IA-2(5): 2 shared accounts can be used without individual authentication first"}
}

test_ia2_5_count_as_string_is_evidence_missing if {
	fx := object.union(_pass, {"ia_controls": {"user_id_auth": {"shared_accounts": {"reachable_without_individual_auth": "0"}}}})
	r := ia.compliance_report with input as fx
	_ids(r) == {"IA-2(5)"}
	contains(concat("", r.violations), "evidence missing")
}

test_ia2_6_remote_without_separate_device_flips_only_ia2_6 if {
	fx := object.union(_pass, {"ia_controls": {"user_id_auth": {"separate_device": {"separate_device_access_types": ["network"]}}}})
	r := ia.compliance_report with input as fx
	r.violations == {"NIST IA-2(6): remote access does not require a factor from a separate device"}
}

test_ia2_6_weak_device_flips_only_ia2_6 if {
	fx := object.union(_pass, {"ia_controls": {"user_id_auth": {"separate_device": {"device_meets_strength_requirements": false}}}})
	r := ia.compliance_report with input as fx
	_ids(r) == {"IA-2(6)"}
}

test_ia2_6_missing_odp_is_evidence_missing if {
	fx := json.remove(_pass, ["ia_controls/user_id_auth/separate_device/odp/account_types"])
	r := ia.compliance_report with input as fx
	_ids(r) == {"IA-2(6)"}
	contains(concat("", r.violations), "evidence missing")
	contains(concat("", r.violations), "odp.account_types")
}

test_ia5_7_embedded_secret_flips_only_ia5_7 if {
	fx := object.union(_pass, {"ia_controls": {"authenticator_management": {"embedded_authenticators": {"unencrypted_static_found": 4}}}})
	r := ia.compliance_report with input as fx
	_ids(r) == {"IA-5(7)"}
	contains(concat("", r.violations), "4 unencrypted static authenticators")
}

test_ia5_7_count_as_null_is_evidence_missing if {
	fx := object.union(_pass, {"ia_controls": {"authenticator_management": {"embedded_authenticators": {"unencrypted_static_found": null}}}})
	r := ia.compliance_report with input as fx
	_ids(r) == {"IA-5(7)"}
	contains(concat("", r.violations), "evidence missing")
}

test_ia5_8_control_missing_flips_only_ia5_8 if {
	fx := object.union(_pass, {"ia_controls": {"authenticator_management": {"multiple_system_accounts": {"controls_implemented": []}}}})
	r := ia.compliance_report with input as fx
	_ids(r) == {"IA-5(8)"}
	contains(concat("", r.violations), "single sign-on")
}

test_ia5_8_observed_not_a_list_is_evidence_missing if {
	fx := object.union(_pass, {"ia_controls": {"authenticator_management": {"multiple_system_accounts": {"controls_implemented": "single sign-on"}}}})
	r := ia.compliance_report with input as fx
	_ids(r) == {"IA-5(8)"}
	contains(concat("", r.violations), "evidence missing")
}

test_ia5_13_long_cache_flips_only_ia5_13 if {
	fx := object.union(_pass, {"ia_controls": {"authenticator_management": {"cached_authenticators": {"max_cache_hours": 168}}}})
	r := ia.compliance_report with input as fx
	r.violations == {"NIST IA-5(13): cached authenticators usable for up to 168 hours; the organization-defined period is 72 hours"}
}

test_ia5_13_hours_as_string_is_evidence_missing if {
	fx := object.union(_pass, {"ia_controls": {"authenticator_management": {"cached_authenticators": {"max_cache_hours": "1"}}}})
	r := ia.compliance_report with input as fx
	_ids(r) == {"IA-5(13)"}
	contains(concat("", r.violations), "evidence missing — input.ia_controls.authenticator_management.cached_authenticators.max_cache_hours")
}

test_ia5_13_odp_as_null_is_evidence_missing if {
	fx := object.union(_pass, {"ia_controls": {"authenticator_management": {"cached_authenticators": {"odp": {"max_hours": null}}}}})
	r := ia.compliance_report with input as fx
	_ids(r) == {"IA-5(13)"}
	contains(concat("", r.violations), "odp.max_hours")
}

test_ia9_unauthenticated_service_flips_only_ia9 if {
	fx := object.union(_pass, {"ia_controls": {"service_authentication": {"authenticated_services": ["api-gateway"]}}})
	r := ia.compliance_report with input as fx
	r.violations == {"NIST IA-9: service billing not uniquely identified and authenticated before communicating"}
}

test_ia9_missing_is_evidence_missing if {
	fx := json.remove(_pass, ["ia_controls/service_authentication"])
	r := ia.compliance_report with input as fx
	_ids(r) == {"IA-9"}
	contains(concat("", r.violations), "evidence missing")
}

test_ia10_circumstance_not_enforced_flips_only_ia10 if {
	fx := object.union(_pass, {"ia_controls": {"adaptive_authentication": {"enforced_circumstances": ["new device"]}}})
	r := ia.compliance_report with input as fx
	r.violations == {"NIST IA-10: supplemental authentication not required when unusual location"}
}

test_ia10_missing_techniques_is_evidence_missing if {
	fx := json.remove(_pass, ["ia_controls/adaptive_authentication/techniques_configured"])
	r := ia.compliance_report with input as fx
	_ids(r) == {"IA-10"}
	contains(concat("", r.violations), "evidence missing")
}

test_ia12_4_not_required_flips_only_ia12_4 if {
	fx := object.union(_pass, {"ia_controls": {"identity_proofing": {"in_person": {"required": false}}}})
	r := ia.compliance_report with input as fx
	_ids(r) == {"IA-12(4)"}
}

test_ia12_4_missing_is_evidence_missing if {
	fx := json.remove(_pass, ["ia_controls/identity_proofing/in_person"])
	r := ia.compliance_report with input as fx
	_ids(r) == {"IA-12(4)"}
	contains(concat("", r.violations), "evidence missing")
}

test_ia13_local_auth_apps_flip_only_ia13 if {
	fx := object.union(_pass, {"ia_controls": {"identity_providers": {"applications_with_local_authentication": 1}}})
	r := ia.compliance_report with input as fx
	_ids(r) == {"IA-13"}
	contains(concat("", r.violations), "1 applications authenticate")
}

test_ia13_missing_is_evidence_missing if {
	fx := json.remove(_pass, ["ia_controls/identity_providers"])
	r := ia.compliance_report with input as fx
	_ids(r) == {"IA-13"}
	contains(concat("", r.violations), "evidence missing")
}
