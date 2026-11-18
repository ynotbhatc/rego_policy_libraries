package hipaa.technical_regulation_only_test

import rego.v1

import data.hipaa.test_fixtures as fx

# Audit 2026-11-17 follow-up. Each technical module keeps only what 45 CFR 164.312 states; library periods,
# frequencies and mechanisms are advisories that never change `compliant`.

_u(patch) := object.union(fx.full_input, patch)

_sys(patch) := _u({"phi_systems": [object.union(fx.full_input.phi_systems[0], patch)]})

_clean(m, inp) if {
	count(data.hipaa[m].violations) == 0 with input as inp
	data.hipaa[m].compliant with input as inp
}

_advised(m, inp) if count(data.hipaa[m].advisories) > 0 with input as inp

_cites(m, inp, prefix) if {
	some v in data.hipaa[m].violations with input as inp
	startswith(v, prefix)
}

# --- 164.312(b) audit controls: record and examine -----------------------------------

test_b_logging_disabled_fails if _cites("audit_controls", _sys({"audit_logging_enabled": false}), "HIPAA 164.312(b)")

test_b_monthly_review_is_advisory_only if {
	inp := _u({"monitoring": {"audit_review_frequency_days": 30}})
	_clean("audit_controls", inp)
	_advised("audit_controls", inp)
}

test_b_review_performed_flag_is_examination_evidence if {
	inp := object.union(object.remove(fx.full_input, ["monitoring"]), {"monitoring": {"audit_review_performed": true}})
	count(data.hipaa.audit_controls.violations) == 0 with input as inp
}

test_b_no_examination_evidence_fails if {
	inp := object.remove(fx.full_input, ["monitoring"])
	_cites("audit_controls", inp, "HIPAA 164.312(b): evidence missing")
}

test_b_retention_event_list_and_tamper_evidence_are_advisories if {
	inp := _u({
		"audit_logging": {"retention_days": 365, "tamper_evident": false, "centralized": false, "includes_source_ip": false},
		"phi_systems": [object.union(fx.full_input.phi_systems[0], {"audited_events": ["phi_access"]})],
	})
	_clean("audit_controls", inp)
	_advised("audit_controls", inp)
}

# --- 164.312(d) person or entity authentication -----------------------------------------

test_d_password_rules_and_mfa_details_are_advisories if {
	inp := _u({
		"password_policy": {"minimum_length": 8, "max_age_days": 365, "history_count": 1, "lockout_threshold": 10},
		"mfa": {"required_for_remote_access": false},
	})
	_clean("authentication", inp)
	_advised("authentication", inp)
}

test_d_no_authentication_evidence_fails if {
	inp := _u({"mfa": {"enabled_for_phi_access": false}})
	_cites("authentication", inp, "HIPAA 164.312(d): evidence missing")
}

test_d_password_only_authentication_passes if {
	inp := _u({"mfa": {"enabled_for_phi_access": false}, "authentication": {"ephi_access_requires_authentication": true}})
	count(data.hipaa.authentication.violations) == 0 with input as inp
}

test_d_default_password_fails if {
	_cites("authentication", _u({"users": [{"username": "bob", "using_default_password": true}]}), "HIPAA 164.312(d)")
}

# --- 164.312(c) integrity ----------------------------------------------------------------

test_c1_policies_missing_fails if {
	_cites("integrity", _u({"integrity": {"policies_and_procedures_implemented": false}}), "HIPAA 164.312(c)(1)")
}

test_c_backup_cadence_md5_and_signatures_are_advisories if {
	inp := _u({
		"backup": {"backup_frequency_hours": 72, "restore_test_days": 400},
		"integrity": {"hash_algorithm": "MD5", "digital_signatures_for_phi_export": false},
	})
	_clean("integrity", inp)
	_advised("integrity", inp)
}

test_c2_hashing_alone_is_a_mechanism if {
	inp := object.union(_sys({"integrity_checking_enabled": false}), {"integrity": {"checksum_or_hash_enabled": true}})
	count(data.hipaa.integrity.violations) == 0 with input as inp
}

test_c2_no_mechanism_fails if {
	inp := object.union(_sys({"integrity_checking_enabled": false}), {"integrity": {"checksum_or_hash_enabled": false}})
	_cites("integrity", inp, "HIPAA 164.312(c)(2)")
}

# --- 164.312(e) transmission security ------------------------------------------------------

test_e_plaintext_protocol_fails_on_e2ii if _cites("transmission_security", _sys({"protocols_in_use": ["FTP"]}), "HIPAA 164.312(e)(2)(ii)")

test_e_tls_1_1_is_advisory_only if {
	inp := _sys({"protocols_in_use": ["TLSv1.1"]})
	_clean("transmission_security", inp)
	_advised("transmission_security", inp)
}

test_e_mtls_dlp_vpn_segmentation_are_advisories if {
	inp := _u({
		"tls": {"mutual_tls_for_phi_apis": false, "minimum_version": "1.0"},
		"network": {"phi_network_segmented": false, "remote_phi_access_enabled": true},
		"vpn": {"required_for_remote_phi_access": false, "split_tunneling_enabled": true},
		"email": {"phi_sent_via_email": true, "encrypted_email_required": true, "dlp_enabled": false},
	})
	_clean("transmission_security", inp)
	count(data.hipaa.transmission_security.advisories) >= 5 with input as inp
}

test_e2i_stated_integrity_control_passes if {
	inp := _u({"network": {"message_authentication_enabled": false, "transmission_integrity_controls_implemented": true}})
	count(data.hipaa.transmission_security.violations) == 0 with input as inp
}

test_e2i_no_integrity_control_fails if {
	_cites("transmission_security", _u({"network": {"message_authentication_enabled": false}}), "HIPAA 164.312(e)(2)(i)")
}

test_e2ii_email_without_encryption_fails if {
	_cites("transmission_security", _u({"email": {"phi_sent_via_email": true, "encrypted_email_required": false}}), "HIPAA 164.312(e)(2)(ii)")
}

# --- 164.312(a) access control -------------------------------------------------------------

test_a_generic_names_screen_lock_algorithm_are_advisories if {
	inp := _u({
		"users": [{"username": "admin", "shared_account": false}],
		"session": {"screen_lock_enabled": false},
		"phi_systems": [object.union(fx.full_input.phi_systems[0], {"encryption_algorithm": "3DES"})],
		"access_controls": {"emergency_access_tested": false},
	})
	_clean("access_control", inp)
	count(data.hipaa.access_control.advisories) >= 4 with input as inp
}

test_a1_access_restricted_statement_passes if {
	inp := _u({"access_controls": {"role_based_access_implemented": false, "access_restricted_to_granted_rights": true}})
	count(data.hipaa.access_control.violations) == 0 with input as inp
}

test_a1_no_access_restriction_evidence_fails if {
	_cites("access_control", _u({"access_controls": {"role_based_access_implemented": false}}), "HIPAA 164.312(a)(1)")
}

test_a2i_shared_account_still_fails if {
	_cites("access_control", _u({"users": [{"username": "ops", "shared_account": true}]}), "HIPAA 164.312(a)(2)(i)")
}

# --- every advisory message disclaims the regulation -----------------------------------------

test_no_advisory_cites_45_cfr_as_a_requirement if {
	inp := _u({
		"encryption": {"key_rotation_days": 900},
		"tls": {"mutual_tls_for_phi_apis": false},
		"password_policy": {"minimum_length": 6},
		"backup": {"backup_frequency_hours": 72},
		"monitoring": {"audit_review_frequency_days": 30},
	})
	adv := data.hipaa.main.advisories with input as inp
	count(adv) >= 5
	every a in adv {
		startswith(a, "Advisory (")
		not startswith(a, "HIPAA 16")
	}
}
