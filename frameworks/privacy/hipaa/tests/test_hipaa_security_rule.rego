# Reconciliation tests — Security Rule technical safeguards (§164.312) now
# delegate to the data-activity modules (measured, not attested), with a
# fail-closed ePHI-scope gate. These tests pin the verdict semantics the
# smoke test cannot (it only checks report well-formedness).
package hipaa.security_rule_test

import rego.v1

import data.hipaa.security_rule as sr

# ---------------------------------------------------------------------------
# Fail-closed: no ePHI scope → technical safeguards NOT compliant.
# This is the regression the delegation could have introduced (modules are
# vacuously compliant on empty input); the gate + module guards prevent it.
# ---------------------------------------------------------------------------

test_technical_fails_closed_on_empty_input if {
	not sr.technical_safeguards_compliant with input as {}
}

test_technical_fails_closed_when_phi_systems_empty if {
	# Even if every module were compliant, no declared ePHI scope must fail.
	not sr.technical_safeguards_compliant with input as {"phi_systems": []}
		with data.hipaa.access_control.compliant as true
		with data.hipaa.audit_controls.compliant as true
		with data.hipaa.integrity.compliant as true
		with data.hipaa.authentication.compliant as true
		with data.hipaa.transmission_security.compliant as true
}

# ---------------------------------------------------------------------------
# Positive control: scope declared AND all modules compliant → compliant.
# Proves the delegation can actually return true (guards against an
# always-false regression that a fail-closed-only test would miss).
# ---------------------------------------------------------------------------

test_technical_compliant_when_scope_and_modules_pass if {
	sr.technical_safeguards_compliant with input as {"phi_systems": [{"name": "ehr-db"}]}
		with data.hipaa.access_control.compliant as true
		with data.hipaa.audit_controls.compliant as true
		with data.hipaa.integrity.compliant as true
		with data.hipaa.authentication.compliant as true
		with data.hipaa.transmission_security.compliant as true
}

# ---------------------------------------------------------------------------
# Any single technical module failing fails the aggregate.
# ---------------------------------------------------------------------------

test_technical_fails_when_one_module_fails if {
	not sr.technical_safeguards_compliant with input as {"phi_systems": [{"name": "ehr-db"}]}
		with data.hipaa.access_control.compliant as true
		with data.hipaa.audit_controls.compliant as false
		with data.hipaa.integrity.compliant as true
		with data.hipaa.authentication.compliant as true
		with data.hipaa.transmission_security.compliant as true
}

# ---------------------------------------------------------------------------
# Report stays well-formed and surfaces the richer module reports.
# ---------------------------------------------------------------------------

test_report_technical_uses_module_reports if {
	report := sr.report with input as {"phi_systems": [{"name": "ehr-db"}]}
	is_object(report.technical_modules.audit_controls) # module compliance_report, not a bare bool
	report.ephi_scope_declared == true
}

test_report_wellformed_on_empty_input if {
	report := sr.report with input as {}
	is_object(report)
	count(report) > 0
	report.ephi_scope_declared == false
}

# ---------------------------------------------------------------------------
# End-to-end: a realistic, UNMOCKED Guardium-shaped input actually satisfies
# all five §164.312 data-activity modules. Proves the delegated path can return
# true against real facts — not just that the aggregation ANDs booleans.
# ---------------------------------------------------------------------------

_compliant_technical_input := {
	"phi_systems": [{
		"name": "ehr-db",
		"audit_logging_enabled": true,
		"audited_events": [
			"login_success", "login_failure", "logout", "phi_access", "phi_create",
			"phi_modify", "phi_delete", "phi_export", "permission_change",
			"account_creation", "account_deletion", "password_change",
		],
		"data_at_rest_encrypted": true,
		"encryption_algorithm": "AES-256",
		"integrity_checking_enabled": true,
		"integrity_check_frequency_hours": 12,
		"transmission_encrypted": true,
		"protocols_in_use": ["TLSv1.3"],
		"api_endpoint": "https://ehr.internal/api",
		"request_signing_enabled": true,
	}],
	"audit_logs": [{"event": "phi_access", "user_id": "u1", "timestamp": "2026-07-31T00:00:00Z"}],
	"audit_logging": {
		"centralized": true, "includes_user_id": true, "includes_timestamp": true,
		"includes_action_type": true, "includes_source_ip": true, "offsite_backup_enabled": true,
		"retention_days": 2555, "tamper_evident": true,
	},
	"monitoring": {
		"after_hours_access_alerts": true, "audit_review_frequency_days": 7,
		"automated_alerting_enabled": true, "unauthorized_access_alerts": true,
	},
	"users": [{"username": "alice", "shared_account": false, "phi_access_disabled": false}],
	"access_controls": {
		"emergency_access_procedure_documented": true, "emergency_access_tested": true,
		"emergency_accounts_reviewed_days": 30, "role_based_access_implemented": true,
	},
	"session": {"automatic_logoff_enabled": true, "inactivity_timeout_minutes": 10, "screen_lock_enabled": true},
	"encryption": {"key_management_policy_documented": true, "key_rotation_days": 90},
	"integrity": {
		"change_management_process": true, "checksum_or_hash_enabled": true,
		"digital_signatures_for_phi_export": true, "hash_algorithm": "SHA-256",
		"media_reuse_without_sanitization": false, "secure_deletion_policy": true,
		"write_protection_on_archived_phi": true,
	},
	"backup": {
		"regular_backups_enabled": true, "backup_frequency_hours": 24,
		"offsite_or_cloud_backup": true, "restore_tested": true, "restore_test_days": 90,
	},
	"mfa": {
		"enabled_for_phi_access": true, "required_for_remote_access": true,
		"required_for_privileged_accounts": true, "methods_allowed": ["totp", "fido2"],
		"stronger_method_also_available": true,
	},
	"password_policy": {
		"complexity_required": true, "history_count": 12, "lockout_enabled": true,
		"lockout_threshold": 5, "max_age_days": 90, "minimum_length": 14,
	},
	"authentication": {"concurrent_sessions_unlimited": false, "re_authentication_for_sensitive_ops": true},
	"privileged_accounts": [],
	"network": {"message_authentication_enabled": true, "phi_network_segmented": true, "remote_phi_access_enabled": false},
	"tls": {
		"minimum_version": "1.3", "enabled_ciphers": ["TLS_AES_256_GCM_SHA384"],
		"certificate_expiry_days": 200, "certificate_expiry_monitoring": true, "mutual_tls_for_phi_apis": true,
	},
	"vpn": {"required_for_remote_phi_access": true, "protocol": "IKEv2", "split_tunneling_enabled": false},
	"email": {"phi_sent_via_email": false, "dlp_enabled": true, "encrypted_email_required": true},
	"transmission": {},
	"api": {},
}

test_technical_compliant_with_real_input if {
	sr.technical_safeguards_compliant with input as _compliant_technical_input
}

# ---------------------------------------------------------------------------
# CFR-keyed Security Rule (45 CFR 164.308-164.316): ids, counts, fail-closed, attestation, facts.
# ---------------------------------------------------------------------------

_fx := data.hipaa.test_fixtures

test_counts_pinned if {
	count(sr.specifications) == 68
	count(sr.specifications_table) == 68
	count({id | some id, r in sr.specifications; r.status == "standard"}) == 22
	count({id | some id, r in sr.specifications; r.status == "required"}) == 24
	count({id | some id, r in sr.specifications; r.status == "addressable"}) == 22
	count(sr.fact_basis) == 48
	count(sr.technical_rows) == 12
	count({id | some id, _ in sr.specifications; not sr.fact_basis[id]}) == 20
	sum([count(t) | some t in sr.nist_800_66_r2_key_activities]) == 104
}

test_every_row_is_well_formed if {
	# every implementation specification names a standard of the same section as parent
	count({id |
		some id, r in sr.specifications
		r.status != "standard"
		p := sr.specifications[r.parent]
		p.status == "standard"
		p.section == r.section
	}) == 46
	count({id | some id, r in sr.specifications; r.status == "standard"; r.parent != ""}) == 0
	count({id | some id, r in sr.specifications; not sr.sections[r.section]}) == 0
	count({id | some id, r in sr.specifications; not startswith(id, r.section)}) == 0
	count({id | some id, _ in sr.fact_basis; not sr.specifications[id]}) == 0

	# standards carry an 800-66r2 section that has key-activity titles, and their count matches
	count({id |
		some id, r in sr.specifications
		r.status == "standard"
		count(sr.nist_800_66_r2_key_activities[r.nist_800_66_r2[0]]) == r.key_activities
	}) == 22
}

test_empty_input_fails_closed if {
	r := sr.report with input as {}
	r.compliant == false
	some v in r.violations
	contains(v, "FAIL-CLOSED - attestations 'input.hipaa.specifications'")

	# 4 undeclared scope flags + no role + missing container + 63 rows (5 group-health-plan rows gated off)
	r.violation_count == 69
	r.applicable == 63
}

test_all_green_is_compliant if {
	r := sr.report with input as _fx.full_input
	r.compliant == true
	r.satisfied == 68
	r.violation_count == 0
	sr.technical_safeguards_compliant with input as _fx.full_input
	sr.administrative_safeguards_compliant with input as _fx.full_input
}

test_one_attestation_false_is_named if {
	inp := object.union(_fx.full_input, {"hipaa": {"specifications": {"164.316(a)": false}}})
	v := sr.violations with input as inp
	count(v) == 1
	some m in v
	startswith(m, "HIPAA 164.316(a) Policies and procedures (standard): not attested")
}

test_string_true_is_not_an_attestation if {
	inp := object.union(_fx.full_input, {"hipaa": {"specifications": {"164.308(a)(5)(ii)(A)": "true"}}})
	v := sr.violations with input as inp
	count(v) == 1
	some m in v
	contains(m, "164.308(a)(5)(ii)(A) Security reminders (addressable)")
}

test_unknown_id_is_a_violation if {
	inp := object.union(_fx.full_input, {"hipaa": {"specifications": {"164.308(a)(9)": true}}})
	v := sr.violations with input as inp
	count(v) == 1
	some m in v
	contains(m, "unknown id 164.308(a)(9)")
}

test_failed_fact_is_named_under_its_citation if {
	inp := object.union(_fx.full_input, {"hipaa": {"administrative": {"security_management": {"risk_analysis": {"frequency_months": 24}}}}})
	v := sr.violations with input as inp
	count(v) == 1
	some m in v
	startswith(m, "HIPAA 164.308(a)(1)(ii)(A) Risk analysis (required): fact check failed")
}

test_attestation_does_not_decide_a_fact_row if {
	inp := object.union(_fx.full_input, {"hipaa": {"physical": {"workstation_security": {"ephi_access": {"restricted": false}}}}})
	r := sr.report with input as inp
	r.specifications["164.310(c)"].attested == true
	r.specifications["164.310(c)"].satisfied == false
	r.violation_count == 1
}

test_technical_finding_lands_on_the_cited_specification if {
	inp := object.union(_fx.full_input, {"session": {"inactivity_timeout_minutes": 30}})
	v := sr.violations with input as inp
	count(v) == 1
	some m in v
	startswith(m, "HIPAA 164.312(a)(2)(iii) Automatic logoff (addressable): fact check failed")
}

test_uncited_technical_finding_lands_on_the_standard if {
	# the access-control module cites 164.514(d) for minimum necessary; it is not a Security Rule row
	inp := object.union(_fx.full_input, {"users": [{"username": "alice", "phi_access_level": "full"}]})
	f := sr.technical_attribution with input as inp
	count(f["164.312(a)(1)"]) == 1
	count(f["164.312(a)(2)(i)"]) == 0
}

test_no_ephi_scope_fails_every_technical_row if {
	inp := object.union(_fx.full_input, {"phi_systems": []})
	r := sr.report with input as inp
	count([id | some id, _ in sr.technical_rows; r.specifications[id].satisfied == false]) == 12
}

test_group_health_plan_rows_follow_the_health_plan_flag if {
	inp := object.union(_fx.full_input, {"hipaa": {"scope": {"health_plan": false}}})
	r := sr.report with input as inp
	r.applicable == 63
	r.sections["164.314"].applicable == 4
	r.compliant == true
}

test_every_technical_finding_is_attributed_to_one_row_of_its_module if {
	# failing input for all five modules: each module's findings, spread over its rows, are exactly its violations
	inp := object.union(_fx.full_input, {
		"session": {"inactivity_timeout_minutes": 30},
		"users": [{"username": "admin", "shared_account": true, "phi_access_level": "full"}],
		"audit_logging": {"tamper_evident": false},
		"integrity": {"hash_algorithm": "MD5"},
		"mfa": {"enabled_for_phi_access": false},
		"network": {"phi_network_segmented": false},
	})
	f := sr.technical_attribution with input as inp
	every m in {"access_control", "audit_controls", "integrity", "authentication", "transmission_security"} {
		attributed := [x | some id, mod in sr.technical_rows; mod == m; some x in f[id]]
		v := data.hipaa[m].violations with input as inp
		count(v) > 0
		count(attributed) == count(v)
		{x | some x in attributed} == v
	}
}
