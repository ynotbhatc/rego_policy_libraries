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
	not sr.technical_safeguards_compliant
		with input as {"phi_systems": []}
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
	sr.technical_safeguards_compliant
		with input as {"phi_systems": [{"name": "ehr-db"}]}
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
	not sr.technical_safeguards_compliant
		with input as {"phi_systems": [{"name": "ehr-db"}]}
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
	is_object(report.safeguards.technical.audit_controls) # module compliance_report, not a bare bool
	report.safeguards.technical.ephi_scope_declared == true
}

test_report_wellformed_on_empty_input if {
	report := sr.report with input as {}
	is_object(report)
	count(report) > 0
	report.safeguards.technical.ephi_scope_declared == false
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
