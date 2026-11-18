package cmmc_odp_test

import rego.v1

# Organisation-defined parameters (NIST SP 800-171A "... is defined" objectives):
# the observed value is compared with the organisation's own value; either one
# missing is a finding; strings and nulls never pass a comparison.

_odp := data.cmmc_test_fixtures.org_defined

_has(vs, prefix) if {
	some v in vs
	startswith(v, prefix)
}

_none(vs, prefix) if {
	every v in vs {
		not startswith(v, prefix)
	}
}

# --- 3.1.10 session lock (AC, legacy-style module) ---
test_3_1_10_longer_than_org_value_fails_shorter_passes if {
	bad := data.cmmc.access_control.violations with input as {"cmmc_level": 2, "session": {"lock_timeout_minutes": 30}, "org_defined": {"session_lock_minutes": 20}}
	"CMMC AC.L2-3.1.10: Session lock timeout is 30 minutes, beyond the organisation-defined 20 minutes of inactivity." in bad
	ok := data.cmmc.access_control.violations with input as {"cmmc_level": 2, "session": {"lock_timeout_minutes": 30}, "org_defined": {"session_lock_minutes": 30}}
	_none(ok, "CMMC AC.L2-3.1.10")
}

test_3_1_10_org_value_missing_or_string_fails_closed if {
	v := data.cmmc.access_control.violations with input as {"cmmc_level": 2, "session": {"lock_timeout_minutes": 5}}
	_has(v, "CMMC AC.L2-3.1.10: evidence missing - input.org_defined.session_lock_minutes")
	w := data.cmmc.access_control.violations with input as {"cmmc_level": 2, "session": {"lock_timeout_minutes": 5}, "org_defined": {"session_lock_minutes": "15"}}
	_has(w, "CMMC AC.L2-3.1.10: evidence missing - input.org_defined.session_lock_minutes")
}

# --- 3.3.1 audit retention ---
_au(retention, odp) := {"audit": {"logging_enabled": true, "auditd_active": true, "log_retention_days": retention}, "org_defined": odp}

test_3_3_1_retention_against_org_value if {
	data.cmmc.audit_accountability.compliant_3_3_1 with input as _au(30, {"audit_log_retention_days": 30})
	not data.cmmc.audit_accountability.compliant_3_3_1 with input as _au(30, {"audit_log_retention_days": 60})
	v := data.cmmc.audit_accountability.all_violations with input as _au(30, {"audit_log_retention_days": 60})
	"3.3.1: audit records retained 30 days, less than the organisation-defined 60 days" in v
}

test_3_3_1_missing_org_value_and_null_actual_fail_closed if {
	not data.cmmc.audit_accountability.compliant_3_3_1 with input as _au(400, {})
	v := data.cmmc.audit_accountability.all_violations with input as _au(400, {})
	_has(v, "3.3.1: evidence missing - input.org_defined.audit_log_retention_days")
	not data.cmmc.audit_accountability.compliant_3_3_1 with input as _au(null, {"audit_log_retention_days": 30})
	w := data.cmmc.audit_accountability.all_violations with input as _au(null, {"audit_log_retention_days": 30})
	"3.3.1: evidence missing - input.audit.log_retention_days not collected or not a number" in w
}

# --- 3.3.9 subset of privileged users ---
test_3_3_9_admins_must_be_in_the_defined_subset if {
	base := {"audit": {"management_restricted": true, "audit_admins": ["a", "b", "c", "d", "e", "f", "g"]}}
	data.cmmc.audit_accountability.compliant_3_3_9 with input as object.union(base, {"org_defined": {"audit_logging_managers": ["a", "b", "c", "d", "e", "f", "g"]}})
	not data.cmmc.audit_accountability.compliant_3_3_9 with input as object.union(base, {"org_defined": {"audit_logging_managers": ["a"]}})
	v := data.cmmc.audit_accountability.all_violations with input as base
	_has(v, "3.3.9: evidence missing - input.org_defined.audit_logging_managers")
}

# --- 3.5.5 identifier reuse / 3.5.6 inactivity / 3.5.7 length / 3.5.8 history / 3.5.9 ---
test_3_5_5_reuse_period_against_org_value if {
	inp := {"identity": {"automated_account_management": true, "identifier_reuse_prevented_days": 180}}
	data.cmmc.identification_authentication.compliant_3_5_5 with input as object.union(inp, {"org_defined": {"identifier_reuse_period_days": 180}})
	not data.cmmc.identification_authentication.compliant_3_5_5 with input as object.union(inp, {"org_defined": {"identifier_reuse_period_days": 365}})
	not data.cmmc.identification_authentication.compliant_3_5_5 with input as inp
}

test_3_5_6_inactivity_against_org_value if {
	inp := {"identity": {"identifier_management_policy": true, "terminated_accounts_disabled_immediately": true, "inactive_account_disable_days": 90}}
	data.cmmc.identification_authentication.compliant_3_5_6 with input as object.union(inp, {"org_defined": {"identifier_inactivity_days": 90}})
	not data.cmmc.identification_authentication.compliant_3_5_6 with input as object.union(inp, {"org_defined": {"identifier_inactivity_days": 60}})
	v := data.cmmc.identification_authentication.all_violations with input as object.union(inp, {"org_defined": {"identifier_inactivity_days": 60}})
	"3.5.6: identifiers disabled after 90 days of inactivity, beyond the organisation-defined period of 60 days" in v
}

test_3_5_7_length_8_passes_when_org_defines_8 if {
	inp := {"identity": {"password_min_length": 8, "password_complexity_uppercase": true, "password_complexity_lowercase": true, "password_complexity_numbers": true, "password_complexity_special": true}}
	data.cmmc.identification_authentication.compliant_3_5_7 with input as object.union(inp, {"org_defined": {"password_min_length": 8}})
	not data.cmmc.identification_authentication.compliant_3_5_7 with input as object.union(inp, {"org_defined": {"password_min_length": 14}})
	not data.cmmc.identification_authentication.compliant_3_5_7 with input as inp
}

test_3_5_8_history_against_org_value if {
	data.cmmc.identification_authentication.compliant_3_5_8 with input as {"identity": {"password_history_count": 3}, "org_defined": {"password_history_generations": 3}}
	not data.cmmc.identification_authentication.compliant_3_5_8 with input as {"identity": {"password_history_count": 3}, "org_defined": {"password_history_generations": 4}}
	not data.cmmc.identification_authentication.compliant_3_5_8 with input as {"identity": {"password_history_count": "24"}, "org_defined": {"password_history_generations": 4}}
}

test_3_5_9_no_expiry_limit if {
	data.cmmc.identification_authentication.compliant_3_5_9 with input as {"identity": {"temp_password_change_on_first_login": true, "temp_password_expiry_hours": 72}}
	not data.cmmc.identification_authentication.compliant_3_5_9 with input as {"identity": {"temp_password_change_on_first_login": false}}
}

# --- periodic intervals capped at one year by 32 CFR 170.14(d) ---
test_3_11_2_scan_interval_org_defined_and_capped if {
	risk := {"vulnerability_scanning_enabled": true, "scan_results_reviewed": true, "new_vuln_scan_triggered": true, "scan_frequency_days": 90}
	data.cmmc.risk_assessment.compliant_3_11_2 with input as {"risk": risk, "org_defined": {"vulnerability_scan_interval_days": 90}}
	not data.cmmc.risk_assessment.compliant_3_11_2 with input as {"risk": risk, "org_defined": {"vulnerability_scan_interval_days": 30}}
	not data.cmmc.risk_assessment.compliant_3_11_2 with input as {"risk": object.union(risk, {"scan_frequency_days": 400}), "org_defined": {"vulnerability_scan_interval_days": 400}}
}

test_3_12_1_interval_over_a_year_fails_even_if_met if {
	inp := {"assessment": {"assessment_frequency_days": 500}, "org_defined": {"control_assessment_interval_days": 500}}
	v := data.cmmc.security_assessment.all_violations with input as inp
	"3.12.1: the organisation-defined interval of 500 days exceeds one year; 32 CFR 170.14(d) limits a periodic interval to one year" in v
	not data.cmmc.security_assessment.compliant_3_12_1 with input as inp
}

test_3_11_3_remediation_uses_org_risk_based_days if {
	v := data.cmmc.risk_assessment.all_violations with input as {"risk": {"critical_vuln_remediation_days": 20, "high_vuln_remediation_days": 45}, "org_defined": {"critical_vulnerability_remediation_days": 30, "high_vulnerability_remediation_days": 30}}
	_none(v, "3.11.3: critical vulnerabilities remediated")
	"3.11.3: high vulnerabilities remediated within 45 days, beyond the organisation's risk-based 30 days" in v
}

# --- 3.13.9 / 3.14.1 / 3.14.4 / 3.14.5 / 3.10.4 ---
test_3_13_9_network_session_against_org_value if {
	v := data.cmmc.system_communications_protection.all_violations with input as {"scp": {"network_session_timeout_minutes": 60}, "org_defined": {"network_session_inactivity_minutes": 45}}
	"3.13.9: network connections terminated after 60 minutes of inactivity, beyond the organisation-defined 45 minutes" in v
}

test_3_14_1_flaw_correction_against_org_value if {
	v := data.cmmc.system_information_integrity.all_violations with input as {"integrity": {"critical_patch_days": 45}, "org_defined": {"flaw_correction_days": 60}}
	_none(v, "3.14.1: system flaws corrected")
	w := data.cmmc.system_information_integrity.all_violations with input as {"integrity": {"critical_patch_days": 45}}
	_has(w, "3.14.1: evidence missing - input.org_defined.flaw_correction_days")
}

test_3_14_4_no_hourly_limit if {
	data.cmmc.system_information_integrity.compliant_3_14_4 with input as {"integrity": {"antimalware_auto_update": true, "signature_update_frequency_hours": 72}}
}

test_3_14_5_scan_interval_against_org_value if {
	inp := {"integrity": {"periodic_system_scans": true, "scan_frequency_days": 14, "realtime_file_scanning": true, "download_scanning_enabled": true}}
	data.cmmc.system_information_integrity.compliant_3_14_5 with input as object.union(inp, {"org_defined": {"malware_scan_interval_days": 14}})
	not data.cmmc.system_information_integrity.compliant_3_14_5 with input as object.union(inp, {"org_defined": {"malware_scan_interval_days": 7}})
}

test_3_10_4_log_retention_against_org_value if {
	inp := {"physical": {"physical_access_audit_logs": true, "access_logs_reviewed_regularly": true, "access_log_retention_days": 30}}
	data.cmmc.physical_protection.compliant_3_10_4 with input as object.union(inp, {"org_defined": {"physical_access_log_retention_days": 30}})
	not data.cmmc.physical_protection.compliant_3_10_4 with input as object.union(inp, {"org_defined": {"physical_access_log_retention_days": 90}})
	not data.cmmc.physical_protection.compliant_3_10_4 with input as inp
}

test_3_2_1_training_interval_against_org_value if {
	v := data.cmmc.awareness_training.all_violations with input as {"training": {"training_frequency_days": 400}, "org_defined": {"awareness_training_interval_days": 180}}
	"3.2.1: security awareness delivered every 400 days, beyond the organisation-defined interval of 180 days" in v
}
