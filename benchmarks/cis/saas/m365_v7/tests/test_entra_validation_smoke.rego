package cis_m365_v7.entra_test

import rego.v1

# Generated smoke test for benchmarks/cis/saas/m365_v7/entra_validation.rego (scripts/gen_tests.py). Each rule states one thing the module was proven
# to do on empty input; a missing rule means the module does not do that, see docs/TEST_GENERATION.md.

test_entra_validation_loads_on_empty_input if {
	m := data.cis_m365_v7.entra with input as {}
	is_object(m)
}

test_entra_validation_report_wellformed_on_empty_input if {
	report := data.cis_m365_v7.entra.compliance_report with input as {}
	is_object(report)
	count(report) > 0
}

test_entra_validation_fail_closed_on_empty_input if {
	report := data.cis_m365_v7.entra.compliance_report with input as {}
	not object.get(report, "compliant", false) == true
}

# Semantic review 2026-11-13 regressions.
_has(v, id) := count({m | some m in v; startswith(m, id)}) > 0

_ca(p) := {"entra": {"collected": true, "conditional_access_policies": [p]}}

test_legacy_auth_only_eas_blocked_still_violates if {
	v := data.cis_m365_v7.entra.violation with input as _ca({"state": "enabled", "conditions": {"clientAppTypes": ["exchangeActiveSync"]}, "grant_controls": {"builtInControls": ["block"]}})
	_has(v, "CIS 5.2.2.3:")
}

test_legacy_auth_both_blocked_passes if {
	v := data.cis_m365_v7.entra.violation with input as _ca({"state": "enabled", "conditions": {"clientAppTypes": ["exchangeActiveSync", "other"]}, "grant_controls": {"builtInControls": ["block"]}})
	not _has(v, "CIS 5.2.2.3:")
}

test_signin_risk_with_mfa_only_violates_5_2_2_8 if {
	v := data.cis_m365_v7.entra.violation with input as _ca({"state": "enabled", "conditions": {"signInRiskLevels": ["high", "medium"]}, "grant_controls": {"builtInControls": ["mfa"]}})
	_has(v, "CIS 5.2.2.8:")
}

test_signin_risk_blocked_passes_5_2_2_8 if {
	v := data.cis_m365_v7.entra.violation with input as _ca({"state": "enabled", "conditions": {"signInRiskLevels": ["high", "medium"]}, "grant_controls": {"builtInControls": ["block"]}})
	not _has(v, "CIS 5.2.2.8:")
}

test_missing_allow_invites_from_violates_5_1_6_3 if {
	v := data.cis_m365_v7.entra.violation with input as {"entra": {"collected": true, "authorization_policy": {}}}
	_has(v, "CIS 5.1.6.3:")
}
