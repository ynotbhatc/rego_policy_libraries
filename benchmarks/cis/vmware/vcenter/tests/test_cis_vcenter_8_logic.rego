package cis_vcenter_8_test

import rego.v1

# Validation fix 2026-10-17: one undefined condition rule made its whole section's violations
# array undefined, so a partly-configured vCenter was compliant with no violations.

pkg := data.cis_vcenter_8

test_failing_control_reports_violation_and_not_compliant if {
	inp := {"vcenter": {"logging": {"enabled": false}}}
	v := pkg.violations with input as inp
	count(v) == 73
	not pkg.compliant with input as inp
}

test_every_section_reports_when_only_vcenter_present if {
	count(pkg.vcenter_server_violations) > 0 with input as {"vcenter": {}}
	count(pkg.sso_violations) > 0 with input as {"vcenter": {}}
	count(pkg.performance_charts_violations) > 0 with input as {"vcenter": {}}
}

test_findings_populated_for_partial_input if {
	f := pkg.findings with input as {"vcenter": {"logging": {"enabled": false}}}
	count(f[0].violations) == 73
}

# #300 type traps: a non-number must not pass vcenter_session_timeout_configured.
test_vcenter_session_timeout_configured_number_type_traps if {
	data.cis_vcenter_8.vcenter_session_timeout_configured with input as {"vcenter": {"session": {"timeout_minutes": 15}}}
	not data.cis_vcenter_8.vcenter_session_timeout_configured with input as {"vcenter": {"session": {"timeout_minutes": "1"}}}
	not data.cis_vcenter_8.vcenter_session_timeout_configured with input as {"vcenter": {"session": {"timeout_minutes": null}}}
	not data.cis_vcenter_8.vcenter_session_timeout_configured with input as {"vcenter": {"session": {"timeout_minutes": "not-a-number"}}}
}
