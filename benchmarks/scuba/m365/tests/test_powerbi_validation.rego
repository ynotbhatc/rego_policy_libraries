package scuba_m365.powerbi_test

import data.scuba_m365.powerbi
import rego.v1

# Fully compliant Power BI facts — every MS.POWERBI control satisfied.
# Each single-rule test starts from this and flips exactly one field.
compliant_input := {"scuba": {"powerbi": {
	"publish_to_web_disabled": true,
	"guest_access_disabled": true,
	"external_invitations_disabled": true,
	"service_principals": {
		"api_restricted_to_groups": true,
		"profiles_restricted_to_groups": true,
	},
	"resourcekey_auth_blocked": true,
	"python_r_interactions_disabled": true,
	"sensitivity_labels_enabled": true,
}}}

# ── One test per violation rule (fire exactly one, assert message present) ────

test_powerbi_1_1_publish_to_web if {
	inp := json.patch(compliant_input, [{"op": "replace", "path": "/scuba/powerbi/publish_to_web_disabled", "value": false}])
	v := powerbi.violations with input as inp
	count(v) == 1
	some msg in v
	contains(msg, "MS.POWERBI.1.1v1")
}

test_powerbi_2_1_guest_access if {
	inp := json.patch(compliant_input, [{"op": "replace", "path": "/scuba/powerbi/guest_access_disabled", "value": false}])
	v := powerbi.violations with input as inp
	count(v) == 1
	some msg in v
	contains(msg, "MS.POWERBI.2.1v1")
}

test_powerbi_3_1_external_invitations if {
	inp := json.patch(compliant_input, [{"op": "replace", "path": "/scuba/powerbi/external_invitations_disabled", "value": false}])
	v := powerbi.violations with input as inp
	count(v) == 1
	some msg in v
	contains(msg, "MS.POWERBI.3.1v1")
}

test_powerbi_4_1_api_restricted_to_groups if {
	inp := json.patch(compliant_input, [{"op": "replace", "path": "/scuba/powerbi/service_principals/api_restricted_to_groups", "value": false}])
	v := powerbi.violations with input as inp
	count(v) == 1
	some msg in v
	contains(msg, "MS.POWERBI.4.1v1")
}

test_powerbi_4_2_profiles_restricted_to_groups if {
	inp := json.patch(compliant_input, [{"op": "replace", "path": "/scuba/powerbi/service_principals/profiles_restricted_to_groups", "value": false}])
	v := powerbi.violations with input as inp
	count(v) == 1
	some msg in v
	contains(msg, "MS.POWERBI.4.2v1")
}

test_powerbi_5_1_resourcekey_auth if {
	inp := json.patch(compliant_input, [{"op": "replace", "path": "/scuba/powerbi/resourcekey_auth_blocked", "value": false}])
	v := powerbi.violations with input as inp
	count(v) == 1
	some msg in v
	contains(msg, "MS.POWERBI.5.1v1")
}

test_powerbi_6_1_python_r_interactions if {
	inp := json.patch(compliant_input, [{"op": "replace", "path": "/scuba/powerbi/python_r_interactions_disabled", "value": false}])
	v := powerbi.violations with input as inp
	count(v) == 1
	some msg in v
	contains(msg, "MS.POWERBI.6.1v1")
}

test_powerbi_7_1_sensitivity_labels if {
	inp := json.patch(compliant_input, [{"op": "replace", "path": "/scuba/powerbi/sensitivity_labels_enabled", "value": false}])
	v := powerbi.violations with input as inp
	count(v) == 1
	some msg in v
	contains(msg, "MS.POWERBI.7.1v1")
}

# ── Compliant input: no violations, compliant true ───────────────────────────

test_powerbi_fully_compliant if {
	powerbi.compliant with input as compliant_input
	v := powerbi.violations with input as compliant_input
	count(v) == 0
}

# ── Report is a populated object on empty input {} (fail-closed) ──────────────

test_powerbi_report_populated_on_empty_input if {
	r := powerbi.compliance_report with input as {}
	r.product == "Power BI"
	r.baseline == "MS.POWERBI"
	r.controls_evaluated == 8
	r.compliant == false
	r.violation_count == 8
	r.should_violation_count == 8
	r.shall_violation_count == 0
}
