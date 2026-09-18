package scuba_m365.powerplatform_test

import data.scuba_m365.powerplatform
import rego.v1

# Fully compliant Power Platform facts — every SCuBA control satisfied.
compliant_input := {"scuba": {"powerplatform": {
	"environment_creation": {
		"production_restricted_to_admins": true,
		"trial_restricted_to_admins": true,
	},
	"dlp": {
		"default_environment_policy": true,
		"nondefault_environments_covered": true,
	},
	"tenant_isolation": {
		"enabled": true,
		"connection_allowlist": true,
	},
	"apps_csp_enforced": true,
	"power_pages_creation_restricted": true,
	"share_with_everyone_disabled": true,
}}}

# Helper: does any violation message contain the given control ID?
fires(msgs, id) if {
	some m in msgs
	contains(m, id)
}

# ── One test per violation rule ──────────────────────────────────────────────

test_ms_powerplatform_1_1_production_not_restricted if {
	i := json.patch(compliant_input, [{"op": "replace", "path": "/scuba/powerplatform/environment_creation/production_restricted_to_admins", "value": false}])
	fires(powerplatform.violations, "MS.POWERPLATFORM.1.1v1") with input as i
}

test_ms_powerplatform_1_2_trial_not_restricted if {
	i := json.patch(compliant_input, [{"op": "replace", "path": "/scuba/powerplatform/environment_creation/trial_restricted_to_admins", "value": false}])
	fires(powerplatform.violations, "MS.POWERPLATFORM.1.2v1") with input as i
}

test_ms_powerplatform_2_1_no_default_dlp if {
	i := json.patch(compliant_input, [{"op": "replace", "path": "/scuba/powerplatform/dlp/default_environment_policy", "value": false}])
	fires(powerplatform.violations, "MS.POWERPLATFORM.2.1v1") with input as i
}

test_ms_powerplatform_2_2_nondefault_uncovered if {
	i := json.patch(compliant_input, [{"op": "replace", "path": "/scuba/powerplatform/dlp/nondefault_environments_covered", "value": false}])
	fires(powerplatform.violations, "MS.POWERPLATFORM.2.2v1") with input as i
}

test_ms_powerplatform_3_1_tenant_isolation_disabled if {
	i := json.patch(compliant_input, [{"op": "replace", "path": "/scuba/powerplatform/tenant_isolation/enabled", "value": false}])
	fires(powerplatform.violations, "MS.POWERPLATFORM.3.1v1") with input as i
}

test_ms_powerplatform_3_2_no_connection_allowlist if {
	i := json.patch(compliant_input, [{"op": "replace", "path": "/scuba/powerplatform/tenant_isolation/connection_allowlist", "value": false}])
	fires(powerplatform.violations, "MS.POWERPLATFORM.3.2v1") with input as i
}

test_ms_powerplatform_4_1_apps_csp_not_enforced if {
	i := json.patch(compliant_input, [{"op": "replace", "path": "/scuba/powerplatform/apps_csp_enforced", "value": false}])
	fires(powerplatform.violations, "MS.POWERPLATFORM.4.1v1") with input as i
}

test_ms_powerplatform_5_1_power_pages_unrestricted if {
	i := json.patch(compliant_input, [{"op": "replace", "path": "/scuba/powerplatform/power_pages_creation_restricted", "value": false}])
	fires(powerplatform.violations, "MS.POWERPLATFORM.5.1v1") with input as i
}

test_ms_powerplatform_6_1_share_with_everyone_enabled if {
	i := json.patch(compliant_input, [{"op": "replace", "path": "/scuba/powerplatform/share_with_everyone_disabled", "value": false}])
	fires(powerplatform.violations, "MS.POWERPLATFORM.6.1v1") with input as i
}

# ── Compliant input: fully satisfied facts produce zero violations ───────────

test_compliant_input_no_violations if {
	count(powerplatform.violations) == 0 with input as compliant_input
	powerplatform.compliant == true with input as compliant_input
}

# ── Report shape: empty input yields a populated report object ────────────────

test_report_populated_on_empty_input if {
	r := powerplatform.compliance_report with input as {}
	r.product == "Power Platform"
	r.baseline == "MS.POWERPLATFORM"
	r.controls_evaluated == 9
	r.compliant == false
	r.violation_count == 9
	count(r.violations) == 9
}
