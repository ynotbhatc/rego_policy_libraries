package governance.geisa.api_test

import rego.v1

import data.governance.geisa.api

# ─── Fully compliant baseline input ──────────────────────────────────────────
# applicationId "com.example.grid" →
#   pub topic: geisa/api/platform/discovery/req/com.example.grid
#   sub topic: geisa/api/platform/discovery/rsp/com.example.grid

compliant_input := {
	"manifest": {
		"applicationId": "com.example.grid",
		"geisa": {"uses": ["platform-discovery"]},
		"permissions": {"mqtt": {
			"publish": ["geisa/api/platform/discovery/req/com.example.grid"],
			"subscribe": ["geisa/api/platform/discovery/rsp/com.example.grid"],
		}},
	},
	"discovery_response": {
		"status_code": 1,
		"geisa_version": {"major": 1, "minor": 0, "patch": 0},
		"pillars": {"api": true},
	},
}

# ─── Compliant path: nothing fires ───────────────────────────────────────────

test_compliant_input_no_violations if {
	count(api.violations) == 0 with input as compliant_input
	api.compliant with input as compliant_input
}

# ─── Violation 1: discovery response missing / not an object ─────────────────

# discovery_response present but not an object. An entirely absent field is
# `undefined`, and `not is_object(undefined)` is itself undefined — the rule
# only fires on a present, non-object value.
test_discovery_response_not_object if {
	test_input := json.patch(compliant_input, [{"op": "replace", "path": "/discovery_response", "value": "not-an-object"}])
	api.violations["API: platform discovery response missing or not an object"] with input as test_input
	count(api.violations) == 1 with input as test_input
	not api.compliant with input as test_input
}

# ─── Violation 2: status_code must be 1 ──────────────────────────────────────

test_status_code_not_ok if {
	test_input := json.patch(compliant_input, [{"op": "replace", "path": "/discovery_response/status_code", "value": 2}])
	api.violations["API: platform discovery status_code must be 1 (OK), got 2"] with input as test_input
	count(api.violations) == 1 with input as test_input
}

# ─── Violation 3: GEISA version must be >= 1.0 ───────────────────────────────

test_geisa_version_too_low if {
	test_input := json.patch(compliant_input, [{"op": "replace", "path": "/discovery_response/geisa_version/major", "value": 0}])
	api.violations["API: GEISA version must be >= 1.0"] with input as test_input
	count(api.violations) == 1 with input as test_input
}

# ─── Violation 4: pillars.api must be true ───────────────────────────────────

test_pillars_api_false if {
	test_input := json.patch(compliant_input, [{"op": "replace", "path": "/discovery_response/pillars/api", "value": false}])
	api.violations["API: discovery_response.pillars.api must be true"] with input as test_input
	count(api.violations) == 1 with input as test_input
}

# ─── Violation 5: uses must include 'platform-discovery' ─────────────────────

test_uses_missing_platform_discovery if {
	test_input := json.patch(compliant_input, [{"op": "replace", "path": "/manifest/geisa/uses", "value": ["metrics"]}])
	api.violations["API: manifest.geisa.uses must include 'platform-discovery'"] with input as test_input
	count(api.violations) == 1 with input as test_input
}

# ─── Violation 6: manifest must declare publish topic ────────────────────────

test_missing_publish_topic if {
	test_input := json.patch(compliant_input, [{"op": "replace", "path": "/manifest/permissions/mqtt/publish", "value": []}])
	api.violations["API: manifest must declare publish topic 'geisa/api/platform/discovery/req/com.example.grid'"] with input as test_input
	count(api.violations) == 1 with input as test_input
}

# ─── Violation 7: manifest must declare subscribe topic ──────────────────────

test_missing_subscribe_topic if {
	test_input := json.patch(compliant_input, [{"op": "replace", "path": "/manifest/permissions/mqtt/subscribe", "value": []}])
	api.violations["API: manifest must declare subscribe topic 'geisa/api/platform/discovery/rsp/com.example.grid'"] with input as test_input
	count(api.violations) == 1 with input as test_input
}

# ─── Violation 8: applicationId must be set (string) ─────────────────────────
# Non-string applicationId. mqtt permissions omitted so is_array() gates keep
# the publish/subscribe rules silent, isolating this violation.

test_application_id_not_string if {
	test_input := {
		"manifest": {
			"applicationId": 123,
			"geisa": {"uses": ["platform-discovery"]},
		},
		"discovery_response": {
			"status_code": 1,
			"geisa_version": {"major": 1},
			"pillars": {"api": true},
		},
	}
	api.violations["API: manifest.applicationId must be set"] with input as test_input
	count(api.violations) == 1 with input as test_input
}

# ─── Violation 9: applicationId must be non-empty ────────────────────────────
# Empty string applicationId. mqtt permissions omitted to isolate this rule.

test_application_id_empty if {
	test_input := {
		"manifest": {
			"applicationId": "",
			"geisa": {"uses": ["platform-discovery"]},
		},
		"discovery_response": {
			"status_code": 1,
			"geisa_version": {"major": 1},
			"pillars": {"api": true},
		},
	}
	api.violations["API: manifest.applicationId must be non-empty"] with input as test_input
	count(api.violations) == 1 with input as test_input
}

# ─── Report object is populated even on empty input ──────────────────────────

# On empty input {} no violation rule fires (their `is_object`/`is_array` gates
# are all undefined), so the report is still a fully populated object built from
# defaulted helpers — with app_id/geisa_version defaulted to "unknown".
test_compliance_report_populated_on_empty_input if {
	report := api.compliance_report with input as {}
	is_object(report)
	count(report) == 7
	report.pillar == "API"
	report.app_id == "unknown"
	report.geisa_version == "unknown"
	report.platform_discovery_status == 0
}
