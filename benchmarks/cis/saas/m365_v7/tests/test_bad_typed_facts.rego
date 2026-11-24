# Hand-written for the evidence rule (CIS Microsoft 365 Foundations v7.0.0): a boolean or number fact that arrives
# as another type, as null, or not at all never leaves the report without a failed control. Data-driven over every
# boolean and number leaf of the compliant fixture of test_control_results.rego, one test per input section so no
# single test is long. Settings that Graph returns as strings (the directory settings under entra.lockout,
# entra.group_creation and entra.password_protection) are strings in the fixture and are read as such.
package cis_m365_v7.bad_typed_facts_test

import data.cis_m365_v7.control_results_test.fixture_compliant as F
import rego.v1

_failed(inp) := n if {
	r := data.cis_m365_v7.main.compliance_report with input as inp
	n := r.failed_controls
}

_leaves(section) := [[path, v] |
	walk(F[section], [rel, v])
	_typed(v)
	path := array.concat([section], rel)
]

# the string form of the value (true -> "true", 10 -> "10") and null; two per leaf keeps each test short
_typed(v) if is_boolean(v)

_typed(v) if is_number(v)

_wrong(v) := [sprintf("%v", [v]), null]

# Fixture leaves no rule reads, or whose absence is read as the stricter case:
#   is_app_and_services_trial_enabled  collected with the store flag; 1.3.4 reads the store flag only
#   verified_domains[0].is_initial     absent means a custom domain, which is the one that gets checked
#   attestations[].observed            read through the ledger; covered by test_control_results.rego
_unread := {["admin_center", "user_owned_apps_and_services", "is_app_and_services_trial_enabled"]}

_may_be_absent := {["exchange", "verified_domains", 0, "is_initial"]}

_survivors(section) := {[path, json.marshal(nv)] |
	some [path, v] in _leaves(section)
	not path in _unread
	some nv in _wrong(v)
	_failed(json.patch(F, [{"op": "replace", "path": path, "value": nv}])) == 0
} | {[path, "removed"] |
	some [path, _] in _leaves(section)
	not path in _unread
	not path in _may_be_absent
	_failed(json.patch(F, [{"op": "remove", "path": path}])) == 0
}

test_fixture_is_compliant_and_sections_are_covered if {
	_failed(F) == 0
	covered := {"admin_center", "defender", "entra", "exchange", "fabric", "intune", "purview", "purview_ps", "sharepoint", "teams"}
	object.keys(F) - covered == {"attestations"}
	count([1 | some s in covered; some _ in _leaves(s)]) > 100
}

test_admin_center_facts if count(_survivors("admin_center")) == 0

test_defender_facts if count(_survivors("defender")) == 0

test_entra_facts if count(_survivors("entra")) == 0

test_exchange_facts if count(_survivors("exchange")) == 0

test_fabric_facts if count(_survivors("fabric")) == 0

test_intune_facts if count(_survivors("intune")) == 0

test_purview_facts if count(_survivors("purview")) == 0

test_purview_ps_facts if count(_survivors("purview_ps")) == 0

test_sharepoint_facts if count(_survivors("sharepoint")) == 0

test_teams_facts if count(_survivors("teams")) == 0

# attestations: an observation that is not the boolean true is not an attestation
test_attestation_observed_must_be_boolean_true if {
	every i, _ in F.attestations {
		every nv in ["true", 1, null] {
			_failed(json.patch(F, [{"op": "replace", "path": ["attestations", i, "observed"], "value": nv}])) > 0
		}
	}
}

# Graph directory settings are strings; the numeric form of the same value reads the same
test_directory_settings_read_as_strings_or_numbers if {
	_failed(json.patch(F, [{"op": "replace", "path": "/entra/lockout", "value": {"settings_present": true, "threshold": 10, "duration_seconds": 60}}])) == 0
	_failed(json.patch(F, [{"op": "replace", "path": "/entra/lockout", "value": {"settings_present": true, "threshold": "10", "duration_seconds": "60"}}])) == 0
	_failed(json.patch(F, [{"op": "replace", "path": "/entra/lockout/threshold", "value": "ten"}])) == 1
	_failed(json.patch(F, [{"op": "replace", "path": "/entra/lockout/threshold", "value": "50"}])) == 1
}

# userDeviceQuota is an Int32 in Graph: a string, numeric or not, is not evidence
test_device_quota_must_be_a_number if {
	_failed(json.patch(F, [{"op": "replace", "path": "/entra/device_registration/user_device_quota", "value": "10"}])) == 1
	vs := data.cis_m365_v7.entra.violation with input as json.patch(F, [{"op": "replace", "path": "/entra/device_registration/user_device_quota", "value": "10"}])
	"CIS 5.1.4.2: evidence missing -- entra.device_registration.user_device_quota not collected or not of the expected type (this is not a pass)" in vs
}
