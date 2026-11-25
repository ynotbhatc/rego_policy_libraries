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

# Each section's leaves are swept in slices (leaf index modulo the section's slice count), one test per slice, so that
# no test runs long enough to meet the suite's per-test timeout on the oldest supported OPA. Every leaf is in exactly
# one slice; test_the_slices_cover_every_leaf checks it.
_slices := {"admin_center": 4, "defender": 8, "entra": 10, "exchange": 8, "fabric": 5, "intune": 1, "purview": 1, "purview_ps": 1, "sharepoint": 3, "teams": 7}

_slice(xs, i, n) := [x | some j, x in xs; j % n == i]

_survivors(section) := _survivors_in(section, 0, 1)

_survivors_in(section, i, n) := {[path, json.marshal(nv)] |
	some [path, v] in _slice(_leaves(section), i, n)
	not path in _unread
	some nv in _wrong(v)
	_failed(json.patch(F, [{"op": "replace", "path": path, "value": nv}])) == 0
} | {[path, "removed"] |
	some [path, _] in _slice(_leaves(section), i, n)
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

# every section's slices are exactly its leaves
test_the_slices_cover_every_leaf if {
	every section, n in _slices {
		sum([count(_slice(_leaves(section), i, n)) | some i in numbers.range(0, n - 1)]) == count(_leaves(section))
		every j, leaf in _leaves(section) {
			leaf in _slice(_leaves(section), j % n, n)
		}
	}
	count(_slices) == 10
}

test_admin_center_facts_slice_0 if count(_survivors_in("admin_center", 0, 4)) == 0

test_admin_center_facts_slice_1 if count(_survivors_in("admin_center", 1, 4)) == 0

test_admin_center_facts_slice_2 if count(_survivors_in("admin_center", 2, 4)) == 0

test_admin_center_facts_slice_3 if count(_survivors_in("admin_center", 3, 4)) == 0

test_defender_facts_slice_0 if count(_survivors_in("defender", 0, 8)) == 0

test_defender_facts_slice_1 if count(_survivors_in("defender", 1, 8)) == 0

test_defender_facts_slice_2 if count(_survivors_in("defender", 2, 8)) == 0

test_defender_facts_slice_3 if count(_survivors_in("defender", 3, 8)) == 0

test_defender_facts_slice_4 if count(_survivors_in("defender", 4, 8)) == 0

test_defender_facts_slice_5 if count(_survivors_in("defender", 5, 8)) == 0

test_defender_facts_slice_6 if count(_survivors_in("defender", 6, 8)) == 0

test_defender_facts_slice_7 if count(_survivors_in("defender", 7, 8)) == 0

test_entra_facts_slice_0 if count(_survivors_in("entra", 0, 10)) == 0

test_entra_facts_slice_1 if count(_survivors_in("entra", 1, 10)) == 0

test_entra_facts_slice_2 if count(_survivors_in("entra", 2, 10)) == 0

test_entra_facts_slice_3 if count(_survivors_in("entra", 3, 10)) == 0

test_entra_facts_slice_4 if count(_survivors_in("entra", 4, 10)) == 0

test_entra_facts_slice_5 if count(_survivors_in("entra", 5, 10)) == 0

test_entra_facts_slice_6 if count(_survivors_in("entra", 6, 10)) == 0

test_entra_facts_slice_7 if count(_survivors_in("entra", 7, 10)) == 0

test_entra_facts_slice_8 if count(_survivors_in("entra", 8, 10)) == 0

test_entra_facts_slice_9 if count(_survivors_in("entra", 9, 10)) == 0

test_exchange_facts_slice_0 if count(_survivors_in("exchange", 0, 8)) == 0

test_exchange_facts_slice_1 if count(_survivors_in("exchange", 1, 8)) == 0

test_exchange_facts_slice_2 if count(_survivors_in("exchange", 2, 8)) == 0

test_exchange_facts_slice_3 if count(_survivors_in("exchange", 3, 8)) == 0

test_exchange_facts_slice_4 if count(_survivors_in("exchange", 4, 8)) == 0

test_exchange_facts_slice_5 if count(_survivors_in("exchange", 5, 8)) == 0

test_exchange_facts_slice_6 if count(_survivors_in("exchange", 6, 8)) == 0

test_exchange_facts_slice_7 if count(_survivors_in("exchange", 7, 8)) == 0

test_fabric_facts_slice_0 if count(_survivors_in("fabric", 0, 5)) == 0

test_fabric_facts_slice_1 if count(_survivors_in("fabric", 1, 5)) == 0

test_fabric_facts_slice_2 if count(_survivors_in("fabric", 2, 5)) == 0

test_fabric_facts_slice_3 if count(_survivors_in("fabric", 3, 5)) == 0

test_fabric_facts_slice_4 if count(_survivors_in("fabric", 4, 5)) == 0

test_intune_facts if count(_survivors("intune")) == 0

test_purview_facts if count(_survivors("purview")) == 0

test_purview_ps_facts if count(_survivors("purview_ps")) == 0

test_sharepoint_facts_slice_0 if count(_survivors_in("sharepoint", 0, 3)) == 0

test_sharepoint_facts_slice_1 if count(_survivors_in("sharepoint", 1, 3)) == 0

test_sharepoint_facts_slice_2 if count(_survivors_in("sharepoint", 2, 3)) == 0

test_teams_facts_slice_0 if count(_survivors_in("teams", 0, 7)) == 0

test_teams_facts_slice_1 if count(_survivors_in("teams", 1, 7)) == 0

test_teams_facts_slice_2 if count(_survivors_in("teams", 2, 7)) == 0

test_teams_facts_slice_3 if count(_survivors_in("teams", 3, 7)) == 0

test_teams_facts_slice_4 if count(_survivors_in("teams", 4, 7)) == 0

test_teams_facts_slice_5 if count(_survivors_in("teams", 5, 7)) == 0

test_teams_facts_slice_6 if count(_survivors_in("teams", 6, 7)) == 0

# attestations: an observation that is not the boolean true is not an attestation
# the attestations are checked in 6 slices (index modulo 6): three evaluations per attestation
_attestation_slice(k) := [i | some i, _ in F.attestations; i % 6 == k]

test_the_attestation_slices_cover_every_attestation if {
	sum([count(_attestation_slice(k)) | some k in numbers.range(0, 5)]) == count(F.attestations)
	every i, _ in F.attestations {
		i in _attestation_slice(i % 6)
	}
}

test_attestation_observed_must_be_boolean_true_slice_0 if {
	every i in _attestation_slice(0) {
		every nv in ["true", 1, null] {
			_failed(json.patch(F, [{"op": "replace", "path": ["attestations", i, "observed"], "value": nv}])) > 0
		}
	}
}

test_attestation_observed_must_be_boolean_true_slice_1 if {
	every i in _attestation_slice(1) {
		every nv in ["true", 1, null] {
			_failed(json.patch(F, [{"op": "replace", "path": ["attestations", i, "observed"], "value": nv}])) > 0
		}
	}
}

test_attestation_observed_must_be_boolean_true_slice_2 if {
	every i in _attestation_slice(2) {
		every nv in ["true", 1, null] {
			_failed(json.patch(F, [{"op": "replace", "path": ["attestations", i, "observed"], "value": nv}])) > 0
		}
	}
}

test_attestation_observed_must_be_boolean_true_slice_3 if {
	every i in _attestation_slice(3) {
		every nv in ["true", 1, null] {
			_failed(json.patch(F, [{"op": "replace", "path": ["attestations", i, "observed"], "value": nv}])) > 0
		}
	}
}

test_attestation_observed_must_be_boolean_true_slice_4 if {
	every i in _attestation_slice(4) {
		every nv in ["true", 1, null] {
			_failed(json.patch(F, [{"op": "replace", "path": ["attestations", i, "observed"], "value": nv}])) > 0
		}
	}
}

test_attestation_observed_must_be_boolean_true_slice_5 if {
	every i in _attestation_slice(5) {
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
