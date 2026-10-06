# Tests for the second amendment's final tranche (enforceable 2025-11-01).

package ny_dfs.main_tranche_test

import rego.v1

import data.ny_dfs.main

test_universal_mfa_missing_flagged if {
	inp := {"mfa": {
		"remote_access": {"enforced": true},
		"third_party_access": {"enforced": true},
		"privileged_accounts": {"enforced": true},
		"all_individuals_all_systems": {"enforced": false},
	}}
	v := main.violations with input as inp
	count([m | some m in v; contains(m, "all individuals accessing any information system")]) == 1
}

test_universal_mfa_satisfied if {
	inp := {"mfa": {"all_individuals_all_systems": {"enforced": true}}}
	v := main.violations with input as inp
	count([m | some m in v; contains(m, "all individuals accessing any information system")]) == 0
}

test_ciso_compensating_controls_exception if {
	inp := {"mfa": {
		"all_individuals_all_systems": {"enforced": false},
		"ciso_approved_compensating_controls": {"documented": true},
	}}
	v := main.violations with input as inp
	count([m | some m in v; contains(m, "all individuals accessing any information system")]) == 0
}

test_asset_inventory_missing_flagged if {
	v := main.violations with input as {}
	count([m | some m in v; contains(m, "500.13(a)"); contains(m, "not maintained")]) == 1
}

test_asset_inventory_fields_flagged if {
	inp := {"asset_inventory": {"maintained": true, "tracks_required_fields": false}}
	v := main.violations with input as inp
	count([m | some m in v; contains(m, "recovery time objectives")]) == 1
}

test_asset_inventory_complete if {
	inp := {"asset_inventory": {"maintained": true, "tracks_required_fields": true}}
	v := main.violations with input as inp
	count([m | some m in v; contains(m, "500.13(a)")]) == 0
}

test_string_true_fails_closed if {
	inp := {"asset_inventory": {"maintained": "true", "tracks_required_fields": true}}
	v := main.violations with input as inp
	count([m | some m in v; contains(m, "500.13(a)"); contains(m, "not maintained")]) == 1
}
