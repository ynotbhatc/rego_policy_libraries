# Tests for pqc.main — PQC Readiness v1.0
#
# Per-rule tests: a fully-compliant nss-profile fixture with exactly one fact
# flipped false, asserting that rule's violation fires. Plus profile-gating
# tests (general must not fire federal/nss rules), data-driven algorithm
# classification tests (vulnerable, planned-migration, hybrid, SHA-1), a
# compliant test, and an empty-input report test.

package pqc.main_test

import rego.v1

import data.pqc.main

# Fully compliant NSS-profile fixture — every fact affirmatively true,
# inventory already on PQC algorithms.
base := {"pqc": {
	"profile": "nss",
	"inventory": {
		"complete": true,
		"refreshed_within_year": true,
		"hndl_data_identified": true,
		"migration_plan_exists": true,
	},
	"crypto_inventory": [
		{"asset": "api-gw", "algorithm": "ML-KEM-1024", "usage": "key_establishment", "pqc_migration_planned": false},
		{"asset": "fw-signer", "algorithm": "ML-DSA-87", "usage": "signature", "pqc_migration_planned": false},
		{"asset": "db", "algorithm": "AES-256", "usage": "symmetric", "pqc_migration_planned": false},
		{"asset": "tls-edge", "algorithm": "X25519MLKEM768", "usage": "key_establishment", "pqc_migration_planned": false},
	],
	"agility": {
		"algorithms_replaceable": true,
		"library_inventory_maintained": true,
		"vendor_roadmaps_tracked": true,
	},
	"federal": {
		"key_establishment_migration_on_track": true,
		"signature_migration_on_track": true,
		"tls_endpoints_support_pqc_kem": true,
		"contractor_fips_pqc_required": true,
	},
	"nss": {
		"sw_fw_signing_cnsa": true,
		"acquisitions_require_cnsa": true,
		"network_equipment_on_track": true,
		"symmetric_cnsa_compliant": true,
	},
}}

# Helper: base with one path flipped false.
flip(path) := json.patch(base, [{"op": "replace", "path": path, "value": false}])

test_compliant_nss if {
	main.compliant with input as base
	count(main.violations) == 0 with input as base
}

# ── Inventory ────────────────────────────────────────────────────────────────

test_inventory_complete if {
	v := main.violations with input as flip("/pqc/inventory/complete")
	count(v) == 1
	some msg in v
	contains(msg, "cryptographic inventory")
}

test_inventory_refreshed if {
	v := main.violations with input as flip("/pqc/inventory/refreshed_within_year")
	count(v) == 1
	some msg in v
	contains(msg, "refreshed")
}

test_hndl_identified if {
	v := main.violations with input as flip("/pqc/inventory/hndl_data_identified")
	count(v) == 1
	some msg in v
	contains(msg, "harvest-now-decrypt-later")
}

test_migration_plan if {
	v := main.violations with input as flip("/pqc/inventory/migration_plan_exists")
	count(v) == 1
	some msg in v
	contains(msg, "migration plan")
}

# ── Agility ──────────────────────────────────────────────────────────────────

test_algorithms_replaceable if {
	v := main.violations with input as flip("/pqc/agility/algorithms_replaceable")
	count(v) == 1
	some msg in v
	contains(msg, "redesign")
}

test_library_inventory if {
	v := main.violations with input as flip("/pqc/agility/library_inventory_maintained")
	count(v) == 1
	some msg in v
	contains(msg, "libraries")
}

test_vendor_roadmaps if {
	v := main.violations with input as flip("/pqc/agility/vendor_roadmaps_tracked")
	count(v) == 1
	some msg in v
	contains(msg, "roadmaps")
}

# ── Federal (EO 14412 / OMB M-26-15) ─────────────────────────────────────────

test_federal_kem_on_track if {
	v := main.violations with input as flip("/pqc/federal/key_establishment_migration_on_track")
	count(v) == 1
	some msg in v
	contains(msg, "2030-12-31")
}

test_federal_sig_on_track if {
	v := main.violations with input as flip("/pqc/federal/signature_migration_on_track")
	count(v) == 1
	some msg in v
	contains(msg, "2031-12-31")
}

test_federal_tls_pqc if {
	v := main.violations with input as flip("/pqc/federal/tls_endpoints_support_pqc_kem")
	count(v) == 1
	some msg in v
	contains(msg, "TLS")
}

test_federal_contractor_flowdown if {
	v := main.violations with input as flip("/pqc/federal/contractor_fips_pqc_required")
	count(v) == 1
	some msg in v
	contains(msg, "contractors")
}

# ── CNSA 2.0 (NSS) ───────────────────────────────────────────────────────────

test_nss_signing if {
	v := main.violations with input as flip("/pqc/nss/sw_fw_signing_cnsa")
	count(v) == 1
	some msg in v
	contains(msg, "ML-DSA-87")
}

test_nss_acquisitions if {
	v := main.violations with input as flip("/pqc/nss/acquisitions_require_cnsa")
	count(v) == 1
	some msg in v
	contains(msg, "2027-01-01")
}

test_nss_network_equipment if {
	v := main.violations with input as flip("/pqc/nss/network_equipment_on_track")
	count(v) == 1
	some msg in v
	contains(msg, "2030")
}

test_nss_symmetric if {
	v := main.violations with input as flip("/pqc/nss/symmetric_cnsa_compliant")
	count(v) == 1
	some msg in v
	contains(msg, "AES-256")
}

# ── Profile gating ───────────────────────────────────────────────────────────

# general profile with federal+nss facts absent: no federal/nss violations.
general_base := {"pqc": object.union(
	object.remove(base.pqc, {"federal", "nss"}),
	{"profile": "general"},
)}

test_general_profile_skips_federal_and_nss if {
	count(main.violations) == 0 with input as general_base
}

# federal profile fires federal checks but not nss checks.
federal_base := {"pqc": object.union(
	object.remove(base.pqc, {"nss"}),
	{"profile": "federal"},
)}

test_federal_profile_skips_nss if {
	count(main.violations) == 0 with input as federal_base
}

test_federal_profile_fires_federal if {
	v := main.violations with input as json.patch(federal_base, [{
		"op": "replace",
		"path": "/pqc/federal/tls_endpoints_support_pqc_kem",
		"value": false,
	}])
	count(v) == 1
}

# ── Data-driven algorithm checks ─────────────────────────────────────────────

test_vulnerable_algorithm_flagged if {
	inp := json.patch(base, [{"op": "add", "path": "/pqc/crypto_inventory/-", "value": {
		"asset": "legacy-vpn",
		"algorithm": "RSA-2048",
		"usage": "key_establishment",
		"pqc_migration_planned": false,
	}}])
	v := main.violations with input as inp
	count(v) == 1
	some msg in v
	contains(msg, "legacy-vpn")
	contains(msg, "RSA-2048")
}

test_vulnerable_with_planned_migration_not_flagged if {
	inp := json.patch(base, [{"op": "add", "path": "/pqc/crypto_inventory/-", "value": {
		"asset": "legacy-vpn",
		"algorithm": "ECDSA-P256",
		"usage": "signature",
		"pqc_migration_planned": true,
	}}])
	count(main.violations) == 0 with input as inp
}

test_hybrid_counts_as_pqc if {
	# X25519MLKEM768 is in the compliant base fixture — no violation.
	count(main.violations) == 0 with input as base
}

test_sha1_flagged if {
	inp := json.patch(base, [{"op": "add", "path": "/pqc/crypto_inventory/-", "value": {
		"asset": "old-ci",
		"algorithm": "SHA-1",
		"usage": "hashing",
		"pqc_migration_planned": false,
	}}])
	v := main.violations with input as inp
	count(v) == 1
	some msg in v
	contains(msg, "broken hash")
}

test_malformed_inventory_row_flagged if {
	inp := json.patch(base, [{"op": "add", "path": "/pqc/crypto_inventory/-", "value": {
		"asset": "mystery-box",
		"algorithm": "RSA-2048",
	}}])
	v := main.violations with input as inp
	count(v) == 1
	some msg in v
	contains(msg, "malformed")
}

test_symmetric_not_flagged_as_vulnerable if {
	# AES-128 symmetric: not a public-key usage, base checks don't flag it.
	inp := json.patch(base, [{"op": "add", "path": "/pqc/crypto_inventory/-", "value": {
		"asset": "cache",
		"algorithm": "AES-128",
		"usage": "symmetric",
		"pqc_migration_planned": false,
	}}])
	count(main.violations) == 0 with input as inp
}

# ── Regression tests (reviewer findings, 2026-10-06) ─────────────────────────

# pqc-01: a non-boolean truthy pqc_migration_planned must NOT suppress the
# vulnerable-algorithm violation.
test_string_migration_planned_still_flagged if {
	inp := json.patch(base, [{"op": "add", "path": "/pqc/crypto_inventory/-", "value": {
		"asset": "legacy-vpn",
		"algorithm": "RSA-2048",
		"usage": "key_establishment",
		"pqc_migration_planned": "no",
	}}])
	v := main.violations with input as inp
	count(v) == 1
	some msg in v
	contains(msg, "RSA-2048")
}

# pqc-02: an unrecognized profile fails closed with an explicit violation.
test_unrecognized_profile_flagged if {
	inp := json.patch(base, [{"op": "replace", "path": "/pqc/profile", "value": "NSS"}])
	v := main.violations with input as inp
	count(v) == 1
	not main.compliant with input as inp
	some msg in v
	contains(msg, "unrecognized profile")
}

# pqc-03: tooling-spelled vulnerable names classify as vulnerable.
test_tooling_spellings_flagged if {
	rows := [
		{"asset": "tls-ffdhe", "algorithm": "ffdhe2048", "usage": "key_establishment", "pqc_migration_planned": false},
		{"asset": "openssl-p256", "algorithm": "prime256v1", "usage": "key_establishment", "pqc_migration_planned": false},
		{"asset": "ssh-ed", "algorithm": "EdDSA", "usage": "signature", "pqc_migration_planned": false},
		{"asset": "bp-cert", "algorithm": "brainpoolP256r1", "usage": "signature", "pqc_migration_planned": false},
	]
	inp := json.patch(base, [{"op": "add", "path": "/pqc/crypto_inventory", "value": rows}])
	v := main.violations with input as inp
	count(v) == 4
}

# Classification-order property: SLH-DSA/LMS/XMSS survive the DSA/EC prefixes.
test_pqc_names_not_misclassified if {
	rows := [
		{"asset": "a1", "algorithm": "SLH-DSA-SHA2-128s", "usage": "signature", "pqc_migration_planned": false},
		{"asset": "a2", "algorithm": "LMS", "usage": "signature", "pqc_migration_planned": false},
		{"asset": "a3", "algorithm": "XMSS", "usage": "signature", "pqc_migration_planned": false},
		{"asset": "a4", "algorithm": "X25519Kyber768Draft00", "usage": "key_establishment", "pqc_migration_planned": false},
	]
	inp := json.patch(base, [{"op": "add", "path": "/pqc/crypto_inventory", "value": rows}])
	count(main.violations) == 0 with input as inp
	r := main.compliance_report with input as inp
	r.inventory_assets_quantum_vulnerable == 0
}

# pqc-04: SHA-1 in its tooling spelling (no hyphen, lowercase) is flagged.
test_sha1_no_hyphen_flagged if {
	inp := json.patch(base, [{"op": "add", "path": "/pqc/crypto_inventory/-", "value": {
		"asset": "old-ci",
		"algorithm": "sha1",
		"usage": "hashing",
		"pqc_migration_planned": false,
	}}])
	v := main.violations with input as inp
	count(v) == 1
	some msg in v
	contains(msg, "broken hash")
}

# pqc-05: a malformed row (wrong asset type) gets ONLY the input-contract
# violation — not a second, garbled algorithm violation.
test_malformed_row_single_violation if {
	inp := json.patch(base, [{"op": "add", "path": "/pqc/crypto_inventory/-", "value": {
		"asset": 42,
		"algorithm": "RSA-2048",
		"usage": "key_establishment",
		"pqc_migration_planned": false,
	}}])
	v := main.violations with input as inp
	count(v) == 1
	some msg in v
	contains(msg, "malformed")
}

# pqc-06: controls_evaluated tracks the active profile.
test_controls_evaluated_by_profile if {
	rg := main.compliance_report with input as general_base
	rg.controls_evaluated == 10
	rf := main.compliance_report with input as federal_base
	rf.controls_evaluated == 14
	rn := main.compliance_report with input as base
	rn.controls_evaluated == 18
}

# F1: a string "false" (truthy non-boolean) must NOT satisfy a boolean check.
test_string_false_fails_closed if {
	inp := json.patch(base, [{"op": "replace", "path": "/pqc/inventory/complete", "value": "false"}])
	v := main.violations with input as inp
	count(v) == 1
	not main.compliant with input as inp
}

# F4: a non-array crypto_inventory is itself a violation, and the report
# must not fabricate an asset count from it.
test_non_array_inventory_flagged if {
	inp := json.patch(base, [{"op": "replace", "path": "/pqc/crypto_inventory", "value": "RSA-2048 on everything"}])
	v := main.violations with input as inp
	count(v) == 1
	some msg in v
	contains(msg, "must be an array")
	r := main.compliance_report with input as inp
	r.inventory_assets_total == 0
}

# F5: ElGamal / Curve25519 spellings and MD5 hashing are flagged.
test_denylist_additions_flagged if {
	rows := [
		{"asset": "kms-legacy", "algorithm": "ElGamal-2048", "usage": "key_establishment", "pqc_migration_planned": false},
		{"asset": "ssh-curve", "algorithm": "Curve25519", "usage": "key_establishment", "pqc_migration_planned": false},
		{"asset": "old-sum", "algorithm": "MD5", "usage": "hashing", "pqc_migration_planned": false},
	]
	inp := json.patch(base, [{"op": "add", "path": "/pqc/crypto_inventory", "value": rows}])
	v := main.violations with input as inp
	count(v) == 3
}

# F6: free-text algorithm annotation cannot substring-match a PQC marker —
# it is malformed, and the asset is not counted as PQC.
test_freetext_algorithm_malformed if {
	inp := json.patch(base, [{"op": "add", "path": "/pqc/crypto_inventory/-", "value": {
		"asset": "annotated",
		"algorithm": "RSA-2048 (ML-KEM planned)",
		"usage": "key_establishment",
		"pqc_migration_planned": false,
	}}])
	v := main.violations with input as inp
	count(v) == 1
	some msg in v
	contains(msg, "malformed")
	r := main.compliance_report with input as inp
	r.inventory_assets_pqc == 3
}

# ── Empty input ──────────────────────────────────────────────────────────────

test_empty_input_fails_closed if {
	not main.compliant with input as {}

	# 7 base boolean controls fire; profile-gated and data-driven do not.
	count(main.violations) == 7 with input as {}
}

test_empty_input_report_populated if {
	r := main.compliance_report with input as {}
	r.compliant == false
	r.violation_count == 7
	r.profile == "general"
	r.inventory_assets_total == 0
}

test_report_counts_inventory if {
	r := main.compliance_report with input as base
	r.inventory_assets_total == 4
	r.inventory_assets_pqc == 3
	r.inventory_assets_quantum_vulnerable == 0
	r.compliant == true
}
