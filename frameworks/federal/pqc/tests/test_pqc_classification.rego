# Tests for pqc.main inventory evidence and algorithm classification —
# external audit 2026-11-17, finding 1 (omitted inventory reported compliant;
# "Dilithium3" classified as neither PQC nor vulnerable).

package pqc.classification_test

import rego.v1

import data.pqc.main

# general profile, every inventory and agility boolean true.
attested := {"pqc": {
	"profile": "general",
	"inventory": {
		"complete": true,
		"refreshed_within_year": true,
		"hndl_data_identified": true,
		"migration_plan_exists": true,
	},
	"agility": {
		"algorithms_replaceable": true,
		"library_inventory_maintained": true,
		"vendor_roadmaps_tracked": true,
	},
}}

with_inv(rows) := json.patch(attested, [{"op": "add", "path": "/pqc/crypto_inventory", "value": rows}])

row(asset, alg, usage, planned) := {"asset": asset, "algorithm": alg, "usage": usage, "pqc_migration_planned": planned}

ok_row := row("api-gw", "ML-KEM-768", "key_establishment", false)

# ── Inventory evidence ───────────────────────────────────────────────────────

# Reviewer's case 1: attestations true, no crypto_inventory.
test_missing_inventory_is_evidence_missing if {
	r := main.compliance_report with input as attested
	r.compliant == false
	r.violations == {"PQC Evidence missing — input.pqc.crypto_inventory not collected (no cryptographic asset was classified; the data-driven algorithm checks were NOT evaluated)"}
}

test_null_inventory_is_evidence_missing if {
	v := main.violations with input as with_inv(null)
	count(v) == 1
	some msg in v
	contains(msg, "input.pqc.crypto_inventory not collected")
}

test_empty_inventory_is_a_finding if {
	r := main.compliance_report with input as with_inv([])
	r.compliant == false
	count(r.violations) == 1
	some msg in r.violations
	contains(msg, "input.pqc.crypto_inventory is empty")
}

test_object_inventory_is_contract_violation_only if {
	v := main.violations with input as with_inv({"asset": "x"})
	count(v) == 1
	some msg in v
	contains(msg, "must be an array")
}

test_one_pqc_row_is_compliant if {
	r := main.compliance_report with input as with_inv([ok_row])
	r.compliant == true
	count(r.violations) == 0
}

# ── Reviewer's case 2: Dilithium3 ────────────────────────────────────────────

test_dilithium3_classified_post_quantum_pre_standard if {
	r := main.compliance_report with input as with_inv([row("signer", "Dilithium3", "signature", false)])
	r.inventory_classification == [{"asset": "signer", "algorithm": "Dilithium3", "class": "post_quantum"}]
	r.inventory_assets_pqc == 1
	r.inventory_assets_pqc_pre_standard == 1
	r.inventory_assets_quantum_vulnerable == 0
	r.inventory_assets_unrecognised == 0
	r.compliant == true
}

# ── Exact classification table ───────────────────────────────────────────────

expected := {
	# FIPS 203/204/205, SP 800-208
	"ML-KEM-512": "post_quantum",
	"ml_kem_1024": "post_quantum",
	"ML-DSA-44": "post_quantum",
	"id-ml-dsa-65": "post_quantum",
	"HashML-DSA-87": "post_quantum",
	"HashSLH-DSA-SHA2-256s": "post_quantum",
	"SLH-DSA-SHA2-128s": "post_quantum",
	"SLH-DSA-SHAKE-256f": "post_quantum",
	"LMS_SHA256_M32_H10": "post_quantum",
	"HSS/LMS": "post_quantum",
	"XMSS": "post_quantum",
	"XMSS^MT": "post_quantum",
	# pre-standard names
	"Kyber768": "post_quantum",
	"CRYSTALS-Kyber-1024": "post_quantum",
	"Dilithium2": "post_quantum",
	"Dilithium5": "post_quantum",
	"SPHINCS+-SHA2-128s-simple": "post_quantum",
	# selected, FIPS pending
	"FN-DSA-512": "post_quantum",
	"Falcon-1024": "post_quantum",
	"HQC-256": "post_quantum",
	# hybrids
	"X25519MLKEM768": "hybrid",
	"SecP256r1MLKEM768": "hybrid",
	"SecP384r1MLKEM1024": "hybrid",
	"X25519Kyber768Draft00": "hybrid",
	"mlkem768x25519-sha256": "hybrid",
	# quantum-vulnerable, in every spelling
	"RSASSA-PSS": "quantum_vulnerable",
	"rsassaPss": "quantum_vulnerable",
	"rsa2048": "quantum_vulnerable",
	"Rsa_2048": "quantum_vulnerable",
	"RSA-unknown": "quantum_vulnerable",
	"sha256WithRSAEncryption": "quantum_vulnerable",
	"ecdsa-p256": "quantum_vulnerable",
	"ECDSA-prime256v1": "quantum_vulnerable",
	"ecdsa-with-SHA256": "quantum_vulnerable",
	"ecdh-sha2-nistp256": "quantum_vulnerable",
	"curve25519-sha256@libssh.org": "quantum_vulnerable",
	"DH-group-exchange-sha256": "quantum_vulnerable",
	"ffdhe2048": "quantum_vulnerable",
	"ECMQV": "quantum_vulnerable",
	"Ed25519": "quantum_vulnerable",
	"ED25519-SK": "quantum_vulnerable",
	"Ed448": "quantum_vulnerable",
	"X448": "quantum_vulnerable",
	"DSA-1024": "quantum_vulnerable",
	"secp384r1": "quantum_vulnerable",
	"brainpoolP256r1": "quantum_vulnerable",
	"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256": "quantum_vulnerable",
	# symmetric and hashes
	"AES-128": "symmetric_or_hash",
	"AES-256-GCM": "symmetric_or_hash",
	"Ascon-AEAD128": "symmetric_or_hash",
	"TLS_AES_256_GCM_SHA384": "symmetric_or_hash",
	"SHA-256": "symmetric_or_hash",
	"SHA-512/256": "symmetric_or_hash",
	"SHA-512/224": "symmetric_or_hash",
	"SHA3-224": "symmetric_or_hash",
	"SHA3-512": "symmetric_or_hash",
	"SHAKE128": "symmetric_or_hash",
	"3DES": "symmetric_or_hash",
	# unrecognised: typo parameter set, annotation glued on, filler only,
	# and algorithms the cited NIST guidance does not assess
	"ML-KEM-786": "unrecognised",
	"HashML-KEM-768": "unrecognised",
	"RSA2048PLANNED": "unrecognised",
	"GCM": "unrecognised",
	"unknown": "unrecognised",
	"ChaCha20-Poly1305": "unrecognised",
	"sntrup761x25519-sha512@openssh.com": "unrecognised",
	"": "unrecognised",
}

# Classified through the public report (inventory_classification), one row
# per name, so the assertion is on what a consumer of the report sees.
classified := {c.algorithm: c.class |
	rows := [row(sprintf("a%v", [i]), alg, "signature", true) | some i, alg in sort(object.keys(expected))]
	r := main.compliance_report with input as with_inv(rows)
	some c in r.inventory_classification
}

test_classification_table if {
	classified == expected
}

# A PQC name must never count as quantum-vulnerable and vice versa: the
# report's vulnerable count equals exactly the names expected vulnerable.
test_no_pqc_name_misread_as_vulnerable if {
	rows := [row(sprintf("a%v", [i]), alg, "signature", true) | some i, alg in sort(object.keys(expected))]
	r := main.compliance_report with input as with_inv(rows)
	r.inventory_assets_quantum_vulnerable == count({alg | some alg, cls in expected; cls == "quantum_vulnerable"})
	r.inventory_assets_pqc == count({alg | some alg, cls in expected; cls in {"post_quantum", "hybrid"}})
}

# ── Violations per class ─────────────────────────────────────────────────────

test_unrecognised_algorithm_names_the_asset if {
	r := main.compliance_report with input as with_inv([ok_row, row("mystery", "Dilithium-3x", "signature", true)])
	r.compliant == false
	count(r.violations) == 1
	some msg in r.violations
	contains(msg, "Unrecognised algorithm")
	contains(msg, "'mystery'")
	contains(msg, "'Dilithium-3x'")
	r.inventory_assets_unrecognised == 1
}

test_vulnerable_flagged_whatever_the_usage if {
	v := main.violations with input as with_inv([row("mislabelled", "RSA-2048", "symmetric", false)])
	count(v) == 1
	some msg in v
	contains(msg, "quantum-vulnerable algorithm 'RSA-2048'")
}

# Reviewed, not changed: IR 8547 §4.1.1–4.1.2 allow continued use while
# migrating, so a recorded migration clears a vulnerable row.
test_vulnerable_with_planned_migration_passes if {
	r := main.compliance_report with input as with_inv([row("legacy-vpn", "RSA-2048", "key_establishment", true)])
	r.compliant == true
	r.inventory_assets_quantum_vulnerable == 1
}

test_hybrid_not_flagged if {
	r := main.compliance_report with input as with_inv([row("edge", "X25519MLKEM768", "key_establishment", false)])
	r.compliant == true
	r.inventory_assets_hybrid == 1
	r.inventory_assets_pqc == 1
	r.inventory_assets_quantum_vulnerable == 0
}

test_legacy_112_flagged_without_plan if {
	v := main.violations with input as with_inv([ok_row, row("old-sig", "SHA-224", "hashing", false)])
	count(v) == 1
	some msg in v
	contains(msg, "112-bit")
	contains(msg, "'old-sig'")
}

test_legacy_112_cleared_by_plan if {
	count(main.violations) == 0 with input as with_inv([ok_row, row("old-sig", "SHA-224", "hashing", true)])
}

# TDEA encryption is already disallowed (SP 800-131A Rev. 2): a plan does not clear it.
test_tdea_flagged_even_with_plan if {
	v := main.violations with input as with_inv([ok_row, row("old-enc", "3DES", "symmetric", true)])
	count(v) == 1
	some msg in v
	contains(msg, "TDEA")
	contains(msg, "'old-enc'")
}

test_sha1_in_kex_flagged_even_with_plan if {
	v := main.violations with input as with_inv([ok_row, row("host:sshd", "DH-group14-sha1", "key_establishment", true)])
	count(v) == 1
	some msg in v
	contains(msg, "SHA-1")
	contains(msg, "deprecated")
}

test_not_approved_primitive_flagged if {
	v := main.violations with input as with_inv([ok_row, row("legacy-db", "DES", "symmetric", true)])
	count(v) == 1
	some msg in v
	contains(msg, "not NIST-approved")
}

test_strong_symmetric_and_hash_pass if {
	rows := [ok_row, row("db", "AES-256", "symmetric", false), row("ci", "SHA-384", "hashing", false)]
	r := main.compliance_report with input as with_inv(rows)
	r.compliant == true
	r.inventory_assets_symmetric_or_hash == 2
}

test_pending_standard_counted_not_flagged if {
	rows := [row("s1", "FN-DSA-512", "signature", false), row("k1", "HQC-128", "key_establishment", false)]
	r := main.compliance_report with input as with_inv(rows)
	r.compliant == true
	r.inventory_assets_pqc_pending_standard == 2
	r.inventory_assets_pqc == 2
}
