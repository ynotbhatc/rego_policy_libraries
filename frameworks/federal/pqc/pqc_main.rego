# Post-Quantum Cryptography (PQC) Readiness — v1.0
#
# Sources (all verified 2026-10-06):
#   FIPS 203 (ML-KEM), FIPS 204 (ML-DSA), FIPS 205 (SLH-DSA) — final Aug 2024
#   NIST SP 800-208 (LMS/XMSS stateful hash-based signatures, firmware signing)
#   NIST IR 8547 (Transition to PQC Standards — DRAFT, ipd Nov 2024):
#     112-bit-security public-key algorithms deprecated after 2030,
#     disallowed after 2035
#   EO 14412 "Securing the Nation Against Advanced Cryptographic Attacks"
#     (2026-06-22) + OMB M-26-15: high-value/high-impact federal systems
#     migrate key establishment to PQC by 2030-12-31 and digital signatures
#     by 2031-12-31; FAR rule to bind covered contractors to FIPS PQC
#   NSA CNSA 2.0 (National Security Systems): ML-KEM-1024, ML-DSA-87,
#     AES-256, SHA-384/512; new NSS acquisitions must support CNSA 2.0
#     from 2027-01-01; networking equipment exclusive-use by 2030; full
#     migration 2033 (NSM-10 backstop 2035)
#
# Spine context (public crosswalk, docs/CONTROL_CORRELATION_PATTERN.md):
# PQC obligations land on the 800-53 cryptographic controls the spine
# already carries — SC-8, SC-12, SC-13, SC-28, IA-5 — so a PQC assessment
# here discharges the quantum-readiness dimension of those controls for
# every framework that inherits them. The ISO 27001 cryptography module's
# `quantum_resistance_planned` (frameworks/management/iso27001/) is the
# shallow self-attestation hook; this module is the deep, algorithm-level
# assessment behind it.
#
# Query: POST /v1/data/pqc/main/compliance_report
#
# Fail-closed: every boolean fact must be affirmatively true. Empty input
# yields every base violation (profile-gated sections require the profile).
#
# Input contract — input.pqc.*
#
#   profile                      — "general" | "federal" | "nss"
#     general : inventory, algorithm, and agility checks only
#     federal : + EO 14412 / OMB M-26-15 / NIST IR 8547 timeline checks
#     nss     : + all federal checks + CNSA 2.0 checks
#
#   inventory.*                  — source: CBOM/discovery tooling + program records
#     complete                     bool — automated cryptographic inventory
#                                  covers systems, protocols, libraries, certs
#     refreshed_within_year        bool
#     hndl_data_identified         bool — long-confidentiality-lifetime data
#                                  flagged for harvest-now-decrypt-later risk
#     migration_plan_exists        bool — prioritized, milestoned plan
#
#   crypto_inventory             — list of asset records (data-driven checks):
#     [ { "asset":              "<name>",
#         "algorithm":          "RSA-2048" | "ECDSA-P256" | "ML-KEM-768" | ...,
#         "usage":              "key_establishment" | "signature" |
#                               "symmetric" | "hashing",
#         "pqc_migration_planned": bool    # only consulted for vulnerable algs;
#                                          # must be the boolean true to count
#       }, ... ]
#
#   agility.*                    — source: architecture review
#     algorithms_replaceable       bool — crypto swappable without redesign
#     library_inventory_maintained bool
#     vendor_roadmaps_tracked      bool
#
#   federal.*                    — profile "federal"/"nss" only; program records
#     key_establishment_migration_on_track   bool — PQC KEM by 2030-12-31
#     signature_migration_on_track           bool — PQC signatures by 2031-12-31
#     tls_endpoints_support_pqc_kem          bool — hybrid acceptable
#     contractor_fips_pqc_required           bool — FIPS PQC flowed to vendors
#
#   nss.*                        — profile "nss" only; program records
#     sw_fw_signing_cnsa             bool — ML-DSA-87 / LMS / XMSS signing
#     acquisitions_require_cnsa      bool — CNSA 2.0 in new procurements
#     network_equipment_on_track     bool — VPN/router exclusive-use by 2030
#     symmetric_cnsa_compliant       bool — AES-256, SHA-384/512 only

# METADATA
# title: "Post-Quantum Cryptography (PQC) Readiness — v1.0"
# custom:
#   class: compliance
#   framework: pqc
#   source: nist
#   domains: [us-federal, cryptography]
package pqc.main

import rego.v1

default compliant := false

compliant if {
	count(violations) == 0
}

# ── Algorithm classification ─────────────────────────────────────────────────

# Quantum-vulnerable public-key algorithms (Shor-breakable): RSA, ECC
# (ECDSA/ECDH/EdDSA), finite-field DH/DSA — NIST IR 8547 scope.
# Covers both NIST-document spellings and the names scan/TLS tooling emits
# (ffdhe* RFC 7919 groups, prime256v1, brainpool*, EdDSA).
_vulnerable_prefixes := [
	"RSA", "ECDSA", "ECDH", "ECC", "DH", "DSA", "EDDSA", "ED25519", "ED448",
	"X25519", "X448", "SECP", "SECT", "P-256", "P-384", "P-521", "P256",
	"P384", "P521", "FFDHE", "PRIME192", "PRIME256", "BRAINPOOL", "ELGAMAL",
	"CURVE25519", "CURVE448",
]

# FIPS-approved PQC + stateful hash-based signatures + hybrids that embed
# an approved PQC component (hybrid counts as HNDL-protected). KYBER covers
# the pre-standard hybrid groups (e.g. X25519Kyber768Draft00) still deployed;
# they are HNDL-protected, though migration to the FIPS-final groups is due.
_pqc_markers := ["ML-KEM", "ML-DSA", "SLH-DSA", "LMS", "XMSS", "MLKEM", "MLDSA", "SLHDSA", "KYBER"]

# Broken/disallowed hashes, matched on the hyphen-stripped spelling so both
# the NIST form ("SHA-1") and the tooling form ("sha1") are caught.
_broken_hashes := {"SHA1", "MD5", "MD4", "MD2"}

_norm(alg) := upper(alg)

_is_pqc(alg) if {
	some m in _pqc_markers
	contains(_norm(alg), m)
}

_is_vulnerable(alg) if {
	not _is_pqc(alg)
	some p in _vulnerable_prefixes
	startswith(_norm(alg), p)
}

# Profile gates — federal checks apply to "federal" and "nss";
# CNSA 2.0 checks apply to "nss" only. An absent profile means "general";
# a present-but-unrecognized profile is a violation (fail-closed), so a
# typo like "NSS" cannot silently skip the federal/CNSA sections.
_federal_profile if input.pqc.profile in {"federal", "nss"}

_nss_profile if input.pqc.profile == "nss"

# A crypto_inventory row the data-driven checks can actually evaluate.
# Malformed rows are flagged (fail-closed) rather than silently skipped.
# The algorithm must be a single token — free text like
# "RSA-2048 (ML-KEM planned)" would otherwise substring-match a PQC marker
# and reclassify a vulnerable asset as protected.
_valid_item(item) if {
	is_string(item.asset)
	is_string(item.algorithm)
	not contains(item.algorithm, " ")
	item.usage in {"key_establishment", "signature", "symmetric", "hashing"}
}

violations contains msg if {
	profile := input.pqc.profile
	not profile in {"general", "federal", "nss"}
	msg := sprintf(
		"PQC Input Contract: unrecognized profile %v — must be one of general, federal, nss (profile-gated checks were NOT evaluated)",
		[profile],
	)
}

# ── Inventory & prioritization (OMB M-26-15) ─────────────────────────────────

violations contains msg if {
	not input.pqc.inventory.complete == true
	msg := "PQC OMB M-26-15: Automated cryptographic inventory (systems, protocols, libraries, certificates) is not complete"
}

violations contains msg if {
	not input.pqc.inventory.refreshed_within_year == true
	msg := "PQC OMB M-26-15: Cryptographic inventory has not been refreshed within the last year"
}

violations contains msg if {
	not input.pqc.inventory.hndl_data_identified == true
	msg := "PQC NIST IR 8547: Data with long confidentiality lifetimes has not been identified for harvest-now-decrypt-later risk prioritization"
}

violations contains msg if {
	not input.pqc.inventory.migration_plan_exists == true
	msg := "PQC EO 14412: No prioritized, milestoned PQC migration plan exists"
}

# ── Algorithm usage (NIST IR 8547 / FIPS 203-205) — data-driven ─────────────

# The inventory itself must be an array — a scalar/object here would make
# every data-driven rule (the malformed-row guard included) silently skip.
violations contains msg if {
	inv := input.pqc.crypto_inventory
	not is_array(inv)
	msg := "PQC Input Contract: crypto_inventory must be an array of asset records (data-driven algorithm checks were NOT evaluated)"
}

violations contains msg if {
	some i, item in input.pqc.crypto_inventory
	not _valid_item(item)
	msg := sprintf(
		"PQC Input Contract: crypto_inventory[%v] is malformed — asset, algorithm (single token), and a valid usage (key_establishment|signature|symmetric|hashing) are required",
		[i],
	)
}

# `== true` (not bare truthiness): a non-boolean like the string "no" must
# not count as a planned migration. Malformed rows are excluded here — they
# already fail closed via the input-contract rule above.
violations contains msg if {
	some item in input.pqc.crypto_inventory
	_valid_item(item)
	item.usage in {"key_establishment", "signature"}
	_is_vulnerable(item.algorithm)
	not item.pqc_migration_planned == true
	msg := sprintf(
		"PQC NIST IR 8547: Asset '%s' uses quantum-vulnerable algorithm '%s' for %s with no PQC migration planned (deprecated after 2030, disallowed after 2035)",
		[item.asset, item.algorithm, item.usage],
	)
}

violations contains msg if {
	some item in input.pqc.crypto_inventory
	_valid_item(item)
	item.usage == "hashing"
	replace(_norm(item.algorithm), "-", "") in _broken_hashes
	msg := sprintf(
		"PQC FIPS 180-4: Asset '%s' uses broken hash algorithm '%s', which is disallowed for all cryptographic use",
		[item.asset, item.algorithm],
	)
}

# ── Crypto-agility ───────────────────────────────────────────────────────────

violations contains msg if {
	not input.pqc.agility.algorithms_replaceable == true
	msg := "PQC Crypto-Agility: Cryptographic algorithms cannot be replaced without application redesign"
}

violations contains msg if {
	not input.pqc.agility.library_inventory_maintained == true
	msg := "PQC Crypto-Agility: No maintained inventory of cryptographic libraries and their PQC support status"
}

violations contains msg if {
	not input.pqc.agility.vendor_roadmaps_tracked == true
	msg := "PQC Crypto-Agility: Vendor PQC roadmaps and FIPS 140-3 PQC validation status are not tracked"
}

# ── Federal timeline (EO 14412 / OMB M-26-15) — profile federal or nss ──────

violations contains msg if {
	_federal_profile
	not input.pqc.federal.key_establishment_migration_on_track == true
	msg := "PQC EO 14412: Key-establishment migration to ML-KEM (FIPS 203) for high-value/high-impact systems is not on track for 2030-12-31"
}

violations contains msg if {
	_federal_profile
	not input.pqc.federal.signature_migration_on_track == true
	msg := "PQC EO 14412: Digital-signature migration to ML-DSA/SLH-DSA (FIPS 204/205) for high-value/high-impact systems is not on track for 2031-12-31"
}

violations contains msg if {
	_federal_profile
	not input.pqc.federal.tls_endpoints_support_pqc_kem == true
	msg := "PQC OMB M-26-15: TLS endpoints do not support PQC key establishment (hybrid ML-KEM groups acceptable)"
}

violations contains msg if {
	_federal_profile
	not input.pqc.federal.contractor_fips_pqc_required == true
	msg := "PQC EO 14412: FIPS PQC requirements are not flowed down to covered contractors and vendors"
}

# ── CNSA 2.0 (NSS) — profile nss only ────────────────────────────────────────

violations contains msg if {
	_nss_profile
	not input.pqc.nss.sw_fw_signing_cnsa == true
	msg := "PQC CNSA 2.0: Software/firmware signing does not use ML-DSA-87, LMS, or XMSS (SP 800-208)"
}

violations contains msg if {
	_nss_profile
	not input.pqc.nss.acquisitions_require_cnsa == true
	msg := "PQC CNSA 2.0: New NSS acquisitions do not require CNSA 2.0 algorithm support (mandatory from 2027-01-01)"
}

violations contains msg if {
	_nss_profile
	not input.pqc.nss.network_equipment_on_track == true
	msg := "PQC CNSA 2.0: VPN/router/network equipment is not on track for CNSA 2.0 exclusive use by 2030"
}

violations contains msg if {
	_nss_profile
	not input.pqc.nss.symmetric_cnsa_compliant == true
	msg := "PQC CNSA 2.0: Symmetric/hash usage is not restricted to AES-256 and SHA-384/SHA-512"
}

# ── Report ───────────────────────────────────────────────────────────────────

# Inventory posture summary — how much of the supplied crypto inventory is
# already PQC vs vulnerable (informational, independent of violations).
# Guarded on is_array so a scalar here can never publish e.g. a string
# length as an asset count.
default _inventory_total := 0

_inventory_total := count(inv) if {
	inv := input.pqc.crypto_inventory
	is_array(inv)
}

# Both posture counts consider only well-formed rows — a malformed row
# (flagged above) must not be counted as PQC-protected.
_pqc_assets := [item |
	some item in input.pqc.crypto_inventory
	_valid_item(item)
	_is_pqc(item.algorithm)
]

_vulnerable_assets := [item |
	some item in input.pqc.crypto_inventory
	_valid_item(item)
	item.usage in {"key_establishment", "signature"}
	_is_vulnerable(item.algorithm)
]

default _profile := "general"

_profile := input.pqc.profile

# Controls actually evaluated for the active profile: 7 base boolean
# + 3 data-driven rule classes (input contract, vulnerable algorithm,
# SHA-1), + 4 federal, + 4 more for nss.
default _federal_controls := 0

_federal_controls := 4 if _federal_profile

default _nss_controls := 0

_nss_controls := 4 if _nss_profile

_controls_evaluated := (10 + _federal_controls) + _nss_controls

compliance_report := {
	"framework": "Post-Quantum Cryptography Readiness",
	"version": "1.0",
	"sources": [
		"FIPS 203/204/205 (Aug 2024)",
		"NIST IR 8547 (draft)",
		"EO 14412 (2026-06-22)",
		"OMB M-26-15",
		"NSA CNSA 2.0",
	],
	"profile": _profile,
	"controls_evaluated": _controls_evaluated,
	"inventory_assets_total": _inventory_total,
	"inventory_assets_pqc": count(_pqc_assets),
	"inventory_assets_quantum_vulnerable": count(_vulnerable_assets),
	"violations": violations,
	"violation_count": count(violations),
	"compliant": compliant,
}
