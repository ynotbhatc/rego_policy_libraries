# Post-Quantum Cryptography (PQC) Readiness — v1.0
#
# Sources (all verified 2026-10-06):
#   FIPS 203 (ML-KEM), FIPS 204 (ML-DSA), FIPS 205 (SLH-DSA) — final Aug 2024
#   NIST SP 800-208 (LMS/XMSS stateful hash-based signatures, firmware signing)
#   NIST IR 8545 (Mar 2025): HQC selected as the KEM alternative to ML-KEM
#   NIST SP 800-131A Rev. 2 (Table 1): TDEA encryption disallowed after 2023
#   Algorithm vocabulary re-verified 2026-11-17 against the IR 8547 final PDF
#   (https://nvlpubs.nist.gov/nistpubs/ir/2026/NIST.IR.8547.pdf, Tables 2–8,
#   §2.1) and https://csrc.nist.gov/projects/post-quantum-cryptography
#   NIST IR 8547 (Transition to PQC Standards — FINAL 2026-10-27, verified
#     2026-11-06; cited as the Nov 2024 initial public draft until then):
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
# The report also carries `crypto_agility_cswp39`, the NIST CSWP 39
# crypto-agility practice view (cswp39_crypto_agility.rego, input
# input.pqc.cswp39.*), as a separate section with its own compliant flag.
#
# Fail-closed: every boolean fact must be affirmatively true, and the
# crypto_inventory must be present, a non-empty array, and every row must
# classify. Empty input yields the 7 base boolean violations plus "evidence
# missing — input.pqc.crypto_inventory not collected" (profile-gated
# sections require the profile).
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
#   crypto_inventory             — REQUIRED, non-empty list of asset records
#                                  (missing / non-array / empty are findings):
#     [ { "asset":              "<name>",
#         "algorithm":          "RSA-2048" | "ECDSA-P256" | "ML-KEM-768" | ...
#                               single token; case and separators are
#                               ignored; see the vocabulary below — a name
#                               it does not fully recognise is a finding,
#         "usage":              "key_establishment" | "signature" |
#                               "symmetric" | "hashing",
#         "pqc_migration_planned": bool    # consulted for quantum-vulnerable
#                                          # and 112-bit legacy algorithms;
#                                          # must be the boolean true to count
#       }, ... ]
#     Each row is classified quantum_vulnerable | post_quantum | hybrid |
#     symmetric_or_hash | unrecognised (report: inventory_classification).
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
#   coverage:
#     checks: 20
#     cited: 5
#     density: orchestrator
#     basis: role
#     tested: true
#     entrypoint: compliance_report
#     guard: self
#     as_of: v2.4.2
package pqc.main

import rego.v1

import data.pqc.cswp39

default compliant := false

compliant if {
	count(violations) == 0
}

# ── Algorithm classification ─────────────────────────────────────────────────
#
# Every inventory algorithm is normalised (anything after '@' dropped, as in
# OpenSSH's "@openssh.com" suffixes; upper-cased; every non-alphanumeric
# removed, so "ML-KEM-768", "ml_kem_768" and "MLKEM768" are one spelling) and
# then tokenised against the vocabulary below. The WHOLE normalised name must
# be consumed by known tokens and must contain at least one algorithm token;
# otherwise the asset is UNRECOGNISED and reported by name. This is what keeps
# a substring from deciding the class: "RSA2048PLANNED" leaves "PLANNED"
# unconsumed and is unrecognised, and "SLH-DSA" / "ML-DSA" / "FN-DSA" are
# consumed as whole PQC tokens before "DSA" can ever be tried at that position.
#
# The tokenizer is one alternation, leftmost-first (RE2), so ORDER MATTERS:
# a longer token must precede any shorter token that is its prefix
# (SHA512224 before SHA512, SHA3224 before SHA3, DESEDE before DES, ...).
# No alternative can match the empty string.
#
# Token classes, and the source for each:
#   pq          FIPS-approved post-quantum: ML-KEM-512/768/1024 (FIPS 203),
#               ML-DSA-44/65/87 incl. HashML-DSA (FIPS 204), SLH-DSA
#               SHA2/SHAKE-128/192/256 s/f incl. HashSLH-DSA (FIPS 205) — there
#               is no "HashML-KEM", so that spelling is unrecognised — LMS/HSS and XMSS/XMSS^MT
#               (SP 800-208) — NIST IR 8547 Tables 3 and 5
#   pq_pre      pre-standard names of the same schemes: CRYSTALS-KYBER
#               (Kyber512/768/1024), CRYSTALS-Dilithium (Dilithium2/3/5),
#               SPHINCS+ — IR 8547 §2.1: FIPS 203/204/205 are "derived from"
#               these submissions. Quantum-resistant, but not the FIPS
#               algorithm (round-3 Dilithium is not wire-identical to ML-DSA);
#               reported in their own count, not a violation
#   pq_pending  selected for standardisation, FIPS not yet published:
#               FN-DSA / FALCON (IR 8547 §2.1.1: a FALCON-derived FIPS is under
#               development; NIST calls it FIPS 206 FN-DSA) and HQC (NIST IR
#               8545, March 2025; IR 8547 §4.1.2: approved once published).
#               Reported in their own count, not a violation
#   qv          quantum-vulnerable public-key (Shor): RSA (incl. RSASSA-PSS,
#               RSAES-OAEP, rsaEncryption), DSA, ECDSA, EdDSA/Ed25519/Ed448,
#               finite-field DH/FFDHE/MODP, ECDH, MQV/ECMQV, X25519/X448,
#               ElGamal, ECIES and the named curves — IR 8547 Tables 2 and 4
#   sym         AES-128/192/256, Ascon-AEAD128 — IR 8547 §4.1.3 / Tables 6–7:
#               ≥128-bit approved symmetric primitives meet Category 1+
#   hash        SHA-256, SHA-512/256, SHA-384, SHA-512, SHA3-256/384/512,
#               SHAKE128/256, Ascon-Hash256/XOF128 — IR 8547 Table 8
#   legacy112   112-bit-security approved hashes: SHA-224, SHA-512/224,
#               SHA3-224 (Table 8: collision category <1) — IR 8547 §4.1.3:
#               112-bit symmetric standards "will be disallowed in 2030"
#   tdea        TDEA / Triple DES — NIST SP 800-131A Rev. 2 Table 1: two-key
#               encryption disallowed, three-key encryption disallowed after
#               2023, decryption legacy use only (not a migration-plan item)
#   sha1        SHA-1 — IR 8547 Table 8 note 4: deprecated for all remaining
#               applications, disallowed in FIPS-validated modules after 2030
#   not_approved MD5, MD4, MD2, DES, RC4, RC2 — not NIST-approved primitives
#   neutral     modes, encodings and naming filler that are never an algorithm
#               on their own (GCM, HMAC, PSS, WITH, TLS, DRAFT00, SK, ...)
#
# Not in the vocabulary, therefore UNRECOGNISED (classify manually): anything
# the cited NIST guidance does not assess, e.g. ChaCha20-Poly1305, Camellia,
# OpenSSH's sntrup761x25519, Classic McEliece, FrodoKEM.
_tokens := [
	# post-quantum, FIPS-approved
	["pq", `MLKEM(?:1024|768|512)?`],
	["pq", `(?:HASH)?MLDSA(?:44|65|87)?`],
	["pq", `(?:HASH)?SLHDSA(?:SHA2|SHAKE)?(?:128|192|256)?(?:S|F)?`],
	["pq", `LMOTS(?:SHA256|SHAKE256)?(?:N\d+)?(?:W\d+)?`],
	["pq", `(?:HSS|LMS)(?:SHA256|SHAKE256)?(?:M\d+)?(?:H\d+)?(?:W\d+)?`],
	["pq", `XMSS(?:MT)?(?:SHA2|SHAKE256|SHAKE)?\d*`],
	# post-quantum, pre-standard names
	["pq_pre", `(?:CRYSTALS)?KYBER(?:1024|768|512)?(?:90S)?`],
	["pq_pre", `(?:CRYSTALS)?DILITHIUM(?:2|3|5)?(?:AES)?`],
	["pq_pre", `SPHINCS(?:PLUS)?(?:SHA2|SHA256|SHAKE256|SHAKE|HARAKA)?(?:128|192|256)?(?:S|F)?(?:SIMPLE|ROBUST)?`],
	# post-quantum, selected but FIPS not yet published
	["pq_pending", `FNDSA(?:1024|512)?`],
	["pq_pending", `FALCON(?:1024|512)?`],
	["pq_pending", `HQC(?:128|192|256)?`],
	# quantum-vulnerable public-key
	["qv", `RSAENCRYPTION`],
	["qv", `RSA(?:SSA|ES)?\d*`],
	["qv", `DSAENCRYPTION`],
	["qv", `ECDSA`],
	["qv", `ECDHE?`],
	["qv", `ECMQV`],
	["qv", `ECIES`],
	["qv", `ECC\d*`],
	["qv", `ECPUBLICKEY`],
	["qv", `EDDSA`],
	["qv", `ED25519(?:PH|CTX)?`],
	["qv", `ED448(?:PH)?`],
	["qv", `X25519`],
	["qv", `X448`],
	["qv", `CURVE25519`],
	["qv", `CURVE448`],
	["qv", `(?:FF)?DHE?(?:GROUPEXCHANGE|GROUP)?\d*`],
	["qv", `MODP\d*`],
	["qv", `MQV`],
	["qv", `ELGAMAL\d*`],
	["qv", `DSA\d*`],
	["qv", `SECP\d+[RK]\d`],
	["qv", `SECT\d+[RK]\d`],
	["qv", `(?:NIST)?P(?:192|224|256|384|521)`],
	["qv", `PRIME(?:192|239|256)V\d`],
	["qv", `BRAINPOOLP\d+[RT]\d`],
	# symmetric
	["sym", `AES(?:128|192|256)?`],
	["sym", `ASCONAEAD128`],
	["hash", `ASCONHASH256`],
	["hash", `ASCONC?XOF128`],
	["tdea", `TRIPLEDES`],
	["tdea", `3DES`],
	["tdea", `TDEA`],
	["tdea", `TDES`],
	["tdea", `DESEDE3?`],
	["not_approved", `DES`],
	["not_approved", `RC4`],
	["not_approved", `ARCFOUR`],
	["not_approved", `RC2`],
	["not_approved", `MD5`],
	["not_approved", `MD4`],
	["not_approved", `MD2`],
	# hashes (longest first)
	["legacy112", `SHA512224`],
	["hash", `SHA512256`],
	["hash", `SHA512`],
	["hash", `SHA384`],
	["hash", `SHA256(?:192)?`],
	["legacy112", `SHA224`],
	["legacy112", `SHA3224`],
	["hash", `SHA3(?:256|384|512)`],
	["hash", `SHAKE(?:128|256)`],
	["sha1", `SHA1`],
	# neutral filler — never an algorithm on its own
	["neutral", `SHA2`],
	["neutral", `SHA3`],
	["neutral", `GCMSIV`],
	["neutral", `GCM`],
	["neutral", `CCM`],
	["neutral", `CBC`],
	["neutral", `CTR`],
	["neutral", `XTS`],
	["neutral", `CFB\d*`],
	["neutral", `OFB`],
	["neutral", `SIV`],
	["neutral", `KWP`],
	["neutral", `KW`],
	["neutral", `CMAC`],
	["neutral", `GMAC`],
	["neutral", `HMAC`],
	["neutral", `HKDF`],
	["neutral", `KMAC(?:128|256)`],
	["neutral", `PBKDF2`],
	["neutral", `PSS`],
	["neutral", `OAEP`],
	["neutral", `PKCS1(?:V15)?`],
	["neutral", `WITH`],
	["neutral", `ENCRYPTION`],
	["neutral", `TLS(?:13|12)?`],
	["neutral", `DRAFT\d*`],
	["neutral", `SK`],
	["neutral", `ID`],
	["neutral", `UNKNOWN`],
]

_token_re := concat("|", [sprintf("(?:%s)", [t[1]]) | some t in _tokens])

_norm(alg) := regex.replace(upper(split(alg, "@")[0]), `[^A-Z0-9]`, "")

_token_class(tok) := _tokens[i][0] if {
	i := min({j | some j, t in _tokens; regex.match(sprintf("^(?:%s)$", [t[1]]), tok)})
}

# Set of token classes found in an algorithm name.
_classes(alg) := {_token_class(tok) | some tok in regex.find_n(_token_re, _norm(alg), -1)}

_pq_classes := {"pq", "pq_pre", "pq_pending"}

_recognised(alg) if {
	n := _norm(alg)
	n != ""
	regex.replace(n, _token_re, "") == ""
	count(_classes(alg) - {"neutral"}) > 0
}

# One class per asset: quantum_vulnerable | post_quantum | hybrid |
# symmetric_or_hash | unrecognised. A hybrid has a post-quantum and a
# quantum-vulnerable component (e.g. X25519MLKEM768); IR 8547 §4.1.2 accepts
# a composite as long as one input is an approved scheme.
_asset_class(alg) := "unrecognised" if {
	not _recognised(alg)
} else := "hybrid" if {
	c := _classes(alg)
	"qv" in c
	count(c & _pq_classes) > 0
} else := "post_quantum" if {
	count(_classes(alg) & _pq_classes) > 0
} else := "quantum_vulnerable" if {
	"qv" in _classes(alg)
} else := "symmetric_or_hash"

_is_pqc(alg) if _asset_class(alg) in {"post_quantum", "hybrid"}

_is_vulnerable(alg) if _asset_class(alg) == "quantum_vulnerable"

_has_class(alg, cls) if {
	_recognised(alg)
	cls in _classes(alg)
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

# The inventory is the evidence every data-driven rule iterates, so its
# absence must be a finding, not an empty loop. Three distinct cases, exactly
# one of which can fire:
#   missing (or null)  → evidence missing
#   not an array       → input contract
#   empty array        → no cryptographic asset assessed. An explicitly empty
#     inventory is never accepted: this module's own inventory.complete fact
#     asserts the inventory covers systems, protocols, libraries and
#     certificates; EO 14412 / OMB M-26-15 require that inventory; NIST CSWP
#     39 §5 ("Inventory the use of cryptography ... across the organization")
#     makes it the first data step. Any system in scope of a PQC assessment
#     uses public-key cryptography somewhere (TLS, SSH, code signing), so an
#     empty list means the collection did not happen. A scope that genuinely
#     uses no cryptography is out of scope for this assessment, not compliant.
_inv_raw := object.get(input, ["pqc", "crypto_inventory"], null)

# The rows every data-driven rule iterates: only ever an array, so an object
# here cannot be iterated as if its values were rows.
default _inv_rows := []

_inv_rows := _inv_raw if is_array(_inv_raw)

violations contains msg if {
	_inv_raw == null
	msg := "PQC Evidence missing — input.pqc.crypto_inventory not collected (no cryptographic asset was classified; the data-driven algorithm checks were NOT evaluated)"
}

violations contains msg if {
	_inv_raw != null
	not is_array(_inv_raw)
	msg := "PQC Input Contract: crypto_inventory must be an array of asset records (data-driven algorithm checks were NOT evaluated)"
}

violations contains msg if {
	_inv_raw == []
	msg := "PQC Evidence missing — input.pqc.crypto_inventory is empty: no cryptographic asset was assessed (an inventory that lists no TLS, SSH, certificate or signing algorithm means collection did not happen)"
}

violations contains msg if {
	some i, item in _inv_rows
	not _valid_item(item)
	msg := sprintf(
		"PQC Input Contract: crypto_inventory[%v] is malformed — asset, algorithm (single token), and a valid usage (key_establishment|signature|symmetric|hashing) are required",
		[i],
	)
}

# Every well-formed row must classify. An algorithm name the vocabulary does
# not fully consume is reported by asset — never silently passed.
violations contains msg if {
	some item in _inv_rows
	_valid_item(item)
	_asset_class(item.algorithm) == "unrecognised"
	msg := sprintf(
		"PQC Unrecognised algorithm: asset '%s' uses '%s', which is not in the NIST vocabulary this module assesses (FIPS 203/204/205, SP 800-208, NIST IR 8547 Tables 2–8) — it was NOT classified as quantum-vulnerable or post-quantum; correct the name or classify the asset manually",
		[item.asset, item.algorithm],
	)
}

# Quantum-vulnerable public-key algorithm, whatever usage the row declares
# (an RSA key filed under "symmetric" is still RSA). IR 8547 §4.1.1–4.1.2:
# organisations may continue using these while they migrate, so a recorded
# migration (`== true`, not bare truthiness: the string "no" must not count)
# clears the finding. Hybrids are not quantum-vulnerable.
violations contains msg if {
	some item in _inv_rows
	_valid_item(item)
	_is_vulnerable(item.algorithm)
	not item.pqc_migration_planned == true
	msg := sprintf(
		"PQC NIST IR 8547: Asset '%s' uses quantum-vulnerable algorithm '%s' for %s with no PQC migration planned (deprecated after 2030, disallowed after 2035)",
		[item.asset, item.algorithm, item.usage],
	)
}

# 112-bit-security hashes (SHA-224, SHA-512/224, SHA3-224): IR 8547 §4.1.3
# — "will be disallowed in 2030"; same migration treatment as vulnerable
# public-key algorithms.
violations contains msg if {
	some item in _inv_rows
	_valid_item(item)
	_has_class(item.algorithm, "legacy112")
	not item.pqc_migration_planned == true
	msg := sprintf(
		"PQC NIST IR 8547 §4.1.3: Asset '%s' uses '%s', a 112-bit-security hash (SHA-224, SHA-512/224 or SHA3-224) that will be disallowed in 2030, with no migration planned",
		[item.asset, item.algorithm],
	)
}

# TDEA is already past its disallowance date for encryption, so a migration
# plan does not clear it. NIST SP 800-131A Rev. 2 Table 1.
violations contains msg if {
	some item in _inv_rows
	_valid_item(item)
	_has_class(item.algorithm, "tdea")
	msg := sprintf(
		"PQC NIST SP 800-131A Rev. 2: Asset '%s' uses TDEA ('%s'); TDEA encryption is disallowed (three-key after 2023) and decryption is permitted only for legacy use",
		[item.asset, item.algorithm],
	)
}

# SHA-1, in any usage (a "sha1WithRSAEncryption" or "DH-group14-sha1" row
# uses SHA-1 too). IR 8547 Table 8 note 4.
violations contains msg if {
	some item in _inv_rows
	_valid_item(item)
	_has_class(item.algorithm, "sha1")
	msg := sprintf(
		"PQC NIST IR 8547 Table 8: Asset '%s' uses SHA-1 ('%s'), which is deprecated for all remaining applications and disallowed in FIPS-validated cryptographic modules after 2030",
		[item.asset, item.algorithm],
	)
}

violations contains msg if {
	some item in _inv_rows
	_valid_item(item)
	_has_class(item.algorithm, "not_approved")
	msg := sprintf(
		"PQC NIST-approved algorithms: Asset '%s' uses '%s', which contains a primitive that is not NIST-approved for any use (MD5, MD4, MD2, DES, RC4 or RC2)",
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

# Posture counts consider only well-formed rows — a malformed row (flagged
# above) must not be counted as PQC-protected. inventory_assets_pqc counts
# post-quantum AND hybrid assets (both HNDL-protected).
_valid_rows := [item |
	some item in _inv_rows
	_valid_item(item)
]

_pqc_assets := [item | some item in _valid_rows; _is_pqc(item.algorithm)]

_vulnerable_assets := [item | some item in _valid_rows; _is_vulnerable(item.algorithm)]

_count_class(cls) := count([item | some item in _valid_rows; _asset_class(item.algorithm) == cls])

_count_token_class(cls) := count([item | some item in _valid_rows; _has_class(item.algorithm, cls)])

_inventory_classification := [{"asset": item.asset, "algorithm": item.algorithm, "class": _asset_class(item.algorithm)} |
	some item in _valid_rows
]

default _profile := "general"

_profile := input.pqc.profile

# Controls actually evaluated for the active profile: 7 base boolean
# + 5 data-driven rule classes (inventory evidence & input contract,
# unrecognised algorithm, quantum-vulnerable public-key, 112-bit legacy
# hash, disallowed or deprecated symmetric/hash primitive: TDEA, SHA-1,
# non-approved) + 4 federal, + 4 more for nss.
default _federal_controls := 0

_federal_controls := 4 if _federal_profile

default _nss_controls := 0

_nss_controls := 4 if _nss_profile

_controls_evaluated := (12 + _federal_controls) + _nss_controls

compliance_report := {
	"framework": "Post-Quantum Cryptography Readiness",
	"version": "1.0",
	"sources": [
		"FIPS 203/204/205 (Aug 2024)",
		"NIST SP 800-208",
		"NIST IR 8547 (final, 2026-10-27)",
		"NIST IR 8545 (HQC selection, Mar 2025)",
		"EO 14412 (2026-06-22)",
		"OMB M-26-15",
		"NSA CNSA 2.0",
	],
	"profile": _profile,
	"controls_evaluated": _controls_evaluated,
	"inventory_assets_total": _inventory_total,
	"inventory_assets_pqc": count(_pqc_assets),
	"inventory_assets_quantum_vulnerable": count(_vulnerable_assets),
	"inventory_assets_hybrid": _count_class("hybrid"),
	"inventory_assets_symmetric_or_hash": _count_class("symmetric_or_hash"),
	"inventory_assets_unrecognised": _count_class("unrecognised"),
	"inventory_assets_pqc_pre_standard": _count_token_class("pq_pre"),
	"inventory_assets_pqc_pending_standard": _count_token_class("pq_pending"),
	"inventory_classification": _inventory_classification,
	"violations": violations,
	"violation_count": count(violations),
	"compliant": compliant,
	# NIST CSWP 39 crypto-agility practices (cswp39_crypto_agility.rego):
	# reported and counted separately — not part of this report's
	# violations, compliant or controls_evaluated.
	"crypto_agility_cswp39": cswp39.compliance_report,
}
