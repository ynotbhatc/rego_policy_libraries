# Tests for pqc.cswp39 — NIST CSWP 39-upd1 crypto-agility practices (updated 2026-06-29).
package pqc.cswp39_test

import rego.v1

import data.pqc.cswp39
import data.pqc.main

_all := {id: true | some id, _ in cswp39.practices}

_ungated := {id: true | some id, p in cswp39.practices; p.gate == ""}

_flags_on := {"develops_cryptographic_implementations": true, "self_manages_cloud_cryptography": true}

_flags_off := {"develops_cryptographic_implementations": false, "self_manages_cloud_cryptography": false}

_inp(flags, practices) := {"pqc": {"cswp39": object.union(flags, {"practices": practices})}}

# ── Table shape (row count pinned to the paper; see the module header) ──────

test_row_count_pinned if {
	count(cswp39.practices) == 67
	count({id | some id, p in cswp39.practices; p.ch == "3"}) == 23
	count({id | some id, p in cswp39.practices; p.ch == "4"}) == 12
	count({id | some id, p in cswp39.practices; p.ch == "5"}) == 19
	count({id | some id, p in cswp39.practices; p.ch == "6"}) == 10
	count({id | some id, p in cswp39.practices; p.ch == "7"}) == 3
	count(_ungated) == 33
	count({id | some id, p in cswp39.practices; p.gate == "develops_cryptographic_implementations"}) == 33
	count({id | some id, p in cswp39.practices; p.gate == "self_manages_cloud_cryptography"}) == 1
}

test_every_gate_is_a_declared_flag if {
	count({id | some id, p in cswp39.practices; p.gate != ""; not cswp39._flags[p.gate]}) == 0
}

test_every_id_matches_its_chapter if {
	count({id | some id, p in cswp39.practices; not cswp39.chapters[p.ch]}) == 0
	count({id |
		some id, p in cswp39.practices
		id != p.ch
		not startswith(id, concat("", [p.ch, "."]))
		not startswith(id, concat("", [p.ch, "-"]))
	}) == 0
	count({id | some id, _ in cswp39.practices; not regex.match(`^[3-7](\.[0-9]+)*(-[a-k])?$`, id)}) == 0
}

test_report_cites_upd1 if {
	r := cswp39.compliance_report with input as {}
	contains(r.source, "NIST.CSWP.39-upd1.pdf")
	contains(r.source, "e6b147d23eba193653f2abb3abe03fc25e63a9a91df918440b5445f9f58e9ac6")
}

test_one_sentence_per_row if {
	count({id | some id, p in cswp39.practices; not endswith(p.text, ".")}) == 0
}

# ── Fail-closed ──────────────────────────────────────────────────────────────

test_empty_input_fails_closed if {
	r := cswp39.compliance_report with input as {}
	r.compliant == false
	r.flags.develops_cryptographic_implementations == "undeclared"
	some msg in r.violations
	contains(msg, "FAIL-CLOSED")

	# 1 FAIL-CLOSED + 2 undeclared flags + 33 ungated practices
	r.violation_count == 36
	r.practices_evaluated == 33
	r.practices_attested == 0
}

test_empty_input_pqc_main_counts_unchanged if {
	r := main.compliance_report with input as {}
	r.violation_count == 7
	r.crypto_agility_cswp39.compliant == false
}

# ── Compliant paths ──────────────────────────────────────────────────────────

test_all_true_section_compliant if {
	inp := _inp(_flags_on, _all)
	r := cswp39.compliance_report with input as inp
	r.compliant == true
	r.violation_count == 0
	r.practices_evaluated == 67
	r.practices_attested == 67
	count({ch | some ch, c in r.chapters; not c.complete}) == 0
}

test_flags_off_needs_only_33 if {
	inp := _inp(_flags_off, _ungated)
	cswp39.compliant with input as inp
	r := cswp39.compliance_report with input as inp
	r.practices_evaluated == 33
	r.chapters["4"].practices_evaluated == 0
	r.chapters["4"].practices_total == 12
}

test_cloud_flag_opens_6_4 if {
	inp := _inp({"develops_cryptographic_implementations": false, "self_manages_cloud_cryptography": true}, _ungated)
	r := cswp39.compliance_report with input as inp
	r.chapters["6"].gaps == ["6.4"]
	r.violation_count == 1
}

# ── Violations ───────────────────────────────────────────────────────────────

test_one_false_is_named if {
	inp := _inp(_flags_on, object.union(_all, {"5-d": false}))
	r := cswp39.compliance_report with input as inp
	r.compliant == false
	r.violation_count == 1
	r.chapters["5"].gaps == ["5-d"]
	some msg in r.violations
	contains(msg, "§5-d")
	contains(msg, "Inventory the use of cryptography")
}

test_non_boolean_attestation_not_counted if {
	inp := _inp(_flags_on, object.union(_all, {"3.2.3-a": "yes"}))
	r := cswp39.compliance_report with input as inp
	r.violation_count == 1
	r.chapters["3"].gaps == ["3.2.3-a"]
}

test_unknown_id_is_a_violation if {
	inp := _inp(_flags_on, object.union(_all, {"9.9": true}))
	v := cswp39.violations with input as inp
	count(v) == 1
	some msg in v
	contains(msg, "unknown practice id 9.9")
}

test_practices_array_is_contract_violation if {
	inp := {"pqc": {"cswp39": object.union(_flags_on, {"practices": ["3-a"]})}}
	v := cswp39.violations with input as inp
	some msg in v
	contains(msg, "must be an object")
	count({m | some m in v; contains(m, "unknown practice id")}) == 0

	# the parent PQC report stays defined
	r := main.compliance_report with input as inp
	is_object(r.crypto_agility_cswp39)
}

test_cswp39_string_container_flagged if {
	v := cswp39.violations with input as {"pqc": {"cswp39": "all done"}}
	some msg in v
	contains(msg, "input.pqc.cswp39 must be an object")
	r := main.compliance_report with input as {"pqc": {"cswp39": "all done"}}
	is_object(r)
}
