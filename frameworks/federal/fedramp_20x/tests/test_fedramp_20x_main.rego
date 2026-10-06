# Tests for fedramp_20x.main — Consolidated Rules KSI set.

package fedramp_20x.main_test

import rego.v1

import data.fedramp_20x.main

# ── Table integrity (anchored to the Consolidated Rules datafile) ────────────

test_table_has_46_ksis if {
	count(main.ksis) == 46
}

test_exactly_five_optional_at_b if {
	{id | some id, m in main.ksis; m.optional_at_b} == {
		"KSI-CNA-EIS", "KSI-MLA-ALA",
		"KSI-SVC-PRR", "KSI-SVC-RUD", "KSI-SVC-VCM",
	}
}

test_class_b_applicable_41 if {
	count(main.applicable) == 41 with input as {"fedramp_20x": {"target_class": "b"}}
}

test_class_c_applicable_46 if {
	count(main.applicable) == 46 with input as {"fedramp_20x": {"target_class": "c"}}
}

# ── Fail-closed behavior ─────────────────────────────────────────────────────

test_empty_input_evaluates_class_c if {
	r := main.compliance_report with input as {}
	r.target_class == "c"
	r.ksis_evaluated == 46
	r.violation_count == 46
	r.compliant == false
}

test_unrecognized_class_flagged_and_strict if {
	inp := {"fedramp_20x": {"target_class": "moderate", "ksis": {}}}
	r := main.compliance_report with input as inp

	# 46 unattested + 1 input-contract violation
	r.violation_count == 47
	r.target_class == "c"
	some msg in main.violations with input as inp
	contains(msg, "unrecognized target_class")
}

test_string_true_fails_closed if {
	all_true := {id: true | some id, _ in main.ksis}
	broken := object.union(all_true, {"KSI-IAM-ELP": "true"})
	inp := {"fedramp_20x": {"target_class": "c", "ksis": broken}}
	v := main.violations with input as inp
	count(v) == 1
	some msg in v
	contains(msg, "KSI-IAM-ELP")
}

test_unknown_ksi_id_flagged if {
	all_true := {id: true | some id, _ in main.ksis}
	inp := {"fedramp_20x": {"target_class": "c", "ksis": object.union(all_true, {"KSI-TPR-01": true})}}
	v := main.violations with input as inp
	count(v) == 1
	some msg in v
	contains(msg, "unknown KSI id")
}

test_non_object_ksis_flagged if {
	inp := {"fedramp_20x": {"target_class": "b", "ksis": "all of them"}}
	v := main.violations with input as inp
	some msg in v
	contains(msg, "must be an object")
}

# ── Positive compliance ──────────────────────────────────────────────────────

test_class_c_full_attestation_compliant if {
	all_true := {id: true | some id, _ in main.ksis}
	inp := {"fedramp_20x": {"target_class": "c", "ksis": all_true}}
	main.compliant with input as inp
	r := main.compliance_report with input as inp
	r.ksis_attested == 46
}

test_class_b_without_optional_ksis_compliant if {
	required := {id: true | some id, m in main.ksis; not m.optional_at_b}
	inp := {"fedramp_20x": {"target_class": "b", "ksis": required}}
	main.compliant with input as inp
	r := main.compliance_report with input as inp
	r.ksis_attested == 41
}

test_optional_ksi_required_at_c if {
	required_only := {id: true | some id, m in main.ksis; not m.optional_at_b}
	inp := {"fedramp_20x": {"target_class": "c", "ksis": required_only}}
	v := main.violations with input as inp
	count(v) == 5
}
