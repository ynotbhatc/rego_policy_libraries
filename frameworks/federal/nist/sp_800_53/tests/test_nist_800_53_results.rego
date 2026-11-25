package nist.sp800_53.results_test

import rego.v1

import data.nist.sp800_53.index
import data.nist.sp800_53.main
import data.nist.sp800_53.main_test.fully_compliant_input

_row(r, id) := x if {
	some x in r.control_results
	x.id == id
}

# The sweeps are split into slices (item index modulo the slice count), one test per slice, so that no test runs long
# enough to meet the suite's per-test timeout on the oldest supported OPA. Every item is in exactly one slice; the
# test_the_slices_cover_* tests check it.
_slice(xs, i, n) := [x | some j, x in xs; j % n == i]

test_the_slices_cover_totals_inputs_3 if {
	sum([count(_slice(_totals_inputs, i, 3)) | some i in numbers.range(0, 2)]) == count(_totals_inputs)
	every j, x in _totals_inputs {
		x in _slice(_totals_inputs, j % 3, 3)
	}
}

test_one_row_per_evaluated_id_in_natural_order if {
	r := main.compliance_report with input as {}
	ids := [x.id | some x in r.control_results]
	count(ids) == 544
	{i | some i in ids} == main.evaluated_controls
	ids == index.order
	array.slice(ids, 0, 3) == ["AC-1", "AC-2", "AC-2(1)"]
}

test_empty_input_nothing_passes if {
	r := main.compliance_report with input as {}
	r.control_result_counts == {"pass": 0, "fail": 0, "evidence_missing": 478, "not_attested": 66}
	_row(r, "MA-2").status == "evidence_missing"
	_row(r, "PM-2").status == "not_attested"
	_row(r, "AC-2").status == "evidence_missing"
	count(_row(r, "AC-2").findings) == 1
}

test_compliant_input_every_row_passes if {
	r := main.compliance_report with input as fully_compliant_input
	r.control_result_counts == {"pass": 544, "fail": 0, "evidence_missing": 0, "not_attested": 0}
	every x in r.control_results {
		x.status == "pass"
		x.findings == []
	}
}

test_basis_marks_attestation_controls if {
	r := main.compliance_report with input as fully_compliant_input
	count([x | some x in r.control_results; x.basis == "attestation"]) == count(index.attestation_controls)
	_row(r, "PM-2").basis == "attestation"
	_row(r, "AC-2").basis == "evidence"
}

test_partial_input_passes_only_what_it_proves if {
	r := main.compliance_report with input as {"ac_controls": {"access_enforcement": {"role_based_access_control": true}}}
	r.control_result_counts.pass == 1
	_row(r, "AC-3").status == "pass"
}

test_single_failure_fails_its_rows_only if {
	inp := object.union(fully_compliant_input, {"sc_controls": object.union(fully_compliant_input.sc_controls, {"secure_dns": {"dnssec_enforced": false}})})
	r := main.compliance_report with input as inp
	r.control_result_counts.pass == 542
	r.control_result_counts.fail == 2
	failed := {x.id | some x in r.control_results; x.status == "fail"}
	failed == {i | some i in r.failed_control_ids}
}

test_baselines_sizes_match_the_profiles if {
	r := main.compliance_report with input as {}
	{k: b.in_scope | some k, b in r.baseline_results} == {
		"nist_low": 149, "nist_moderate": 287, "nist_high": 370, "nist_privacy": 96,
		"fedramp_low": 156, "fedramp_moderate": 323, "fedramp_high": 410,
	}
}

test_baseline_counts_add_up if {
	r := main.compliance_report with input as fully_compliant_input
	every b in r.baseline_results {
		b.evaluated + b.not_evaluated == b.in_scope
		b.passed + b.not_passed == b.evaluated
		b.passed == b.evaluated
		count(b.not_evaluated_ids) == b.not_evaluated
		every id in b.not_evaluated_ids {
			not id in main.evaluated_controls
		}
	}
}

test_baseline_not_passed_on_empty_input if {
	r := main.compliance_report with input as {}
	b := r.baseline_results.fedramp_moderate
	b.passed == 0
	b.not_passed == b.evaluated
	count(b.not_passed_ids) == b.evaluated
}

test_row_lists_selecting_baselines if {
	r := main.compliance_report with input as {}
	"nist_low" in _row(r, "AC-2").baselines
	not "nist_low" in _row(r, "AC-2(1)").baselines
	"nist_moderate" in _row(r, "AC-2(1)").baselines
}

test_bridge_carries_results if {
	r := data.nist_800_53.main.compliance_report with input as fully_compliant_input
	count(r.control_results) == 544
	r.control_result_counts.pass == 544
	r.baseline_results.nist_moderate.in_scope == 287
}

test_every_baseline_fully_evaluated if {
	r := main.compliance_report with input as {}
	r.baseline_results.nist_low.not_evaluated == 0
	r.baseline_results.nist_moderate.not_evaluated == 0
	r.baseline_results.nist_moderate.evaluated == 287
	r.baseline_results.nist_high.not_evaluated == 0
	r.baseline_results.fedramp_low.not_evaluated == 0
	r.baseline_results.fedramp_moderate.not_evaluated == 0
	r.baseline_results.fedramp_high.not_evaluated == 0
	r.baseline_results.fedramp_high.evaluated == 410
	r.baseline_results.nist_privacy.not_evaluated == 0
	r.baseline_results.nist_privacy.evaluated == 96
}

# --- SP 800-53 Release 5.2.0 (27 August 2025): SA-15(13), SA-24 and SI-2(7) ---------------------------------

_r520 := ["SA-15(13)", "SA-24", "SI-2(7)"]

test_release_5_2_0_additions_are_evaluated if {
	r := main.compliance_report with input as {}
	r.release == "5.2.0"
	r.coverage.release_5_2_0_additions_evaluated == _r520
	every id in _r520 {
		id in main.evaluated_controls
		_row(r, id).status != "pass"
		count(_row(r, id).findings) == 1

		# NIST put none of the three in an SP 800-53B baseline, and FedRAMP Rev 5 selects none of them
		_row(r, id).baselines == []
	}
	_row(r, "SA-15(13)").basis == "evidence"
	_row(r, "SA-15(13)").status == "evidence_missing"
	_row(r, "SI-2(7)").basis == "evidence"
	_row(r, "SI-2(7)").status == "evidence_missing"
	_row(r, "SA-24").basis == "attestation"
	_row(r, "SA-24").status == "not_attested"
}

test_release_5_2_0_additions_pass_on_the_compliant_input if {
	r := main.compliance_report with input as fully_compliant_input
	every id in _r520 {
		_row(r, id).status == "pass"
	}
}

test_release_5_2_0_string_booleans_do_not_pass if {
	inp := object.union(fully_compliant_input, {
		"sa_controls": object.union(fully_compliant_input.sa_controls, {"development_process": {"logging_syntax": {"developer_required": "true"}}}),
		"si_controls": object.union(fully_compliant_input.si_controls, {"flaw_remediation": {"root_cause_analysis": {"conducted": "false"}}}),
	})
	r := main.compliance_report with input as inp
	not r.compliant
	_row(r, "SA-15(13)").status == "evidence_missing"
	_row(r, "SI-2(7)").status == "evidence_missing"

	# the base controls do not fail on their enhancement
	_row(r, "SA-15").status == "pass"
	_row(r, "SI-2").status == "pass"
	r.failed_control_ids == ["SA-15(13)", "SI-2(7)"]
	r.failed_controls == 2
}

# passed + failed + not applicable = total (the module has no not-applicable outcome), and one row per id.
_totals_inputs := [{}, fully_compliant_input, {"ac_controls": {"access_enforcement": {"role_based_access_control": true}}}]

test_totals_add_up_slice_0 if {
	every inp in _slice(_totals_inputs, 0, 3) {
		r := main.compliance_report with input as inp
		c := r.control_result_counts
		passed := c.pass
		not_passed := (c.fail + c.evidence_missing) + c.not_attested
		passed + not_passed == r.total_controls
		not_passed == r.failed_controls
		count(r.control_results) == r.total_controls
		r.total_controls == 544
		r.coverage.catalog_active_controls_and_enhancements == 1014
	}
}

test_totals_add_up_slice_1 if {
	every inp in _slice(_totals_inputs, 1, 3) {
		r := main.compliance_report with input as inp
		c := r.control_result_counts
		passed := c.pass
		not_passed := (c.fail + c.evidence_missing) + c.not_attested
		passed + not_passed == r.total_controls
		not_passed == r.failed_controls
		count(r.control_results) == r.total_controls
		r.total_controls == 544
		r.coverage.catalog_active_controls_and_enhancements == 1014
	}
}

test_totals_add_up_slice_2 if {
	every inp in _slice(_totals_inputs, 2, 3) {
		r := main.compliance_report with input as inp
		c := r.control_result_counts
		passed := c.pass
		not_passed := (c.fail + c.evidence_missing) + c.not_attested
		passed + not_passed == r.total_controls
		not_passed == r.failed_controls
		count(r.control_results) == r.total_controls
		r.total_controls == 544
		r.coverage.catalog_active_controls_and_enhancements == 1014
	}
}
