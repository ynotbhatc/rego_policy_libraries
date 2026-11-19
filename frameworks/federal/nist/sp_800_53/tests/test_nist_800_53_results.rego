package nist.sp800_53.results_test

import rego.v1

import data.nist.sp800_53.index
import data.nist.sp800_53.main
import data.nist.sp800_53.main_test.fully_compliant_input

_row(r, id) := x if {
	some x in r.control_results
	x.id == id
}

test_one_row_per_evaluated_id_in_natural_order if {
	r := main.compliance_report with input as {}
	ids := [x.id | some x in r.control_results]
	count(ids) == 370
	{i | some i in ids} == main.evaluated_controls
	ids == index.order
	array.slice(ids, 0, 3) == ["AC-1", "AC-2", "AC-2(1)"]
}

test_empty_input_nothing_passes if {
	r := main.compliance_report with input as {}
	r.control_result_counts == {"pass": 0, "fail": 0, "evidence_missing": 330, "not_attested": 40}
	_row(r, "MA-2").status == "evidence_missing"
	_row(r, "PM-2").status == "not_attested"
	_row(r, "AC-2").status == "evidence_missing"
	count(_row(r, "AC-2").findings) == 1
}

test_compliant_input_every_row_passes if {
	r := main.compliance_report with input as fully_compliant_input
	r.control_result_counts == {"pass": 370, "fail": 0, "evidence_missing": 0, "not_attested": 0}
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
	r.control_result_counts.pass == 368
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
	count(r.control_results) == 370
	r.control_result_counts.pass == 370
	r.baseline_results.nist_moderate.in_scope == 287
}

test_low_and_moderate_fully_evaluated if {
	r := main.compliance_report with input as {}
	r.baseline_results.nist_low.not_evaluated == 0
	r.baseline_results.nist_moderate.not_evaluated == 0
	r.baseline_results.nist_moderate.evaluated == 287
}
