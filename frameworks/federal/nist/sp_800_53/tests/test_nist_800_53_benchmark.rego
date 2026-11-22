package nist.sp800_53.benchmark_test

import rego.v1

import data.nist.sp800_53.main
import data.nist.sp800_53.main_test.fully_compliant_input

# The combination rule of nist.sp800_53.main, tested on its own: the crosswalk spine's output is supplied with
# `with`, so these run whether or not crosswalk/ is loaded next to the module. The spine itself is tested in
# crosswalk/tests, and the two together (with the RHEL 9 STIG) in tests/crosswalk_800_53.

_ev(st, rules, open) := {"status": st, "rules": rules, "open_rules": open, "not_reviewed_rules": []}

_row(r, id) := x if {
	some x in r.control_results
	x.id == id
}

_bench_input := object.union(fully_compliant_input, {"findings": [{"stig_id": "R-1", "status": "Not_a_Finding"}]})

# The report's keys before benchmark results existed; the byte-for-byte comparison with the previous release
# is in the pull request, this keeps the set from growing unnoticed.
_report_keys := {
	"framework", "version", "regulation", "assessed_at", "total_controls", "failed_controls", "failed_control_ids",
	"coverage", "control_results", "control_result_counts", "baseline_results", "violations", "violation_count",
	"compliant", "families_evaluated", "family_summary",
}

_summary(supplied, unmapped) := {"rules_supplied": supplied, "rules_unmapped": unmapped}

test_no_benchmark_input_report_is_unchanged if {
	# the spine has verdicts to give, but the input carries no benchmark results: none of it reaches the report
	r := main.compliance_report with input as fully_compliant_input
		with data.crosswalk.correlation.spine_loaded as true
		with data.crosswalk.correlation.control_evidence as {"AC-7": _ev("gap", ["R-1"], ["R-1"])}
	object.keys(r) == _report_keys
	not r.benchmark_evidence
	r.compliant
	every x in r.control_results {
		not x.benchmark
	}
	empty := main.compliance_report with input as {}
	not empty.benchmark_evidence
	empty.violation_count == 542
}

test_benchmark_satisfied_is_recorded_and_changes_no_status if {
	r := main.compliance_report with input as _bench_input
		with data.crosswalk.correlation.spine_loaded as true
		with data.crosswalk.correlation.summary as _summary(2, 0)
		with data.crosswalk.correlation.unmapped_rules as set()
		with data.crosswalk.correlation.reports_without_facts as 0
		with data.crosswalk.correlation.control_evidence as {"AC-7": _ev("satisfied", ["R-1", "R-2"], [])}
	r.compliant
	r.violations == []
	_row(r, "AC-7").status == "pass"
	_row(r, "AC-7").benchmark == {"status": "satisfied", "rules": ["R-1", "R-2"], "open_rules": [], "not_reviewed_rules": []}
	r.benchmark_evidence.satisfied == ["AC-7"]
	r.benchmark_evidence.gap == []
	r.benchmark_evidence.spine_loaded
	r.control_result_counts.pass == 542
}

test_benchmark_satisfied_never_passes_a_control_by_itself if {
	# no family facts and no attestations: AC-7 has no evidence and AU-14 no attestation, whatever the benchmark says
	r := main.compliance_report with input as {"findings": [{"stig_id": "R-1", "status": "Not_a_Finding"}]}
		with data.crosswalk.correlation.spine_loaded as true
		with data.crosswalk.correlation.summary as _summary(1, 0)
		with data.crosswalk.correlation.unmapped_rules as set()
		with data.crosswalk.correlation.reports_without_facts as 0
		with data.crosswalk.correlation.control_evidence as {
			"AC-7": _ev("satisfied", ["R-1"], []),
			"AU-14": _ev("satisfied", ["R-1"], []),
		}
	_row(r, "AC-7").status == "evidence_missing"
	_row(r, "AC-7").benchmark.status == "satisfied"
	_row(r, "AU-14").status == "not_attested"
	_row(r, "AU-14").basis == "attestation"
	_row(r, "AU-14").benchmark.status == "satisfied"
	r.control_result_counts == {"pass": 0, "fail": 0, "evidence_missing": 476, "not_attested": 66}
	not r.compliant
}

test_benchmark_gap_overrides_an_attested_pass if {
	clean := main.compliance_report with input as fully_compliant_input
	_row(clean, "AU-14").status == "pass"
	_row(clean, "AU-14").basis == "attestation"

	r := main.compliance_report with input as _bench_input
		with data.crosswalk.correlation.spine_loaded as true
		with data.crosswalk.correlation.summary as _summary(2, 0)
		with data.crosswalk.correlation.unmapped_rules as set()
		with data.crosswalk.correlation.reports_without_facts as 0
		with data.crosswalk.correlation.control_evidence as {
			"AU-14": _ev("gap", ["R-1", "R-2"], ["R-2"]),
			"AC-7": _ev("gap", ["R-3"], ["R-3"]),
		}
	not r.compliant
	_row(r, "AU-14").status == "fail"
	_row(r, "AU-14").benchmark.open_rules == ["R-2"]
	_row(r, "AU-14").findings == ["NIST AU-14: benchmark results show a gap: 1 mapped STIG rule(s) Open (R-2); the control fails regardless of its declared evidence or attestation"]
	_row(r, "AC-7").status == "fail"
	r.failed_control_ids == ["AC-7", "AU-14"]
	r.failed_controls == 2
	r.violation_count == 2
	r.control_result_counts == {"pass": 540, "fail": 2, "evidence_missing": 0, "not_attested": 0}
	r.family_summary.AU == {"violations": 1, "compliant": false}
	r.family_summary.AC == {"violations": 1, "compliant": false}
	r.family_summary.CM == {"violations": 0, "compliant": true}
	r.benchmark_evidence.gap == ["AC-7", "AU-14"]
	r.baseline_results.nist_low.not_passed_ids == ["AC-7"]
}

test_benchmark_gap_reaches_the_framework_key if {
	r := data.nist_800_53.main.compliance_report with input as _bench_input
		with data.crosswalk.correlation.spine_loaded as true
		with data.crosswalk.correlation.summary as _summary(1, 0)
		with data.crosswalk.correlation.unmapped_rules as set()
		with data.crosswalk.correlation.reports_without_facts as 0
		with data.crosswalk.correlation.control_evidence as {"AC-7": _ev("gap", ["R-3"], ["R-3"])}
	not r.compliant
	r.failed_controls == 1
	r.violation_count == 1
	r.facts_supplied
	r.benchmark_evidence.gap == ["AC-7"]
}

test_mixed_verdicts if {
	r := main.compliance_report with input as _bench_input
		with data.crosswalk.correlation.spine_loaded as true
		with data.crosswalk.correlation.summary as _summary(6, 1)
		with data.crosswalk.correlation.unmapped_rules as {"R-X"}
		with data.crosswalk.correlation.reports_without_facts as 0
		with data.crosswalk.correlation.control_evidence as {
			"AC-7": _ev("gap", ["R-1", "R-2"], ["R-1"]),
			"AC-8": _ev("satisfied", ["R-3"], []),
			"IA-5": {"status": "not_reviewed", "rules": ["R-4"], "open_rules": [], "not_reviewed_rules": ["R-4"]},
			"SC-8": _ev("not_applicable", ["R-5"], []),
		}
	b := r.benchmark_evidence
	b.gap == ["AC-7"]
	b.satisfied == ["AC-8"]
	b.not_reviewed == ["IA-5"]
	b.not_applicable == ["SC-8"]
	b.rules_supplied == 6
	b.rules_unmapped == 1
	b.unmapped_rules == ["R-X"]
	b.controls_not_in_module == []

	# only the gap changes a status
	{x.id | some x in r.control_results; x.status != "pass"} == {"AC-7"}
	_row(r, "IA-5").benchmark.not_reviewed_rules == ["R-4"]

	# a control no rule speaks to, and every enhancement, is not evaluated by the benchmark
	_row(r, "AC-2").benchmark == {"status": "not_evaluated", "rules": [], "open_rules": [], "not_reviewed_rules": []}
	_row(r, "AC-7").benchmark.status == "gap"
	every x in r.control_results {
		x.benchmark.status in {"gap", "satisfied", "not_reviewed", "not_applicable", "not_evaluated"}
	}
	count([x | some x in r.control_results; x.benchmark.status == "not_evaluated"]) == 538
}

test_report_without_facts_is_a_fail_closed_finding if {
	r := main.compliance_report with input as object.union(fully_compliant_input, {"reports": [{"facts_supplied": false, "rule_results": [{"rule": "R-1", "status": "Not_a_Finding"}]}]})
		with data.crosswalk.correlation.spine_loaded as true
		with data.crosswalk.correlation.summary as _summary(1, 0)
		with data.crosswalk.correlation.unmapped_rules as set()
		with data.crosswalk.correlation.reports_without_facts as 1
		with data.crosswalk.correlation.control_evidence as {"AC-7": _ev("gap", ["R-1"], ["R-1"])}
	not r.compliant
	r.benchmark_evidence.reports_without_facts == 1
	r.benchmark_evidence.satisfied == []
	"FAIL-CLOSED: 1 benchmark report(s) had no facts supplied (facts_supplied is false); every rule in them counts as Open" in r.violations
	_row(r, "AC-7").status == "fail"
}

test_only_unmapped_rules_is_a_fail_closed_finding if {
	r := main.compliance_report with input as _bench_input
		with data.crosswalk.correlation.spine_loaded as true
		with data.crosswalk.correlation.summary as _summary(2, 2)
		with data.crosswalk.correlation.unmapped_rules as {"R-1", "R-9"}
		with data.crosswalk.correlation.reports_without_facts as 0
		with data.crosswalk.correlation.control_evidence as {}
	not r.compliant
	r.violations == ["FAIL-CLOSED: none of the 2 benchmark rule id(s) supplied is in the crosswalk, so no technical verdict could be taken; this is not a passing result"]
	r.benchmark_evidence.unmapped_rules == ["R-1", "R-9"]
	r.benchmark_evidence.satisfied == []
	r.failed_controls == 0
	every x in r.control_results {
		x.benchmark.status == "not_evaluated"
	}
}

test_unreadable_benchmark_input_is_a_fail_closed_finding if {
	r := main.compliance_report with input as object.union(fully_compliant_input, {"reports": "none"})
		with data.crosswalk.correlation.spine_loaded as true
		with data.crosswalk.correlation.summary as _summary(0, 0)
		with data.crosswalk.correlation.unmapped_rules as set()
		with data.crosswalk.correlation.reports_without_facts as 0
		with data.crosswalk.correlation.control_evidence as {}
	not r.compliant
	count(r.violations) == 1
	startswith(r.violations[0], "FAIL-CLOSED: benchmark results were supplied (input.reports / input.findings) but no rule row could be read")
}

test_spine_not_loaded_is_a_fail_closed_finding if {
	r := main.compliance_report with input as _bench_input
		with data.crosswalk.correlation.spine_loaded as false
		with data.crosswalk.correlation.control_evidence as {"AC-7": _ev("satisfied", ["R-1"], [])}
	not r.compliant
	count(r.violations) == 1
	startswith(r.violations[0], "FAIL-CLOSED: benchmark results were supplied (input.reports / input.findings) but the crosswalk spine")
	r.benchmark_evidence.supplied
	r.benchmark_evidence.spine_loaded == false
	not r.benchmark_evidence.satisfied
	every x in r.control_results {
		x.benchmark.status == "not_evaluated"
	}
	k := data.nist_800_53.main.compliance_report with input as _bench_input
		with data.crosswalk.correlation.spine_loaded as false
	not k.compliant
}

test_long_rule_list_is_shortened_in_the_finding_and_whole_on_the_row if {
	rules := ["R-1", "R-2", "R-3", "R-4", "R-5", "R-6", "R-7"]
	r := main.compliance_report with input as _bench_input
		with data.crosswalk.correlation.spine_loaded as true
		with data.crosswalk.correlation.summary as _summary(7, 0)
		with data.crosswalk.correlation.unmapped_rules as set()
		with data.crosswalk.correlation.reports_without_facts as 0
		with data.crosswalk.correlation.control_evidence as {"CM-6": _ev("gap", rules, rules)}
	r.violations == ["NIST CM-6: benchmark results show a gap: 7 mapped STIG rule(s) Open (R-1, R-2, R-3, R-4, R-5 and 2 more, listed on the control's row); the control fails regardless of its declared evidence or attestation"]
	_row(r, "CM-6").benchmark.open_rules == rules
}

test_gap_on_a_control_the_module_does_not_evaluate_still_fails if {
	r := main.compliance_report with input as _bench_input
		with data.crosswalk.correlation.spine_loaded as true
		with data.crosswalk.correlation.summary as _summary(1, 0)
		with data.crosswalk.correlation.unmapped_rules as set()
		with data.crosswalk.correlation.reports_without_facts as 0
		with data.crosswalk.correlation.control_evidence as {"ZZ-1": _ev("gap", ["R-1"], ["R-1"])}
	not r.compliant
	r.benchmark_evidence.controls_not_in_module == ["ZZ-1"]
	count(r.violations) == 1
	startswith(r.violations[0], "NIST ZZ-1: benchmark results show a gap")

	# failed_controls counts evaluated ids only, so it stays within total_controls
	r.failed_controls == 0
}
