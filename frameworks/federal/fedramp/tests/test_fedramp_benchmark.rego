package fedramp.benchmark_test

import rego.v1

import data.fedramp
import data.fedramp.main
import data.fedramp_test.good

# The combination rule of package fedramp for benchmark results, tested on its own: the crosswalk's output is
# supplied with `with`, so these run whether or not crosswalk/ is loaded next to the module. The crosswalk is
# tested in crosswalk/tests, and the pieces together (with the RHEL 9 STIG and the shipped maps) in
# tests/crosswalk_fedramp.

_ev(st, rules, open) := {"status": st, "rules": rules, "open_rules": open, "not_reviewed_rules": []}

# One baseline control as crosswalk.framework_overlay.control_evidence gives it (identity map: one spine id).
_reached(id, ev) := {"status": _overlay_status(ev.status), "spine": {id: ev}, "not_evaluated": []}

_overlay_status(st) := st if {
	st in {"gap", "satisfied"}
} else := "not_covered"

_not_reached(id) := {"status": "not_covered", "spine": {}, "not_evaluated": [id]}

# A small stand-in for the Low baseline map: verdicts for the ids in `spine_ev`, nothing for the rest.
_low_ids := ["AC-2", "AC-2(1)", "AC-7", "AC-8", "AC-10", "CA-2", "CM-6", "IA-5", "SC-8"]

_overlay(key, spine_ev) := {key: {id: e |
	some id in _low_ids
	e := _entry(id, spine_ev)
}}

_entry(id, spine_ev) := _reached(id, spine_ev[id]) if {
	spine_ev[id]
} else := _not_reached(id)

_summary(supplied, unmapped) := {"rules_supplied": supplied, "rules_unmapped": unmapped}

_row(r, id) := x if {
	some x in r.control_results
	x.id == id
}

_low := object.union(good, {"impact_level": "low"})

_bench_input := object.union(_low, {"findings": [{"stig_id": "R-1", "status": "Not_a_Finding"}]})

# The reports' keys before benchmark results existed; the byte-for-byte comparison with the previous release is
# in the pull request, this keeps the sets from growing unnoticed.
_adapter_keys := {
	"framework", "regulation", "baseline", "impact_level", "impact_level_normalized", "assessed_at", "compliant",
	"violations", "violation_count", "failed_controls", "failed_control_ids", "total_controls",
	"controls_evaluated", "baseline_size", "kev_assessed", "kev_note", "baseline_sizes", "coverage_note",
	"area_summary",
}

_policy_keys := {
	"standard", "impact_level", "compliant", "compliance_score", "checks_evaluated", "checks_failed",
	"baseline_size", "kev_assessed", "total_violations", "violations", "areas",
}

_added := {"control_results", "control_result_counts", "benchmark_evidence"}

test_no_benchmark_input_reports_are_unchanged if {
	# the crosswalk has a gap to give, but the input carries no benchmark results: none of it reaches the reports
	spine_ev := {"CA-2": _ev("gap", ["R-1"], ["R-1"])}
	r := main.compliance_report with input as _low
		with data.crosswalk.correlation.spine_loaded as true
		with data.crosswalk.correlation.summary as _summary(1, 0)
		with data.crosswalk.correlation.control_evidence as spine_ev
		with data.crosswalk.framework_overlay.control_evidence as _overlay("fedramp_rev5_low", spine_ev)
	object.keys(r) == _adapter_keys
	r.compliant
	r.violations == []
	r.failed_control_ids == []
	p := fedramp.fedramp_compliance_report with input as _low
		with data.crosswalk.correlation.spine_loaded as true
		with data.crosswalk.correlation.summary as _summary(1, 0)
		with data.crosswalk.correlation.control_evidence as spine_ev
		with data.crosswalk.framework_overlay.control_evidence as _overlay("fedramp_rev5_low", spine_ev)
	object.keys(p) == _policy_keys
	p.compliant
	empty := main.compliance_report with input as {}
	object.keys(empty) == _adapter_keys
	empty.violation_count == 23
}

test_benchmark_satisfied_is_recorded_and_changes_no_status if {
	spine_ev := {"AC-7": _ev("satisfied", ["R-1", "R-2"], []), "CA-2": _ev("satisfied", ["R-3"], [])}
	r := main.compliance_report with input as _bench_input
		with data.crosswalk.correlation.spine_loaded as true
		with data.crosswalk.correlation.summary as _summary(3, 0)
		with data.crosswalk.correlation.unmapped_rules as set()
		with data.crosswalk.correlation.reports_without_facts as 0
		with data.crosswalk.correlation.control_evidence as spine_ev
		with data.crosswalk.framework_overlay.control_evidence as _overlay("fedramp_rev5_low", spine_ev)
	object.keys(r) == _adapter_keys | _added
	r.compliant
	r.violations == []
	r.failed_controls == 0
	r.failed_control_ids == []

	# a control this module checks keeps its own result; one it does not check stays not evaluated
	_row(r, "CA-2") == {"id": "CA-2", "status": "pass", "checked": true, "findings": [], "benchmark": {"status": "satisfied", "rules": ["R-3"], "open_rules": [], "not_reviewed_rules": []}}
	_row(r, "AC-7") == {"id": "AC-7", "status": "not_evaluated", "checked": false, "findings": [], "benchmark": {"status": "satisfied", "rules": ["R-1", "R-2"], "open_rules": [], "not_reviewed_rules": []}}
	b := r.benchmark_evidence
	b.satisfied == ["AC-7", "CA-2"]
	b.gap == []
	b.spine_loaded
	b.map == "fedramp_rev5_low"
	b.baseline == "low"
	b.baseline_controls == 9
	b.baseline_controls_reached == 2

	# 10 checks of the module, 8 other controls in the stand-in baseline
	r.control_result_counts == {"pass": 10, "fail": 0, "not_evaluated": 8}
	r.total_controls == 10
}

test_benchmark_satisfied_never_passes_a_control_by_itself if {
	# no FedRAMP facts at all: CA-2 has no evidence, whatever the benchmark says, and AC-7 has no check here
	spine_ev := {"AC-7": _ev("satisfied", ["R-1"], []), "CA-2": _ev("satisfied", ["R-1"], [])}
	r := main.compliance_report with input as {"impact_level": "low", "findings": [{"stig_id": "R-1", "status": "Not_a_Finding"}]}
		with data.crosswalk.correlation.spine_loaded as true
		with data.crosswalk.correlation.summary as _summary(1, 0)
		with data.crosswalk.correlation.unmapped_rules as set()
		with data.crosswalk.correlation.reports_without_facts as 0
		with data.crosswalk.correlation.control_evidence as spine_ev
		with data.crosswalk.framework_overlay.control_evidence as _overlay("fedramp_rev5_low", spine_ev)
	not r.compliant
	_row(r, "CA-2").status == "fail"
	_row(r, "CA-2").benchmark.status == "satisfied"
	_row(r, "AC-7").status == "not_evaluated"
	_row(r, "AC-7").benchmark.status == "satisfied"

	# the one pass is this module's own: RA-2, the declared impact level
	{x.id | some x in r.control_results; x.status == "pass"} == {"RA-2"}
	r.control_result_counts == {"pass": 1, "fail": 9, "not_evaluated": 8}
}

test_benchmark_gap_overrides_a_declared_pass if {
	clean := main.compliance_report with input as _low
	clean.compliant
	"CA-2" in clean.controls_evaluated

	spine_ev := {"CA-2": _ev("gap", ["R-1", "R-2"], ["R-2"]), "AC-7": _ev("gap", ["R-3"], ["R-3"])}
	r := main.compliance_report with input as _bench_input
		with data.crosswalk.correlation.spine_loaded as true
		with data.crosswalk.correlation.summary as _summary(3, 0)
		with data.crosswalk.correlation.unmapped_rules as set()
		with data.crosswalk.correlation.reports_without_facts as 0
		with data.crosswalk.correlation.control_evidence as spine_ev
		with data.crosswalk.framework_overlay.control_evidence as _overlay("fedramp_rev5_low", spine_ev)
	not r.compliant
	r.violations == [
		"FedRAMP AC-7: benchmark results show a gap: 1 mapped STIG rule(s) Open (R-3); the control fails regardless of its declared evidence or attestation",
		"FedRAMP CA-2: benchmark results show a gap: 1 mapped STIG rule(s) Open (R-2); the control fails regardless of its declared evidence or attestation",
	]
	r.violation_count == 2
	_row(r, "CA-2").status == "fail"
	_row(r, "CA-2").checked
	_row(r, "CA-2").benchmark.open_rules == ["R-2"]
	_row(r, "CA-2").findings == [r.violations[1]]
	_row(r, "AC-7").status == "fail"
	_row(r, "AC-7").checked == false
	r.benchmark_evidence.gap == ["AC-7", "CA-2"]

	# failed_control_ids names both; failed_controls counts this module's checks, so it stays within total_controls
	r.failed_control_ids == ["AC-7", "CA-2"]
	r.failed_controls == 1
	r.total_controls == 10
	r.control_result_counts == {"pass": 9, "fail": 2, "not_evaluated": 7}

	# the module's own areas are untouched: a benchmark gap is not an area
	r.area_summary == clean.area_summary

	p := fedramp.fedramp_compliance_report with input as _bench_input
		with data.crosswalk.correlation.spine_loaded as true
		with data.crosswalk.correlation.summary as _summary(3, 0)
		with data.crosswalk.correlation.unmapped_rules as set()
		with data.crosswalk.correlation.reports_without_facts as 0
		with data.crosswalk.correlation.control_evidence as spine_ev
		with data.crosswalk.framework_overlay.control_evidence as _overlay("fedramp_rev5_low", spine_ev)
	p.compliant == false
	p.checks_failed == 1
	p.total_violations == 2
	p.benchmark_evidence.gap == ["AC-7", "CA-2"]
	p.control_results == r.control_results
}

test_mixed_verdicts if {
	spine_ev := {
		"AC-7": _ev("gap", ["R-1", "R-2"], ["R-1"]),
		"AC-8": _ev("satisfied", ["R-3"], []),
		"IA-5": {"status": "not_reviewed", "rules": ["R-4"], "open_rules": [], "not_reviewed_rules": ["R-4"]},
		"SC-8": _ev("not_applicable", ["R-5"], []),
	}
	r := main.compliance_report with input as _bench_input
		with data.crosswalk.correlation.spine_loaded as true
		with data.crosswalk.correlation.summary as _summary(6, 1)
		with data.crosswalk.correlation.unmapped_rules as {"R-X"}
		with data.crosswalk.correlation.reports_without_facts as 0
		with data.crosswalk.correlation.control_evidence as spine_ev
		with data.crosswalk.framework_overlay.control_evidence as _overlay("fedramp_rev5_low", spine_ev)
	b := r.benchmark_evidence
	b.gap == ["AC-7"]
	b.satisfied == ["AC-8"]
	b.not_reviewed == ["IA-5"]
	b.not_applicable == ["SC-8"]
	b.rules_supplied == 6
	b.rules_unmapped == 1
	b.unmapped_rules == ["R-X"]
	b.controls_not_in_baseline == []
	b.baseline_controls_reached == 4

	# only the gap changes a status
	{x.id | some x in r.control_results; x.status == "fail"} == {"AC-7"}
	_row(r, "IA-5").status == "not_evaluated"
	_row(r, "IA-5").benchmark.not_reviewed_rules == ["R-4"]
	_row(r, "SC-8").status == "not_evaluated"

	# a control no rule speaks to, and an enhancement, is not evaluated by the benchmark
	_row(r, "AC-2").benchmark == {"status": "not_evaluated", "rules": [], "open_rules": [], "not_reviewed_rules": []}
	_row(r, "AC-2(1)").benchmark.status == "not_evaluated"

	# natural id order: AC-2 before AC-2(1) before AC-7 before AC-10, then the next family
	[x.id | some x in r.control_results; startswith(x.id, "AC-")] == ["AC-2", "AC-2(1)", "AC-7", "AC-8", "AC-10"]
	every x in r.control_results {
		x.benchmark.status in {"gap", "satisfied", "not_reviewed", "not_applicable", "not_evaluated"}
		x.status in {"pass", "fail", "not_evaluated"}
	}
}

test_report_without_facts_is_a_fail_closed_finding if {
	spine_ev := {"AC-7": _ev("gap", ["R-1"], ["R-1"])}
	r := main.compliance_report with input as object.union(_low, {"reports": [{"facts_supplied": false, "rule_results": [{"rule": "R-1", "status": "Not_a_Finding"}]}]})
		with data.crosswalk.correlation.spine_loaded as true
		with data.crosswalk.correlation.summary as _summary(1, 0)
		with data.crosswalk.correlation.unmapped_rules as set()
		with data.crosswalk.correlation.reports_without_facts as 1
		with data.crosswalk.correlation.control_evidence as spine_ev
		with data.crosswalk.framework_overlay.control_evidence as _overlay("fedramp_rev5_low", spine_ev)
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
		with data.crosswalk.framework_overlay.control_evidence as _overlay("fedramp_rev5_low", {})
	not r.compliant
	r.violations == ["FAIL-CLOSED: none of the 2 benchmark rule id(s) supplied is in the crosswalk, so no technical verdict could be taken; this is not a passing result"]
	r.benchmark_evidence.unmapped_rules == ["R-1", "R-9"]
	r.benchmark_evidence.satisfied == []
	r.benchmark_evidence.baseline_controls_reached == 0
	r.failed_controls == 0
	every x in r.control_results {
		x.benchmark.status == "not_evaluated"
	}
}

test_unreadable_benchmark_input_is_a_fail_closed_finding if {
	r := main.compliance_report with input as object.union(_low, {"reports": "none"})
		with data.crosswalk.correlation.spine_loaded as true
		with data.crosswalk.correlation.summary as _summary(0, 0)
		with data.crosswalk.correlation.unmapped_rules as set()
		with data.crosswalk.correlation.reports_without_facts as 0
		with data.crosswalk.correlation.control_evidence as {}
		with data.crosswalk.framework_overlay.control_evidence as _overlay("fedramp_rev5_low", {})
	not r.compliant
	count(r.violations) == 1
	startswith(r.violations[0], "FAIL-CLOSED: benchmark results were supplied (input.reports / input.findings) but no rule row could be read")
}

test_spine_not_loaded_is_a_fail_closed_finding if {
	spine_ev := {"AC-7": _ev("satisfied", ["R-1"], [])}
	r := main.compliance_report with input as _bench_input
		with data.crosswalk.correlation.spine_loaded as false
		with data.crosswalk.correlation.control_evidence as spine_ev
		with data.crosswalk.framework_overlay.control_evidence as _overlay("fedramp_rev5_low", spine_ev)
	not r.compliant
	count(r.violations) == 1
	startswith(r.violations[0], "FAIL-CLOSED: benchmark results were supplied (input.reports / input.findings) but the crosswalk (")
	r.benchmark_evidence == {
		"supplied": true, "spine_loaded": false, "map": "fedramp_rev5_low", "baseline": "low",
		"combination_rule": r.benchmark_evidence.combination_rule,
	}

	# without the baseline map the rows are this module's own checks, none with a benchmark verdict
	[x.id | some x in r.control_results] == ["CA-2", "CA-6", "CA-7", "CA-8", "IR-8", "PS-3", "RA-2", "RA-5", "SC-13", "SR-2"]
	every x in r.control_results {
		x.benchmark.status == "not_evaluated"
	}
	p := fedramp.fedramp_compliant with input as _bench_input
		with data.crosswalk.correlation.spine_loaded as false
	p == false
}

test_nothing_of_the_crosswalk_loaded_is_a_fail_closed_finding if {
	# no `with` at all on the crosswalk: when this file runs without crosswalk/ every reference is undefined;
	# when it runs from the repository root the stand-in rule id is simply unknown. Fail closed both ways.
	r := main.compliance_report with input as _bench_input
	not r.compliant
	count(r.violations) == 1
	startswith(r.violations[0], "FAIL-CLOSED: ")
	r.benchmark_evidence.supplied
	r.control_result_counts.fail == 0
}

test_baseline_map_missing_is_a_fail_closed_finding if {
	# the spine and its STIG map are loaded, the FedRAMP baseline map is not: no verdict can reach a control
	spine_ev := {"AC-7": _ev("gap", ["R-1"], ["R-1"])}
	r := main.compliance_report with input as _bench_input
		with data.crosswalk.correlation.spine_loaded as true
		with data.crosswalk.correlation.summary as _summary(1, 0)
		with data.crosswalk.correlation.unmapped_rules as set()
		with data.crosswalk.correlation.reports_without_facts as 0
		with data.crosswalk.correlation.control_evidence as spine_ev
		with data.crosswalk.framework_overlay.control_evidence as {"nist_800_53b_low": {"AC-7": _reached("AC-7", spine_ev["AC-7"])}}
	not r.compliant
	count(r.violations) == 1
	startswith(r.violations[0], "FAIL-CLOSED: benchmark results were supplied (input.reports / input.findings) but the crosswalk (")
	r.benchmark_evidence.spine_loaded == false
}

test_baseline_follows_the_declared_level_and_is_high_until_declared if {
	spine_ev := {"AC-7": _ev("gap", ["R-1"], ["R-1"])}
	maps := object.union(_overlay("fedramp_rev5_moderate", spine_ev), _overlay("fedramp_rev5_high", {}))

	mod := main.compliance_report with input as object.union(_bench_input, {"impact_level": "moderate"})
		with data.crosswalk.correlation.spine_loaded as true
		with data.crosswalk.correlation.summary as _summary(1, 0)
		with data.crosswalk.correlation.unmapped_rules as set()
		with data.crosswalk.correlation.reports_without_facts as 0
		with data.crosswalk.correlation.control_evidence as spine_ev
		with data.crosswalk.framework_overlay.control_evidence as maps
	mod.benchmark_evidence.map == "fedramp_rev5_moderate"
	mod.benchmark_evidence.gap == ["AC-7"]

	# the stand-in High map has no verdict for AC-7, so the spine's gap is outside it and listed as such
	undeclared := main.compliance_report with input as object.union(good, {"findings": []})
		with data.crosswalk.correlation.spine_loaded as true
		with data.crosswalk.correlation.summary as _summary(1, 0)
		with data.crosswalk.correlation.unmapped_rules as set()
		with data.crosswalk.correlation.reports_without_facts as 0
		with data.crosswalk.correlation.control_evidence as {"ZZ-1": _ev("gap", ["R-1"], ["R-1"])}
		with data.crosswalk.framework_overlay.control_evidence as maps
	undeclared.impact_level_normalized == "unknown"
	undeclared.benchmark_evidence.map == "fedramp_rev5_high"
	undeclared.benchmark_evidence.baseline == "high"
	undeclared.benchmark_evidence.gap == []
	undeclared.benchmark_evidence.controls_not_in_baseline == ["ZZ-1"]
	undeclared.benchmark_evidence.gap_not_in_baseline == ["ZZ-1"]
}

test_gap_on_a_control_the_baseline_does_not_select_is_listed_and_is_not_a_finding if {
	# AC-12 is in the stand-in spine verdicts and not in the stand-in Low baseline
	spine_ev := {"AC-12": _ev("gap", ["R-1"], ["R-1"]), "AC-7": _ev("satisfied", ["R-2"], [])}
	r := main.compliance_report with input as _bench_input
		with data.crosswalk.correlation.spine_loaded as true
		with data.crosswalk.correlation.summary as _summary(2, 0)
		with data.crosswalk.correlation.unmapped_rules as set()
		with data.crosswalk.correlation.reports_without_facts as 0
		with data.crosswalk.correlation.control_evidence as spine_ev
		with data.crosswalk.framework_overlay.control_evidence as _overlay("fedramp_rev5_low", spine_ev)
	r.compliant
	r.violations == []
	r.benchmark_evidence.controls_not_in_baseline == ["AC-12"]
	r.benchmark_evidence.gap_not_in_baseline == ["AC-12"]
	r.benchmark_evidence.gap == []
	not _row(r, "AC-12")
}

test_check_outside_the_baseline_keeps_its_row if {
	# SA-9(5) is not in the Low baseline; this module checks it at Low when the agency requires U.S. locations
	inp := object.union(_bench_input, {"data_residency": {"us_only_required": true, "storage_locations": [{"region": "eu-west-1"}], "processing_locations": [{"region": "us-east-1", "us_territory": true}]}})
	r := main.compliance_report with input as inp
		with data.crosswalk.correlation.spine_loaded as true
		with data.crosswalk.correlation.summary as _summary(1, 0)
		with data.crosswalk.correlation.unmapped_rules as set()
		with data.crosswalk.correlation.reports_without_facts as 0
		with data.crosswalk.correlation.control_evidence as {"AC-7": _ev("satisfied", ["R-1"], [])}
		with data.crosswalk.framework_overlay.control_evidence as _overlay("fedramp_rev5_low", {"AC-7": _ev("satisfied", ["R-1"], [])})
	_row(r, "SA-9(5)").status == "fail"
	_row(r, "SA-9(5)").checked
	count(_row(r, "SA-9(5)").findings) == 1
	r.failed_control_ids == ["SA-9(5)"]
}

test_long_rule_list_is_shortened_in_the_finding_and_whole_on_the_row if {
	rules := ["R-1", "R-2", "R-3", "R-4", "R-5", "R-6", "R-7"]
	spine_ev := {"CM-6": _ev("gap", rules, rules)}
	r := main.compliance_report with input as _bench_input
		with data.crosswalk.correlation.spine_loaded as true
		with data.crosswalk.correlation.summary as _summary(7, 0)
		with data.crosswalk.correlation.unmapped_rules as set()
		with data.crosswalk.correlation.reports_without_facts as 0
		with data.crosswalk.correlation.control_evidence as spine_ev
		with data.crosswalk.framework_overlay.control_evidence as _overlay("fedramp_rev5_low", spine_ev)
	r.violations == ["FedRAMP CM-6: benchmark results show a gap: 7 mapped STIG rule(s) Open (R-1, R-2, R-3, R-4, R-5 and 2 more, listed on the control's row); the control fails regardless of its declared evidence or attestation"]
	_row(r, "CM-6").benchmark.open_rules == rules
}
