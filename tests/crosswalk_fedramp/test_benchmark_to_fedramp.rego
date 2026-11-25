package crosswalk_fedramp_test

import rego.v1

import data.crosswalk.correlation
import data.crosswalk.framework_maps
import data.fedramp
import data.fedramp.main
import data.fedramp_test.good
import data.stig.rhel_9.green_test.green_fixture

# The pieces together, on the shipped data: a STIG report -> crosswalk.correlation (the shipped DISA map) ->
# crosswalk.framework_overlay (the shipped FedRAMP Rev 5 baseline maps) -> the FedRAMP report. Needs the
# repository root loaded (benchmarks/stig/rhel_9, crosswalk and frameworks/federal/fedramp), which is how CI
# runs `opa test .`. The combination rule is tested case by case in
# frameworks/federal/fedramp/tests/test_fedramp_benchmark.rego.

_row(r, id) := x if {
	some x in r.control_results
	x.id == id
}

_at(level) := object.union(good, {"impact_level": level})

# The shipped maps are the baselines' own control selection, each id mapped to itself, with a cited source.
test_shipped_fedramp_maps_are_identity_maps_of_the_baselines if {
	sizes := {"fedramp_rev5_low": 156, "fedramp_rev5_moderate": 323, "fedramp_rev5_high": 410, "fedramp_rev5_li_saas": 156}
	every key, size in sizes {
		spec := framework_maps.maps[key]
		spec.status == "authoritative"
		contains(spec.source, "sha256")
		count(spec.map) == size
		every id, ctrls in spec.map {
			ctrls == [id]
		}
	}

	# the module's own figures agree with the maps
	every level, size in fedramp.baseline_sizes {
		count(framework_maps.maps[concat("", ["fedramp_rev5_", level])].map) == size
	}

	# Low is within Moderate, Moderate within High: the High map is the fail-closed choice for an undeclared level
	every id, _ in framework_maps.maps.fedramp_rev5_low.map {
		framework_maps.maps.fedramp_rev5_moderate.map[id]
	}
	every id, _ in framework_maps.maps.fedramp_rev5_moderate.map {
		framework_maps.maps.fedramp_rev5_high.map[id]
	}
}

# The RHEL 9 STIG module's own report on its all-green fixture, at each impact level. The reach figures are the
# ones crosswalk/README.md states.
test_rhel9_stig_report_reaches_each_baseline_and_passes_nothing_by_itself if {
	stig := data.stig.rhel_9.main.compliance_report with input as green_fixture
	count(stig.rule_results) == 445
	stig.compliant
	reach := {"low": [156, 27, 20], "moderate": [323, 41, 6], "high": [410, 45, 2]}
	every level, want in reach {
		r := main.compliance_report with input as object.union(data.fedramp_test._stated, {"impact_level": level, "reports": [stig]})
		b := r.benchmark_evidence
		b.rules_supplied == 445
		b.rules_unmapped == 0
		b.unmapped_rules == []
		b.gap == []
		b.gap_not_in_baseline == []
		[b.baseline_controls, b.baseline_controls_reached, count(b.controls_not_in_baseline)] == want
		count(r.control_results) == want[0]

		# benchmark evidence alone passes nothing: the FedRAMP facts were not supplied, so the only pass is RA-2
		# (the declared impact level), which is this module's own check
		{x.id | some x in r.control_results; x.status == "pass"} == {"RA-2"}
		not r.compliant
		_row(r, "AC-7").status == "not_evaluated"
		"RHEL-09-411075" in _row(r, "AC-7").benchmark.rules
		_row(r, "CA-2").status == "fail"
	}
	hi := main.compliance_report with input as object.union(data.fedramp_test._stated, {"impact_level": "high", "reports": [stig]})
	hi.benchmark_evidence.controls_not_in_baseline == ["AU-14", "SC-11"]
	_row(hi, "AC-2(1)").benchmark.status == "not_evaluated"
}

# The same host with one release-support attestation withdrawn (RHEL-09-211010, which DISA maps to CM-6),
# against FedRAMP facts that pass every check of the module.
test_one_open_stig_rule_fails_its_control_over_declared_evidence if {
	clean := main.compliance_report with input as _at("moderate")
	clean.compliant
	stig := data.stig.rhel_9.main.compliance_report with input as object.union(green_fixture, {"attest": object.union(green_fixture.attest, {"rhel_09_211010_release_supported": false})})
	[x.rule | some x in stig.rule_results; x.status == "Open"] == ["RHEL-09-211010"]
	r := main.compliance_report with input as object.union(_at("moderate"), {"reports": [stig]})
	not r.compliant
	r.benchmark_evidence.gap == ["CM-6"]
	r.failed_control_ids == ["CM-6"]
	r.violations == ["FedRAMP CM-6: benchmark results show a gap: 1 mapped STIG rule(s) Open (RHEL-09-211010); the control fails regardless of its declared evidence or attestation"]
	_row(r, "CM-6").status == "fail"
	_row(r, "CM-6").benchmark.open_rules == ["RHEL-09-211010"]
	r.control_result_counts == {"pass": 11, "fail": 1, "not_evaluated": 311}
	r.area_summary == clean.area_summary

	# every other control the benchmark reached is recorded and changes nothing
	_row(r, "AC-7").status == "not_evaluated"
	_row(r, "AC-7").benchmark.status == "satisfied"
}

test_stig_report_without_facts_fails_every_reached_control if {
	stig := data.stig.rhel_9.main.compliance_report with input as {}
	stig.facts_supplied == false
	r := main.compliance_report with input as object.union(_at("high"), {"reports": [stig]})
	b := r.benchmark_evidence
	b.reports_without_facts == 1
	b.satisfied == []
	count(b.gap) == 45
	b.gap_not_in_baseline == ["AU-14", "SC-11"]
	r.control_result_counts.fail == 45
	_row(r, "AC-7").status == "fail"
	"FAIL-CLOSED: 1 benchmark report(s) had no facts supplied (facts_supplied is false); every rule in them counts as Open" in r.violations
}

test_passing_rows_cannot_hide_behind_a_report_without_facts if {
	rep := {"facts_supplied": false, "rule_results": [{"rule": "RHEL-09-411075", "status": "Not_a_Finding"}]}
	r := main.compliance_report with input as object.union(_at("low"), {"reports": [rep]})
	r.benchmark_evidence.satisfied == []
	r.benchmark_evidence.gap == ["AC-7"]
	_row(r, "AC-7").status == "fail"
	not r.compliant
}

test_findings_shape_and_unmapped_rule_ids if {
	r := main.compliance_report with input as object.union(_at("low"), {"findings": [
		{"stig_id": "RHEL-09-411075", "status": "Not_a_Finding"},
		{"stig_id": "RHEL-09-211020", "status": "Open"},
		{"stig_id": "NOT-A-STIG-RULE", "status": "Not_a_Finding"},
		{"stig_id": "5.2.4", "status": "Not_a_Finding"},
	]})
	b := r.benchmark_evidence
	b.unmapped_rules == ["5.2.4", "NOT-A-STIG-RULE"]
	b.rules_unmapped == 2
	b.satisfied == ["AC-7"]
	b.gap == ["AC-8"]
	r.control_result_counts == {"pass": 10, "fail": 1, "not_evaluated": 145}
	r.failed_control_ids == ["AC-8"]

	# only rules the DISA map knows appear as evidence anywhere
	every x in r.control_results {
		every rule in x.benchmark.rules {
			correlation.crosswalk[rule]
		}
	}
}

test_only_unmapped_rule_ids_never_satisfy if {
	r := main.compliance_report with input as object.union(_at("low"), {"findings": [{"stig_id": "NOT-A-STIG-RULE", "status": "Not_a_Finding"}]})
	r.benchmark_evidence.satisfied == []
	not r.compliant
	r.violations == ["FAIL-CLOSED: none of the 1 benchmark rule id(s) supplied is in the crosswalk, so no technical verdict could be taken; this is not a passing result"]
}

# RHEL-09-211045 maps to AC-6 only, which the Moderate and High baselines select and the Low baseline does not.
test_a_gap_fails_only_the_baselines_that_select_the_control if {
	open := {"findings": [{"stig_id": "RHEL-09-211045", "status": "Open"}]}
	low := main.compliance_report with input as object.union(_at("low"), open)
	low.compliant
	low.benchmark_evidence.gap == []
	low.benchmark_evidence.gap_not_in_baseline == ["AC-6"]
	not _row(low, "AC-6")

	mod := main.compliance_report with input as object.union(_at("moderate"), open)
	not mod.compliant
	mod.benchmark_evidence.gap == ["AC-6"]
	_row(mod, "AC-6").status == "fail"

	# until a level is declared the High baseline is used (and the missing level is a finding of its own)
	undeclared := main.compliance_report with input as object.union(good, open)
	undeclared.benchmark_evidence.map == "fedramp_rev5_high"
	"AC-6" in undeclared.failed_control_ids
}
