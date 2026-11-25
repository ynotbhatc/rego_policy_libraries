package crosswalk_800_53_test

import rego.v1

import data.crosswalk.correlation
import data.nist.sp800_53.main
import data.nist.sp800_53.main_test.fully_compliant_input
import data.stig.rhel_9.green_test.green_fixture

# The three pieces together, on the shipped data: a STIG report -> crosswalk.correlation (the shipped DISA map)
# -> the NIST SP 800-53 report. Needs the repository root loaded (benchmarks/stig/rhel_9, crosswalk and
# frameworks/federal/nist/sp_800_53), which is how CI runs `opa test .`. The combination rule is tested case
# by case in frameworks/federal/nist/sp_800_53/tests/test_nist_800_53_benchmark.rego; each test here evaluates
# the 800-53 report once.

_row(r, id) := x if {
	some x in r.control_results
	x.id == id
}

# The RHEL 9 STIG module's own report on its all-green fixture.
test_rhel9_stig_report_reaches_the_spine_and_passes_nothing_by_itself if {
	stig := data.stig.rhel_9.main.compliance_report with input as green_fixture
	count(stig.rule_results) == 445
	stig.compliant
	r := main.compliance_report with input as {"reports": [stig]}
	b := r.benchmark_evidence
	b.rules_supplied == 445

	# every rule of the module is in the map (regenerated from the V2R10 XCCDF)
	b.rules_unmapped == count(b.unmapped_rules)
	b.rules_unmapped == 0
	b.gap == []
	b.not_reviewed == []
	count(b.satisfied) >= 47
	"AC-7" in b.satisfied
	"RHEL-09-411075" in _row(r, "AC-7").benchmark.rules
	_row(r, "AC-2(1)").benchmark.status == "not_evaluated"

	# benchmark evidence alone passes nothing: the family facts and attestations were not supplied
	r.control_result_counts == {"pass": 0, "fail": 0, "evidence_missing": 478, "not_attested": 66}
	_row(r, "AC-7").status == "evidence_missing"
	_row(r, "AU-14").status == "not_attested"
	_row(r, "AU-14").benchmark.status == "satisfied"
	not r.compliant
}

# The same host with one release-support attestation withdrawn (RHEL-09-211010, which DISA maps to CM-6),
# against declared evidence that passes every control.
test_one_open_stig_rule_fails_its_control_over_declared_evidence if {
	stig := data.stig.rhel_9.main.compliance_report with input as object.union(green_fixture, {"attest": object.union(green_fixture.attest, {"rhel_09_211010_release_supported": false})})
	[x.rule | some x in stig.rule_results; x.status == "Open"] == ["RHEL-09-211010"]
	r := main.compliance_report with input as object.union(fully_compliant_input, {"reports": [stig]})
	not r.compliant
	r.benchmark_evidence.gap == ["CM-6"]
	r.failed_control_ids == ["CM-6"]
	_row(r, "CM-6").status == "fail"
	_row(r, "CM-6").benchmark.open_rules == ["RHEL-09-211010"]
	_row(r, "CM-6").findings == ["NIST CM-6: benchmark results show a gap: 1 mapped STIG rule(s) Open (RHEL-09-211010); the control fails regardless of its declared evidence or attestation"]
	r.family_summary.CM == {"violations": 1, "compliant": false}
	r.control_result_counts == {"pass": 543, "fail": 1, "evidence_missing": 0, "not_attested": 0}

	# every other control the benchmark reached is satisfied there and passes on its own declared evidence
	_row(r, "AC-7").status == "pass"
	_row(r, "AC-7").benchmark.status == "satisfied"
}

test_stig_report_without_facts_fails_every_reached_control if {
	stig := data.stig.rhel_9.main.compliance_report with input as {}
	stig.facts_supplied == false
	r := main.compliance_report with input as {"reports": [stig]}
	b := r.benchmark_evidence
	b.reports_without_facts == 1
	b.satisfied == []
	count(b.gap) >= 47
	r.control_result_counts.fail == count(b.gap)
	_row(r, "AC-7").status == "fail"
	"FAIL-CLOSED: 1 benchmark report(s) had no facts supplied (facts_supplied is false); every rule in them counts as Open" in r.violations
}

test_passing_rows_cannot_hide_behind_a_report_without_facts if {
	# a report that claims a pass but says its facts were not supplied
	rep := {"facts_supplied": false, "rule_results": [{"rule": "RHEL-09-411075", "status": "Not_a_Finding"}]}
	r := main.compliance_report with input as {"reports": [rep]}
	r.benchmark_evidence.satisfied == []
	r.benchmark_evidence.gap == ["AC-7"]
	_row(r, "AC-7").status == "fail"
}

test_findings_shape_and_unmapped_rule_ids if {
	r := main.compliance_report with input as {"findings": [
		{"stig_id": "RHEL-09-411075", "status": "Not_a_Finding"},
		{"stig_id": "RHEL-09-211020", "status": "Open"},
		{"stig_id": "NOT-A-STIG-RULE", "status": "Not_a_Finding"},
		{"stig_id": "5.2.4", "status": "Not_a_Finding"},
	]}
	b := r.benchmark_evidence
	b.unmapped_rules == ["5.2.4", "NOT-A-STIG-RULE"]
	b.rules_unmapped == 2
	b.satisfied == ["AC-7"]
	b.gap == ["AC-8"]
	r.control_result_counts.fail == 1
	r.control_result_counts.pass == 0

	# only rules the DISA map knows appear as evidence anywhere
	every x in r.control_results {
		every rule in x.benchmark.rules {
			correlation.crosswalk[rule]
		}
	}
}

test_only_unmapped_rule_ids_never_satisfy if {
	r := main.compliance_report with input as {"findings": [{"stig_id": "NOT-A-STIG-RULE", "status": "Not_a_Finding"}]}
	r.benchmark_evidence.satisfied == []
	r.control_result_counts.pass == 0
	"FAIL-CLOSED: none of the 1 benchmark rule id(s) supplied is in the crosswalk, so no technical verdict could be taken; this is not a passing result" in r.violations
}
