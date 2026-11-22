package crosswalk.control_evidence_test

import rego.v1

import data.crosswalk.correlation
import data.crosswalk.framework_overlay

_map := {
	"R-PASS": ["AC-2"],
	"R-OPEN": ["AC-2", "AU-3"],
	"R-NA": ["CM-6", "SC-8"],
	"R-PASS2": ["SC-8"],
	"R-REVIEW": ["IA-5"],
	"R-PASS3": ["IA-5", "SI-2"],
}

_report := {"facts_supplied": true, "rule_results": [
	{"rule": "R-PASS", "status": "Not_a_Finding"},
	{"rule": "R-OPEN", "status": "Open"},
	{"rule": "R-NA", "status": "Not_Applicable"},
	{"rule": "R-PASS2", "status": "Not_a_Finding"},
	{"rule": "R-REVIEW", "status": "Not_Reviewed"},
	{"rule": "R-PASS3", "status": "Not_a_Finding"},
	{"rule": "R-UNKNOWN", "status": "Not_a_Finding"},
]}

test_evidence_lists_the_contributing_rules if {
	ev := correlation.control_evidence with input as {"reports": [_report]}
		with data.crosswalk.stig_800_53.map as _map
	ev == {
		"AC-2": {"status": "gap", "rules": ["R-OPEN", "R-PASS"], "open_rules": ["R-OPEN"], "not_reviewed_rules": []},
		"AU-3": {"status": "gap", "rules": ["R-OPEN"], "open_rules": ["R-OPEN"], "not_reviewed_rules": []},
		"CM-6": {"status": "not_applicable", "rules": ["R-NA"], "open_rules": [], "not_reviewed_rules": []},
		"SC-8": {"status": "satisfied", "rules": ["R-NA", "R-PASS2"], "open_rules": [], "not_reviewed_rules": []},
		"IA-5": {"status": "not_reviewed", "rules": ["R-PASS3", "R-REVIEW"], "open_rules": [], "not_reviewed_rules": ["R-REVIEW"]},
		"SI-2": {"status": "satisfied", "rules": ["R-PASS3"], "open_rules": [], "not_reviewed_rules": []},
	}
}

test_evidence_status_always_equals_control_status if {
	inp := {"reports": [_report], "findings": [{"stig_id": "R-PASS2", "status": "Open"}]}
	ev := correlation.control_evidence with input as inp with data.crosswalk.stig_800_53.map as _map
	cs := correlation.control_status with input as inp with data.crosswalk.stig_800_53.map as _map
	{c: e.status | some c, e in ev} == cs
	ev["SC-8"].status == "gap"
	ev["SC-8"].open_rules == ["R-PASS2"]
}

test_findings_shape_gives_the_same_evidence if {
	ev := correlation.control_evidence with input as {"findings": [
		{"stig_id": "R-PASS", "status": "Not_a_Finding"},
		{"stig_id": "R-PASS2", "status": "Not_a_Finding"},
	]}
		with data.crosswalk.stig_800_53.map as _map
	ev == {
		"AC-2": {"status": "satisfied", "rules": ["R-PASS"], "open_rules": [], "not_reviewed_rules": []},
		"SC-8": {"status": "satisfied", "rules": ["R-PASS2"], "open_rules": [], "not_reviewed_rules": []},
	}
}

test_report_without_facts_never_satisfies if {
	rep := object.union(_report, {"facts_supplied": false})
	ev := correlation.control_evidence with input as {"reports": [rep]}
		with data.crosswalk.stig_800_53.map as _map
	count(ev) == 6
	every _, e in ev {
		e.status == "gap"
		e.open_rules == e.rules
	}
	n := correlation.reports_without_facts with input as {"reports": [rep, _report]}
	n == 1
}

test_unmapped_rules_give_no_evidence if {
	inp := {"findings": [{"stig_id": "R-UNKNOWN", "status": "Not_a_Finding"}, {"stig_id": "R-OTHER", "status": "Open"}]}
	ev := correlation.control_evidence with input as inp with data.crosswalk.stig_800_53.map as _map
	count(ev) == 0
	um := correlation.unmapped_rules with input as inp with data.crosswalk.stig_800_53.map as _map
	um == {"R-UNKNOWN", "R-OTHER"}
}

test_evidence_supplied_reads_either_key if {
	correlation.evidence_supplied with input as {"reports": []}
	correlation.evidence_supplied with input as {"findings": []}
	not correlation.evidence_supplied with input as {"ac_controls": {}}
	not correlation.evidence_supplied with input as {}
	n := correlation.reports_without_facts with input as {}
	n == 0
}

test_spine_loaded_needs_the_map if {
	correlation.spine_loaded with data.crosswalk.stig_800_53.map as _map
	not correlation.spine_loaded with data.crosswalk.stig_800_53.map as {}
	not correlation.spine_loaded with data.crosswalk.stig_800_53 as {}
}

_fw_maps := {
	"fw_a": {"name": "A", "source": "test", "status": "authoritative", "map": {
		"A.1": ["SC-8"],
		"A.2": ["SC-8", "SI-2"],
		"A.3": ["AC-2", "SC-8"],
		"A.4": ["SC-8", "PE-3"],
		"A.5": ["PE-3"],
		"A.6": ["IA-5"],
		"A.7": [],
	}},
	"fw_pending": {"name": "P", "source": "none", "status": "pending", "map": {"P.1": ["SC-8"]}},
}

test_framework_evidence_follows_the_map if {
	ev := framework_overlay.control_evidence with input as {"reports": [_report]}
		with data.crosswalk.stig_800_53.map as _map
		with data.crosswalk.framework_maps.maps as _fw_maps
	object.keys(ev) == {"fw_a"}
	a := ev.fw_a
	a["A.1"].status == "satisfied"
	a["A.1"].spine == {"SC-8": {"status": "satisfied", "rules": ["R-NA", "R-PASS2"], "open_rules": [], "not_reviewed_rules": []}}
	a["A.1"].not_evaluated == []
	a["A.2"].status == "satisfied"
	a["A.3"].status == "gap"
	a["A.3"].spine["AC-2"].open_rules == ["R-OPEN"]

	# partly evaluated, never evaluated, an unresolved review, and an empty mapping are all not_covered
	a["A.4"].status == "not_covered"
	a["A.4"].not_evaluated == ["PE-3"]
	object.keys(a["A.4"].spine) == {"SC-8"}
	a["A.5"] == {"status": "not_covered", "spine": {}, "not_evaluated": ["PE-3"]}
	a["A.6"].status == "not_covered"
	a["A.7"].status == "not_covered"
}

test_framework_evidence_agrees_with_coverage if {
	ev := framework_overlay.control_evidence.fw_a with input as {"reports": [_report]}
		with data.crosswalk.stig_800_53.map as _map
		with data.crosswalk.framework_maps.maps as _fw_maps
	cov := framework_overlay.coverage.fw_a with input as {"reports": [_report]}
		with data.crosswalk.stig_800_53.map as _map
		with data.crosswalk.framework_maps.maps as _fw_maps

	# a control mapped to two satisfied spine controls is counted once
	cov.satisfied == ["A.1", "A.2"]
	cov.controls_satisfied == 2
	every st in ["satisfied", "gap", "not_covered"] {
		sort([fc | some fc, e in ev; e.status == st]) == {"satisfied": cov.satisfied, "gap": cov.gaps, "not_covered": cov.not_covered}[st]
	}
}

test_framework_evidence_without_input_is_all_not_covered if {
	ev := framework_overlay.control_evidence.fw_a with input as {}
		with data.crosswalk.stig_800_53.map as _map
		with data.crosswalk.framework_maps.maps as _fw_maps
	every _, e in ev {
		e.status == "not_covered"
		e.spine == {}
	}
}
