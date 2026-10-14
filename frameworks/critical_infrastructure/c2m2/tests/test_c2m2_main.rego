# Tests for c2m2.main — DOE C2M2 Version 2.1 (June 2022).
package c2m2.main_test

import rego.v1

import data.c2m2.main

_all := {id: true | some id, _ in main.practices}

_upto(l) := {id: true | some id, p in main.practices; p.mil <= l}

_mil(l) := count({id | some id, p in main.practices; p.mil == l})

_dom(d) := count({id | some id, p in main.practices; p.domain == d})

test_row_counts_pinned if {
	count(main.practices) == 356
	count(main.model_domains) == 10
	count(main.objectives) == 43
	_mil(1) == 56
	_mil(2) == 166
	_mil(3) == 134
	_dom("ASSET") == 36
	_dom("THREAT") == 30
	_dom("RISK") == 39
	_dom("ACCESS") == 35
	_dom("SITUATION") == 28
	_dom("RESPONSE") == 49
	_dom("THIRD-PARTIES") == 25
	_dom("WORKFORCE") == 32
	_dom("ARCHITECTURE") == 58
	_dom("PROGRAM") == 24
}

test_every_practice_has_known_domain_objective_and_prefix if {
	count({id | some id, p in main.practices; not main.model_domains[p.domain]}) == 0
	count({id | some id, p in main.practices; not main.objectives[p.objective]}) == 0
	count({id | some id, p in main.practices; not startswith(id, p.objective)}) == 0
	count({id | some id, p in main.practices; not p.mil in {1, 2, 3}}) == 0
}

test_unlabelled_bands_are_mil3 if {
	every id in ["RESPONSE-4m", "RESPONSE-4p", "ARCHITECTURE-2h", "ARCHITECTURE-2l", "ARCHITECTURE-6c", "ARCHITECTURE-6f"] {
		main.practices[id].mil == 3
	}
	main.practices["RESPONSE-4l"].mil == 2
}

test_empty_input_fails_closed if {
	r := main.compliance_report with input as {}
	r.compliant == false
	r.target_mil == 3
	some m in r.violations
	contains(m, "FAIL-CLOSED")

	# FAIL-CLOSED + all 356 practices at the default target MIL3
	r.violation_count == 357
}

test_all_performed_is_compliant_mil3 if {
	inp := {"c2m2": {"practices": _all}}
	main.compliant with input as inp
	r := main.compliance_report with input as inp
	r.practices_evaluated == 356
	r.domains.ASSET.mil_achieved == 3
	r.mils.MIL3.domains_achieved == sort([d | some d, _ in main.model_domains])
}

test_target_mil1_evaluates_only_mil1 if {
	inp := {"c2m2": {"target_mil": 1, "practices": _upto(1)}}
	main.compliant with input as inp
	r := main.compliance_report with input as inp
	r.practices_evaluated == 56
	r.mils.MIL2.evaluated == false
	r.domains.RISK.mil_achieved == 1
}

test_target_mil2_needs_mil1_and_mil2 if {
	inp := {"c2m2": {"target_mil": 2, "practices": _upto(1)}}
	r := main.compliance_report with input as inp
	r.practices_evaluated == 222
	r.violation_count == 166
	inp2 := {"c2m2": {"target_mil": 2, "practices": _upto(2)}}
	main.compliant with input as inp2
}

test_one_false_is_named_and_lowers_mil_achieved if {
	inp := {"c2m2": {"practices": object.union(_all, {"ASSET-1a": false})}}
	v := main.violations with input as inp
	count(v) == 1
	some m in v
	contains(m, "ASSET-1a")
	contains(m, "MIL1")
	r := main.compliance_report with input as inp
	r.domains.ASSET.mil_achieved == 0
	r.domains.ASSET.gaps == ["ASSET-1a"]
	r.domains.THREAT.mil_achieved == 3
}

test_string_true_rejected_and_unknown_id_flagged if {
	inp := {"c2m2": {"practices": object.union(_all, {"RISK-2a": "true", "ASSET-9z": true})}}
	v := main.violations with input as inp
	count(v) == 2
	some m1 in v
	contains(m1, "RISK-2a")
	some m2 in v
	contains(m2, "unknown practice id ASSET-9z")
}

test_attested_above_target_is_not_unknown if {
	inp := {"c2m2": {"target_mil": 1, "practices": _all}}
	main.compliant with input as inp
}

test_invalid_target_mil_is_violation_and_strict if {
	every t in [4, "2", 2.5, null, 0] {
		r := main.compliance_report with input as {"c2m2": {"target_mil": t, "practices": _upto(1)}}
		r.target_mil == 3
		some m in r.violations
		contains(m, "target_mil must be 1, 2 or 3")
	}
}

test_non_object_container_fails_closed if {
	v := main.violations with input as {"c2m2": {"practices": ["ASSET-1a"]}}
	some m in v
	contains(m, "FAIL-CLOSED")
}

test_non_object_namespace_fails_closed if {
	v := main.violations with input as {"c2m2": 5}
	some m in v
	contains(m, "FAIL-CLOSED")
	r := main.compliance_report with input as {"c2m2": 5}
	r.compliant == false
	r.target_mil == 3
}
