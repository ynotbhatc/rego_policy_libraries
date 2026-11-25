package nist_800_82.main_evidence_test

import rego.v1

# Evidence rule (audit 2026-11-24, round 2). Every yes/no fact the module reads passes only as the boolean
# true. Missing, null, "true", "false", "no", 0, 1, a list or an object fail the control, and the finding
# names the problem. Data-driven over the 35 facts.

report := data.nist_800_82.main.compliance_report

violations := data.nist_800_82.main.violations

all_pass := {
	"risk_assessment": {
		"ot_specific": {
			"conducted": true,
		},
		"consequence_analysis": {
			"life_safety": true,
			"environmental": true,
		},
		"asset_inventory": {
			"ot_systems": true,
		},
	},
	"network": {
		"ot_it_segmentation": {
			"implemented": true,
		},
		"demilitarized_zone": {
			"exists": true,
		},
		"wireless": {
			"ot_wireless_restricted": true,
		},
		"remote_access": {
			"ot_specific_controls": true,
		},
		"dial_up": {
			"disabled_or_controlled": true,
		},
		"data_flows": {
			"documented": true,
		},
	},
	"access_control": {
		"ot_accounts": {
			"managed": true,
		},
		"privileged_access": {
			"ot": {
				"controlled": true,
			},
		},
		"vendor_remote": {
			"managed": true,
		},
		"physical_ot_access": {
			"controlled": true,
		},
	},
	"configuration": {
		"ot_baseline": {
			"established": true,
		},
		"change_management": {
			"ot_process": true,
		},
		"removable_media": {
			"controlled": true,
		},
		"software": {
			"authorized_only": true,
		},
	},
	"patch_management": {
		"ot": {
			"policy_exists": true,
			"compensating_controls": true,
			"vendor_coordination": true,
		},
	},
	"incident_response": {
		"ot_specific": {
			"plan_exists": true,
			"coordination_with_safety": true,
			"forensics_consideration": true,
		},
		"reporting": {
			"ics_cert": true,
		},
	},
	"monitoring": {
		"ot_network": {
			"continuous": true,
			"protocol_aware": true,
		},
		"historian": {
			"log_integrity": true,
		},
	},
	"system_integrity": {
		"malware_protection": {
			"ot_appropriate": true,
		},
		"firmware": {
			"integrity_verified": true,
		},
	},
	"contingency": {
		"backup": {
			"ot_configurations": true,
		},
		"recovery": {
			"ot_rto_defined": true,
		},
		"manual_operations": {
			"procedures_documented": true,
		},
	},
	"supply_chain": {
		"ot_equipment": {
			"vendor_assessment": true,
			"counterfeit_protection": true,
		},
	},
}

fact_paths := [["risk_assessment", "ot_specific", "conducted"], ["risk_assessment", "consequence_analysis", "life_safety"], ["risk_assessment", "consequence_analysis", "environmental"], ["risk_assessment", "asset_inventory", "ot_systems"], ["network", "ot_it_segmentation", "implemented"], ["network", "demilitarized_zone", "exists"], ["network", "wireless", "ot_wireless_restricted"], ["network", "remote_access", "ot_specific_controls"], ["network", "dial_up", "disabled_or_controlled"], ["network", "data_flows", "documented"], ["access_control", "ot_accounts", "managed"], ["access_control", "privileged_access", "ot", "controlled"], ["access_control", "vendor_remote", "managed"], ["access_control", "physical_ot_access", "controlled"], ["configuration", "ot_baseline", "established"], ["configuration", "change_management", "ot_process"], ["configuration", "removable_media", "controlled"], ["configuration", "software", "authorized_only"], ["patch_management", "ot", "policy_exists"], ["patch_management", "ot", "compensating_controls"], ["patch_management", "ot", "vendor_coordination"], ["incident_response", "ot_specific", "plan_exists"], ["incident_response", "ot_specific", "coordination_with_safety"], ["incident_response", "ot_specific", "forensics_consideration"], ["incident_response", "reporting", "ics_cert"], ["monitoring", "ot_network", "continuous"], ["monitoring", "ot_network", "protocol_aware"], ["monitoring", "historian", "log_integrity"], ["system_integrity", "malware_protection", "ot_appropriate"], ["system_integrity", "firmware", "integrity_verified"], ["contingency", "backup", "ot_configurations"], ["contingency", "recovery", "ot_rto_defined"], ["contingency", "manual_operations", "procedures_documented"], ["supply_chain", "ot_equipment", "vendor_assessment"], ["supply_chain", "ot_equipment", "counterfeit_protection"]]

bad_values := ["false", "true", "no", "yes", 0, 1, [], {}]

_set(path, value) := json.patch(all_pass, [{"op": "replace", "path": concat("/", array.concat([""], path)), "value": value}])

# every fact holds the same value (paths are three or four levels deep)
_all(value) := object.union_n(array.concat(
	[all_pass],
	array.concat(
		[{p[0]: {p[1]: {p[2]: value}}} | some p in fact_paths; count(p) == 3],
		[{p[0]: {p[1]: {p[2]: {p[3]: value}}}} | some p in fact_paths; count(p) == 4],
	),
))

# The sweeps are split into slices (item index modulo the slice count), one test per slice, so that no test runs long
# enough to meet the suite's per-test timeout on the oldest supported OPA. Every item is in exactly one slice; the
# test_the_slices_cover_* tests check it.
_slice(xs, i, n) := [x | some j, x in xs; j % n == i]

test_the_slices_cover_fact_paths_7 if {
	sum([count(_slice(fact_paths, i, 7)) | some i in numbers.range(0, 6)]) == count(fact_paths)
	every i in numbers.range(0, 6) {
		every k, x in _slice(fact_paths, i, 7) {
			x == fact_paths[i + (k * 7)]
		}
	}
}

test_all_pass_fixture_passes if {
	r := report with input as all_pass
	r.compliant == true
	r.violation_count == 0
	r.failed_controls == 0
}

test_empty_input_fails_every_check if {
	r := report with input as {}
	r.compliant == false
	r.violation_count == 35
	every v in r.violations { contains(v, "[evidence missing: input.") }
}

test_non_object_input_fails_every_check if {
	every bad in ["true", 1, null, [], true] {
		r := report with input as bad
		r.compliant == false
		r.violation_count == 35
	}
}

test_boolean_false_keeps_the_plain_finding if {
	every p in fact_paths {
		v := violations with input as _set(p, false)
		count(v) == 1
		every m in v { not contains(m, "[evidence ") }
	}
}

test_each_fact_of_the_wrong_type_fails_and_is_named_slice_0 if {
	every p in _slice(fact_paths, 0, 7) {
		every bad in bad_values {
			r := report with input as _set(p, bad)
			r.compliant == false
			r.violations == {m | some m in r.violations; endswith(m, sprintf("[evidence invalid: input.%s is not a boolean (got %s)]", [concat(".", p), type_name(bad)]))}
			r.violation_count == 1
		}
	}
}

test_each_fact_of_the_wrong_type_fails_and_is_named_slice_1 if {
	every p in _slice(fact_paths, 1, 7) {
		every bad in bad_values {
			r := report with input as _set(p, bad)
			r.compliant == false
			r.violations == {m | some m in r.violations; endswith(m, sprintf("[evidence invalid: input.%s is not a boolean (got %s)]", [concat(".", p), type_name(bad)]))}
			r.violation_count == 1
		}
	}
}

test_each_fact_of_the_wrong_type_fails_and_is_named_slice_2 if {
	every p in _slice(fact_paths, 2, 7) {
		every bad in bad_values {
			r := report with input as _set(p, bad)
			r.compliant == false
			r.violations == {m | some m in r.violations; endswith(m, sprintf("[evidence invalid: input.%s is not a boolean (got %s)]", [concat(".", p), type_name(bad)]))}
			r.violation_count == 1
		}
	}
}

test_each_fact_of_the_wrong_type_fails_and_is_named_slice_3 if {
	every p in _slice(fact_paths, 3, 7) {
		every bad in bad_values {
			r := report with input as _set(p, bad)
			r.compliant == false
			r.violations == {m | some m in r.violations; endswith(m, sprintf("[evidence invalid: input.%s is not a boolean (got %s)]", [concat(".", p), type_name(bad)]))}
			r.violation_count == 1
		}
	}
}

test_each_fact_of_the_wrong_type_fails_and_is_named_slice_4 if {
	every p in _slice(fact_paths, 4, 7) {
		every bad in bad_values {
			r := report with input as _set(p, bad)
			r.compliant == false
			r.violations == {m | some m in r.violations; endswith(m, sprintf("[evidence invalid: input.%s is not a boolean (got %s)]", [concat(".", p), type_name(bad)]))}
			r.violation_count == 1
		}
	}
}

test_each_fact_of_the_wrong_type_fails_and_is_named_slice_5 if {
	every p in _slice(fact_paths, 5, 7) {
		every bad in bad_values {
			r := report with input as _set(p, bad)
			r.compliant == false
			r.violations == {m | some m in r.violations; endswith(m, sprintf("[evidence invalid: input.%s is not a boolean (got %s)]", [concat(".", p), type_name(bad)]))}
			r.violation_count == 1
		}
	}
}

test_each_fact_of_the_wrong_type_fails_and_is_named_slice_6 if {
	every p in _slice(fact_paths, 6, 7) {
		every bad in bad_values {
			r := report with input as _set(p, bad)
			r.compliant == false
			r.violations == {m | some m in r.violations; endswith(m, sprintf("[evidence invalid: input.%s is not a boolean (got %s)]", [concat(".", p), type_name(bad)]))}
			r.violation_count == 1
		}
	}
}

test_each_fact_null_or_removed_fails_as_missing if {
	every p in fact_paths {
		want := sprintf("[evidence missing: input.%s not collected]", [concat(".", p)])
		v1 := violations with input as _set(p, null)
		count(v1) == 1
		every m in v1 { endswith(m, want) }
		v2 := violations with input as json.remove(all_pass, [concat("/", p)])
		count(v2) == 1
		every m in v2 { endswith(m, want) }
	}
}

test_every_fact_bad_fails_every_check if {
	every bad in array.concat(bad_values, [null, false]) {
		r := report with input as _all(bad)
		r.compliant == false
		r.violation_count == 35
	}
}

test_section_of_the_wrong_type_fails_its_checks if {
	every section in {p[0] | some p in fact_paths} {
		every bad in ["true", null, 1, []] {
			r := report with input as object.union(all_pass, {section: bad})
			r.compliant == false
			r.violation_count == count([p | some p in fact_paths; p[0] == section])
		}
	}
}
