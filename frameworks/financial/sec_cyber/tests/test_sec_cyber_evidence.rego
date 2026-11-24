package sec_cyber.main_evidence_test

import rego.v1

# Evidence rule (audit 2026-11-24, round 2). Every yes/no fact the module reads passes only as the boolean
# true. Missing, null, "true", "false", "no", 0, 1, a list or an object fail the control, and the finding
# names the problem. Data-driven over the 23 facts.

report := data.sec_cyber.main.compliance_report

violations := data.sec_cyber.main.violations

all_pass := {
	"incident_disclosure": {
		"materiality_determination": {
			"process_documented": true,
			"timely": true,
		},
		"form_8k": {
			"filed_within_4_business_days": true,
			"includes_nature_and_scope": true,
			"includes_material_impact": true,
		},
		"delay_request": {
			"national_security_process": true,
		},
		"incident_register": {
			"maintained": true,
		},
	},
	"annual_disclosure": {
		"risk_management": {
			"strategy_documented": true,
			"integrated_with_overall_risk": true,
		},
		"third_party_risk": {
			"assessment_process": true,
		},
		"material_risks": {
			"identified_and_disclosed": true,
		},
		"previous_incidents": {
			"impact_disclosed": true,
		},
	},
	"governance": {
		"board": {
			"oversight_responsibility_assigned": true,
			"informed_of_risks_frequency": true,
			"oversight_process_disclosed": true,
		},
		"management": {
			"cybersecurity_roles_defined": true,
			"expertise_or_expertise_access": true,
			"reports_to_board": true,
			"ciso_or_equivalent": true,
		},
	},
	"risk_management": {
		"program": {
			"formal_program_exists": true,
		},
		"standards": {
			"framework_adopted": true,
		},
		"assessments": {
			"regular_risk_assessments": true,
		},
		"incident_response": {
			"plan_exists": true,
		},
	},
}

fact_paths := [["incident_disclosure", "materiality_determination", "process_documented"], ["incident_disclosure", "materiality_determination", "timely"], ["incident_disclosure", "form_8k", "filed_within_4_business_days"], ["incident_disclosure", "form_8k", "includes_nature_and_scope"], ["incident_disclosure", "form_8k", "includes_material_impact"], ["incident_disclosure", "delay_request", "national_security_process"], ["incident_disclosure", "incident_register", "maintained"], ["annual_disclosure", "risk_management", "strategy_documented"], ["annual_disclosure", "risk_management", "integrated_with_overall_risk"], ["annual_disclosure", "third_party_risk", "assessment_process"], ["annual_disclosure", "material_risks", "identified_and_disclosed"], ["annual_disclosure", "previous_incidents", "impact_disclosed"], ["governance", "board", "oversight_responsibility_assigned"], ["governance", "board", "informed_of_risks_frequency"], ["governance", "board", "oversight_process_disclosed"], ["governance", "management", "cybersecurity_roles_defined"], ["governance", "management", "expertise_or_expertise_access"], ["governance", "management", "reports_to_board"], ["governance", "management", "ciso_or_equivalent"], ["risk_management", "program", "formal_program_exists"], ["risk_management", "standards", "framework_adopted"], ["risk_management", "assessments", "regular_risk_assessments"], ["risk_management", "incident_response", "plan_exists"]]

bad_values := ["false", "true", "no", "yes", 0, 1, [], {}]

_set(path, value) := json.patch(all_pass, [{"op": "replace", "path": concat("/", array.concat([""], path)), "value": value}])

# every fact holds the same value (paths are three or four levels deep)
_all(value) := object.union_n(array.concat(
	[all_pass],
	array.concat(
		[{p[0]: {p[1]: {p[2]: value}}} | some p in fact_paths; count(p) == 3],
		[],
	),
))

test_all_pass_fixture_passes if {
	r := report with input as all_pass
	r.compliant == true
	r.violation_count == 0
	r.failed_controls == 0
}

test_empty_input_fails_every_check if {
	r := report with input as {}
	r.compliant == false
	r.violation_count == 23
	every v in r.violations { contains(v, "[evidence missing: input.") }
}

test_non_object_input_fails_every_check if {
	every bad in ["true", 1, null, [], true] {
		r := report with input as bad
		r.compliant == false
		r.violation_count == 23
	}
}

test_boolean_false_keeps_the_plain_finding if {
	every p in fact_paths {
		v := violations with input as _set(p, false)
		count(v) == 1
		every m in v { not contains(m, "[evidence ") }
	}
}

test_each_fact_of_the_wrong_type_fails_and_is_named if {
	every p in fact_paths {
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
		r.violation_count == 23
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
