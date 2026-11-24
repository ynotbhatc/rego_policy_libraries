# Bad evidence never passes: every fact of cis_gke.main, sent as a string, null, a number or not at all,
# fails its control and is named in evidence_problems. Only the boolean true passes.

package cis_gke.bad_evidence_test

import rego.v1

import data.cis_gke.main

_all_true := {"cis_gke": {section: {field: true | some field in fields} | some section, fields in main._facts}}

_bad_values := ["false", "true", "no", null, 0, 1]

_with(section, field, value) := json.patch(_all_true, [{"op": "replace", "path": sprintf("/cis_gke/%s/%s", [section, field]), "value": value}])

_without(section, field) := json.patch(_all_true, [{"op": "remove", "path": sprintf("/cis_gke/%s/%s", [section, field])}])

test_fact_list_covers_every_control if {
	count([f | some fields in main._facts; some f in fields]) == 40
}

test_all_true_passes if {
	r := main.compliance_report with input as _all_true
	r.compliant == true
	count(r.violations) == 0
	count(r.evidence_problems) == 0
}

test_empty_input_fails_every_control if {
	r := main.compliance_report with input as {}
	r.compliant == false
	count(r.violations) == 40
	count(r.evidence_problems) == 40
}

test_null_root_and_null_section_fail if {
	r := main.compliance_report with input as {"cis_gke": null}
	r.compliant == false
	count(r.violations) == 40
	every section, fields in main._facts {
		s := main.compliance_report with input as json.patch(_all_true, [{"op": "replace", "path": sprintf("/cis_gke/%s", [section]), "value": null}])
		s.compliant == false
		count(s.violations) == count(fields)
		count(s.evidence_problems) == count(fields)
	}
}

test_boolean_false_fails_without_an_evidence_finding if {
	every section, fields in main._facts {
		every field in fields {
			r := main.compliance_report with input as _with(section, field, false)
			r.compliant == false
			count(r.violations) == 1
			count(r.evidence_problems) == 0
		}
	}
}

test_wrong_type_fails_and_is_named if {
	every section, fields in main._facts {
		every field in fields {
			every value in _bad_values {
				r := main.compliance_report with input as _with(section, field, value)
				r.compliant == false
				count(r.violations) == 1
				count(r.evidence_problems) == 1
				some msg in r.evidence_problems
				contains(msg, sprintf("cis_gke.%s.%s", [section, field]))
			}
		}
	}
}

test_removed_fact_fails_and_is_named if {
	every section, fields in main._facts {
		every field in fields {
			r := main.compliance_report with input as _without(section, field)
			r.compliant == false
			count(r.violations) == 1
			r.evidence_problems == {sprintf("evidence missing: cis_gke.%s.%s not collected", [section, field])}
		}
	}
}

test_string_is_reported_with_its_type if {
	some section, fields in main._facts
	some field in fields
	r := main.compliance_report with input as _with(section, field, "true")
	r.evidence_problems == {sprintf("cis_gke.%s.%s is not a boolean (got string)", [section, field])}
}
