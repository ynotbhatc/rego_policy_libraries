# Bad evidence never passes: every fact of nsa_cisa_k8s.main, sent as a string, null, a number or not at all,
# fails its control and is named in evidence_findings. Only the boolean true passes.

package nsa_cisa_k8s.bad_evidence_test

import rego.v1

import data.nsa_cisa_k8s.main

_all_true := {"nsa_cisa": {section: {field: true | some field in fields} | some section, fields in main._facts}}

_bad_values := ["false", "true", "no", null, 0, 1]

_with(section, field, value) := json.patch(_all_true, [{"op": "replace", "path": sprintf("/nsa_cisa/%s/%s", [section, field]), "value": value}])

_without(section, field) := json.patch(_all_true, [{"op": "remove", "path": sprintf("/nsa_cisa/%s/%s", [section, field])}])

test_fact_list_covers_every_control if {
	count([f | some fields in main._facts; some f in fields]) == 43
}

test_all_true_passes if {
	r := main.compliance_report with input as _all_true
	r.compliant == true
	count(r.violations) == 0
	count(r.evidence_findings) == 0
}

test_empty_input_fails_every_control if {
	r := main.compliance_report with input as {}
	r.compliant == false
	count(r.violations) == 43
	count(r.evidence_findings) == 43
}

test_null_root_and_null_section_fail if {
	r := main.compliance_report with input as {"nsa_cisa": null}
	r.compliant == false
	count(r.violations) == 43
	every section, fields in main._facts {
		s := main.compliance_report with input as json.patch(_all_true, [{"op": "replace", "path": sprintf("/nsa_cisa/%s", [section]), "value": null}])
		s.compliant == false
		count(s.violations) == count(fields)
		count(s.evidence_findings) == count(fields)
	}
}

test_boolean_false_fails_without_an_evidence_finding if {
	every section, fields in main._facts {
		every field in fields {
			r := main.compliance_report with input as _with(section, field, false)
			r.compliant == false
			count(r.violations) == 1
			count(r.evidence_findings) == 0
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
				count(r.evidence_findings) == 1
				some msg in r.evidence_findings
				contains(msg, sprintf("nsa_cisa.%s.%s", [section, field]))
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
			r.evidence_findings == {sprintf("evidence missing: nsa_cisa.%s.%s not collected", [section, field])}
		}
	}
}

test_string_is_reported_with_its_type if {
	some section, fields in main._facts
	some field in fields
	r := main.compliance_report with input as _with(section, field, "true")
	r.evidence_findings == {sprintf("nsa_cisa.%s.%s is not a boolean (got string)", [section, field])}
}
