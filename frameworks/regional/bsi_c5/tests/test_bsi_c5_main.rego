# Tests for the BSI C5:2026 main entry point.
package bsi_c5.main_test

import rego.v1

import data.bsi_c5.main

_all_true := {"bsi_c5": {"criteria": {id: true | some id, _ in main.criteria}}}

_fail_closed(r) if {
	some v in r.violations
	contains(v, "FAIL-CLOSED")
}

test_empty_input_fail_closed if {
	r := main.compliance_report with input as {}
	r.compliant == false
	_fail_closed(r)
	r.criteria_satisfied == 0
	r.violation_count == 169 # 168 unattested criteria + the FAIL-CLOSED notice
}

test_non_object_container_fail_closed if {
	r := main.compliance_report with input as {"bsi_c5": {"criteria": ["OIS-01"]}}
	r.compliant == false
	_fail_closed(r)
}

test_all_attested_compliant if {
	r := main.compliance_report with input as _all_true
	r.compliant == true
	r.violation_count == 0
	r.criteria_satisfied == 168
	r.subject_areas_passing == 17
}

test_one_false_named if {
	inp := json.patch(_all_true, [{"op": "replace", "path": "/bsi_c5/criteria/OPS-22", "value": false}])
	r := main.compliance_report with input as inp
	r.compliant == false
	r.violation_count == 1
	some v in r.violations
	contains(v, "OPS-22")
	r.subject_areas.OPS.gaps == ["OPS-22"]
	r.subject_areas.OPS.compliant == false
	r.criteria["OPS-22"].satisfied == false
}

test_unknown_id_is_violation if {
	inp := json.patch(_all_true, [{"op": "add", "path": "/bsi_c5/criteria/OIS-11", "value": true}])
	r := main.compliance_report with input as inp
	r.compliant == false
	r.violation_count == 1
	some v in r.violations
	contains(v, "unknown criterion id OIS-11")
}

test_legacy_2020_module_id_is_violation if {
	inp := json.patch(_all_true, [{"op": "add", "path": "/bsi_c5/criteria/IDM-5", "value": true}])
	r := main.compliance_report with input as inp
	r.compliant == false
	r.violation_count == 1
	some v in r.violations
	contains(v, "IDM-5 is a retired AAC C5:2020-module requirement id")
	contains(v, "IAM-08")
}

test_c5_2020_idm_area_id_is_violation if {
	inp := json.patch(_all_true, [{"op": "add", "path": "/bsi_c5/criteria/IDM-01", "value": true}])
	r := main.compliance_report with input as inp
	r.violation_count == 1
	some v in r.violations
	contains(v, "area code IDM")
}

test_general_condition_is_not_attestable if {
	inp := json.patch(_all_true, [{"op": "add", "path": "/bsi_c5/criteria/GC-01", "value": true}])
	r := main.compliance_report with input as inp
	r.violation_count == 1
	some v in r.violations
	contains(v, "GC-01 is a General Condition")
}

test_c5_2020_input_shape_is_violation if {
	inp := {"bsi_c5": {"criteria": _all_true.bsi_c5.criteria, "cryptography": {"requirements": {"CRY-3": true}}}}
	r := main.compliance_report with input as inp
	r.violation_count == 1
	some v in r.violations
	contains(v, "input.bsi_c5.cryptography.requirements")
}

test_criteria_count_pinned if {
	count(main.criteria) == 168
	r := main.compliance_report with input as {}
	r.standard_total == 168
	r.total_controls == 168
	r.subject_areas_total == 17
	r.criteria_with_additional == 79
	r.subcriteria == {"basic": 462, "additional_sharpening": 29, "additional_complementing": 132}
}

test_per_area_counts_pinned if {
	r := main.compliance_report with input as {}
	counts := {code: a.criteria | some code, a in r.subject_areas}
	counts == {
		"OIS": 10, "SP": 3, "HR": 8, "AM": 12, "PS": 8, "OPS": 35, "IAM": 9, "CRY": 19, "COS": 8,
		"PI": 3, "DEV": 15, "SSO": 8, "SIM": 6, "BCM": 4, "COM": 4, "INQ": 4, "PSS": 12,
	}
}

test_one_id_per_area_resolves if {
	sample := {
		"OIS": "OIS-01", "SP": "SP-03", "HR": "HR-08", "AM": "AM-12", "PS": "PS-06", "OPS": "OPS-35",
		"IAM": "IAM-07", "CRY": "CRY-19", "COS": "COS-08", "PI": "PI-02", "DEV": "DEV-15", "SSO": "SSO-08",
		"SIM": "SIM-06", "BCM": "BCM-04", "COM": "COM-01", "INQ": "INQ-04", "PSS": "PSS-12",
	}
	r := main.compliance_report with input as {}
	every code, id in sample {
		main.criteria[id].area == code
		r.criteria[id].basis == "attestation"
		startswith(r.subject_areas[code].name, "5.")
	}
}

test_basis_counts if {
	r := main.compliance_report with input as {}
	r.criteria_fact_evaluated == 0
	r.criteria_attested_basis == 168
	count([id | some id, s in r.criteria; s.basis == "attestation"]) == 168
}

test_legacy_lineage_complete if {
	count(main.legacy) == 61
	every id, l in main.legacy {
		count(l.candidate_2026) > 0
		every c in l.candidate_2026 {
			main.criteria[c]
		}
		not main.criteria[id]
	}
	r := main.compliance_report with input as {}
	r.legacy_c5_2020_module == {"kept": 0, "renumbered": 0, "retired": 61}
}

test_sharpening_refs_resolve if {
	every _, c in main.criteria {
		count(c.sharpens) == count(c.additional_sharpening)
		every pair in c.sharpens {
			pair[0] in c.additional_sharpening
			pair[1] in c.basic
		}
		count(c.basic) > 0
	}
}

test_effective_date if {
	r := main.compliance_report with input as {}
	r.effective["2027-06-01"]
	r.source.sha256 == "b48f7ccdd6844b2a0bb5055edf5ce109dfb186b1680c49a52c5b92cb16537163"
}
