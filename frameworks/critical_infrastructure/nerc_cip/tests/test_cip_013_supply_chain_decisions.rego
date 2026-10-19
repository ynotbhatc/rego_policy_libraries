package nerc_cip.cip_013_test

import rego.v1

import data.nerc_cip.cip_013 as c

# decisions 2026-10-19: comprehensive vendor assessments gate compliant.

covers_all := {"vulnerability_disclosure_capability": true, "incident_response_capability": true, "software_development_practices": true, "third_party_dependencies": true}

test_incomplete_assessment_violation if {
	i := {
		"vendors": [{"vendor_id": "v1", "criticality_level": "high"}],
		"vendor_risk_assessments": {"v1": {"covers": object.union(covers_all, {"third_party_dependencies": false})}},
	}
	not c.vendor_assessments_comprehensive with input as i
	count([v | some v in c.violations with input as i; v.requirement == "R2"; contains(v.description, "third-party dependencies")]) == 1
	not c.compliant with input as i
}

test_comprehensive_assessment_passes if {
	i := {
		"vendors": [{"vendor_id": "v1", "criticality_level": "high"}, {"vendor_id": "v2", "criticality_level": "low"}],
		"vendor_risk_assessments": {"v1": {"covers": covers_all}},
	}
	c.vendor_assessments_comprehensive with input as i
}

test_no_vendor_inventory_fails_closed if {
	not c.vendor_assessments_comprehensive with input as {}
}
