package nist.sp800_171.risk_assessment_numeric_guards_test

import rego.v1

test_non_number_remediation_days_not_met if {
	every v in ["1", null, "x"] {
		not data.nist.sp800_171.risk_assessment.vulnerability_remediation with input as {"nist_800_171": {"risk_assessment": {"remediation": {
			"risk_based_prioritization": true,
			"critical_days": v,
			"high_days": 30,
			"tracking_system": true,
		}}}}
	}
}

test_numeric_remediation_days_unchanged if {
	data.nist.sp800_171.risk_assessment.vulnerability_remediation with input as {"nist_800_171": {"risk_assessment": {"remediation": {
		"risk_based_prioritization": true,
		"critical_days": 15,
		"high_days": 30,
		"tracking_system": true,
	}}}}
}
