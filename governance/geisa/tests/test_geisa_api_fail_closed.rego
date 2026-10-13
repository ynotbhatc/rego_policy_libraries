package governance.geisa.api_test

import rego.v1

test_not_compliant_without_facts if {
	r := data.governance.geisa.api.compliance_report with input as {}
	not r.compliant == true
	r.violation_count > 0
}

test_discovery_response_missing_is_a_violation if {
	v := data.governance.geisa.api.violations with input as {"manifest": {"applicationId": "x"}}
	"API: platform discovery response missing or not an object" in v
}
