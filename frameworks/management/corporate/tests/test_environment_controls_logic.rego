package corporate.environment.controls_test

import rego.v1

import data.corporate.environment.controls as c

# Validation 2026-10-17.

envs(d, q, p) := {"environments": {
	"development": {"network": {"vlan_id": d}},
	"qa": {"network": {"vlan_id": q}},
	"production": {"network": {"vlan_id": p}},
}}

test_distinct_vlans_adequate if {
	c.network_separation_adequate with input as envs(10, 20, 30)
}

test_dev_and_qa_sharing_vlan_not_adequate if {
	not c.network_separation_adequate with input as envs(10, 10, 20)
}

test_prod_sharing_vlan_with_dev_not_adequate if {
	not c.network_separation_adequate with input as envs(10, 20, 10)
}

test_missing_vlan_not_adequate if {
	not c.network_separation_adequate with input as {}
	not c.network_separation_adequate with input as {"environments": {"development": {"network": {"vlan_id": 1}}}}
}

test_sox_ignores_unscoped_deployment if {
	deployments := [
		{"target_environment": "production", "impact_areas": ["financial_reporting"], "authorization": {"change_board_approval": true}},
		{"target_environment": "qa", "impact_areas": ["wiki"]},
	]
	c.sox_environment_controls_compliant with input as {"deployments": deployments} with c.environment_controls_compliant as true with c.segregation_of_duties_maintained as true
}

test_sox_unapproved_production_deployment_fails if {
	deployments := [{"target_environment": "production", "impact_areas": ["wiki"], "authorization": {"change_board_approval": false}}]
	not c.sox_environment_controls_compliant with input as {"deployments": deployments} with c.environment_controls_compliant as true with c.segregation_of_duties_maintained as true
}

test_sox_unapproved_financial_deployment_fails if {
	deployments := [{"target_environment": "qa", "impact_areas": ["financial_reporting"], "authorization": {}}]
	not c.sox_environment_controls_compliant with input as {"deployments": deployments} with c.environment_controls_compliant as true with c.segregation_of_duties_maintained as true
}
