package nerc_cip.cip_013_test

import rego.v1

import data.nerc_cip.cip_013 as c

test_vendor_incident_notification_process_has_violation if {
	count([v | some v in c.violations with input as {}; v.description == "CIP-013 R1.2.2: vendor incident notification process requirement not met"]) == 1
}

test_incident_coordination_process_has_violation if {
	count([v | some v in c.violations with input as {}; v.description == "CIP-013 R1.2.4: incident coordination process requirement not met"]) == 1
}

test_supply_chain_monitoring_implemented_has_violation if {
	count([v | some v in c.violations with input as {}; v.description == "CIP-013 R4: supply chain monitoring implemented requirement not met"]) == 1
}

test_vendor_notification_monitoring_has_violation if {
	count([v | some v in c.violations with input as {}; v.description == "CIP-013 R1: vendor notification monitoring requirement not met"]) == 1
}

test_cip_senior_manager_approved_has_violation if {
	count([v | some v in c.violations with input as {}; v.description == "CIP-013 R5: cip senior manager approved requirement not met"]) == 1
}

test_incident_response_coordination_established_has_violation if {
	count([v | some v in c.violations with input as {}; v.description == "CIP-013 R6: incident response coordination established requirement not met"]) == 1
}
