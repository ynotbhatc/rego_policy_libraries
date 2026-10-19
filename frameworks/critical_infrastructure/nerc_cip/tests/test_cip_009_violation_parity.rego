package nerc_cip.cip_009_test

import rego.v1

import data.nerc_cip.cip_009 as c

test_recovery_plan_roles_defined_has_violation if {
	count([v | some v in c.violations with input as {}; v.description == "CIP-009 R1.2: recovery plan roles defined requirement not met"]) == 1
}

test_log_preservation_process_has_violation if {
	count([v | some v in c.violations with input as {}; v.description == "CIP-009 R1.4: log preservation process requirement not met"]) == 1
}

test_network_reconnection_process_has_violation if {
	count([v | some v in c.violations with input as {}; v.description == "CIP-009 R1.5: network reconnection process requirement not met"]) == 1
}

test_plans_communicated_has_violation if {
	count([v | some v in c.violations with input as {}; v.description == "CIP-009 R2.3: plans communicated requirement not met"]) == 1
}

test_activation_criteria_tested_has_violation if {
	count([v | some v in c.violations with input as {}; v.description == "CIP-009 R3.3: activation criteria tested requirement not met"]) == 1
}
