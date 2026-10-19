package nerc_cip.cip_007_test

import rego.v1

import data.nerc_cip.cip_007 as c

test_ports_and_services_policy_has_violation if {
	count([v | some v in c.violations with input as {}; v.description == "CIP-007 R1.1: ports and services policy requirement not met"]) == 1
}

test_physical_io_ports_protected_has_violation if {
	count([v | some v in c.violations with input as {}; v.description == "CIP-007 R1.3: physical io ports protected requirement not met"]) == 1
}

test_malicious_code_response_documented_has_violation if {
	count([v | some v in c.violations with input as {}; v.description == "CIP-007 R3.2: malicious code response documented requirement not met"]) == 1
}

test_security_event_alerting_has_violation if {
	count([v | some v in c.violations with input as {}; v.description == "CIP-007 R4.2: security event alerting requirement not met"]) == 1
}

test_default_passwords_changed_has_violation if {
	count([v | some v in c.violations with input as {}; v.description == "CIP-007 R5.3: default passwords changed requirement not met"]) == 1
}

test_shared_accounts_minimized_has_violation if {
	count([v | some v in c.violations with input as {"user_accounts": [{"shared": true}]}; v.description == "CIP-007 R5.4: shared accounts minimized requirement not met"]) == 1
}

test_login_attempt_limiting_has_violation if {
	count([v | some v in c.violations with input as {}; v.description == "CIP-007 R5.5: login attempt limiting requirement not met"]) == 1
}
