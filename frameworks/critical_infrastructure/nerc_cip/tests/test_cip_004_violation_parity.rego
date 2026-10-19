package nerc_cip.cip_004_test

import rego.v1

import data.nerc_cip.cip_004 as c

test_training_records_maintained_has_violation if {
	count([v | some v in c.violations with input as {}; v.description == "CIP-004 R2: training records maintained requirement not met"]) == 1
}

test_access_authorization_documented_has_violation if {
	count([v | some v in c.violations with input as {}; v.description == "CIP-004 R4: access authorization documented requirement not met"]) == 1
}

test_access_based_on_need_to_know_has_violation if {
	count([v | some v in c.violations with input as {}; v.description == "CIP-004 R4: access based on need to know requirement not met"]) == 1
}

test_shared_accounts_managed_has_violation if {
	count([v | some v in c.violations with input as {}; v.description == "CIP-004 R5: shared accounts managed requirement not met"]) == 1
}
