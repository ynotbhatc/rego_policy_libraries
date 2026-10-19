package nerc_cip.cip_012_test

import rego.v1

import data.nerc_cip.cip_012 as c

test_communication_encryption_has_violation if {
	count([v | some v in c.violations with input as {}; v.description == "CIP-012 R2: communication encryption requirement not met"]) == 1
}

test_communication_authentication_has_violation if {
	count([v | some v in c.violations with input as {}; v.description == "CIP-012 R2: communication authentication requirement not met"]) == 1
}

test_backup_communication_protected_has_violation if {
	count([v | some v in c.violations with input as {}; v.description == "CIP-012 R4: backup communication protected requirement not met"]) == 1
}

test_communication_protection_tested_has_violation if {
	count([v | some v in c.violations with input as {}; v.description == "CIP-012 R5: communication protection tested requirement not met"]) == 1
}
