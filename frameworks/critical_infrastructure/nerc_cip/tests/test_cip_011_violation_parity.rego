package nerc_cip.cip_011_test

import rego.v1

import data.nerc_cip.cip_011 as c

test_bcsi_categories_addressed_has_violation if {
	count([v | some v in c.violations with input as {}; v.description == "CIP-011 R1.1: bcsi categories addressed requirement not met"]) == 1
}

test_bcsi_access_need_to_know_has_violation if {
	count([v | some v in c.violations with input as {}; v.description == "CIP-011 R2: bcsi access need to know requirement not met"]) == 1
}

test_bcsi_electronic_access_controlled_has_violation if {
	count([v | some v in c.violations with input as {}; v.description == "CIP-011 R1: bcsi electronic access controlled requirement not met"]) == 1
}

test_bcsi_physical_access_controlled_has_violation if {
	count([v | some v in c.violations with input as {}; v.description == "CIP-011 R1: bcsi physical access controlled requirement not met"]) == 1
}

test_media_sanitization_verified_has_violation if {
	count([v | some v in c.violations with input as {}; v.description == "CIP-011 R3: media sanitization verified requirement not met"]) == 1
}
