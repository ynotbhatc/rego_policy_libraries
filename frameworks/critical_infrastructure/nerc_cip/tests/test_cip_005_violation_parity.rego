package nerc_cip.cip_005_test

import rego.v1

import data.nerc_cip.cip_005 as c

test_unused_ports_disabled_has_violation if {
	count([v | some v in c.violations with input as {}; v.description == "CIP-005 R1.5: unused ports disabled requirement not met"]) == 1
}

test_remote_access_managed_has_violation if {
	count([v | some v in c.violations with input as {}; v.description == "CIP-005 R1: remote access managed requirement not met"]) == 1
}

test_access_attempt_logging_has_violation if {
	count([v | some v in c.violations with input as {}; v.description == "CIP-005 R3: access attempt logging requirement not met"]) == 1
}
