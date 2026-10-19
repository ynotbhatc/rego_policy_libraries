package nerc_cip.cip_010_test

import rego.v1

import data.nerc_cip.cip_010 as c

test_active_vulnerability_monitoring_has_violation if {
	count([v | some v in c.violations with input as {}; v.description == "CIP-010 R1.5: active vulnerability monitoring requirement not met"]) == 1
}

test_software_integrity_verification_has_violation if {
	count([v | some v in c.violations with input as {}; v.description == "CIP-010 R1.6: software integrity verification requirement not met"]) == 1
}

test_post_change_assessment_has_violation if {
	count([v | some v in c.violations with input as {"configuration_changes": [{"is_major_change": true}]}; v.description == "CIP-010 R3.4: post change assessment requirement not met"]) == 1
}

test_transient_asset_config_managed_has_violation if {
	count([v | some v in c.violations with input as {}; v.description == "CIP-010 R4: transient asset config managed requirement not met"]) == 1
}
