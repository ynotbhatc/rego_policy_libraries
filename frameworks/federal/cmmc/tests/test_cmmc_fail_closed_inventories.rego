package cmmc_inventory_test

import rego.v1

# Practices that iterate an inventory fail closed when it is missing, and when
# an item lacks the fact the check reads.

test_ac_missing_users_fails_3_1_1_5_6_at_level_2 if {
	v := data.cmmc.access_control.violations with input as {"cmmc_level": 2}
	some a in v
	startswith(a, "CMMC AC.L1-b.1.i / AC.L2-3.1.1: evidence missing - input.users")
	some b in v
	startswith(b, "CMMC AC.L2-3.1.5: evidence missing - input.users")
	some c in v
	startswith(c, "CMMC AC.L2-3.1.6: evidence missing - input.users")
}

test_ac_empty_users_list_is_missing_evidence if {
	v := data.cmmc.access_control.violations with input as {"cmmc_level": 1, "users": []}
	some a in v
	startswith(a, "CMMC AC.L1-b.1.i / AC.L2-3.1.1: evidence missing")
}

test_ac_authorized_users_pass_3_1_1 if {
	inp := {"cmmc_level": 1, "users": [{"username": "a", "authorized": true, "system_access": true}]}
	v := data.cmmc.access_control.violations with input as inp
	every a in v {
		not startswith(a, "CMMC AC.L1-b.1.i /")
	}
}

test_ac_system_without_public_flag_fails_3_1_22 if {
	v := data.cmmc.access_control.violations with input as {"cmmc_level": 1, "cui_systems": [{"name": "s1"}]}
	"CMMC AC.L1-b.1.iv / AC.L2-3.1.22: evidence missing - system 's1' has no boolean 'publicly_accessible'" in v
}

test_ac_privileged_user_without_flag_fails_3_1_5 if {
	inp := {"cmmc_level": 2, "users": [{"username": "a", "authorized": true, "system_access": true}]}
	v := data.cmmc.access_control.violations with input as inp
	"CMMC AC.L2-3.1.5: evidence missing - user 'a' has no boolean 'privileged'" in v
}

test_ac_missing_wireless_and_mobile_flags_fail_closed if {
	v := data.cmmc.access_control.violations with input as {"cmmc_level": 2}
	some a in v
	startswith(a, "CMMC AC.L2-3.1.16: evidence missing")
	some b in v
	startswith(b, "CMMC AC.L2-3.1.17: evidence missing")
	some c in v
	startswith(c, "CMMC AC.L2-3.1.19: evidence missing")
}

test_ac_no_wireless_stated_passes_3_1_16_and_17 if {
	inp := {"cmmc_level": 2, "access_controls": {"wireless_access_enabled": false}}
	v := data.cmmc.access_control.violations with input as inp
	every a in v {
		not startswith(a, "CMMC AC.L2-3.1.16")
		not startswith(a, "CMMC AC.L2-3.1.17")
	}
}

test_ac_missing_session_lock_value_fails_3_1_10 if {
	v := data.cmmc.access_control.violations with input as {"cmmc_level": 2, "session": {}}
	some a in v
	startswith(a, "CMMC AC.L2-3.1.10: evidence missing")
	v2 := data.cmmc.access_control.violations with input as {"cmmc_level": 2, "session": {"lock_timeout_minutes": 10}, "org_defined": {"session_lock_minutes": 10}}
	every b in v2 {
		not startswith(b, "CMMC AC.L2-3.1.10")
	}
}

test_ac_missing_level_is_an_input_contract_finding_not_a_practice if {
	v := data.cmmc.access_control.violations with input as {}
	some a in v
	startswith(a, "CMMC AC input contract: FAIL-CLOSED")
	every b in v {
		not startswith(b, "CMMC AC.L2-3.1.1: FAIL-CLOSED")
	}
}

test_cm_missing_systems_fails_each_per_system_practice if {
	v := data.cmmc.configuration_management.violations with input as {"cmmc_level": 2}
	every id in ["3.4.1", "3.4.2", "3.4.6", "3.4.7"] {
		sprintf("CMMC CM.L2-%v: evidence missing - input.systems not supplied, not an array or empty; per-system configuration checks cannot be evaluated", [id]) in v
	}
}

test_cm_system_without_service_list_fails_3_4_6 if {
	inp := {"cmmc_level": 2, "systems": [{"name": "h1", "baseline_configuration_documented": true, "security_configuration_enforced": true, "unauthorized_software": []}]}
	v := data.cmmc.configuration_management.violations with input as inp
	"CMMC CM.L2-3.4.6: evidence missing - system 'h1' has no 'unnecessary_services' list; least functionality cannot be shown" in v
	every a in v {
		not startswith(a, "CMMC CM.L2-3.4.7: evidence missing - system")
	}
}

test_cm_passing_counts_practices_never_negative if {
	r := data.cmmc.configuration_management.compliance_report with input as {"cmmc_level": 2}
	r.passing == 0
	r.total_practices == 9
}

test_ir_missing_object_fails_each_practice if {
	v := data.cmmc.incident_response.violations with input as {"cmmc_level": 2}
	every id in ["3.6.1", "3.6.2", "3.6.3"] {
		sprintf("CMMC IR.L2-%v: evidence missing - input.incident_response not supplied (or not an object); this practice cannot be evaluated", [id]) in v
	}
}

test_ma_unmet_practice_without_finding_gets_one if {
	v := data.cmmc.maintenance.all_violations with data.cmmc.maintenance.base_violations as []
		with data.cmmc.maintenance.practices as [{"id": "3.7.1", "level": 2, "compliant": false}, {"id": "3.7.2", "level": 2, "compliant": true}]
	v == ["3.7.1: evidence missing or requirement not met — all facts required by this practice must be present and passing"]
}

test_mp_unmet_not_duplicated_when_specific_finding_exists if {
	v := data.cmmc.media_protection.all_violations with data.cmmc.media_protection.base_violations as ["3.8.1: x"]
		with data.cmmc.media_protection.practices as [{"id": "3.8.1", "level": 2, "compliant": false}]
	v == ["3.8.1: x"]
}

test_ps_unmet_on_empty_input_covers_both_practices if {
	v := data.cmmc.personnel_security.all_violations with input as {}
	some a in v
	startswith(a, "3.9.1:")
	some b in v
	startswith(b, "3.9.2:")
}
