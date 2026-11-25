package stig.rhel_9.num_contract_test

# The documented numeric contract of the Linux STIG modules (benchmarks/stig/LINUX_COLLECTOR_CONTRACT.md,
# "How the rules read a fact", `_num`): a whole number, or a string holding a decimal integer with optional
# surrounding whitespace. Everything else is not a pass. Hand-written (audit 2026-11-24, round 2): each fact of
# the green fixture that a rule reads through `_num` is replaced in turn, and the status of every rule the
# contract lists for that fact is read.

import rego.v1

fx := data.stig.rhel_9.green_test.green_fixture

# [JSON pointer, the fixture's value, [[section, status rule] of each rule that reads it]]
num_facts := [
	["/auditd_config/freq", 100, [["audit_logging", "status_rhel_09_653095"]]],
	["/crypto_policy_state/min_rsa_size", 2048, [["configuration_management", "status_rhel_09_215105"]]],
	["/faillock_conf/deny", 3, [["account_auth", "status_rhel_09_411075"]]],
	["/faillock_conf/fail_interval", 900, [["account_auth", "status_rhel_09_411085"]]],
	["/faillock_conf/unlock_time", 0, [["account_auth", "status_rhel_09_411090"]]],
	["/login_defs/FAIL_DELAY", 4, [["account_auth", "status_rhel_09_412050"]]],
	["/password_policy/dcredit", -1, [["account_auth", "status_rhel_09_611070"]]],
	["/password_policy/dictcheck", 1, [["account_auth", "status_rhel_09_611105"]]],
	["/password_policy/difok", 8, [["account_auth", "status_rhel_09_611115"]]],
	["/password_policy/inactive_days", 35, [["account_auth", "status_rhel_09_411050"]]],
	["/password_policy/lcredit", -1, [["account_auth", "status_rhel_09_611065"]]],
	["/password_policy/maxclassrepeat", 4, [["account_auth", "status_rhel_09_611120"]]],
	["/password_policy/maxdays", 180, [["account_auth", "status_rhel_09_411010"]]],
	["/password_policy/maxrepeat", 3, [["account_auth", "status_rhel_09_611125"]]],
	["/password_policy/minclass", 4, [["account_auth", "status_rhel_09_611130"]]],
	["/password_policy/mindays", 1, [["account_auth", "status_rhel_09_611075"]]],
	["/password_policy/minlen", 15, [["account_auth", "status_rhel_09_611090"]]],
	["/password_policy/ocredit", -1, [["account_auth", "status_rhel_09_611100"]]],
	["/password_policy/retry", 3, [["account_auth", "status_rhel_09_611010"]]],
	["/password_policy/ucredit", -1, [["account_auth", "status_rhel_09_611110"]]],
	["/ssh_config/ClientAliveCountMax", 1, [["ssh_config", "status_rhel_09_255095"]]],
	["/ssh_config/ClientAliveInterval", 600, [["ssh_config", "status_rhel_09_255100"], ["account_auth", "status_rhel_09_412080"]]],
]

# one clause per section: a dynamic data.stig.rhel_9[section] reference would include this test package
status("account_auth", name, inp) := s if {
	s := data.stig.rhel_9.account_auth[name] with input as inp
}

status("audit_logging", name, inp) := s if {
	s := data.stig.rhel_9.audit_logging[name] with input as inp
}

status("configuration_management", name, inp) := s if {
	s := data.stig.rhel_9.configuration_management[name] with input as inp
}

status("ssh_config", name, inp) := s if {
	s := data.stig.rhel_9.ssh_config[name] with input as inp
}

passes(f, inp) if {
	every r in f[2] {
		status(r[0], r[1], inp) == "Not_a_Finding"
	}
}

with_value(f, v) := json.patch(fx, [{"op": "replace", "path": f[0], "value": v}])

test_fixture_passes if {
	every f in num_facts { passes(f, fx) }
}

test_decimal_string_passes_as_documented if {
	every f in num_facts {
		passes(f, with_value(f, sprintf("%d", [f[1]])))
		passes(f, with_value(f, sprintf(" %d ", [f[1]])))
	}
}

test_null_and_removed_do_not_pass if {
	every f in num_facts {
		not passes(f, with_value(f, null))
		not passes(f, json.patch(fx, [{"op": "remove", "path": f[0]}]))
	}
}

test_booleans_do_not_pass if {
	every f in num_facts {
		not passes(f, with_value(f, true))
		not passes(f, with_value(f, false))
	}
}

test_garbage_and_empty_strings_do_not_pass if {
	every f in num_facts {
		not passes(f, with_value(f, "abc"))
		not passes(f, with_value(f, ""))
		not passes(f, with_value(f, sprintf("%ds", [f[1]])))
	}
}

test_fraction_does_not_pass if {
	every f in num_facts {
		not passes(f, with_value(f, f[1] + 0.5))
		not passes(f, with_value(f, sprintf("%d.5", [f[1]])))
	}
}

test_list_does_not_pass if {
	every f in num_facts { not passes(f, with_value(f, [f[1]])) }
}
