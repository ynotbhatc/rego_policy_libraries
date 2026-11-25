package stig.oracle_linux_9.num_contract_test

# The documented numeric contract of the Linux STIG modules (benchmarks/stig/LINUX_COLLECTOR_CONTRACT.md,
# "How the rules read a fact", `_num`): a whole number, or a string holding a decimal integer with optional
# surrounding whitespace. Everything else is not a pass. Hand-written (audit 2026-11-24, round 2): each fact of
# the green fixture that a rule reads through `_num` is replaced in turn, and the status of every rule the
# contract lists for that fact is read.

import rego.v1

fx := data.stig.oracle_linux_9.green_test.green_fixture

# [JSON pointer, the fixture's value, [[section, status rule] of each rule that reads it]]
num_facts := [
	["/crypto_policy_state/min_rsa_size", 2048, [["configuration_management", "status_ol09_00_000241"]]],
	["/faillock_conf/deny", 3, [["account_auth", "status_ol09_00_003020"]]],
	["/faillock_conf/fail_interval", 900, [["account_auth", "status_ol09_00_002416"]]],
	["/password_policy/dcredit", -1, [["account_auth", "status_ol09_00_001020"]]],
	["/password_policy/inactive_days", 35, [["account_auth", "status_ol09_00_003065"]]],
	["/password_policy/lcredit", -1, [["account_auth", "status_ol09_00_001015"]]],
	["/password_policy/maxdays", 180, [["account_auth", "status_ol09_00_001095"]]],
	["/password_policy/mindays", 1, [["account_auth", "status_ol09_00_001085"]]],
	["/password_policy/minlen", 15, [["account_auth", "status_ol09_00_001105"]]],
	["/password_policy/ocredit", -1, [["account_auth", "status_ol09_00_001120"]]],
	["/password_policy/ucredit", -1, [["account_auth", "status_ol09_00_001005"]]],
	["/ssh_config/ClientAliveCountMax", 1, [["ssh_config", "status_ol09_00_002346"]]],
	["/ssh_config/ClientAliveInterval", 600, [["ssh_config", "status_ol09_00_002347"]]],
]

# one clause per section: a dynamic data.stig.oracle_linux_9[section] reference would include this test package
status("account_auth", name, inp) := s if {
	s := data.stig.oracle_linux_9.account_auth[name] with input as inp
}

status("configuration_management", name, inp) := s if {
	s := data.stig.oracle_linux_9.configuration_management[name] with input as inp
}

status("ssh_config", name, inp) := s if {
	s := data.stig.oracle_linux_9.ssh_config[name] with input as inp
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
