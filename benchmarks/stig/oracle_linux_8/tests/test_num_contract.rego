package stig.oracle_linux_8.num_contract_test

# The numeric contract of the Linux STIG modules (benchmarks/stig/LINUX_COLLECTOR_CONTRACT.md, "How the rules
# read a fact", `_num`): a whole JSON number, and nothing else. A number sent as text ("900", " 900 "), a fraction,
# null, a boolean, a list and a non-numeric string are not a pass; a fact that is collected but is not a number is
# an "evidence invalid" finding naming the fact and the type received (owner ruling 2026-11-24). Hand-written:
# each fact of the green fixture that a rule reads through `_num` is replaced in turn, and the status and detail
# of every rule the contract lists for that fact are read.

import rego.v1

fx := data.stig.oracle_linux_8.green_test.green_fixture

# [JSON pointer, the fixture's value, [[section, status rule] of each rule that reads it]]
num_facts := [
	["/crypto_policy_state/min_rsa_size", 2048, [["configuration_management", "status_ol08_00_010182"]]],
	["/faillock_conf/deny", 3, [["account_auth", "status_ol08_00_020011"]]],
	["/faillock_conf/fail_interval", 900, [["account_auth", "status_ol08_00_020013"]]],
	["/password_policy/maxdays", 180, [["account_auth", "status_ol08_00_020200"]]],
	["/password_policy/mindays", 1, [["account_auth", "status_ol08_00_020190"]]],
]

# one clause per section: a dynamic data.stig.oracle_linux_8[section] reference would include this test package
status("account_auth", name, inp) := s if {
	s := data.stig.oracle_linux_8.account_auth[name] with input as inp
}

status("configuration_management", name, inp) := s if {
	s := data.stig.oracle_linux_8.configuration_management[name] with input as inp
}

detail_of(r, inp) := d if {
	d := status(r[0], replace(r[1], "status_", "detail_"), inp)
}

fact_name(f) := replace(trim_prefix(f[0], "/"), "/", ".")

# every rule that reads the fact reports it as invalid, with the type that was received
invalid_as(f, inp, got) if {
	every r in f[2] {
		contains(detail_of(r, inp), sprintf("evidence invalid — %s is not a number (got %s)", [fact_name(f), got]))
	}
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

test_decimal_string_is_evidence_invalid if {
	every f in num_facts {
		every text in [sprintf("%d", [f[1]]), sprintf(" %d ", [f[1]]), sprintf("%d\n", [f[1]])] {
			not passes(f, with_value(f, text))
			invalid_as(f, with_value(f, text), "string")
		}
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
		invalid_as(f, with_value(f, true), "boolean")
		invalid_as(f, with_value(f, false), "boolean")
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
		invalid_as(f, with_value(f, f[1] + 0.5), "a fraction")
		not passes(f, with_value(f, sprintf("%d.5", [f[1]])))
		invalid_as(f, with_value(f, sprintf("%d.5", [f[1]])), "string")
	}
}

test_list_does_not_pass if {
	every f in num_facts {
		not passes(f, with_value(f, [f[1]]))
		invalid_as(f, with_value(f, [f[1]]), "array")
	}
}
