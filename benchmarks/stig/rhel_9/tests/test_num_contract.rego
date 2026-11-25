package stig.rhel_9.num_contract_test

# The numeric contract of the Linux STIG modules (benchmarks/stig/LINUX_COLLECTOR_CONTRACT.md, "How the rules
# read a fact", `_num`): a whole JSON number, and nothing else. A number sent as text ("900", " 900 "), a fraction,
# null, a boolean, a list and a non-numeric string are not a pass; a fact that is collected but is not a number is
# an "evidence invalid" finding naming the fact and the type received (owner ruling 2026-11-24). Hand-written:
# each fact of the green fixture that a rule reads through `_num` is replaced in turn, and the status and detail
# of every rule the contract lists for that fact are read.

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
	["/ssh_config/ClientAliveInterval", 600, [["ssh_config", "status_rhel_09_255100"]]],
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

# RHEL-09-412080 reads ClientAliveInterval only in its Not Applicable branch (cloud-hosted system, attested): the
# idle-session setting is made to fail so that the branch decides
na_input(v) := object.union(fx, {
	"logind_conf": {"StopIdleSessionSec": "0"},
	"attest": {"rhel_09_412080_cloud_hosted": true},
	"ssh_config": {"ClientAliveInterval": v},
})

test_412080_not_applicable_reads_the_interval_as_a_number if {
	data.stig.rhel_9.account_auth.status_rhel_09_412080 == "Not_Applicable" with input as na_input(600)
	every v in ["600", " 600 ", 600.5, true, null, [600]] {
		data.stig.rhel_9.account_auth.status_rhel_09_412080 == "Open" with input as na_input(v)
	}
	d := data.stig.rhel_9.account_auth.detail_rhel_09_412080 with input as na_input("600")
	d == "RHEL-09-412080: evidence invalid — ssh_config.ClientAliveInterval is not a number (got string)"
}
