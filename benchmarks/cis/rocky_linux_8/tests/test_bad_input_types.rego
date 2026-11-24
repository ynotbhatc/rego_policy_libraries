package cis_rocky_linux_8.bad_input_types_test

# Wrong-typed facts never pass (audit 2026-11-24). Hand-written; the generator does not own this file.
# The all-pass fixture has no finding in these sections. Each case replaces one fact with a value of the
# wrong type and the section must then report a finding:
#   - a numeric fact (a count, days, seconds) is a JSON number: "365", "abc", null, true and [1] do not pass;
#   - has_password decides whether a shadow row is checked, so it is a boolean on every row;
#   - sudo.logfile_exists is optional, but when sent it is a boolean;
#   - a file sweep is finished only when truncated is absent or the boolean false;
#   - mta.inet_interfaces, when sent, is a string.

import rego.v1

fx := data.cis_rocky_linux_8.control_results_test.fixture_compliant

findings(sec, inp) := n if {
	vs := data.cis_rocky_linux_8[sec].violations with input as inp
	n := count(vs)
}

# [section, JSON pointer, the fixture value written as a string]
number_facts := [
	["services", "/chronyd/pools_configured", "1"],
	["services", "/chronyd/servers_configured", "0"],
	["initial_setup", "/initial_setup/gdm_idle_delay", "900"],
	["initial_setup", "/initial_setup/gdm_lock_delay", "5"],
	["pam", "/pam/pass_max_days", "365"],
	["pam", "/pam/pass_warn_age", "7"],
	["pam", "/pam/inactive_days", "30"],
	["pam", "/pam/tmout", "900"],
	["pam", "/user_group/shadow_entries/0/max_days", "365"],
	["pam", "/user_group/shadow_entries/0/warn_days", "7"],
	["pam", "/user_group/shadow_entries/0/inactive", "30"],
	["pam", "/user_group/shadow_entries/0/last_change", "19000"],
]

test_fixture_has_no_finding_in_these_sections if {
	every sec in {"services", "initial_setup", "pam", "sudo", "file_permissions"} {
		findings(sec, fx) == 0
	}
}

test_number_given_as_string_or_other_type_does_not_pass if {
	every f in number_facts {
		every bad in [f[2], "abc", "", null, true, [1]] {
			findings(f[0], json.patch(fx, [{"op": "replace", "path": f[1], "value": bad}])) > 0
		}
	}
}

test_has_password_must_be_boolean if {
	every bad in ["true", "false", null, 0, 1] {
		findings("pam", json.patch(fx, [{"op": "replace", "path": "/user_group/shadow_entries/0/has_password", "value": bad}])) > 0
	}
}

test_has_password_removed_does_not_pass if {
	findings("pam", json.patch(fx, [{"op": "remove", "path": "/user_group/shadow_entries/0/has_password"}])) > 0
}

test_sudo_logfile_exists_must_be_boolean_when_sent if {
	every bad in ["true", "false", 0, 1, false] {
		findings("sudo", json.patch(fx, [{"op": "replace", "path": "/sudo/logfile_exists", "value": bad}])) > 0
	}
}

# optional: without the flag the Defaults logfile line decides, as before
test_sudo_logfile_exists_absent_still_passes if {
	findings("sudo", json.patch(fx, [{"op": "remove", "path": "/sudo/logfile_exists"}])) == 0
}

test_sweep_truncated_must_be_false_or_absent if {
	every key in ["world_writable", "unowned_files", "ungrouped_files"] {
		every bad in ["false", "true", 0, null, true] {
			findings("file_permissions", json.patch(fx, [{"op": "add", "path": sprintf("/%s/truncated", [key]), "value": bad}])) > 0
		}
		findings("file_permissions", json.patch(fx, [{"op": "add", "path": sprintf("/%s/truncated", [key]), "value": false}])) == 0
	}
}

test_mta_inet_interfaces_must_be_a_string_when_sent if {
	every bad in [7, true, ["127.0.0.1"]] {
		findings("services", json.patch(fx, [{"op": "add", "path": "/mta/inet_interfaces", "value": bad}])) > 0
	}
}

# a nulled section input is not collected, exactly like a dropped one
test_null_section_is_not_assessed if {
	dropped := data.cis_rocky_linux_8.not_assessed_sections with input as json.remove(fx, ["/auditd"])
	nulled := data.cis_rocky_linux_8.not_assessed_sections with input as json.patch(fx, [{"op": "replace", "path": "/auditd", "value": null}])
	count(dropped) > 0
	nulled == dropped
}
