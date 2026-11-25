package stig.oracle_linux_8.alive_whole_numbers_test

# ClientAliveInterval and ClientAliveCountMax are numbers by the check text. The line lists stay text (conflict
# detection), but the value compared must parse as a whole number: digits only, no sign, no fraction, no unit.
# Anything else is evidence invalid. Round 4, 2026-11-24.

import rego.v1

green := data.stig.oracle_linux_8.green_test.green_fixture

with_lines(kw, vs) := json.patch(green, [{"op": "replace", "path": sprintf("/sshd_config_lines/%s", [kw]), "value": vs}])

test_green_passes_both if {
	data.stig.oracle_linux_8.ssh_config.status_ol08_00_010200 == "Not_a_Finding" with input as green
	data.stig.oracle_linux_8.ssh_config.status_ol08_00_010201 == "Not_a_Finding" with input as green
}

test_non_whole_values_are_evidence_invalid if {
	every bad in ["1.0", "+1", "-1", "1s", "one", "0x1", "1,0"] {
		f := data.stig.oracle_linux_8.ssh_config.finding_ol08_00_010200 with input as with_lines("ClientAliveCountMax", [bad])
		f.status == "Open"
		contains(f.detail, "evidence invalid")
	}
	every bad in ["600.0", "+600", "-1", "10m", "six", "6e2"] {
		f := data.stig.oracle_linux_8.ssh_config.finding_ol08_00_010201 with input as with_lines("ClientAliveInterval", [bad])
		f.status == "Open"
		contains(f.detail, "evidence invalid")
	}
}

test_one_bad_line_among_good_ones_is_evidence_invalid if {
	f := data.stig.oracle_linux_8.ssh_config.finding_ol08_00_010201 with input as with_lines("ClientAliveInterval", ["600", "1.5"])
	contains(f.detail, "evidence invalid")
}

test_whole_numbers_are_compared_as_numbers if {
	data.stig.oracle_linux_8.ssh_config.status_ol08_00_010200 == "Open" with input as with_lines("ClientAliveCountMax", ["3"])
	data.stig.oracle_linux_8.ssh_config.status_ol08_00_010201 == "Open" with input as with_lines("ClientAliveInterval", ["601"])
}
