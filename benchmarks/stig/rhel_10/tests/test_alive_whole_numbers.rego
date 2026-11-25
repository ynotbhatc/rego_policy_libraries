package stig.rhel_10.alive_whole_numbers_test

# ClientAliveInterval and ClientAliveCountMax are numbers by the check text. The line lists stay text (conflict
# detection), but the value compared must parse as a whole number: digits only, no sign, no fraction, no unit.
# Anything else is evidence invalid. Round 4, 2026-11-24.

import rego.v1

green := data.stig.rhel_10.green_test.green_fixture

drop(_, v) := {"file": "/etc/ssh/sshd_config.d/10-stig.conf", "value": v}

with_files(kw, v) := json.patch(green, [{"op": "replace", "path": sprintf("/sshd_config_files/%s", [kw]), "value": [drop(kw, v)]}])

with_runtime(kw, v) := json.patch(green, [{"op": "replace", "path": sprintf("/sshd_runtime/%s", [lower(kw)]), "value": v}])

test_green_passes_both if {
	data.stig.rhel_10.ssh_config.status_rhel_10_700660 == "Not_a_Finding" with input as green
	data.stig.rhel_10.ssh_config.status_rhel_10_700930 == "Not_a_Finding" with input as green
}

test_non_whole_values_are_evidence_invalid_for_both_sources if {
	every bad in ["1.0", "+1", "-1", "1s", "one", "0x1", "1,0", ""] {
		every inp in [with_files("ClientAliveCountMax", bad), with_runtime("ClientAliveCountMax", bad)] {
			f := data.stig.rhel_10.ssh_config.finding_rhel_10_700660 with input as inp
			f.status == "Open"
			contains(f.detail, "evidence invalid")
		}
	}
	every bad in ["600.0", "+600", "-1", "10m", "six", "6e2", ""] {
		every inp in [with_files("ClientAliveInterval", bad), with_runtime("ClientAliveInterval", bad)] {
			f := data.stig.rhel_10.ssh_config.finding_rhel_10_700930 with input as inp
			f.status == "Open"
			contains(f.detail, "evidence invalid")
		}
	}
}

test_whole_numbers_are_compared_as_numbers if {
	data.stig.rhel_10.ssh_config.status_rhel_10_700660 == "Open" with input as with_files("ClientAliveCountMax", "3")
	data.stig.rhel_10.ssh_config.status_rhel_10_700930 == "Open" with input as with_files("ClientAliveInterval", "601")
	data.stig.rhel_10.ssh_config.status_rhel_10_700930 == "Not_a_Finding" with input as with_files("ClientAliveInterval", "0600")
}
