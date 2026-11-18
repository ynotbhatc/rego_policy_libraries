package stig.oracle_linux_8.services_test

import rego.v1

# Validation fixes 2026-10-17: no package inventory is not proof of absence.

m := data.stig.oracle_linux_8.services

clean := {"packages": {"bash": true, "tftp-server": false}, "services": {"sshd": "active"}}

test_services_empty_input_not_compliant if {
	not m.compliant with input as {}
}

test_services_empty_inventory_not_compliant if {
	not m.compliant with input as {"packages": {}, "services": {}}
}

test_services_cat_i_open_without_inventory if {
	m.status_ol08_00_040190 == "Open" with input as {}
	m.status_ol08_00_040000 == "Open" with input as {}
}

test_services_tftp_installed_is_open if {
	i := {"packages": {"tftp-server": true}}
	m.status_ol08_00_040190 == "Open" with input as i
	not m.compliant with input as i
}

test_services_telnet_server_installed_is_open_even_if_telnetd_absent if {
	i := {"packages": {"telnet-server": true, "telnetd": false}}
	m.status_ol08_00_040000 == "Open" with input as i
}
