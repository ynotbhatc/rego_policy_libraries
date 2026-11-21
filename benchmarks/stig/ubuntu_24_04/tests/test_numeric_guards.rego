package stig.ubuntu_24_04.numeric_guards_test

import rego.v1

# Type traps (#300): a ClientAliveInterval that is not a number must not pass.

test_r_ubtu_24_600010_passes_on_a_number if {
	data.stig.ubuntu_24_04.core.r_ubtu_24_600010 with input as {"sshd_config": {"ClientAliveInterval": 600}}
}

test_r_ubtu_24_600010_type_traps_do_not_pass if {
	every v in ["1", null, "x", "600"] {
		not data.stig.ubuntu_24_04.core.r_ubtu_24_600010 with input as {"sshd_config": {"ClientAliveInterval": v}}
		data.stig.ubuntu_24_04.core.status_r_ubtu_24_600010 == "Open" with input as {"sshd_config": {"ClientAliveInterval": v}}
	}
}
