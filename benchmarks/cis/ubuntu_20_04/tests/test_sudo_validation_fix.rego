package cis_ubuntu_20_04.sudo_test

import rego.v1

# Validation fix pass 2026-10-17.

good := {"sudo": {"installed": true, "use_pty": true, "logfile_configured": true, "su_restricted": true, "timestamp_timeout": 5, "sudoers_mode": "0440"}}

test_good_input_compliant if {
	data.cis_ubuntu_20_04.sudo.compliant with input as good
}

test_missing_sudoers_mode_flagged if {
	not data.cis_ubuntu_20_04.sudo.compliant with input as json.remove(good, ["sudo/sudoers_mode"])
}

test_sudoers_mode_forms if {
	every m in ["440", "0400", "0o440"] {
		data.cis_ubuntu_20_04.sudo.compliant with input as object.union(good, {"sudo": {"sudoers_mode": m}})
	}
	not data.cis_ubuntu_20_04.sudo.compliant with input as object.union(good, {"sudo": {"sudoers_mode": "0644"}})
}
