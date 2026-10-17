package cis_ubuntu_22_04.sudo_test

import rego.v1

# Validation fix 2026-10-17: sudoers_mode exact-string compare ("440" flagged) and absent mode passed.

pkg := data.cis_ubuntu_22_04.sudo

good := {"installed": true, "use_pty": true, "logfile_configured": true, "su_restricted": true, "sudoers_mode": "0440", "timestamp_timeout": 5}

test_good_compliant if {
	pkg.compliant with input as {"sudo": good}
}

test_mode_440_without_zero_ok if {
	pkg.compliant with input as {"sudo": object.union(good, {"sudoers_mode": "440"})}
}

test_mode_0400_ok if {
	pkg.compliant with input as {"sudo": object.union(good, {"sudoers_mode": "0400"})}
}

test_mode_0640_violates if {
	not pkg.compliant with input as {"sudo": object.union(good, {"sudoers_mode": "0640"})}
}

test_mode_absent_violates if {
	not pkg.compliant with input as {"sudo": object.remove(good, ["sudoers_mode"])}
}

test_nopasswd_still_violates if {
	not pkg.compliant with input as {"sudo": object.union(good, {"nopasswd_entries": ["%wheel ALL=(ALL) NOPASSWD: ALL"]})}
}
