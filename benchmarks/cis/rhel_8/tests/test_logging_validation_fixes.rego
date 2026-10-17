package cis_rhel8.logging_test

import rego.v1

# Regression tests for validation 2026-10-17 fixes (octal mode comparison).

test_rsyslog_stricter_create_mode_accepted if {
	v := data.cis_rhel8.logging.rsyslog_violations with input as {"rsyslog": {"file_create_mode": "0400"}}
	not some_createmode_violation(v)
}

test_rsyslog_0640_and_0600_accepted if {
	every m in ["0640", "0600"] {
		v := data.cis_rhel8.logging.rsyslog_violations with input as {"rsyslog": {"file_create_mode": m}}
		not some_createmode_violation(v)
	}
}

test_rsyslog_looser_create_mode_flagged if {
	every m in ["0644", "0660", "0666"] {
		v := data.cis_rhel8.logging.rsyslog_violations with input as {"rsyslog": {"file_create_mode": m}}
		some_createmode_violation(v)
	}
}

some_createmode_violation(v) if {
	some x in v
	startswith(x, "CIS 4.2.1.4")
}
