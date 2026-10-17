package cis_rocky_linux_9.logging_test

import rego.v1

has(prefix, inp) if {
	v := data.cis_rocky_linux_9.logging.violations with input as inp
	some x in v
	startswith(x, prefix)
}

test_create_mode_640_ok if not has("CIS 4.2.1.4", {"rsyslog": {"file_create_mode": "0640"}})
test_create_mode_unpadded_640_ok if not has("CIS 4.2.1.4", {"rsyslog": {"file_create_mode": "640"}})
test_create_mode_0600_ok if not has("CIS 4.2.1.4", {"rsyslog": {"file_create_mode": "0600"}})
test_create_mode_0400_ok if not has("CIS 4.2.1.4", {"rsyslog": {"file_create_mode": "0400"}})
test_create_mode_0644_flagged if has("CIS 4.2.1.4", {"rsyslog": {"file_create_mode": "0644"}})
test_create_mode_absent_flagged if has("CIS 4.2.1.4", {"rsyslog": {}})
