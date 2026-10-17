package cis_oracle.listener_configuration_test

import rego.v1

# Validation fix 2026-10-17: plain TCP exempted from insecure-protocol check; absent
# admin_restrictions / protocol / listeners passed; mode regex was not octal-aware.

good_listener := {
	"name": "L1",
	"services": ["svc"],
	"admin_restrictions": "ON",
	"logging_enabled": true,
	"log_directory": "/var/log",
	"port": 1999,
	"password_protected": true,
	"secure_protocol": "TCPS",
	"valid_node_checking_enabled": true,
}

good_ora := {"admin_restrictions_enabled": true, "file_permissions": "640", "owner": "oracle"}

inp(l) := {"listeners": [l], "listener_ora": good_ora}

test_good_compliant if {
	data.cis_oracle.listener_configuration.compliant with input as inp(good_listener)
}

test_plain_tcp_violates if {
	not data.cis_oracle.listener_configuration.compliant with input as inp(object.union(good_listener, {"secure_protocol": "TCP"}))
}

test_missing_protocol_violates if {
	not data.cis_oracle.listener_configuration.compliant with input as inp(object.remove(good_listener, ["secure_protocol"]))
}

test_missing_admin_restrictions_violates if {
	not data.cis_oracle.listener_configuration.compliant with input as inp(object.remove(good_listener, ["admin_restrictions"]))
}

test_no_listeners_violates if {
	not data.cis_oracle.listener_configuration.compliant with input as {"listener_ora": good_ora}
}

test_leading_zero_mode_ok if {
	data.cis_oracle.listener_configuration.compliant with input as {"listeners": [good_listener], "listener_ora": object.union(good_ora, {"file_permissions": "0640"})}
}

test_group_write_mode_violates if {
	not data.cis_oracle.listener_configuration.compliant with input as {"listeners": [good_listener], "listener_ora": object.union(good_ora, {"file_permissions": "660"})}
}

test_missing_listener_ora_perms_violates if {
	not data.cis_oracle.listener_configuration.compliant with input as {"listeners": [good_listener], "listener_ora": object.remove(good_ora, ["file_permissions"])}
}
