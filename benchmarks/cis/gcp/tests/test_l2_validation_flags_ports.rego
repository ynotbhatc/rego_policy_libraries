package cis_gcp.l2_test

import rego.v1

fw(ports) := {"networking": {"firewall_rules": [{
	"direction": "INGRESS", "action": "allow",
	"ports": ports, "source_ranges": ["0.0.0.0/0"],
}]}}

has(prefix, inp) if {
	v := data.cis_gcp.l2.violations with input as inp
	some x in v
	startswith(x, prefix)
}

test_unset_mysql_flag_is_violation if has("CIS L2 6.1.2", {"cloudsql": {"mysql_instances": [{"name": "db1", "flags": {}}]}})
test_unset_pg_flags_are_violations if has("CIS L2 6.2.1", {"cloudsql": {"postgresql_instances": [{"name": "pg"}]}})
test_pg_flag_off_is_violation if has("CIS L2 6.2.4", {"cloudsql": {"postgresql_instances": [{"flags": {"log_lock_waits": "off"}}]}})

test_flag_on_not_flagged if {
	inp := {"cloudsql": {"mysql_instances": [{"flags": {"skip_show_database": "on"}}]}}
	not has("CIS L2 6.1.2", inp)
}

test_full_range_exposes_rdp_and_ssh if {
	inp := fw([{"protocol": "tcp", "ports": ["0-65535"]}])
	has("CIS L2 3.7", inp)
	has("CIS L2 3.8", inp)
}

test_protocol_all_exposes_ssh if has("CIS L2 3.8", fw([{"protocol": "all"}]))

test_narrow_range_covers_ssh_only if {
	inp := fw([{"protocol": "tcp", "ports": ["20-30"]}])
	has("CIS L2 3.8", inp)
	not has("CIS L2 3.7", inp)
}

test_exact_port_still_flagged if has("CIS L2 3.7", fw([{"protocol": "tcp", "ports": ["3389"]}]))
test_other_port_not_flagged if not has("CIS L2 3.8", fw([{"protocol": "tcp", "ports": ["443"]}]))
test_udp_not_flagged if not has("CIS L2 3.8", fw([{"protocol": "udp", "ports": ["0-65535"]}]))

test_control_count_matches_rules if {
	r := data.cis_gcp.l2.compliance_report with input as {}
	r.l2_controls == 45
}
