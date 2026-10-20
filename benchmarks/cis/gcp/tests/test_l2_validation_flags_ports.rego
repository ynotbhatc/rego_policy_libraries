package cis_gcp.l2_test

import rego.v1

# Rewritten for CIS GCP Foundation Benchmark v5.0.0 (same test names as before). v5 renumbered
# these checks: SSH is 3.6 and RDP 3.7 (both Level 2); the PostgreSQL Level 2 flags are 6.2.1
# log_error_verbosity and 6.2.4 log_statement (log_checkpoints and log_lock_waits are gone);
# MySQL skip_show_database (6.1.2) is Level 1, so it is reported by cis_gcp.main, not here.

fw(allowed) := {"firewall_rules": [{
	"name": "r", "direction": "INGRESS",
	"allowed": allowed, "sourceRanges": ["0.0.0.0/0"],
}]}

has(prefix, inp) if {
	v := data.cis_gcp.l2.violations with input as inp
	some x in v
	startswith(x, prefix)
}

pg(flags) := {"sql_instances": [{"name": "pg", "databaseVersion": "POSTGRES_15", "settings": {"databaseFlags": flags}}]}

test_unset_mysql_flag_is_violation if {
	inp := {"sql_instances": [{"name": "db1", "databaseVersion": "MYSQL_8_0", "settings": {"databaseFlags": []}}]}
	v := data.cis_gcp.main.violations with input as inp
	some x in v
	startswith(x, "CIS GCP 6.1.2: ")
	not has("CIS L2 6.1.2", inp)
}

test_unset_pg_flags_are_violations if has("CIS L2 6.2.4", pg([]))

test_pg_flag_off_is_violation if has("CIS L2 6.2.1", pg([{"name": "log_error_verbosity", "value": "verbose"}]))

test_flag_on_not_flagged if {
	inp := pg([{"name": "log_statement", "value": "ddl"}])
	not has("CIS L2 6.2.4", inp)
}

test_full_range_exposes_rdp_and_ssh if {
	inp := fw([{"IPProtocol": "tcp", "ports": ["0-65535"]}])
	has("CIS L2 3.7", inp)
	has("CIS L2 3.6", inp)
}

test_protocol_all_exposes_ssh if has("CIS L2 3.6", fw([{"IPProtocol": "all"}]))

test_narrow_range_covers_ssh_only if {
	inp := fw([{"IPProtocol": "tcp", "ports": ["20-30"]}])
	has("CIS L2 3.6: ", inp)
	not has("CIS L2 3.7: ", inp)
}

test_exact_port_still_flagged if has("CIS L2 3.7", fw([{"IPProtocol": "tcp", "ports": ["3389"]}]))

test_other_port_not_flagged if not has("CIS L2 3.6: ", fw([{"IPProtocol": "tcp", "ports": ["443"]}]))

test_udp_not_flagged if not has("CIS L2 3.6: ", fw([{"IPProtocol": "udp", "ports": ["0-65535"]}]))

test_control_count_matches_rules if {
	r := data.cis_gcp.l2.compliance_report with input as {}
	r.l2_controls == 39
}
