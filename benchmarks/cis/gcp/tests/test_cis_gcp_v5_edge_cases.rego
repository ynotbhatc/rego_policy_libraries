package cis_gcp_foundations_v5_edge_test

import rego.v1

# Edge cases for cis_gcp_foundations (CIS GCP Foundation Benchmark v5.0.0): empty-versus-absent
# evidence, absent fields inside a resource (must fail, never silently pass), exclusions the
# benchmark names, and partial inventories. The fixture is the all-passing one from
# test_cis_gcp_v5_controls.rego.

now_ns := 1790812800000000000

good := data.cis_gcp_foundations_v5_test.good

failing(inp) := f if {
	f := data.cis_gcp_foundations.failing_controls with input as inp with time.now_ns as now_ns
}

msgs(inp) := v if {
	v := data.cis_gcp_foundations.violations with input as inp with time.now_ns as now_ns
}

patched(ops) := json.patch(good, ops)

# ── existence checks: an empty list is not evidence of compliance ──

test_no_sinks_fails_2_3 if "2.3" in failing(patched([{"op": "replace", "path": "/log_sinks", "value": []}]))

test_no_contacts_fails_1_17 if "1.17" in failing(patched([{"op": "replace", "path": "/essential_contacts", "value": []}]))

test_no_services_fails_2_14 if "2.14" in failing(patched([{"op": "replace", "path": "/enabled_services", "value": []}]))

test_no_metrics_fails_all_metric_checks if {
	f := failing(patched([{"op": "replace", "path": "/log_metrics", "value": []}]))
	every id in ["2.5", "2.6", "2.7", "2.8", "2.9", "2.10", "2.11", "2.12"] {
		id in f
	}
}

test_disabled_alert_fails_metric_check if "2.12" in failing(patched([{"op": "replace", "path": "/alert_policies/7/enabled", "value": false}]))

test_contacts_by_category_pass if not "1.17" in failing(patched([{"op": "replace", "path": "/essential_contacts/0/notificationCategorySubscriptions", "value": ["LEGAL", "SECURITY", "SUSPENSION", "TECHNICAL"]}]))

test_service_objects_accepted if not "2.14" in failing(patched([{"op": "replace", "path": "/enabled_services", "value": [{"name": "projects/1/services/cloudasset.googleapis.com", "state": "ENABLED"}]}]))

# ── offender lists: an empty inventory has nothing to flag ──

test_no_instances_passes_instance_checks if {
	f := failing(patched([{"op": "replace", "path": "/compute_instances", "value": []}]))
	every id in ["4.1", "4.2", "4.3", "4.5", "4.6", "4.8", "4.9", "4.11"] {
		not id in f
	}
}

# ── absent fields inside a resource fail closed ──

test_sa_without_key_list_fails if {
	f := failing(patched([{"op": "remove", "path": "/service_accounts/0/keys"}]))
	"1.5" in f
	"1.8" in f
}

test_user_key_without_timestamp_fails_1_8 if "1.8" in failing(patched([{"op": "add", "path": "/service_accounts/0/keys/-", "value": {"name": "k", "keyType": "USER_MANAGED"}}]))

test_api_key_without_create_time_fails_1_16 if "1.16" in failing(patched([{"op": "add", "path": "/api_keys/-", "value": {"name": "k", "restrictions": {"apiTargets": [{"service": "maps-backend.googleapis.com"}]}}}]))

test_api_key_without_restrictions_fails_1_15 if "1.15" in failing(patched([{"op": "add", "path": "/api_keys/-", "value": {"name": "k", "createTime": "2026-09-30T00:00:00Z"}}]))

test_kms_key_without_policy_fails_1_10 if "1.10" in failing(patched([{"op": "remove", "path": "/kms_keys/0/iam_policy"}]))

test_kms_key_policy_without_bindings_passes_1_10 if not "1.10" in failing(patched([{"op": "replace", "path": "/kms_keys/0/iam_policy", "value": {"etag": "x"}}]))

test_bucket_without_policy_fails_5_1 if "5.1" in failing(patched([{"op": "remove", "path": "/storage_buckets/0/iam_policy"}]))

test_unnamed_instance_still_reported if "4.6" in failing(patched([
	{"op": "remove", "path": "/compute_instances/0/name"},
	{"op": "replace", "path": "/compute_instances/0/canIpForward", "value": true},
]))

test_instance_without_shielded_config_fails_4_8 if "4.8" in failing(patched([{"op": "remove", "path": "/compute_instances/0/shieldedInstanceConfig"}]))

test_kms_rotation_too_far_out_fails if "1.11" in failing(patched([{"op": "replace", "path": "/kms_keys/0/nextRotationTime", "value": "2027-06-01T00:00:00Z"}]))

test_asymmetric_kms_key_not_rotation_checked if not "1.11" in failing(patched([
	{"op": "replace", "path": "/kms_keys/0/purpose", "value": "ASYMMETRIC_SIGN"},
	{"op": "remove", "path": "/kms_keys/0/rotationPeriod"},
]))

# ── exclusions named by the benchmark ──

gke_vm := {
	"name": "gke-pool-1-abc", "labels": {"goog-gke-node": ""}, "canIpForward": true,
	"serviceAccounts": [{"email": "1-compute@developer.gserviceaccount.com", "scopes": ["https://www.googleapis.com/auth/cloud-platform"]}],
	"metadata": {"items": [{"key": "block-project-ssh-keys", "value": "true"}]},
	"networkInterfaces": [{"accessConfigs": [{"type": "ONE_TO_ONE_NAT"}]}],
	"shieldedInstanceConfig": {"enableVtpm": true, "enableIntegrityMonitoring": true},
}

test_gke_nodes_excluded if {
	f := failing(patched([{"op": "add", "path": "/compute_instances/-", "value": gke_vm}]))
	every id in ["4.1", "4.2", "4.6", "4.9"] {
		not id in f
	}
}

test_disk_marked_not_critical_exempt if not "4.7" in failing(patched([
	{"op": "remove", "path": "/compute_disks/0/diskEncryptionKey"},
	{"op": "add", "path": "/compute_disks/0/critical", "value": false},
]))

test_non_n2d_instance_not_confidential_checked if not "4.11" in failing(patched([
	{"op": "replace", "path": "/compute_instances/0/machineType", "value": "zones/z/machineTypes/e2-medium"},
	{"op": "remove", "path": "/compute_instances/0/confidentialInstanceConfig"},
]))

test_proxy_subnet_not_flow_log_checked if not "3.10" in failing(patched([{"op": "add", "path": "/subnetworks/-", "value": {"name": "proxy", "purpose": "REGIONAL_MANAGED_PROXY"}}]))

test_filtered_flow_logs_fail if "3.10" in failing(patched([{"op": "add", "path": "/subnetworks/0/logConfig/filterExpr", "value": "src_ip == '10.0.0.1'"}]))

test_read_replica_not_ip_or_backup_checked if {
	f := failing(patched([{"op": "add", "path": "/sql_instances/-", "value": {
		"name": "replica", "databaseVersion": "MYSQL_8_0", "instanceType": "READ_REPLICA_INSTANCE",
		"settings": {"databaseFlags": [{"name": "skip_show_database", "value": "on"}, {"name": "local_infile", "value": "off"}], "ipConfiguration": {"sslMode": "ENCRYPTED_ONLY"}, "backupConfiguration": {"enabled": false}},
		"ipAddresses": [{"type": "PRIMARY"}],
	}}]))
	not "6.7" in f
	not "6.8" in f
}

# ── firewall port and protocol handling ──

fw(rule) := patched([{"op": "add", "path": "/firewall_rules/-", "value": object.union({"name": "r", "direction": "INGRESS", "sourceRanges": ["0.0.0.0/0"]}, rule)}])

test_protocol_all_exposes_ssh_and_rdp if {
	f := failing(fw({"allowed": [{"IPProtocol": "all"}]}))
	"3.6" in f
	"3.7" in f
}

test_disabled_rule_not_flagged if not "3.6" in failing(fw({"disabled": true, "allowed": [{"IPProtocol": "tcp", "ports": ["22"]}]}))

test_egress_rule_not_flagged if not "3.6" in failing(fw({"direction": "EGRESS", "allowed": [{"IPProtocol": "tcp", "ports": ["22"]}]}))

test_udp_rule_not_flagged if not "3.7" in failing(fw({"allowed": [{"IPProtocol": "udp", "ports": ["3389"]}]}))

test_internal_source_not_flagged if not "3.6" in failing(patched([{"op": "add", "path": "/firewall_rules/-", "value": {"name": "r", "sourceRanges": ["10.0.0.0/8"], "allowed": [{"IPProtocol": "tcp", "ports": ["22"]}]}}]))

# ── Cloud SQL flag defaults ──

test_pg_without_flag_list_uses_defaults if {
	f := failing(patched([{"op": "remove", "path": "/sql_instances/1/settings/databaseFlags"}]))
	"6.2.2" in f # log_connections defaults to off
	not "6.2.5" in f # log_min_messages defaults to a compliant level
	not "6.2.7" in f
}

test_sql_instance_without_settings_fails_flag_checks if {
	f := failing(patched([{"op": "remove", "path": "/sql_instances/2/settings"}]))
	"6.3.1" in f
	"6.4" in f
}

# ── audit logging ──

test_inherited_audit_config_satisfies_2_1 if not "2.1" in failing(patched([
	{"op": "remove", "path": "/iam_policy/auditConfigs"},
	{"op": "add", "path": "/inherited_audit_configs", "value": [{"service": "allServices", "auditLogConfigs": [{"logType": "DATA_READ"}, {"logType": "DATA_WRITE"}]}]},
]))

test_exempted_members_fail_2_1 if "2.1" in failing(patched([{"op": "add", "path": "/iam_policy/auditConfigs/0/auditLogConfigs/1/exemptedMembers", "value": ["user:svc@example.com"]}]))

test_sink_to_unknown_bucket_fails_2_4 if "2.4" in failing(patched([{"op": "add", "path": "/log_sinks/-", "value": {"name": "s2", "destination": "storage.googleapis.com/elsewhere", "filter": ""}}]))

test_uncovered_network_fails_2_13 if "2.13" in failing(patched([{"op": "add", "path": "/vpc_networks/-", "value": {"name": "dev", "x_gcloud_subnet_mode": "CUSTOM"}}]))

# ── partial inventories: only "evidence missing", never a finding from partial data ──

test_missing_alerts_reports_only_evidence if {
	v := msgs(json.remove(good, ["alert_policies"]))
	"2.5: evidence missing — alert_policies not collected" in v
	count([m | some m in v; startswith(m, "2.5: "); not contains(m, "evidence missing")]) == 0
}

test_one_message_per_resource_one_failing_control if {
	inp := patched([
		{"op": "replace", "path": "/compute_instances/0/canIpForward", "value": true},
		{"op": "add", "path": "/compute_instances/-", "value": object.union(good.compute_instances[0], {"name": "vm2", "canIpForward": true})},
	])
	count([m | some m in msgs(inp); startswith(m, "4.6: ")]) == 2
	s := data.cis_gcp_foundations.compliance_summary with input as inp with time.now_ns as now_ns
	s.failing_controls == 1
}

test_empty_iam_policy_is_not_evidence if {
	v := msgs(patched([{"op": "replace", "path": "/iam_policy", "value": {}}]))
	"1.6: evidence missing — iam_policy not collected" in v
	"2.1: evidence missing — iam_policy not collected" in v
}
