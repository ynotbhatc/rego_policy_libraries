package cis_gcp.l2

# CIS Google Cloud Platform Foundation Benchmark v4.0.0 - Level 2 Additional Controls
# Level 2 extends Level 1 with stricter controls for regulated cloud workloads.
# Intended for: FedRAMP High, PCI-DSS, HIPAA, DoD CC SRG IL4/IL5.

import rego.v1

default compliant := false

compliant if { count(violations) == 0 }

# ---------------------------------------------------------------------------
# Section 1 - Identity and Access Management (L2)
# ---------------------------------------------------------------------------

violations contains "CIS L2 1.2: Ensure that multi-factor authentication is enabled for all non-service accounts" if {
	some user in input.iam.users
	not user.mfa_enabled
	not user.service_account
}

violations contains "CIS L2 1.3: Ensure that Security Key Enforcement is enabled for all admin accounts" if {
	some admin in input.iam.admin_users
	not admin.security_key_enforced
}

violations contains "CIS L2 1.7: Ensure that Service Account has no Admin privileges" if {
	some sa in input.iam.service_accounts
	sa.has_admin_privileges
}

violations contains "CIS L2 1.8: Ensure that service account keys are rotated within 90 days or less" if {
	some key in input.iam.service_account_keys
	key.age_days > 90
	key.active
}

violations contains "CIS L2 1.9: Ensure that Separation of duties is enforced while assigning Service Account related roles to users" if {
	some binding in input.iam.bindings
	binding.role == "roles/iam.serviceAccountUser"
	some other_binding in input.iam.bindings
	other_binding.member == binding.member
	other_binding.role == "roles/iam.serviceAccountTokenCreator"
}

violations contains "CIS L2 1.10: Ensure that Cloud KMS cryptokeys are not anonymously or publicly accessible" if {
	some key in input.kms.crypto_keys
	some binding in key.iam_bindings
	binding.member == "allUsers"
}

violations contains "CIS L2 1.15: Ensure that organizational policies are configured to restrict the use of publicly accessible Cloud Storage buckets" if {
	not input.org_policies.storage_public_access_prevention_enforced
}

violations contains "CIS L2 1.16: Ensure Essentials Contacts is configured for Organization" if {
	not input.org.essential_contacts_configured
}

# ---------------------------------------------------------------------------
# Section 2 - Logging and Monitoring (L2)
# ---------------------------------------------------------------------------

violations contains "CIS L2 2.2: Ensure that sinks are configured for all log entries" if {
	not input.logging.sink_for_all_entries_configured
}

violations contains "CIS L2 2.3: Ensure that retention policies on log buckets are configured using Bucket Lock" if {
	some bucket in input.logging.log_buckets
	not bucket.locked
}

violations contains "CIS L2 2.4: Ensure log metric filter and alerts exist for project ownership assignments" if {
	not input.logging.metric_filters.project_ownership_change
}

violations contains "CIS L2 2.5: Ensure log metric filter and alerts exist for audit configuration changes" if {
	not input.logging.metric_filters.audit_config_change
}

violations contains "CIS L2 2.6: Ensure log metric filter and alerts exist for custom role changes" if {
	not input.logging.metric_filters.custom_role_change
}

violations contains "CIS L2 2.7: Ensure log metric filter and alerts exist for VPC network firewall rule changes" if {
	not input.logging.metric_filters.firewall_rule_change
}

violations contains "CIS L2 2.8: Ensure log metric filter and alerts exist for VPC network route changes" if {
	not input.logging.metric_filters.vpc_route_change
}

violations contains "CIS L2 2.9: Ensure log metric filter and alerts exist for VPC network changes" if {
	not input.logging.metric_filters.vpc_network_change
}

violations contains "CIS L2 2.10: Ensure log metric filter and alerts exist for Cloud Storage IAM permission changes" if {
	not input.logging.metric_filters.storage_iam_change
}

violations contains "CIS L2 2.11: Ensure log metric filter and alerts exist for SQL instance configuration changes" if {
	not input.logging.metric_filters.sql_instance_change
}

# ---------------------------------------------------------------------------
# Section 3 - Networking (L2)
# ---------------------------------------------------------------------------

violations contains "CIS L2 3.1: Ensure VPC Flow Logs is enabled for every subnet in a VPC Network" if {
	some subnet in input.networking.subnets
	not subnet.flow_logs_enabled
}

violations contains "CIS L2 3.2: Ensure legacy networks do not exist for older projects" if {
	some project in input.projects
	project.has_legacy_network
}

violations contains "CIS L2 3.7: Ensure that RDP access is restricted from the Internet (0.0.0.0/0)" if {
	some rule in input.networking.firewall_rules
	rule.direction == "INGRESS"
	rule.action == "allow"
	contains_port(rule.ports, "tcp", "3389")
	some source_range in rule.source_ranges
	source_range == "0.0.0.0/0"
}

violations contains "CIS L2 3.8: Ensure that SSH access is restricted from the Internet (0.0.0.0/0)" if {
	some rule in input.networking.firewall_rules
	rule.direction == "INGRESS"
	rule.action == "allow"
	contains_port(rule.ports, "tcp", "22")
	some source_range in rule.source_ranges
	source_range == "0.0.0.0/0"
}

violations contains "CIS L2 3.10: Ensure Firewall Rules for instances behind Identity Aware Proxy (IAP) only allow traffic from Google Cloud Load Balancing and Cloud IAP IP ranges" if {
	input.networking.iap_enabled
	some rule in input.networking.firewall_rules
	not rule.source_is_iap_range
}

violations contains "CIS L2 3.11: Ensure that Cloud DNS logging is enabled for all VPC networks" if {
	some network in input.networking.vpc_networks
	not network.dns_logging_enabled
}

contains_port(ports, protocol, port) if {
	some port_spec in ports
	port_spec.protocol == protocol
	port == port_spec.ports[_]
}

# ---------------------------------------------------------------------------
# Section 4 - Virtual Machines (L2)
# ---------------------------------------------------------------------------

violations contains "CIS L2 4.2: Ensure that instances are not configured to use the default service account with full access to all Cloud APIs" if {
	some instance in input.compute.instances
	instance.service_account == "default"
	instance.service_account_scope == "https://www.googleapis.com/auth/cloud-platform"
}

violations contains "CIS L2 4.3: Ensure that instances are not configured to use the default service account" if {
	some instance in input.compute.instances
	instance.service_account == "default"
	not instance.service_account_scope
}

violations contains "CIS L2 4.5: Ensure 'Enable connecting to serial ports' is not enabled on VM instances" if {
	some instance in input.compute.instances
	instance.serial_port_enabled
}

violations contains "CIS L2 4.6: Ensure that IP forwarding is not enabled on Instances" if {
	some instance in input.compute.instances
	instance.can_ip_forward
}

violations contains "CIS L2 4.7: Ensure VM disks for critical VMs are encrypted with Customer-Supplied Encryption Keys (CSEK)" if {
	some disk in input.compute.disks
	disk.critical
	not disk.csek_encrypted
}

violations contains "CIS L2 4.8: Ensure Compute instances are launched with Shielded VM enabled" if {
	some instance in input.compute.instances
	not instance.shielded_vm.enabled
}

violations contains "CIS L2 4.9: Ensure Compute instances do not have public IP addresses" if {
	some instance in input.compute.instances
	instance.has_public_ip
	not instance.requires_public_ip
}

violations contains "CIS L2 4.11: Ensure that Compute instances have Confidential Computing enabled" if {
	some instance in input.compute.instances
	instance.requires_confidential_computing
	not instance.confidential_computing_enabled
}

# ---------------------------------------------------------------------------
# Section 5 - Storage (L2)
# ---------------------------------------------------------------------------

violations contains "CIS L2 5.1: Ensure that Cloud Storage bucket is not anonymously or publicly accessible" if {
	some bucket in input.storage.buckets
	some binding in bucket.iam_bindings
	binding.member == "allUsers"
}

violations contains "CIS L2 5.2: Ensure that Cloud Storage buckets have uniform bucket-level access enabled" if {
	some bucket in input.storage.buckets
	not bucket.uniform_bucket_level_access
}

# ---------------------------------------------------------------------------
# Section 6 - Cloud SQL Database Services (L2)
# ---------------------------------------------------------------------------

violations contains "CIS L2 6.1.1: Ensure that a MySQL database instance does not allow anyone to connect with administrative privileges" if {
	some instance in input.cloudsql.mysql_instances
	instance.root_password_empty
}

violations contains "CIS L2 6.1.2: Ensure that the MySQL database instance 'skip_show_database' flag is set to 'on'" if {
	some instance in input.cloudsql.mysql_instances
	instance.flags["skip_show_database"] != "on"
}

violations contains "CIS L2 6.2.1: Ensure that the PostgreSQL database instance 'log_checkpoints' flag is set to 'on'" if {
	some instance in input.cloudsql.postgresql_instances
	instance.flags["log_checkpoints"] != "on"
}

violations contains "CIS L2 6.2.2: Ensure that the PostgreSQL database instance 'log_connections' flag is set to 'on'" if {
	some instance in input.cloudsql.postgresql_instances
	instance.flags["log_connections"] != "on"
}

violations contains "CIS L2 6.2.3: Ensure that the PostgreSQL database instance 'log_disconnections' flag is set to 'on'" if {
	some instance in input.cloudsql.postgresql_instances
	instance.flags["log_disconnections"] != "on"
}

violations contains "CIS L2 6.2.4: Ensure that the PostgreSQL database instance 'log_lock_waits' flag is set to 'on'" if {
	some instance in input.cloudsql.postgresql_instances
	instance.flags["log_lock_waits"] != "on"
}

violations contains "CIS L2 6.4: Ensure that Cloud SQL database instances are not open to the world" if {
	some instance in input.cloudsql.instances
	some network in instance.authorized_networks
	network.value == "0.0.0.0/0"
}

violations contains "CIS L2 6.6: Ensure that Cloud SQL database instances do not have public IPs" if {
	some instance in input.cloudsql.instances
	instance.has_public_ip
}

# ---------------------------------------------------------------------------
# Section 7 - BigQuery (L2)
# ---------------------------------------------------------------------------

violations contains "CIS L2 7.1: Ensure that BigQuery datasets are not anonymously or publicly accessible" if {
	some dataset in input.bigquery.datasets
	some binding in dataset.iam_bindings
	binding.member == "allUsers"
}

violations contains "CIS L2 7.2: Ensure that all BigQuery Tables are encrypted with Customer-managed encryption key (CMEK)" if {
	some table in input.bigquery.tables
	not table.cmek_encrypted
}

violations contains "CIS L2 7.3: Ensure that a Default Customer-managed encryption key (CMEK) is specified for all BigQuery datasets" if {
	some dataset in input.bigquery.datasets
	not dataset.default_cmek_configured
}

# ---------------------------------------------------------------------------
# Compliance report
# ---------------------------------------------------------------------------

l2_total_controls := 42

compliance_report := {
	"profile":           "level2",
	"benchmark":         "CIS Google Cloud Platform Foundation Benchmark v4.0.0",
	"l2_controls":       l2_total_controls,
	"l2_violations":     count(violations),
	"l2_compliant":      compliant,
	"l2_violation_list": [v | some v in violations],
	"note": "Level 2 controls supplement Level 1. Intended for regulated GCP workloads (FedRAMP High, PCI-DSS, HIPAA, DoD).",
}
