package cis_gcp.main

import rego.v1

# CIS Google Cloud Platform Foundation Benchmark v2.0.0
# Published: March 2023
#
# Covers GCP services and configurations across:
#   1. IAM                     — Identity and Access Management
#   2. Logging                 — Audit logging and monitoring
#   3. Networking              — VPC, firewall, and network controls
#   4. Virtual Machines        — Compute Engine security
#   5. Storage                 — Cloud Storage bucket controls
#   6. Cloud SQL               — Database security
#   7. BigQuery                — Analytics data protection
#   8. GKE                     — Google Kubernetes Engine
#
# OPA endpoint: POST http://<host>:8181/v1/data/cis_gcp/main/compliance_report

default compliant := false

compliant if {
    count(violations) == 0
}

# ── Section 1 — Identity and Access Management ────────────────────────────────

# 1.1 — Ensure that Corporate Login Credentials are used
violations contains msg if {
    not input.iam.corporate_login.enforced
    msg := "CIS GCP 1.1: Corporate login credentials not enforced — personal Gmail accounts should not have project access"
}

# 1.2 — Ensure that multi-factor authentication is enabled for all non-service accounts
violations contains msg if {
    not input.iam.mfa.enforced_for_users
    msg := "CIS GCP 1.2: MFA not enforced for all non-service account users"
}

# 1.3 — Ensure that Security Key Enforcement is enabled for all admin accounts
violations contains msg if {
    not input.iam.security_key.admin_accounts
    msg := "CIS GCP 1.3: Security key (phishing-resistant MFA) not enforced for admin accounts"
}

# 1.4 — Ensure that Service Account does not have Admin privileges
violations contains msg if {
    not input.iam.service_accounts.no_admin_roles
    msg := "CIS GCP 1.4: One or more service accounts have admin/owner roles — violates least privilege"
}

# 1.5 — Ensure that Service Account Keys are not created for users
violations contains msg if {
    not input.iam.service_account_keys.user_managed_restricted
    msg := "CIS GCP 1.5: User-managed service account keys exist — prefer Google-managed keys"
}

# 1.6 — Ensure that Service Account Keys are rotated within 90 days
violations contains msg if {
    not input.iam.service_account_keys.rotation_90_days
    msg := "CIS GCP 1.6: Service account keys not rotated within 90 days"
}

# 1.7 — Ensure that Separation of duties is enforced while assigning Service Account related roles to users
violations contains msg if {
    not input.iam.service_accounts.separation_of_duties
    msg := "CIS GCP 1.7: Same user can create and use service accounts — separation of duties not enforced"
}

# 1.8 — Ensure that Cloud KMS cryptokeys are not anonymously or publicly accessible
violations contains msg if {
    not input.iam.kms_keys.no_public_access
    msg := "CIS GCP 1.8: Cloud KMS cryptokeys accessible by allUsers or allAuthenticatedUsers"
}

# 1.9 — Ensure that Cloud KMS keys are rotated within 90 days
violations contains msg if {
    not input.iam.kms_keys.rotation_90_days
    msg := "CIS GCP 1.9: Cloud KMS keys not configured for automatic rotation within 90 days"
}

# 1.10 — Ensure KMS encryption keys are protected from deletion
violations contains msg if {
    not input.iam.kms_keys.deletion_protection
    msg := "CIS GCP 1.10: KMS encryption keys not protected against accidental deletion"
}

# 1.11 — Ensure that Workload Identity is used for GKE and other workloads
violations contains msg if {
    not input.iam.workload_identity.enabled
    msg := "CIS GCP 1.11: Workload Identity not used — service account key files in workloads is insecure"
}

# ── Section 2 — Logging ────────────────────────────────────────────────────────

# 2.1 — Ensure that Cloud Audit Logs are configured properly
violations contains msg if {
    not input.logging.audit_logs.data_access_enabled
    msg := "CIS GCP 2.1: Cloud Audit Logs Data Access logging not enabled for all services"
}

# 2.2 — Ensure that sinks are configured for all log entries
violations contains msg if {
    not input.logging.sinks.configured
    msg := "CIS GCP 2.2: Log sink not configured to export all log entries to a long-term storage destination"
}

# 2.3 — Ensure that retention policies on log buckets are configured using Bucket Lock
violations contains msg if {
    not input.logging.retention.bucket_lock_enabled
    msg := "CIS GCP 2.3: Log bucket lock (retention policy) not enabled to prevent log tampering"
}

# 2.4 — Ensure log metric filters and alerts exist for project ownership changes
violations contains msg if {
    not input.logging.alerts.project_ownership_changes
    msg := "CIS GCP 2.4: No metric filter/alert for project ownership assignment or changes"
}

# 2.5 — Ensure log metric filters and alerts exist for audit configuration changes
violations contains msg if {
    not input.logging.alerts.audit_config_changes
    msg := "CIS GCP 2.5: No metric filter/alert for audit configuration changes"
}

# 2.6 — Ensure log metric filters and alerts exist for custom role changes
violations contains msg if {
    not input.logging.alerts.custom_role_changes
    msg := "CIS GCP 2.6: No metric filter/alert for custom IAM role creation, modification, or deletion"
}

# 2.7 — Ensure log metric filters and alerts exist for VPC network changes
violations contains msg if {
    not input.logging.alerts.vpc_network_changes
    msg := "CIS GCP 2.7: No metric filter/alert for VPC network changes"
}

# 2.8 — Ensure log metric filters and alerts exist for VPC network route changes
violations contains msg if {
    not input.logging.alerts.vpc_route_changes
    msg := "CIS GCP 2.8: No metric filter/alert for VPC network route changes"
}

# 2.9 — Ensure log metric filters and alerts exist for VPC network firewall rule changes
violations contains msg if {
    not input.logging.alerts.firewall_rule_changes
    msg := "CIS GCP 2.9: No metric filter/alert for VPC firewall rule changes"
}

# 2.10 — Ensure log metric filters and alerts exist for Cloud Storage IAM permission changes
violations contains msg if {
    not input.logging.alerts.storage_iam_changes
    msg := "CIS GCP 2.10: No metric filter/alert for Cloud Storage bucket IAM permission changes"
}

# 2.11 — Ensure log metric filters and alerts exist for SQL instance configuration changes
violations contains msg if {
    not input.logging.alerts.sql_config_changes
    msg := "CIS GCP 2.11: No metric filter/alert for Cloud SQL instance configuration changes"
}

# ── Section 3 — Networking ─────────────────────────────────────────────────────

# 3.1 — Ensure that the default network does not exist in a project
violations contains msg if {
    not input.networking.default_network.deleted
    msg := "CIS GCP 3.1: Default network exists in the project — delete default network and use custom VPCs"
}

# 3.2 — Ensure that Legacy Networks do not exist in a project
violations contains msg if {
    not input.networking.legacy_networks.none_exist
    msg := "CIS GCP 3.2: Legacy network exists in project — migrate to VPC networks"
}

# 3.3 — Ensure that DNSSEC is enabled for Cloud DNS
violations contains msg if {
    not input.networking.dns.dnssec_enabled
    msg := "CIS GCP 3.3: DNSSEC not enabled for Cloud DNS managed zones"
}

# 3.4 — Ensure that RSASHA1 is not used for the key-signing key in Cloud DNS
violations contains msg if {
    not input.networking.dns.no_rsasha1_key_signing
    msg := "CIS GCP 3.4: RSASHA1 algorithm used for DNSSEC key-signing key — use stronger algorithm"
}

# 3.5 — Ensure that RSASHA1 is not used for the zone-signing key in Cloud DNS
violations contains msg if {
    not input.networking.dns.no_rsasha1_zone_signing
    msg := "CIS GCP 3.5: RSASHA1 algorithm used for DNSSEC zone-signing key — use stronger algorithm"
}

# 3.6 — Ensure that SSH access is restricted from the internet
violations contains msg if {
    not input.networking.firewall.ssh_not_from_internet
    msg := "CIS GCP 3.6: Firewall rule allows SSH (port 22) from 0.0.0.0/0 or ::/0"
}

# 3.7 — Ensure that RDP access is restricted from the internet
violations contains msg if {
    not input.networking.firewall.rdp_not_from_internet
    msg := "CIS GCP 3.7: Firewall rule allows RDP (port 3389) from 0.0.0.0/0 or ::/0"
}

# 3.8 — Ensure that VPC Flow Logs is enabled for every subnet in a VPC Network
violations contains msg if {
    not input.networking.vpc.flow_logs_enabled
    msg := "CIS GCP 3.8: VPC Flow Logs not enabled on all subnets"
}

# 3.9 — Ensure no HTTPS or SSL proxy load balancers permit SSL policies with weak cipher suites
violations contains msg if {
    not input.networking.load_balancer.no_weak_ssl_policies
    msg := "CIS GCP 3.9: Load balancer SSL policy permits weak cipher suites or deprecated TLS versions"
}

# ── Section 4 — Virtual Machines ──────────────────────────────────────────────

# 4.1 — Ensure that instances are not configured to use the default service account with full access to Cloud APIs
violations contains msg if {
    not input.compute.instances.no_default_sa_full_access
    msg := "CIS GCP 4.1: VM instances use default service account with full API access scope"
}

# 4.2 — Ensure that instances are not configured to use the default service account
violations contains msg if {
    not input.compute.instances.no_default_service_account
    msg := "CIS GCP 4.2: VM instances using default service account — create dedicated per-workload service accounts"
}

# 4.3 — Ensure 'Enable connecting to serial ports' is not enabled on VM instance
violations contains msg if {
    not input.compute.instances.serial_port_disabled
    msg := "CIS GCP 4.3: Serial port access enabled on one or more VM instances — disable except for debugging"
}

# 4.4 — Ensure that Compute instances do not have public IP addresses
violations contains msg if {
    not input.compute.instances.no_public_ip
    msg := "CIS GCP 4.4: Compute instances have public IP addresses — use Cloud NAT or IAP for external connectivity"
}

# 4.5 — Ensure that Compute instances have Confidential Computing enabled
violations contains msg if {
    not input.compute.instances.confidential_computing
    msg := "CIS GCP 4.5: Confidential Computing (memory encryption) not enabled on sensitive workload VMs"
}

# 4.6 — Ensure that Compute instances are launched with Shielded VM enabled
violations contains msg if {
    not input.compute.instances.shielded_vm.enabled
    msg := "CIS GCP 4.6: Shielded VM (Secure Boot, vTPM, Integrity Monitoring) not enabled on instances"
}

# 4.7 — Ensure OS login is enabled for a project
violations contains msg if {
    not input.compute.os_login.enabled
    msg := "CIS GCP 4.7: OS Login not enabled — centralized SSH key management via IAM not enforced"
}

# ── Section 5 — Storage ────────────────────────────────────────────────────────

# 5.1 — Ensure that Cloud Storage bucket is not anonymously or publicly accessible
violations contains msg if {
    not input.storage.buckets.no_public_access
    msg := "CIS GCP 5.1: Cloud Storage bucket accessible by allUsers or allAuthenticatedUsers"
}

# 5.2 — Ensure that Cloud Storage buckets have uniform bucket-level access enabled
violations contains msg if {
    not input.storage.buckets.uniform_access
    msg := "CIS GCP 5.2: Uniform bucket-level access not enabled — object-level ACLs create inconsistent controls"
}

# 5.3 — Ensure that logging is enabled for Cloud Storage buckets with sensitive data
violations contains msg if {
    not input.storage.buckets.access_logging
    msg := "CIS GCP 5.3: Access logging not enabled on Cloud Storage buckets containing sensitive data"
}

# ── Section 6 — Cloud SQL ──────────────────────────────────────────────────────

# 6.1 — Ensure that Cloud SQL database instance requires all incoming connections to use SSL
violations contains msg if {
    not input.cloud_sql.ssl.require_ssl
    msg := "CIS GCP 6.1: Cloud SQL database instance does not require SSL for all connections"
}

# 6.2 — Ensure that Cloud SQL database instances are not open to the world
violations contains msg if {
    not input.cloud_sql.authorized_networks.no_public_access
    msg := "CIS GCP 6.2: Cloud SQL authorized network allows 0.0.0.0/0 — restrict to known IPs"
}

# 6.3 — Ensure that Cloud SQL database instances do not have public IPs
violations contains msg if {
    not input.cloud_sql.private_ip.enabled
    msg := "CIS GCP 6.3: Cloud SQL instances use public IP — configure private IP connectivity"
}

# 6.4 — Ensure that Cloud SQL database instances are configured with automated backups
violations contains msg if {
    not input.cloud_sql.backups.automated
    msg := "CIS GCP 6.4: Automated backups not enabled on Cloud SQL instances"
}

# 6.5 — Ensure that Cloud SQL database instances are not using publicly accessible IP addresses
violations contains msg if {
    not input.cloud_sql.flags.no_dangerous_flags
    msg := "CIS GCP 6.5: Cloud SQL database flags set to insecure values (e.g., local_infile=on, log_checkpoints=off)"
}

# ── Section 7 — BigQuery ────────────────────────────────────────────────────────

# 7.1 — Ensure that BigQuery datasets are not anonymously or publicly accessible
violations contains msg if {
    not input.bigquery.datasets.no_public_access
    msg := "CIS GCP 7.1: BigQuery dataset accessible by allUsers or allAuthenticatedUsers"
}

# 7.2 — Ensure that all BigQuery tables are encrypted with Customer Managed Encryption Keys (CMEK)
violations contains msg if {
    not input.bigquery.encryption.cmek_enabled
    msg := "CIS GCP 7.2: BigQuery tables with sensitive data not encrypted with Customer Managed Encryption Keys"
}

# ── Section 8 — Google Kubernetes Engine ──────────────────────────────────────

# 8.1 — Ensure Stackdriver Logging is set to Enabled on Kubernetes Engine Clusters
violations contains msg if {
    not input.gke.logging.enabled
    msg := "CIS GCP 8.1: Cloud Logging (Stackdriver) not enabled on GKE clusters"
}

# 8.2 — Ensure Stackdriver Monitoring is set to Enabled on Kubernetes Engine Clusters
violations contains msg if {
    not input.gke.monitoring.enabled
    msg := "CIS GCP 8.2: Cloud Monitoring (Stackdriver) not enabled on GKE clusters"
}

# 8.3 — Ensure Legacy Authorization is set to Disabled on Kubernetes Engine Clusters
violations contains msg if {
    not input.gke.legacy_abac.disabled
    msg := "CIS GCP 8.3: Legacy Authorization (ABAC) not disabled on GKE cluster — use RBAC"
}

# 8.4 — Ensure Master Authorized Networks is enabled
violations contains msg if {
    not input.gke.master_authorized_networks.enabled
    msg := "CIS GCP 8.4: Master Authorized Networks not enabled — GKE control plane accessible from any IP"
}

# 8.5 — Ensure Kubernetes Clusters are configured with Labels
violations contains msg if {
    not input.gke.cluster.labels_configured
    msg := "CIS GCP 8.5: GKE cluster resource labels not configured for cost attribution and governance"
}

# 8.6 — Ensure Automatic Node Repair is enabled on all node pools
violations contains msg if {
    not input.gke.node_pools.auto_repair
    msg := "CIS GCP 8.6: Automatic node repair not enabled on GKE node pools"
}

# 8.7 — Ensure Automatic Node Upgrades is enabled on node pools
violations contains msg if {
    not input.gke.node_pools.auto_upgrade
    msg := "CIS GCP 8.7: Automatic node upgrades not enabled on GKE node pools"
}

# 8.8 — Ensure Container-Optimized OS is used for Kubernetes Engine Cluster Node image
violations contains msg if {
    not input.gke.node_pools.cos_image
    msg := "CIS GCP 8.8: GKE node pools not using Container-Optimized OS (COS) image"
}

# 8.9 — Ensure Workload Identity is enabled on GKE clusters
violations contains msg if {
    not input.gke.workload_identity.enabled
    msg := "CIS GCP 8.9: Workload Identity not enabled on GKE cluster — pods using node service account instead"
}

# ── Compliance Report ────────────────────────────────────────────────────────

compliance_report := {
    "framework":      "CIS Google Cloud Platform Foundation Benchmark",
    "version":        "v2.0.0",
    "published":      "March 2023",
    "entity_name":    input.entity_name,
    "project_id":     input.gcp_project_id,
    "assessed_at":    input.assessment_date,
    "compliant":      compliant,
    "total_controls": 55,
    "violations":     violations,
    "violation_count": count(violations),
    "section_summary": {
        "iam":              [v | some v in violations; contains(v, "CIS GCP 1.")],
        "logging":          [v | some v in violations; contains(v, "CIS GCP 2.")],
        "networking":       [v | some v in violations; contains(v, "CIS GCP 3.")],
        "virtual_machines": [v | some v in violations; contains(v, "CIS GCP 4.")],
        "storage":          [v | some v in violations; contains(v, "CIS GCP 5.")],
        "cloud_sql":        [v | some v in violations; contains(v, "CIS GCP 6.")],
        "bigquery":         [v | some v in violations; contains(v, "CIS GCP 7.")],
        "gke":              [v | some v in violations; contains(v, "CIS GCP 8.")],
    },
}
