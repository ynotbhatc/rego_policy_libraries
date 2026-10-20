# METADATA
# title: "CIS Google Cloud Platform Foundation Benchmark v5.0.0"
# custom:
#   class: security
#   framework: cis_gcp
#   source: cis
#   domains: [cloud, gcp]
#   coverage:
#     checks: 148
#     cited: 93
#     density: sized
#     basis: size
#     tested: true
#     entrypoint: none
#     guard: self
#     as_of: v2.4.2
package cis_gcp_foundations

# CIS Google Cloud Platform Foundation Benchmark v5.0.0
# All 93 recommendations (54 Level 1, 39 Level 2) in 8 sections: IAM, Logging and Monitoring,
# Networking, Virtual Machines, Storage, Cloud SQL, BigQuery, Dataproc. Ids, titles, profiles and
# Automated/Manual status come from the v5.0.0 workbook; messages are our own words.
#
# 71 Automated recommendations are evaluated from the project's resource inventory. When the
# inventory a check needs was not collected, the check fails with
# "<id>: evidence missing — <field> not collected" (never a pass). An empty list is evidence of
# "no resources of this kind", except for checks that require something to EXIST (a sink, a log
# metric + alert, an essential contact, the Cloud Asset API, DNS logging coverage), where an empty
# list fails.
# 22 Manual recommendations pass only on an explicit attestation: input.attest.<key> == true.
#
# This package is the engine. cis_gcp.main (the /v1/data/cis_gcp/main/compliance_report entrypoint)
# and cis_gcp.l2 (the Level 2 view) read its rules.
#
# Input contract (one GCP project; field names are those of the gcloud/bq JSON output):
#   iam_policy             : gcloud projects get-iam-policy --format=json -> {bindings[{role, members[]}], auditConfigs[]}
#   inherited_audit_configs: optional auditConfigs[] from the parent folder/organization policy (2.1)
#   service_accounts[]     : {email, keys[{name, keyType, validAfterTime}]} (keys = gcloud iam service-accounts keys list)
#   kms_keys[]             : {name, purpose, rotationPeriod, nextRotationTime, iam_policy{bindings[]}}
#   api_keys[]             : gcloud services api-keys list --format=json -> {name, createTime, restrictions{apiTargets[{service}]}}
#   essential_contacts[]   : organization contacts -> {email, notificationCategorySubscriptions[]}
#   log_sinks[]            : {name, destination, filter}
#   log_metrics[]          : {name, filter}
#   alert_policies[]       : {enabled, conditions[{conditionThreshold{filter}}]}
#   enabled_services[]     : enabled API names ("cloudasset.googleapis.com") or {name}/{config{name}} objects
#   backend_services[]     : {name, protocol, logConfig{enable}}
#   vpc_networks[]         : {name, selfLink, x_gcloud_subnet_mode | IPv4Range}
#   dns_policies[]         : {name, enableLogging, networks[{networkUrl}]}
#   dns_managed_zones[]    : {name, visibility, dnssecConfig{state, defaultKeySpecs[{keyType, algorithm}]}}
#   firewall_rules[]       : {name, direction, disabled, sourceRanges[], allowed[{IPProtocol, ports[]}]}
#   subnetworks[]          : {name, purpose, enableFlowLogs, logConfig{enable, aggregationInterval, flowSampling, metadata, filterExpr}}
#   compute_project        : gcloud compute project-info describe -> {commonInstanceMetadata{items[{key, value}]}}
#   compute_instances[]    : gcloud compute instances list --format=json
#   compute_disks[]        : {name, diskEncryptionKey{sha256}, critical}; a disk is in scope for 4.7 unless critical == false
#   storage_buckets[]      : {name, iamConfiguration{uniformBucketLevelAccess{enabled}}, retentionPolicy{isLocked}, iam_policy{bindings[]}}
#   sql_instances[]        : gcloud sql instances list --format=json (settings.databaseFlags may be omitted when none are set)
#   bigquery_datasets[]    : {id, access[{specialGroup, iamMember}], defaultEncryptionConfiguration{kmsKeyName}}
#   bigquery_tables[]      : {id, encryptionConfiguration{kmsKeyName}}
#   dataproc_clusters[]    : {clusterName, config{encryptionConfig{gcePdKmsKeyName}}}
#   attest.<key>           : attestation booleans for the Manual recommendations (see `attestations`)

import rego.v1

default compliant := false

compliant if count(violations) == 0

# ── Recommendation table (ids, titles, profile level and status from the v5.0.0 workbook) ──
controls := {
	"1.1.1": {"section": "1", "level": 1, "automated": false, "title": "Ensure Super Admin Email Address Is Not Tied To A Single User"},
	"1.1.2": {"section": "1", "level": 1, "automated": false, "title": "Ensure Super Admin Account Is Not Used For Google Cloud Administration"},
	"1.1.3": {"section": "1", "level": 2, "automated": false, "title": "Ensure Folders Are Structured By Environment And Sensitivity"},
	"1.1.4": {"section": "1", "level": 2, "automated": false, "title": "Ensure Organization Policies Are Configured For Centralized Constraints"},
	"1.2": {"section": "1", "level": 1, "automated": false, "title": "Ensure that Corporate Login Credentials are Used"},
	"1.3": {"section": "1", "level": 1, "automated": false, "title": "Ensure that Multi-Factor Authentication is 'Enabled' for All Non-Service Accounts"},
	"1.4": {"section": "1", "level": 2, "automated": false, "title": "Ensure that Security Key Enforcement is Enabled for All Admin Accounts"},
	"1.5": {"section": "1", "level": 1, "automated": true, "title": "Ensure That There Are Only GCP-Managed Service Account Keys for Each Service Account"},
	"1.6": {"section": "1", "level": 1, "automated": true, "title": "Ensure That Service Account Has No Admin Privileges"},
	"1.7": {"section": "1", "level": 1, "automated": true, "title": "Ensure That IAM Users Are Not Assigned the Service Account User or Service Account Token Creator Roles at Project Level"},
	"1.8": {"section": "1", "level": 1, "automated": true, "title": "Ensure User-Managed/External Keys for Service Accounts Are Rotated Every 90 Days or Fewer"},
	"1.9": {"section": "1", "level": 2, "automated": true, "title": "Ensure That Separation of Duties Is Enforced While Assigning Service Account Related Roles to Users"},
	"1.10": {"section": "1", "level": 1, "automated": true, "title": "Ensure That Cloud KMS Cryptokeys Are Not Anonymously or Publicly Accessible"},
	"1.11": {"section": "1", "level": 1, "automated": true, "title": "Ensure KMS Encryption Keys Are Rotated Within a Period of 90 Days"},
	"1.12": {"section": "1", "level": 2, "automated": true, "title": "Ensure That Separation of Duties Is Enforced While Assigning KMS Related Roles to Users"},
	"1.13": {"section": "1", "level": 2, "automated": true, "title": "Ensure API Keys Only Exist for Active Services"},
	"1.14": {"section": "1", "level": 2, "automated": false, "title": "Ensure API Keys Are Restricted To Use by Only Specified Hosts and Apps"},
	"1.15": {"section": "1", "level": 2, "automated": true, "title": "Ensure API Keys Are Restricted to Only APIs That Application Needs Access"},
	"1.16": {"section": "1", "level": 2, "automated": true, "title": "Ensure API Keys Are Rotated Every 90 Days"},
	"1.17": {"section": "1", "level": 1, "automated": true, "title": "Ensure Essential Contacts is Configured for Organization"},
	"1.18": {"section": "1", "level": 1, "automated": false, "title": "Ensure Secrets are Not Stored in Cloud Functions Environment Variables by Using Secret Manager"},
	"2.1": {"section": "2", "level": 1, "automated": true, "title": "Ensure That Cloud Audit Logging Is Configured Properly"},
	"2.2": {"section": "2", "level": 1, "automated": false, "title": "Ensure Google Workspace/Cloud Identity Data Sharing with Google Cloud is Enabled for Admin Audit Logging"},
	"2.3": {"section": "2", "level": 1, "automated": true, "title": "Ensure That Sinks Are Configured for All Log Entries"},
	"2.4": {"section": "2", "level": 2, "automated": true, "title": "Ensure That Retention Policies on Cloud Storage Buckets Used for Exporting Logs Are Configured Using Bucket Lock"},
	"2.5": {"section": "2", "level": 1, "automated": true, "title": "Ensure Log Metric Filter and Alerts Exist for Project Ownership Assignments/Changes"},
	"2.6": {"section": "2", "level": 1, "automated": true, "title": "Ensure That the Log Metric Filter and Alerts Exist for Audit Configuration Changes"},
	"2.7": {"section": "2", "level": 1, "automated": true, "title": "Ensure That the Log Metric Filter and Alerts Exist for Custom Role Changes"},
	"2.8": {"section": "2", "level": 2, "automated": true, "title": "Ensure That the Log Metric Filter and Alerts Exist for VPC Network Firewall Rule Changes"},
	"2.9": {"section": "2", "level": 2, "automated": true, "title": "Ensure That the Log Metric Filter and Alerts Exist for VPC Network Route Changes"},
	"2.10": {"section": "2", "level": 2, "automated": true, "title": "Ensure That the Log Metric Filter and Alerts Exist for VPC Network Changes"},
	"2.11": {"section": "2", "level": 2, "automated": true, "title": "Ensure That the Log Metric Filter and Alerts Exist for Cloud Storage IAM Permission Changes"},
	"2.12": {"section": "2", "level": 2, "automated": true, "title": "Ensure That the Log Metric Filter and Alerts Exist for SQL Instance Configuration Changes"},
	"2.13": {"section": "2", "level": 1, "automated": true, "title": "Ensure That Cloud DNS Logging Is Enabled for All VPC Networks"},
	"2.14": {"section": "2", "level": 1, "automated": true, "title": "Ensure Cloud Asset Inventory Is Enabled"},
	"2.15": {"section": "2", "level": 2, "automated": false, "title": "Ensure 'Access Transparency' is 'Enabled'"},
	"2.16": {"section": "2", "level": 2, "automated": false, "title": "Ensure 'Access Approval' is 'Enabled'"},
	"2.17": {"section": "2", "level": 2, "automated": true, "title": "Ensure Logging is enabled for HTTP(S) Load Balancer"},
	"3.1": {"section": "3", "level": 2, "automated": true, "title": "Ensure That the Default Network Does Not Exist in a Project"},
	"3.2": {"section": "3", "level": 1, "automated": true, "title": "Ensure Legacy Networks Do Not Exist for Older Projects"},
	"3.3": {"section": "3", "level": 1, "automated": true, "title": "Ensure That DNSSEC Is Enabled for Cloud DNS"},
	"3.4": {"section": "3", "level": 1, "automated": true, "title": "Ensure That RSASHA1 Is Not Used for the Key-Signing Key in Cloud DNS DNSSEC"},
	"3.5": {"section": "3", "level": 1, "automated": true, "title": "Ensure That RSASHA1 Is Not Used for the Zone-Signing Key in Cloud DNS DNSSEC"},
	"3.6": {"section": "3", "level": 2, "automated": true, "title": "Ensure That SSH Access Is Restricted From the Internet"},
	"3.7": {"section": "3", "level": 2, "automated": true, "title": "Ensure That RDP Access Is Restricted From the Internet"},
	"3.8": {"section": "3", "level": 2, "automated": false, "title": "Ensure VPC Service Controls Is Enabled for Supported Google Cloud Services"},
	"3.9": {"section": "3", "level": 2, "automated": false, "title": "Ensure Private Service Connect is Used for Access to Google APIs"},
	"3.10": {"section": "3", "level": 2, "automated": true, "title": "Ensure that VPC Flow Logs is Enabled for Every Subnet in a VPC Network"},
	"3.11": {"section": "3", "level": 1, "automated": false, "title": "Ensure No HTTPS or SSL Proxy Load Balancers Permit SSL Policies With Weak Cipher Suites"},
	"3.12": {"section": "3", "level": 2, "automated": false, "title": "Use Identity Aware Proxy (IAP) to Ensure Only Traffic From Google IP Addresses are 'Allowed'"},
	"4.1": {"section": "4", "level": 1, "automated": true, "title": "Ensure That Instances Are Not Configured To Use the Default Service Account"},
	"4.2": {"section": "4", "level": 1, "automated": true, "title": "Ensure That Instances Are Not Configured To Use the Default Service Account With Full Access to All Cloud APIs"},
	"4.3": {"section": "4", "level": 1, "automated": true, "title": "Ensure “Block Project-Wide SSH Keys” Is Enabled for VM Instances"},
	"4.4": {"section": "4", "level": 1, "automated": true, "title": "Ensure Oslogin Is Enabled for a Project"},
	"4.5": {"section": "4", "level": 1, "automated": true, "title": "Ensure ‘Enable Connecting to Serial Ports’ Is Not Enabled for VM Instance"},
	"4.6": {"section": "4", "level": 1, "automated": true, "title": "Ensure That IP Forwarding Is Not Enabled on Instances"},
	"4.7": {"section": "4", "level": 2, "automated": true, "title": "Ensure VM Disks for Critical VMs Are Encrypted With Customer-Supplied Encryption Keys (CSEK)"},
	"4.8": {"section": "4", "level": 2, "automated": true, "title": "Ensure Compute Instances Are Launched With Shielded VM Enabled"},
	"4.9": {"section": "4", "level": 2, "automated": true, "title": "Ensure That Compute Instances Do Not Have Public IP Addresses"},
	"4.10": {"section": "4", "level": 2, "automated": false, "title": "Ensure That App Engine Applications Enforce HTTPS Connections"},
	"4.11": {"section": "4", "level": 2, "automated": true, "title": "Ensure That Compute Instances Have Confidential Computing Enabled"},
	"4.12": {"section": "4", "level": 2, "automated": false, "title": "Ensure the Latest Operating System Updates Are Installed On Your Virtual Machines in All Projects"},
	"5.1": {"section": "5", "level": 1, "automated": true, "title": "Ensure That Cloud Storage Bucket Is Not Anonymously or Publicly Accessible"},
	"5.2": {"section": "5", "level": 2, "automated": true, "title": "Ensure That Cloud Storage Buckets Have Uniform Bucket-Level Access Enabled"},
	"6.1.1": {"section": "6", "level": 1, "automated": false, "title": "Ensure That a MySQL Instance Does Not Allow Anyone To Connect With Administrative Privileges"},
	"6.1.2": {"section": "6", "level": 1, "automated": true, "title": "Ensure ‘Skip_show_database’ Database Flag for Cloud SQL MySQL Instance Is Set to ‘On’"},
	"6.1.3": {"section": "6", "level": 1, "automated": true, "title": "Ensure That the ‘Local_infile’ Database Flag for a Cloud SQL MySQL Instance Is Set to ‘Off’"},
	"6.2.1": {"section": "6", "level": 2, "automated": true, "title": "Ensure ‘Log_error_verbosity’ Database Flag for Cloud SQL PostgreSQL Instance Is Set to ‘DEFAULT’ or Stricter"},
	"6.2.2": {"section": "6", "level": 1, "automated": true, "title": "Ensure That the ‘Log_connections’ Database Flag for Cloud SQL PostgreSQL Instance Is Set to ‘On’"},
	"6.2.3": {"section": "6", "level": 1, "automated": true, "title": "Ensure That the ‘Log_disconnections’ Database Flag for Cloud SQL PostgreSQL Instance Is Set to ‘On’"},
	"6.2.4": {"section": "6", "level": 2, "automated": true, "title": "Ensure ‘Log_statement’ Database Flag for Cloud SQL PostgreSQL Instance Is Set Appropriately"},
	"6.2.5": {"section": "6", "level": 1, "automated": true, "title": "Ensure that the ‘Log_min_messages’ Flag for a Cloud SQL PostgreSQL Instance is set at minimum to 'Warning'"},
	"6.2.6": {"section": "6", "level": 1, "automated": true, "title": "Ensure ‘Log_min_error_statement’ Database Flag for Cloud SQL PostgreSQL Instance Is Set to ‘Error’ or Stricter"},
	"6.2.7": {"section": "6", "level": 1, "automated": true, "title": "Ensure That the ‘Log_min_duration_statement’ Database Flag for Cloud SQL PostgreSQL Instance Is Set to '-1' (Disabled)"},
	"6.2.8": {"section": "6", "level": 1, "automated": true, "title": "Ensure That 'cloudsql.enable_pgaudit' Database Flag for each Cloud Sql Postgresql Instance Is Set to 'on' For Centralized Logging"},
	"6.3.1": {"section": "6", "level": 1, "automated": true, "title": "Ensure 'external scripts enabled' Database Flag for Cloud SQL SQL Server Instance Is Set to 'off'"},
	"6.3.2": {"section": "6", "level": 1, "automated": true, "title": "Ensure 'cross db ownership chaining' Database Flag for Cloud SQL SQL Server Instance Is Set to 'off'"},
	"6.3.3": {"section": "6", "level": 1, "automated": true, "title": "Ensure 'user Connections' Database Flag for Cloud SQL SQL Server Instance Is Set to a Non-limiting Value"},
	"6.3.4": {"section": "6", "level": 1, "automated": true, "title": "Ensure 'user options' Database Flag for Cloud SQL SQL Server Instance Is Not Configured"},
	"6.3.5": {"section": "6", "level": 1, "automated": true, "title": "Ensure 'remote access' Database Flag for Cloud SQL SQL Server Instance Is Set to 'off'"},
	"6.3.6": {"section": "6", "level": 1, "automated": true, "title": "Ensure '3625 (trace flag)' Database Flag for all Cloud SQL SQL Server Instances Is Set to 'on'"},
	"6.3.7": {"section": "6", "level": 1, "automated": true, "title": "Ensure 'contained database authentication' Database Flag for Cloud SQL SQL Server Instance Is Set to 'off'"},
	"6.4": {"section": "6", "level": 1, "automated": true, "title": "Ensure That the Cloud SQL Database Instance Requires All Incoming Connections To Use SSL"},
	"6.5": {"section": "6", "level": 1, "automated": true, "title": "Ensure That Cloud SQL Database Instances Do Not Implicitly Whitelist All Public IP Addresses"},
	"6.6": {"section": "6", "level": 1, "automated": false, "title": "Ensure Cloud SQL Database Instances Have IAM Database Authentication Enabled"},
	"6.7": {"section": "6", "level": 2, "automated": true, "title": "Ensure That Cloud SQL Database Instances Do Not Have Public IPs"},
	"6.8": {"section": "6", "level": 1, "automated": true, "title": "Ensure That Cloud SQL Database Instances Are Configured With Automated Backups"},
	"6.9": {"section": "6", "level": 1, "automated": false, "title": "Ensure Cloud SQL Database Instances Have Deletion Protection Enabled"},
	"7.1": {"section": "7", "level": 1, "automated": true, "title": "Ensure That BigQuery Datasets Are Not Anonymously or Publicly Accessible"},
	"7.2": {"section": "7", "level": 2, "automated": true, "title": "Ensure That All BigQuery Tables Are Encrypted With Customer-Managed Encryption Key (CMEK)"},
	"7.3": {"section": "7", "level": 2, "automated": true, "title": "Ensure That a Default Customer-Managed Encryption Key (CMEK) Is Specified for All BigQuery Data Sets"},
	"7.4": {"section": "7", "level": 2, "automated": false, "title": "Ensure all data in BigQuery has been classified"},
	"8.1": {"section": "8", "level": 2, "automated": true, "title": "Ensure that Dataproc Cluster is encrypted using Customer-Managed Encryption Key"},
}

# Manual recommendations: control id -> attestation key under input.attest.
attestations := {
	"1.1.1": "super_admin_email_not_single_user",
	"1.1.2": "super_admin_not_used_for_cloud_admin",
	"1.1.3": "folders_structured_by_environment",
	"1.1.4": "org_policies_centralized",
	"1.2": "corporate_login_credentials_used",
	"1.3": "mfa_enabled_non_service_accounts",
	"1.4": "security_keys_enforced_for_admins",
	"1.14": "api_keys_restricted_to_hosts_and_apps",
	"1.18": "cloud_functions_secrets_in_secret_manager",
	"2.2": "workspace_data_sharing_enabled",
	"2.15": "access_transparency_enabled",
	"2.16": "access_approval_enabled",
	"3.8": "vpc_service_controls_enabled",
	"3.9": "private_service_connect_used",
	"3.11": "lb_ssl_policies_no_weak_ciphers",
	"3.12": "iap_only_google_ip_ranges",
	"4.10": "app_engine_https_enforced",
	"4.12": "vm_os_updates_installed",
	"6.1.1": "mysql_no_anonymous_admin_access",
	"6.6": "sql_iam_database_authentication",
	"6.9": "sql_deletion_protection",
	"7.4": "bigquery_data_classified",
}

attested(key) if input.attest[key] == true

# ── Evidence: the inventory each Automated recommendation needs ───────────────────────
# iam_policy and compute_project are objects; every other key is a list.
evidence := {
	"1.5": ["service_accounts"],
	"1.6": ["iam_policy"],
	"1.7": ["iam_policy"],
	"1.8": ["service_accounts"],
	"1.9": ["iam_policy"],
	"1.10": ["kms_keys"],
	"1.11": ["kms_keys"],
	"1.12": ["iam_policy"],
	"1.13": ["api_keys"],
	"1.15": ["api_keys"],
	"1.16": ["api_keys"],
	"1.17": ["essential_contacts"],
	"2.1": ["iam_policy"],
	"2.3": ["log_sinks"],
	"2.4": ["log_sinks", "storage_buckets"],
	"2.5": ["log_metrics", "alert_policies"],
	"2.6": ["log_metrics", "alert_policies"],
	"2.7": ["log_metrics", "alert_policies"],
	"2.8": ["log_metrics", "alert_policies"],
	"2.9": ["log_metrics", "alert_policies"],
	"2.10": ["log_metrics", "alert_policies"],
	"2.11": ["log_metrics", "alert_policies"],
	"2.12": ["log_metrics", "alert_policies"],
	"2.13": ["vpc_networks", "dns_policies"],
	"2.14": ["enabled_services"],
	"2.17": ["backend_services"],
	"3.1": ["vpc_networks"],
	"3.2": ["vpc_networks"],
	"3.3": ["dns_managed_zones"],
	"3.4": ["dns_managed_zones"],
	"3.5": ["dns_managed_zones"],
	"3.6": ["firewall_rules"],
	"3.7": ["firewall_rules"],
	"3.10": ["subnetworks"],
	"4.1": ["compute_instances"],
	"4.2": ["compute_instances"],
	"4.3": ["compute_instances"],
	"4.4": ["compute_project", "compute_instances"],
	"4.5": ["compute_instances"],
	"4.6": ["compute_instances"],
	"4.7": ["compute_disks"],
	"4.8": ["compute_instances"],
	"4.9": ["compute_instances"],
	"4.11": ["compute_instances"],
	"5.1": ["storage_buckets"],
	"5.2": ["storage_buckets"],
	"6.1.2": ["sql_instances"],
	"6.1.3": ["sql_instances"],
	"6.2.1": ["sql_instances"],
	"6.2.2": ["sql_instances"],
	"6.2.3": ["sql_instances"],
	"6.2.4": ["sql_instances"],
	"6.2.5": ["sql_instances"],
	"6.2.6": ["sql_instances"],
	"6.2.7": ["sql_instances"],
	"6.2.8": ["sql_instances"],
	"6.3.1": ["sql_instances"],
	"6.3.2": ["sql_instances"],
	"6.3.3": ["sql_instances"],
	"6.3.4": ["sql_instances"],
	"6.3.5": ["sql_instances"],
	"6.3.6": ["sql_instances"],
	"6.3.7": ["sql_instances"],
	"6.4": ["sql_instances"],
	"6.5": ["sql_instances"],
	"6.7": ["sql_instances"],
	"6.8": ["sql_instances"],
	"7.1": ["bigquery_datasets"],
	"7.2": ["bigquery_tables"],
	"7.3": ["bigquery_datasets"],
	"8.1": ["dataproc_clusters"],
}

_object_keys := {"iam_policy", "compute_project"}

# A project IAM policy always carries bindings; {} is not evidence.
present("iam_policy") if count(object.get(object.get(input, "iam_policy", {}), "bindings", [])) > 0

present("compute_project") if is_object(input.compute_project)

present(k) if {
	not k in _object_keys
	is_array(input[k])
}

missing_evidence contains [id, k] if {
	some id, keys in evidence
	some k in keys
	not present(k)
}

_incomplete contains id if some [id, _] in missing_evidence

# ── helpers ───────────────────────────────────────────────────────────────────────────

_ns_90_days := ((90 * 86400) * 1000) * 1000000

# A timestamp no more than 90 days in the past. An unparsable time is not recent (fail closed).
within_90_days(ts) if time.now_ns() - time.parse_rfc3339_ns(ts) <= _ns_90_days

# A timestamp no more than 90 days in the future.
due_within_90_days(ts) if time.parse_rfc3339_ns(ts) - time.now_ns() <= _ns_90_days

# Resource name for messages; a resource without one is still reported, never skipped.
nm(x, field) := object.get(x, field, "<unnamed>")

public_member(m) if m in {"allUsers", "allAuthenticatedUsers"}

nonempty_string(s) if {
	is_string(s)
	trim_space(s) != ""
}

_bindings(policy) := object.get(policy, "bindings", []) if is_object(policy)

project_bindings := _bindings(input.iam_policy)

members_with_role(role) := {m | some b in project_bindings; b.role == role; some m in b.members}

# User-managed (user-created) service accounts: NAME@PROJECT_ID.iam.gserviceaccount.com
user_managed_sa(email) if endswith(email, ".iam.gserviceaccount.com")

admin_role(role) if role in {"roles/owner", "roles/editor"}

admin_role(role) if contains(lower(role), "admin")

# GKE-created VMs are excluded where the benchmark says so: name "gke-" and label goog-gke-node.
gke_node(i) if {
	startswith(i.name, "gke-")
	"goog-gke-node" in object.keys(object.get(i, "labels", {}))
}

default_compute_sa(email) if endswith(email, "-compute@developer.gserviceaccount.com")

meta_values(md, key) := {lower(trim_space(sprintf("%v", [it.value]))) |
	some it in object.get(md, "items", [])
	it.key == key
}

instance_meta(i, key) := meta_values(object.get(i, "metadata", {}), key)

# Normalized log/monitoring filter text: lower case, no whitespace, quotes or backslashes.
norm_filter(s) := lower(regex.replace(s, `[\s"\\]`, ""))

# 2.5-2.12: a log metric whose filter carries every token, and an enabled alert policy on it.
metric_alerted(tokens) if {
	some m in input.log_metrics
	f := norm_filter(object.get(m, "filter", ""))
	every t in tokens {
		contains(f, t)
	}
	want := sprintf("metric.type=logging.googleapis.com/user/%s", [lower(m.name)])
	some p in input.alert_policies
	p.enabled == true
	some c in object.get(p, "conditions", [])
	contains(norm_filter(object.get(object.get(c, "conditionThreshold", {}), "filter", "")), want)
}

# A firewall "allowed" entry covers a port when its protocol is tcp or all, and it lists no
# ports (every port), the port itself, or a range containing it.
port_covers(a, _) if count(object.get(a, "ports", [])) == 0

port_covers(a, port) if {
	some p in a.ports
	sprintf("%v", [p]) == sprintf("%v", [port])
}

port_covers(a, port) if {
	some p in a.ports
	bounds := regex.find_all_string_submatch_n(`^(\d+)-(\d+)$`, sprintf("%v", [p]), 1)[0]
	to_number(bounds[1]) <= port
	port <= to_number(bounds[2])
}

open_to_internet(rule, port) if {
	upper(object.get(rule, "direction", "INGRESS")) == "INGRESS"
	not rule.disabled == true
	some src in object.get(rule, "sourceRanges", [])
	src in {"0.0.0.0/0", "::/0"}
	some a in object.get(rule, "allowed", [])
	lower(sprintf("%v", [a.IPProtocol])) in {"tcp", "all"}
	port_covers(a, port)
}

# Cloud SQL database flags (gcloud omits databaseFlags when none are set).
flag_vals(i, name) := {lower(trim_space(sprintf("%v", [f.value]))) |
	some f in object.get(object.get(i, "settings", {}), "databaseFlags", [])
	f.name == name
}

flag_ok(i, name, allowed, _) if {
	is_object(i.settings)
	vals := flag_vals(i, name)
	count(vals) > 0
	every v in vals {
		v in allowed
	}
}

# An unset flag takes the engine default; default_ok says whether that default satisfies the check.
flag_ok(i, name, _, true) if {
	is_object(i.settings)
	count(flag_vals(i, name)) == 0
}

# control id -> [engine prefix of databaseVersion, flag, allowed values, unset flag passes]
sql_flag_checks := {
	"6.1.2": ["MYSQL", "skip_show_database", {"on"}, false],
	"6.1.3": ["MYSQL", "local_infile", {"off"}, false],
	"6.2.1": ["POSTGRES", "log_error_verbosity", {"default", "terse"}, true],
	"6.2.2": ["POSTGRES", "log_connections", {"on"}, false],
	"6.2.3": ["POSTGRES", "log_disconnections", {"on"}, false],
	"6.2.4": ["POSTGRES", "log_statement", {"ddl", "mod", "all"}, false],
	"6.2.5": ["POSTGRES", "log_min_messages", {"warning", "error", "log", "fatal", "panic"}, true],
	"6.2.6": ["POSTGRES", "log_min_error_statement", {"error", "log", "fatal", "panic"}, true],
	"6.2.7": ["POSTGRES", "log_min_duration_statement", {"-1"}, true],
	"6.2.8": ["POSTGRES", "cloudsql.enable_pgaudit", {"on"}, false],
	"6.3.1": ["SQLSERVER", "external scripts enabled", {"off"}, true],
	"6.3.2": ["SQLSERVER", "cross db ownership chaining", {"off"}, true],
	"6.3.3": ["SQLSERVER", "user connections", {"0"}, true],
	"6.3.4": ["SQLSERVER", "user options", set(), true],
	"6.3.5": ["SQLSERVER", "remote access", {"off"}, false],
	"6.3.6": ["SQLSERVER", "3625", {"on"}, false],
	"6.3.7": ["SQLSERVER", "contained database authentication", {"off"}, true],
}

primary_sql(i) if object.get(i, "instanceType", "CLOUD_SQL_INSTANCE") != "READ_REPLICA_INSTANCE"

last_segment(s) := parts[count(parts) - 1] if parts := split(s, "/")

# ── Section 1: Identity and Access Management ─────────────────────────────────────────

findings contains ["1.5", sprintf("service account %s holds user-managed key %s", [nm(sa, "email"), nm(k, "name")])] if {
	some sa in input.service_accounts
	user_managed_sa(sa.email)
	some k in object.get(sa, "keys", [])
	k.keyType == "USER_MANAGED"
}

findings contains [id, sprintf("service account %s: key list not collected", [nm(sa, "email")])] if {
	some sa in input.service_accounts
	not is_array(object.get(sa, "keys", null))
	some id in ["1.5", "1.8"]
}

findings contains ["1.6", sprintf("service account %s holds admin-level role %s", [trim_prefix(m, "serviceAccount:"), b.role])] if {
	some b in project_bindings
	admin_role(b.role)
	some m in b.members
	startswith(m, "serviceAccount:")
	user_managed_sa(m)
}

findings contains ["1.7", sprintf("%s holds %s at project level", [m, role])] if {
	some role in ["roles/iam.serviceAccountUser", "roles/iam.serviceAccountTokenCreator"]
	some m in members_with_role(role)
}

findings contains ["1.8", sprintf("user-managed key %s of %s is older than 90 days", [nm(k, "name"), nm(sa, "email")])] if {
	some sa in input.service_accounts
	some k in object.get(sa, "keys", [])
	k.keyType == "USER_MANAGED"
	not _sa_key_recent(k)
}

# Helper rules, not `not within_90_days(k.x)`: with an absent field that negation never fires.
_sa_key_recent(k) if within_90_days(k.validAfterTime)

_api_key_recent(k) if within_90_days(k.createTime)

findings contains ["1.9", sprintf("%s holds both Service Account Admin and Service Account User", [m])] if {
	some m in members_with_role("roles/iam.serviceAccountAdmin")
	m in members_with_role("roles/iam.serviceAccountUser")
}

findings contains ["1.10", sprintf("KMS key %s: IAM policy not collected", [nm(k, "name")])] if {
	some k in input.kms_keys
	not is_object(object.get(k, "iam_policy", null))
}

findings contains ["1.10", sprintf("KMS key %s is shared with %s", [nm(k, "name"), m])] if {
	some k in input.kms_keys
	some b in _bindings(k.iam_policy)
	some m in b.members
	public_member(m)
}

_symmetric_key(k) if object.get(k, "purpose", "ENCRYPT_DECRYPT") == "ENCRYPT_DECRYPT"

rotation_period_ok(p) if {
	m := regex.find_all_string_submatch_n(`^([0-9]+(\.[0-9]+)?)s$`, p, 1)[0]
	to_number(m[1]) <= 7776000
}

key_rotation_ok(k) if {
	rotation_period_ok(k.rotationPeriod)
	due_within_90_days(k.nextRotationTime)
}

findings contains ["1.11", sprintf("KMS key %s is not scheduled to rotate within 90 days", [nm(k, "name")])] if {
	some k in input.kms_keys
	_symmetric_key(k)
	not key_rotation_ok(k)
}

findings contains ["1.12", sprintf("%s holds Cloud KMS Admin and a CryptoKey encrypt/decrypt role", [m])] if {
	some m in members_with_role("roles/cloudkms.admin")
	some r in ["roles/cloudkms.cryptoKeyEncrypterDecrypter", "roles/cloudkms.cryptoKeyEncrypter", "roles/cloudkms.cryptoKeyDecrypter"]
	m in members_with_role(r)
}

findings contains ["1.13", sprintf("API key %s exists in the project", [nm(k, "name")])] if {
	some k in input.api_keys
}

_api_targets(k) := object.get(object.get(k, "restrictions", {}), "apiTargets", [])

findings contains ["1.15", sprintf("API key %s has no API restriction", [nm(k, "name")])] if {
	some k in input.api_keys
	count(_api_targets(k)) == 0
}

findings contains ["1.15", sprintf("API key %s is allowed every Google Cloud API", [nm(k, "name")])] if {
	some k in input.api_keys
	some t in _api_targets(k)
	t.service == "cloudapis.googleapis.com"
}

findings contains ["1.16", sprintf("API key %s was created more than 90 days ago", [nm(k, "name")])] if {
	some k in input.api_keys
	not _api_key_recent(k)
}

_contact_categories := {c | some ec in input.essential_contacts; some c in object.get(ec, "notificationCategorySubscriptions", [])}

_contacts_ok if "ALL" in _contact_categories

_contacts_ok if {
	every c in ["LEGAL", "SECURITY", "SUSPENSION", "TECHNICAL"] {
		c in _contact_categories
	}
}

findings contains ["1.17", "organization essential contacts do not cover LEGAL, SECURITY, SUSPENSION and TECHNICAL (or ALL)"] if {
	not _contacts_ok
}

# ── Section 2: Logging and Monitoring ─────────────────────────────────────────────────

_inherited_audit_configs := input.inherited_audit_configs if is_array(input.inherited_audit_configs)

default _inherited_audit_configs := []

audit_configs := array.concat(object.get(input.iam_policy, "auditConfigs", []), _inherited_audit_configs)

_audit_all_services if {
	some c in audit_configs
	c.service == "allServices"
	types := {lc.logType | some lc in object.get(c, "auditLogConfigs", [])}
	"DATA_READ" in types
	"DATA_WRITE" in types
}

findings contains ["2.1", "no allServices audit config logging DATA_READ and DATA_WRITE"] if {
	not _audit_all_services
}

findings contains ["2.1", sprintf("audit config for %s exempts members from logging", [nm(c, "service")])] if {
	some c in audit_configs
	some lc in object.get(c, "auditLogConfigs", [])
	count(object.get(lc, "exemptedMembers", [])) > 0
}

_catch_all_sink if {
	some s in input.log_sinks
	trim_space(object.get(s, "filter", "")) == ""
}

findings contains ["2.3", "no log sink exports all log entries (empty filter)"] if not _catch_all_sink

_locked_bucket(name) if {
	some b in input.storage_buckets
	b.name == name
	b.retentionPolicy.isLocked == true
}

findings contains ["2.4", sprintf("log export bucket %s has no locked retention policy", [name])] if {
	some s in input.log_sinks
	startswith(s.destination, "storage.googleapis.com/")
	name := trim_prefix(s.destination, "storage.googleapis.com/")
	not _locked_bucket(name)
}

metric_tokens := {
	"2.5": ["protopayload.servicename=cloudresourcemanager.googleapis.com", "projectownership", "projectownerinvitee", "bindingdeltas.action=remove", "bindingdeltas.action=add", "bindingdeltas.role=roles/owner"],
	"2.6": ["protopayload.methodname=setiampolicy", "auditconfigdeltas:*"],
	"2.7": ["resource.type=iam_role", "google.iam.admin.v1.createrole", "google.iam.admin.v1.deleterole", "google.iam.admin.v1.updaterole", "google.iam.admin.v1.undeleterole"],
	"2.8": ["resource.type=gce_firewall_rule", "compute.firewalls.patch", "compute.firewalls.insert", "compute.firewalls.delete"],
	"2.9": ["resource.type=gce_route", "compute.routes.delete", "compute.routes.insert"],
	"2.10": ["resource.type=gce_network", "compute.networks.insert", "compute.networks.patch", "compute.networks.delete", "compute.networks.removepeering", "compute.networks.addpeering"],
	"2.11": ["resource.type=gcs_bucket", "storage.setiampermissions"],
	"2.12": ["cloudsql.instances.update"],
}

findings contains [id, "no log metric with the prescribed filter and an enabled alert policy on it"] if {
	some id, tokens in metric_tokens
	not metric_alerted(tokens)
}

_dns_logged(n) if {
	some p in input.dns_policies
	p.enableLogging == true
	some pn in object.get(p, "networks", [])
	endswith(pn.networkUrl, sprintf("/networks/%s", [nm(n, "name")]))
}

findings contains ["2.13", sprintf("VPC network %s has no DNS policy with logging enabled", [nm(n, "name")])] if {
	some n in input.vpc_networks
	not _dns_logged(n)
}

_svc_is(s, name) if s == name

_svc_is(s, name) if s.config.name == name

_svc_is(s, name) if s.name == name

_svc_is(s, name) if endswith(s.name, concat("", ["/services/", name]))

findings contains ["2.14", "the Cloud Asset API (cloudasset.googleapis.com) is not enabled"] if {
	not any_service_enabled("cloudasset.googleapis.com")
}

any_service_enabled(name) if {
	some s in input.enabled_services
	_svc_is(s, name)
}

findings contains ["2.17", sprintf("HTTP(S) backend service %s does not log requests", [nm(bs, "name")])] if {
	some bs in input.backend_services
	upper(object.get(bs, "protocol", "")) in {"HTTP", "HTTPS", "HTTP2"}
	not bs.logConfig.enable == true
}

# ── Section 3: Networking ─────────────────────────────────────────────────────────────

findings contains ["3.1", "the default network exists"] if {
	some n in input.vpc_networks
	n.name == "default"
}

_legacy_network(n) if upper(object.get(n, "x_gcloud_subnet_mode", "")) == "LEGACY"

_legacy_network(n) if is_string(n.IPv4Range)

findings contains ["3.2", sprintf("network %s is a legacy network", [nm(n, "name")])] if {
	some n in input.vpc_networks
	_legacy_network(n)
}

findings contains ["3.3", sprintf("public zone %s does not have DNSSEC on", [nm(z, "name")])] if {
	some z in input.dns_managed_zones
	lower(object.get(z, "visibility", "public")) == "public"
	not lower(object.get(object.get(z, "dnssecConfig", {}), "state", "")) == "on"
}

_zone_key_algos(z, key_type) := {lower(s.algorithm) |
	some s in object.get(object.get(z, "dnssecConfig", {}), "defaultKeySpecs", [])
	s.keyType == key_type
}

findings contains ["3.4", sprintf("zone %s signs keys with RSASHA1", [nm(z, "name")])] if {
	some z in input.dns_managed_zones
	"rsasha1" in _zone_key_algos(z, "keySigning")
}

findings contains ["3.5", sprintf("zone %s signs the zone with RSASHA1", [nm(z, "name")])] if {
	some z in input.dns_managed_zones
	"rsasha1" in _zone_key_algos(z, "zoneSigning")
}

findings contains ["3.6", sprintf("firewall rule %s allows SSH (tcp/22) from the internet", [nm(r, "name")])] if {
	some r in input.firewall_rules
	open_to_internet(r, 22)
}

findings contains ["3.7", sprintf("firewall rule %s allows RDP (tcp/3389) from the internet", [nm(r, "name")])] if {
	some r in input.firewall_rules
	open_to_internet(r, 3389)
}

_flow_logs_on(s) if s.enableFlowLogs == true

_flow_logs_on(s) if s.logConfig.enable == true

_flow_logs_filtered(s) if not object.get(object.get(s, "logConfig", {}), "filterExpr", "true") in {"", "true"}

_flow_logs_ok(s) if {
	_flow_logs_on(s)
	lc := object.get(s, "logConfig", {})
	object.get(lc, "aggregationInterval", "") == "INTERVAL_5_SEC"
	to_number(object.get(lc, "flowSampling", 0)) == 1
	object.get(lc, "metadata", "") == "INCLUDE_ALL_METADATA"
	not _flow_logs_filtered(s)
}

findings contains ["3.10", sprintf("subnet %s does not have full VPC Flow Logs", [nm(s, "name")])] if {
	some s in input.subnetworks
	object.get(s, "purpose", "PRIVATE") == "PRIVATE"
	not _flow_logs_ok(s)
}

# ── Section 4: Virtual Machines ───────────────────────────────────────────────────────

findings contains ["4.1", sprintf("instance %s uses the default compute service account", [nm(i, "name")])] if {
	some i in input.compute_instances
	not gke_node(i)
	some sa in object.get(i, "serviceAccounts", [])
	default_compute_sa(sa.email)
}

findings contains ["4.2", sprintf("instance %s uses the default service account with the cloud-platform scope", [nm(i, "name")])] if {
	some i in input.compute_instances
	not gke_node(i)
	some sa in object.get(i, "serviceAccounts", [])
	default_compute_sa(sa.email)
	"https://www.googleapis.com/auth/cloud-platform" in object.get(sa, "scopes", [])
}

findings contains ["4.3", sprintf("instance %s does not block project-wide SSH keys", [nm(i, "name")])] if {
	some i in input.compute_instances
	not "true" in instance_meta(i, "block-project-ssh-keys")
}

findings contains ["4.4", "project metadata does not set enable-oslogin to TRUE"] if {
	not "true" in meta_values(object.get(input.compute_project, "commonInstanceMetadata", {}), "enable-oslogin")
}

findings contains ["4.4", sprintf("instance %s turns OS Login off in its own metadata", [nm(i, "name")])] if {
	some i in input.compute_instances
	not gke_node(i)
	some v in instance_meta(i, "enable-oslogin")
	v in {"false", "0"}
}

findings contains ["4.5", sprintf("instance %s allows serial port connections", [nm(i, "name")])] if {
	some i in input.compute_instances
	some v in instance_meta(i, "serial-port-enable")
	v in {"true", "1"}
}

findings contains ["4.6", sprintf("instance %s has IP forwarding enabled", [nm(i, "name")])] if {
	some i in input.compute_instances
	not startswith(nm(i, "name"), "gke-")
	i.canIpForward == true
}

findings contains ["4.7", sprintf("disk %s is not encrypted with a customer-supplied key", [nm(d, "name")])] if {
	some d in input.compute_disks
	not d.critical == false
	not _csek(d)
}

_csek(d) if nonempty_string(d.diskEncryptionKey.sha256)

_shielded(i) if {
	i.shieldedInstanceConfig.enableVtpm == true
	i.shieldedInstanceConfig.enableIntegrityMonitoring == true
}

findings contains ["4.8", sprintf("instance %s is not a Shielded VM with vTPM and integrity monitoring", [nm(i, "name")])] if {
	some i in input.compute_instances
	not _shielded(i)
}

findings contains ["4.9", sprintf("instance %s has an external IP address", [nm(i, "name")])] if {
	some i in input.compute_instances
	not gke_node(i)
	some ni in object.get(i, "networkInterfaces", [])
	count(object.get(ni, "accessConfigs", [])) > 0
}

findings contains ["4.11", sprintf("N2D instance %s does not have Confidential Computing enabled", [nm(i, "name")])] if {
	some i in input.compute_instances
	startswith(last_segment(object.get(i, "machineType", "")), "n2d-")
	not i.confidentialInstanceConfig.enableConfidentialCompute == true
}

# ── Section 5: Storage ────────────────────────────────────────────────────────────────

findings contains ["5.1", sprintf("bucket %s: IAM policy not collected", [nm(b, "name")])] if {
	some b in input.storage_buckets
	not is_object(object.get(b, "iam_policy", null))
}

findings contains ["5.1", sprintf("bucket %s is shared with %s", [nm(b, "name"), m])] if {
	some b in input.storage_buckets
	some bd in _bindings(b.iam_policy)
	some m in bd.members
	public_member(m)
}

findings contains ["5.2", sprintf("bucket %s does not enforce uniform bucket-level access", [nm(b, "name")])] if {
	some b in input.storage_buckets
	not b.iamConfiguration.uniformBucketLevelAccess.enabled == true
}

# ── Section 6: Cloud SQL ──────────────────────────────────────────────────────────────

findings contains [id, sprintf("instance %s: flag '%s' is not set as required", [nm(i, "name"), chk[1]])] if {
	some id, chk in sql_flag_checks
	some i in input.sql_instances
	startswith(upper(object.get(i, "databaseVersion", "")), chk[0])
	not flag_ok(i, chk[1], chk[2], chk[3])
}

_ssl_enforced(i) if i.settings.ipConfiguration.sslMode in {"ENCRYPTED_ONLY", "TRUSTED_CLIENT_CERTIFICATE_REQUIRED"}

findings contains ["6.4", sprintf("instance %s accepts unencrypted connections", [nm(i, "name")])] if {
	some i in input.sql_instances
	not _ssl_enforced(i)
}

findings contains ["6.5", sprintf("instance %s authorizes every public address", [nm(i, "name")])] if {
	some i in input.sql_instances
	some an in object.get(object.get(object.get(i, "settings", {}), "ipConfiguration", {}), "authorizedNetworks", [])
	an.value in {"0.0.0.0/0", "::/0"}
}

_ip_types(i) := {ip.type | some ip in object.get(i, "ipAddresses", [])}

findings contains ["6.7", sprintf("instance %s has a public IP address", [nm(i, "name")])] if {
	some i in input.sql_instances
	primary_sql(i)
	"PRIMARY" in _ip_types(i)
}

findings contains ["6.7", sprintf("instance %s has no private IP address", [nm(i, "name")])] if {
	some i in input.sql_instances
	primary_sql(i)
	not "PRIVATE" in _ip_types(i)
}

findings contains ["6.8", sprintf("instance %s has no automated backups", [nm(i, "name")])] if {
	some i in input.sql_instances
	primary_sql(i)
	not i.settings.backupConfiguration.enabled == true
}

# ── Section 7: BigQuery ───────────────────────────────────────────────────────────────

_public_access(a) if a.specialGroup in {"allUsers", "allAuthenticatedUsers"}

_public_access(a) if public_member(a.iamMember)

findings contains ["7.1", sprintf("dataset %s is shared publicly", [nm(d, "id")])] if {
	some d in input.bigquery_datasets
	some a in object.get(d, "access", [])
	_public_access(a)
}

findings contains ["7.2", sprintf("table %s is not encrypted with a customer-managed key", [nm(t, "id")])] if {
	some t in input.bigquery_tables
	not _table_cmek(t)
}

_table_cmek(t) if nonempty_string(t.encryptionConfiguration.kmsKeyName)

findings contains ["7.3", sprintf("dataset %s has no default customer-managed key", [nm(d, "id")])] if {
	some d in input.bigquery_datasets
	not _dataset_cmek(d)
}

_dataset_cmek(d) if nonempty_string(d.defaultEncryptionConfiguration.kmsKeyName)

# ── Section 8: Dataproc ───────────────────────────────────────────────────────────────

findings contains ["8.1", sprintf("Dataproc cluster %s is not encrypted with a customer-managed key", [nm(c, "clusterName")])] if {
	some c in input.dataproc_clusters
	not _dataproc_cmek(c)
}

_dataproc_cmek(c) if nonempty_string(c.config.encryptionConfig.gcePdKmsKeyName)

# ── Aggregate ─────────────────────────────────────────────────────────────────────────

# A recommendation whose inventory is incomplete reports only "evidence missing", never a
# finding computed from partial data, so the two messages are mutually exclusive per control.
_messages contains sprintf("%s: evidence missing — %s not collected", [id, k]) if some [id, k] in missing_evidence

_messages contains sprintf("%s: %s", [id, detail]) if {
	some [id, detail] in findings
	not id in _incomplete
}

_messages contains sprintf("%s: not attested — manual review required, set input.attest.%s to true", [id, key]) if {
	some id, key in attestations
	not attested(key)
}

violations := sort([v | some v in _messages])

control_id(v) := regex.find_n(`^[0-9]+(\.[0-9]+)*`, v, 1)[0]

failing_controls := {control_id(v) | some v in violations}

total_controls := count(controls)

evidence_violations := {v | some v in violations; contains(v, ": evidence missing — ")}

_in_section(v, s) if startswith(v, concat("", [s, "."]))

identity_access_violations := [v | some v in violations; _in_section(v, "1")]

logging_violations := [v | some v in violations; _in_section(v, "2")]

networking_violations := [v | some v in violations; _in_section(v, "3")]

virtual_machines_violations := [v | some v in violations; _in_section(v, "4")]

storage_violations := [v | some v in violations; _in_section(v, "5")]

sql_violations := [v | some v in violations; _in_section(v, "6")]

bigquery_violations := [v | some v in violations; _in_section(v, "7")]

dataproc_violations := [v | some v in violations; _in_section(v, "8")]

section_names := {
	"1": "identity_access",
	"2": "logging",
	"3": "networking",
	"4": "virtual_machines",
	"5": "storage",
	"6": "sql",
	"7": "bigquery",
	"8": "dataproc",
}

# Counts are distinct recommendations, never messages: one control can fail on many resources.
compliance_summary := {
	"benchmark": "CIS Google Cloud Platform Foundation Benchmark v5.0.0",
	"total_controls": total_controls,
	"passing_controls": total_controls - count(failing_controls),
	"failing_controls": count(failing_controls),
	"compliance_percentage": ((total_controls - count(failing_controls)) * 100) / total_controls,
	"sections": {name: {
		"total": count({id | some id, c in controls; c.section == sec}),
		"violations": count({id | some id in failing_controls; controls[id].section == sec}),
	} |
		some sec, name in section_names
	},
}

# Detailed findings for remediation
detailed_findings := {
	"identity_access_violations": identity_access_violations,
	"logging_violations": logging_violations,
	"networking_violations": networking_violations,
	"virtual_machines_violations": virtual_machines_violations,
	"storage_violations": storage_violations,
	"sql_violations": sql_violations,
	"bigquery_violations": bigquery_violations,
	"dataproc_violations": dataproc_violations,
}
