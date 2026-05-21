package cis_aws.l2

# CIS Amazon Web Services Foundations Benchmark v7.0.0 - Level 2 Additional Controls
# Level 2 extends Level 1 with stricter controls for regulated cloud workloads.
# Intended for: FedRAMP High, PCI-DSS, HIPAA, DoD CC SRG IL4/IL5.

import rego.v1

default compliant := false

compliant if { count(violations) == 0 }

# ---------------------------------------------------------------------------
# Section 1 - Identity and Access Management (L2)
# ---------------------------------------------------------------------------

violations contains "CIS L2 1.5: Ensure IAM password policy requires at least one uppercase letter" if {
	not input.iam.password_policy.require_uppercase
}

violations contains "CIS L2 1.6: Ensure IAM password policy requires at least one lowercase letter" if {
	not input.iam.password_policy.require_lowercase
}

violations contains "CIS L2 1.7: Ensure IAM password policy requires at least one symbol" if {
	not input.iam.password_policy.require_symbols
}

violations contains "CIS L2 1.8: Ensure IAM password policy requires at least one number" if {
	not input.iam.password_policy.require_numbers
}

violations contains "CIS L2 1.9: Ensure IAM password policy requires minimum length of 14 or greater" if {
	input.iam.password_policy.min_length < 14
}

violations contains "CIS L2 1.10: Ensure IAM password policy prevents password reuse — 24 passwords" if {
	input.iam.password_policy.reuse_prevention < 24
}

violations contains "CIS L2 1.11: Ensure IAM password policy expires passwords within 365 days" if {
	input.iam.password_policy.max_age_days > 365
}

violations contains "CIS L2 1.14: Ensure access keys are rotated every 90 days or less" if {
	some key in input.iam.access_keys
	key.age_days > 90
	key.active
}

violations contains "CIS L2 1.15: Ensure IAM users receive permissions only through groups" if {
	some user in input.iam.users
	count(user.attached_policies) > 0
}

violations contains "CIS L2 1.16: Ensure IAM policies are attached only to groups or roles (not users)" if {
	some user in input.iam.users
	count(user.inline_policies) > 0
}

violations contains "CIS L2 1.17: Ensure a support role has been created to manage incidents" if {
	not input.iam.support_role_exists
}

violations contains "CIS L2 1.19: Ensure that all expired SSL/TLS certificates stored in AWS IAM are removed" if {
	some cert in input.iam.server_certificates
	cert.expired
}

violations contains "CIS L2 1.20: Ensure that IAM Access analyzer is enabled for all regions" if {
	some region in input.iam.regions_without_access_analyzer
	region != ""
}

violations contains "CIS L2 1.22: Ensure IAM user is not created with access to management console" if {
	some user in input.iam.users
	user.console_access
	not user.mfa_enabled
}

# ---------------------------------------------------------------------------
# Section 2 - Storage (L2)
# ---------------------------------------------------------------------------

violations contains "CIS L2 2.1.1: Ensure all S3 buckets employ encryption-at-rest" if {
	some bucket in input.s3.buckets
	not bucket.server_side_encryption_enabled
}

violations contains "CIS L2 2.1.2: Ensure S3 Bucket Policy is set to deny HTTP requests" if {
	some bucket in input.s3.buckets
	not bucket.force_ssl
}

violations contains "CIS L2 2.1.5: Ensure S3 Bucket access logging is enabled" if {
	some bucket in input.s3.buckets
	not bucket.access_logging_enabled
}

violations contains "CIS L2 2.2.1: Ensure EBS volume encryption is enabled in all regions" if {
	some region in input.ec2.regions_without_ebs_encryption_by_default
	region != ""
}

violations contains "CIS L2 2.3.1: Ensure AWS RDS database instance is not publicly accessible" if {
	some db in input.rds.instances
	db.publicly_accessible
}

violations contains "CIS L2 2.3.2: Ensure AWS RDS database instances are encrypted at rest" if {
	some db in input.rds.instances
	not db.storage_encrypted
}

violations contains "CIS L2 2.3.3: Ensure AWS RDS automated backups are enabled" if {
	some db in input.rds.instances
	db.backup_retention_period == 0
}

violations contains "CIS L2 2.4.1: Ensure AWS Aurora database cluster is encrypted at rest" if {
	some cluster in input.rds.aurora_clusters
	not cluster.storage_encrypted
}

# ---------------------------------------------------------------------------
# Section 3 - Logging (L2)
# ---------------------------------------------------------------------------

violations contains "CIS L2 3.1: Ensure CloudTrail is enabled in all regions" if {
	not input.cloudtrail.multi_region_enabled
}

violations contains "CIS L2 3.2: Ensure CloudTrail log file validation is enabled" if {
	some trail in input.cloudtrail.trails
	not trail.log_file_validation_enabled
}

violations contains "CIS L2 3.3: Ensure AWS Config is enabled in all regions" if {
	some region in input.config.regions_without_config
	region != ""
}

violations contains "CIS L2 3.4: Ensure CloudTrail trails are integrated with CloudWatch Logs" if {
	some trail in input.cloudtrail.trails
	not trail.cloudwatch_logs_arn
}

violations contains "CIS L2 3.7: Ensure CloudTrail logs are encrypted at rest using KMS CMKs" if {
	some trail in input.cloudtrail.trails
	not trail.kms_key_id
}

violations contains "CIS L2 3.8: Ensure rotation for customer created symmetric CMKs is enabled" if {
	some key in input.kms.customer_managed_keys
	not key.rotation_enabled
	key.key_state == "Enabled"
}

violations contains "CIS L2 3.10: Ensure that Object-level logging for write events is enabled for S3 buckets" if {
	not input.cloudtrail.s3_write_events_logged
}

violations contains "CIS L2 3.11: Ensure that Object-level logging for read events is enabled for S3 buckets" if {
	not input.cloudtrail.s3_read_events_logged
}

# ---------------------------------------------------------------------------
# Section 4 - Monitoring — CloudWatch Alarms (L2)
# ---------------------------------------------------------------------------

violations contains "CIS L2 4.3: Ensure a log metric filter and alarm exists for usage of root account" if {
	not input.cloudwatch.root_account_usage_alarm_exists
}

violations contains "CIS L2 4.7: Ensure a log metric filter and alarm exists for disabling or deletion of CMKs" if {
	not input.cloudwatch.cmk_disable_deletion_alarm_exists
}

violations contains "CIS L2 4.8: Ensure a log metric filter and alarm exists for S3 bucket policy changes" if {
	not input.cloudwatch.s3_bucket_policy_change_alarm_exists
}

violations contains "CIS L2 4.9: Ensure a log metric filter and alarm exists for AWS Config configuration changes" if {
	not input.cloudwatch.config_change_alarm_exists
}

violations contains "CIS L2 4.11: Ensure a log metric filter and alarm exists for changes to Network Access Control Lists" if {
	not input.cloudwatch.nacl_change_alarm_exists
}

violations contains "CIS L2 4.13: Ensure a log metric filter and alarm exists for route table changes" if {
	not input.cloudwatch.route_table_change_alarm_exists
}

violations contains "CIS L2 4.15: Ensure a log metric filter and alarm exists for AWS Organizations changes" if {
	not input.cloudwatch.organizations_change_alarm_exists
}

# ---------------------------------------------------------------------------
# Section 5 - Networking (L2)
# ---------------------------------------------------------------------------

violations contains "CIS L2 5.1: Ensure no Network ACLs allow ingress from 0.0.0.0/0 to remote server administration ports" if {
	some nacl in input.vpc.network_acls
	some rule in nacl.inbound_rules
	rule.cidr == "0.0.0.0/0"
	rule.action == "allow"
	port_in_range(rule.port_range, [22, 3389])
}

violations contains "CIS L2 5.3: Ensure the default security group of every VPC restricts all traffic" if {
	some vpc in input.vpc.vpcs
	vpc.default_security_group_allows_traffic
}

violations contains "CIS L2 5.4: Ensure routing tables for VPC peering are 'least access'" if {
	some table in input.vpc.route_tables
	table.peering_connection_with_open_cidr
}

violations contains "CIS L2 5.5: Ensure VPC flow logging is enabled in all VPCs" if {
	some vpc in input.vpc.vpcs
	not vpc.flow_logs_enabled
}

port_in_range(port_range, ports) if {
	some p in ports
	port_range.from <= p
	port_range.to >= p
}

# ---------------------------------------------------------------------------
# Compliance report
# ---------------------------------------------------------------------------

l2_total_controls := 40

compliance_report := {
	"profile":           "level2",
	"benchmark":         "CIS Amazon Web Services Foundations Benchmark v7.0.0",
	"l2_controls":       l2_total_controls,
	"l2_violations":     count(violations),
	"l2_compliant":      compliant,
	"l2_violation_list": [v | some v in violations],
	"note": "Level 2 controls supplement Level 1. Intended for regulated cloud workloads (FedRAMP High, PCI-DSS, HIPAA, DoD).",
}
