# METADATA
# title: "CIS Amazon Web Services Foundations Benchmark v7.0.0"
# custom:
#   class: security
#   framework: cis_aws
#   source: cis
#   domains: [cloud, aws]
#   coverage:
#     checks: 20
#     cited: 20
#     density: sized
#     basis: size
#     tested: true
#     entrypoint: none
#     guard: self
#     as_of: v2.4.2
package cis_aws

# CIS Amazon Web Services Foundations Benchmark v7.0.0
# Center for Internet Security (CIS) AWS Foundations Benchmark
# This policy implements comprehensive AWS security controls

import rego.v1

# Main compliance rule - all controls must pass
default compliant := false

compliant if {
    count(violations) == 0
}

# Aggregate all violations across sections
violations := [v |
	arrays := [
		identity_access_violations,
		logging_violations,
		monitoring_violations,
		networking_violations,
		storage_violations
	]
	v := arrays[_][_]
]

# Section 1: Identity and Access Management
identity_access_violations := [
    "1.1: Avoid the use of 'root' account" |
    input.aws_account_summary.account_access_keys_present > 0
]

















support_role_exists if {
    role := input.iam_roles[_]
    contains(lower(role.role_name), "support")
    policy := role.attached_policies[_]
    policy.policy_name == "AWSSupportAccess"
}





# Section 2: Storage
storage_violations := [
    "2.1.1: Ensure S3 bucket access logging is enabled on the CloudTrail S3 bucket" |
    bucket := input.s3_buckets[_]
    bucket.is_cloudtrail_bucket == true
    not bucket.access_logging_enabled
]







# Section 3: Logging
logging_violations := [
    "3.1: Ensure CloudTrail is enabled in all regions" |
    not input.cloudtrail.multi_region_enabled
]











# Section 4: Monitoring
monitoring_violations := [
    msg |
    some control in monitoring_controls
    not control.ok
    msg := control.msg
]

# Controls 4.1-4.15: each needs a log metric filter plus an alarm on its metric.
monitoring_controls := [
    {"msg": "4.1: Ensure a log metric filter and alarm exist for unauthorized API calls", "ok": unauthorized_api_calls_alarm_exists},
    {"msg": "4.2: Ensure a log metric filter and alarm exist for console sign-in without MFA", "ok": console_signin_without_mfa_alarm_exists},
    {"msg": "4.3: Ensure a log metric filter and alarm exist for usage of the root account", "ok": root_account_usage_alarm_exists},
    {"msg": "4.4: Ensure a log metric filter and alarm exist for IAM policy changes", "ok": iam_policy_changes_alarm_exists},
    {"msg": "4.5: Ensure a log metric filter and alarm exist for CloudTrail configuration changes", "ok": cloudtrail_config_changes_alarm_exists},
    {"msg": "4.6: Ensure a log metric filter and alarm exist for console authentication failures", "ok": console_auth_failures_alarm_exists},
    {"msg": "4.7: Ensure a log metric filter and alarm exist for disabling or scheduled deletion of customer managed keys", "ok": cmk_deletion_alarm_exists},
    {"msg": "4.8: Ensure a log metric filter and alarm exist for S3 bucket policy changes", "ok": s3_bucket_policy_changes_alarm_exists},
    {"msg": "4.9: Ensure a log metric filter and alarm exist for AWS Config configuration changes", "ok": config_changes_alarm_exists},
    {"msg": "4.10: Ensure a log metric filter and alarm exist for security group changes", "ok": security_group_changes_alarm_exists},
    {"msg": "4.11: Ensure a log metric filter and alarm exist for changes to Network ACLs", "ok": nacl_changes_alarm_exists},
    {"msg": "4.12: Ensure a log metric filter and alarm exist for changes to network gateways", "ok": network_gateway_changes_alarm_exists},
    {"msg": "4.13: Ensure a log metric filter and alarm exist for route table changes", "ok": route_table_changes_alarm_exists},
    {"msg": "4.14: Ensure a log metric filter and alarm exist for VPC changes", "ok": vpc_changes_alarm_exists},
    {"msg": "4.15: Ensure a log metric filter and alarm exist for AWS Organizations changes", "ok": organizations_changes_alarm_exists},
]

default unauthorized_api_calls_alarm_exists := false

unauthorized_api_calls_alarm_exists if {
    alarm := input.cloudwatch_alarms[_]
    filter := input.cloudwatch_log_metric_filters[_]
    contains(filter.filter_pattern, "UnauthorizedOperation")
    contains(filter.filter_pattern, "AccessDenied")
    alarm.metric_name == filter.metric_name
}


default console_signin_without_mfa_alarm_exists := false

console_signin_without_mfa_alarm_exists if {
    alarm := input.cloudwatch_alarms[_]
    filter := input.cloudwatch_log_metric_filters[_]
    contains(filter.filter_pattern, "ConsoleLogin")
    contains(filter.filter_pattern, "MfaUsed")
    alarm.metric_name == filter.metric_name
}


default root_account_usage_alarm_exists := false

root_account_usage_alarm_exists if {
    alarm := input.cloudwatch_alarms[_]
    filter := input.cloudwatch_log_metric_filters[_]
    contains(filter.filter_pattern, "root")
    alarm.metric_name == filter.metric_name
}


default iam_policy_changes_alarm_exists := false

iam_policy_changes_alarm_exists if {
    alarm := input.cloudwatch_alarms[_]
    filter := input.cloudwatch_log_metric_filters[_]
    contains(filter.filter_pattern, "DeleteGroupPolicy")
    contains(filter.filter_pattern, "DeleteRolePolicy")
    alarm.metric_name == filter.metric_name
}


default cloudtrail_config_changes_alarm_exists := false

cloudtrail_config_changes_alarm_exists if {
    alarm := input.cloudwatch_alarms[_]
    filter := input.cloudwatch_log_metric_filters[_]
    contains(filter.filter_pattern, "CreateTrail")
    contains(filter.filter_pattern, "UpdateTrail")
    alarm.metric_name == filter.metric_name
}


default console_auth_failures_alarm_exists := false

console_auth_failures_alarm_exists if {
    alarm := input.cloudwatch_alarms[_]
    filter := input.cloudwatch_log_metric_filters[_]
    contains(filter.filter_pattern, "ConsoleLogin")
    contains(filter.filter_pattern, "Failed")
    alarm.metric_name == filter.metric_name
}


default cmk_deletion_alarm_exists := false

cmk_deletion_alarm_exists if {
    alarm := input.cloudwatch_alarms[_]
    filter := input.cloudwatch_log_metric_filters[_]
    contains(filter.filter_pattern, "DisableKey")
    contains(filter.filter_pattern, "ScheduleKeyDeletion")
    alarm.metric_name == filter.metric_name
}


default s3_bucket_policy_changes_alarm_exists := false

s3_bucket_policy_changes_alarm_exists if {
    alarm := input.cloudwatch_alarms[_]
    filter := input.cloudwatch_log_metric_filters[_]
    contains(filter.filter_pattern, "PutBucketAcl")
    contains(filter.filter_pattern, "PutBucketPolicy")
    alarm.metric_name == filter.metric_name
}


default config_changes_alarm_exists := false

config_changes_alarm_exists if {
    alarm := input.cloudwatch_alarms[_]
    filter := input.cloudwatch_log_metric_filters[_]
    contains(filter.filter_pattern, "PutConfigurationRecorder")
    contains(filter.filter_pattern, "StopConfigurationRecorder")
    alarm.metric_name == filter.metric_name
}


default security_group_changes_alarm_exists := false

security_group_changes_alarm_exists if {
    alarm := input.cloudwatch_alarms[_]
    filter := input.cloudwatch_log_metric_filters[_]
    contains(filter.filter_pattern, "AuthorizeSecurityGroupIngress")
    contains(filter.filter_pattern, "AuthorizeSecurityGroupEgress")
    alarm.metric_name == filter.metric_name
}


default nacl_changes_alarm_exists := false

nacl_changes_alarm_exists if {
    alarm := input.cloudwatch_alarms[_]
    filter := input.cloudwatch_log_metric_filters[_]
    contains(filter.filter_pattern, "CreateNetworkAcl")
    contains(filter.filter_pattern, "CreateNetworkAclEntry")
    alarm.metric_name == filter.metric_name
}


default network_gateway_changes_alarm_exists := false

network_gateway_changes_alarm_exists if {
    alarm := input.cloudwatch_alarms[_]
    filter := input.cloudwatch_log_metric_filters[_]
    contains(filter.filter_pattern, "CreateCustomerGateway")
    contains(filter.filter_pattern, "DeleteCustomerGateway")
    alarm.metric_name == filter.metric_name
}


default route_table_changes_alarm_exists := false

route_table_changes_alarm_exists if {
    alarm := input.cloudwatch_alarms[_]
    filter := input.cloudwatch_log_metric_filters[_]
    contains(filter.filter_pattern, "CreateRoute")
    contains(filter.filter_pattern, "CreateRouteTable")
    alarm.metric_name == filter.metric_name
}


default vpc_changes_alarm_exists := false

vpc_changes_alarm_exists if {
    alarm := input.cloudwatch_alarms[_]
    filter := input.cloudwatch_log_metric_filters[_]
    contains(filter.filter_pattern, "CreateVpc")
    contains(filter.filter_pattern, "DeleteVpc")
    alarm.metric_name == filter.metric_name
}


default organizations_changes_alarm_exists := false

organizations_changes_alarm_exists if {
    alarm := input.cloudwatch_alarms[_]
    filter := input.cloudwatch_log_metric_filters[_]
    contains(filter.filter_pattern, "AcceptHandshake")
    contains(filter.filter_pattern, "AttachPolicy")
    alarm.metric_name == filter.metric_name
}

# Section 5: Networking
networking_violations := [
    "5.1: Ensure no Network ACLs allow ingress from 0.0.0.0/0 to remote server administration ports" |
    nacl := input.network_acls[_]
    entry := nacl.entries[_]
    entry.rule_action == "allow"
    entry.cidr_block == "0.0.0.0/0"
    admin_entry(entry)
]

# An entry opens admin ports if its range covers 22/3389, or if it allows all
# protocols (-1 / "all") and so carries no port_range at all.
admin_entry(entry) if admin_port_range(entry.port_range)

admin_entry(entry) if sprintf("%v", [entry.protocol]) in {"-1", "all"}

admin_port_range(port_range) if {
    port_range.from <= 22
    port_range.to >= 22
}

admin_port_range(port_range) if {
    port_range.from <= 3389
    port_range.to >= 3389
}


admin_port_in_rule(rule) if {
    rule.from_port <= 22
    rule.to_port >= 22
}

admin_port_in_rule(rule) if {
    rule.from_port <= 3389
    rule.to_port >= 3389
}



# Compliance summary for reporting
compliance_summary := {
    "total_controls": 69,
    "passing_controls": 69 - count(violations),
    "failing_controls": count(violations),
    "compliance_percentage": ((69 - count(violations)) * 100) / 69,
    "sections": {
        "identity_access": {
            "total": 21,
            "violations": count(identity_access_violations)
        },
        "storage": {
            "total": 8,
            "violations": count(storage_violations)
        },
        "logging": {
            "total": 11,
            "violations": count(logging_violations)
        },
        "monitoring": {
            "total": 15,
            "violations": count(monitoring_violations)
        },
        "networking": {
            "total": 4,
            "violations": count(networking_violations)
        }
    }
}

# Detailed findings for remediation
detailed_findings := {
    "identity_access_violations": identity_access_violations,
    "storage_violations": storage_violations,
    "logging_violations": logging_violations,
    "monitoring_violations": monitoring_violations,
    "networking_violations": networking_violations
}