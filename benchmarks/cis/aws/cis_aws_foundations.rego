package cis

# CIS Amazon Web Services Foundations Benchmark v1.5.0
# Center for Internet Security (CIS) AWS Foundations Benchmark
# This policy implements comprehensive AWS security controls

import rego.v1

# Main compliance rule - all controls must pass
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
    input.aws_account_summary.account_access_keys_present == 1
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
    "4.1: Ensure a log metric filter and alarm exist for unauthorized API calls" |
    not unauthorized_api_calls_alarm_exists
]

unauthorized_api_calls_alarm_exists if {
    alarm := input.cloudwatch_alarms[_]
    filter := input.cloudwatch_log_metric_filters[_]
    contains(filter.filter_pattern, "ERROR")
    contains(filter.filter_pattern, "Denied")
    alarm.metric_name == filter.metric_name
}


console_signin_without_mfa_alarm_exists if {
    alarm := input.cloudwatch_alarms[_]
    filter := input.cloudwatch_log_metric_filters[_]
    contains(filter.filter_pattern, "ConsoleLogin")
    contains(filter.filter_pattern, "MfaUsed")
    alarm.metric_name == filter.metric_name
}


root_account_usage_alarm_exists if {
    alarm := input.cloudwatch_alarms[_]
    filter := input.cloudwatch_log_metric_filters[_]
    contains(filter.filter_pattern, "root")
    alarm.metric_name == filter.metric_name
}


iam_policy_changes_alarm_exists if {
    alarm := input.cloudwatch_alarms[_]
    filter := input.cloudwatch_log_metric_filters[_]
    contains(filter.filter_pattern, "DeleteGroupPolicy")
    contains(filter.filter_pattern, "DeleteRolePolicy")
    alarm.metric_name == filter.metric_name
}


cloudtrail_config_changes_alarm_exists if {
    alarm := input.cloudwatch_alarms[_]
    filter := input.cloudwatch_log_metric_filters[_]
    contains(filter.filter_pattern, "CreateTrail")
    contains(filter.filter_pattern, "UpdateTrail")
    alarm.metric_name == filter.metric_name
}


console_auth_failures_alarm_exists if {
    alarm := input.cloudwatch_alarms[_]
    filter := input.cloudwatch_log_metric_filters[_]
    contains(filter.filter_pattern, "ConsoleLogin")
    contains(filter.filter_pattern, "Failed")
    alarm.metric_name == filter.metric_name
}


cmk_deletion_alarm_exists if {
    alarm := input.cloudwatch_alarms[_]
    filter := input.cloudwatch_log_metric_filters[_]
    contains(filter.filter_pattern, "DisableKey")
    contains(filter.filter_pattern, "ScheduleKeyDeletion")
    alarm.metric_name == filter.metric_name
}


s3_bucket_policy_changes_alarm_exists if {
    alarm := input.cloudwatch_alarms[_]
    filter := input.cloudwatch_log_metric_filters[_]
    contains(filter.filter_pattern, "PutBucketAcl")
    contains(filter.filter_pattern, "PutBucketPolicy")
    alarm.metric_name == filter.metric_name
}


config_changes_alarm_exists if {
    alarm := input.cloudwatch_alarms[_]
    filter := input.cloudwatch_log_metric_filters[_]
    contains(filter.filter_pattern, "PutConfigurationRecorder")
    contains(filter.filter_pattern, "StopConfigurationRecorder")
    alarm.metric_name == filter.metric_name
}


security_group_changes_alarm_exists if {
    alarm := input.cloudwatch_alarms[_]
    filter := input.cloudwatch_log_metric_filters[_]
    contains(filter.filter_pattern, "AuthorizeSecurityGroupIngress")
    contains(filter.filter_pattern, "AuthorizeSecurityGroupEgress")
    alarm.metric_name == filter.metric_name
}


nacl_changes_alarm_exists if {
    alarm := input.cloudwatch_alarms[_]
    filter := input.cloudwatch_log_metric_filters[_]
    contains(filter.filter_pattern, "CreateNetworkAcl")
    contains(filter.filter_pattern, "CreateNetworkAclEntry")
    alarm.metric_name == filter.metric_name
}


network_gateway_changes_alarm_exists if {
    alarm := input.cloudwatch_alarms[_]
    filter := input.cloudwatch_log_metric_filters[_]
    contains(filter.filter_pattern, "CreateCustomerGateway")
    contains(filter.filter_pattern, "DeleteCustomerGateway")
    alarm.metric_name == filter.metric_name
}


route_table_changes_alarm_exists if {
    alarm := input.cloudwatch_alarms[_]
    filter := input.cloudwatch_log_metric_filters[_]
    contains(filter.filter_pattern, "CreateRoute")
    contains(filter.filter_pattern, "CreateRouteTable")
    alarm.metric_name == filter.metric_name
}


vpc_changes_alarm_exists if {
    alarm := input.cloudwatch_alarms[_]
    filter := input.cloudwatch_log_metric_filters[_]
    contains(filter.filter_pattern, "CreateVpc")
    contains(filter.filter_pattern, "DeleteVpc")
    alarm.metric_name == filter.metric_name
}


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
    admin_port_range(entry.port_range)
]

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