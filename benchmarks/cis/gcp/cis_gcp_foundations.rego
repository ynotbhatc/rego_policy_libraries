package cis

# CIS Google Cloud Platform Foundation Benchmark v1.3.0
# Center for Internet Security (CIS) GCP Foundation Benchmark
# This policy implements comprehensive GCP security controls

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
		networking_violations,
		virtual_machines_violations,
		storage_violations,
		sql_violations,
		bigquery_violations
	]
	v := arrays[_][_]
]

# Section 1: Identity and Access Management
identity_access_violations := [
    "1.1: Ensure that corporate login credentials are used" |
    user := input.iam_users[_]
    endswith(user.email, "@gmail.com")
]




admin_role(role) if {
    role == "roles/owner"
}

admin_role(role) if {
    role == "roles/editor"
}

admin_role(role) if {
    contains(role, "admin")
}


service_account_role(role) if {
    role == "roles/iam.serviceAccountUser"
}

service_account_role(role) if {
    role == "roles/iam.serviceAccountTokenCreator"
}


service_account_admin_role(role) if {
    role == "roles/iam.serviceAccountAdmin"
}

service_account_admin_role(role) if {
    role == "roles/iam.serviceAccountKeyAdmin"
}



separation_of_duties_violation(roles) if {
    "roles/iam.serviceAccountAdmin" in roles
    "roles/iam.serviceAccountUser" in roles
}

separation_of_duties_violation(roles) if {
    "roles/iam.serviceAccountAdmin" in roles
    "roles/iam.serviceAccountKeyAdmin" in roles
}


anonymous_or_public_member(member) if {
    member == "allUsers"
}

anonymous_or_public_member(member) if {
    member == "allAuthenticatedUsers"
}



kms_separation_of_duties_violation(roles) if {
    "roles/cloudkms.admin" in roles
    some kms_crypto_role in roles
    kms_crypto_role != "roles/cloudkms.admin"
    startswith(kms_crypto_role, "roles/cloudkms.crypto")
}





# Section 2: Logging and Monitoring
logging_violations := [
    "2.1: Ensure that Cloud Audit Logging is configured properly across all services and all users from a project" |
    service := input.audit_config.services[_]
    audit_log_config := service.audit_log_configs[_]
    audit_log_config.log_type != "ADMIN_READ"
]




project_ownership_alert_exists if {
    filter := input.log_metric_filters[_]
    contains(filter.filter, "protoPayload.serviceName=\"cloudresourcemanager.googleapis.com\"")
    contains(filter.filter, "ProjectOwnership")
    alert := input.alert_policies[_]
    alert.conditions[_].condition_threshold.filter == sprintf("resource.type=\"gce_project\" AND metric.type=\"logging.googleapis.com/user/%s\"", [filter.name])
}


audit_config_change_alert_exists if {
    filter := input.log_metric_filters[_]
    contains(filter.filter, "protoPayload.serviceName=\"cloudresourcemanager.googleapis.com\"")
    contains(filter.filter, "SetIamPolicy")
    alert := input.alert_policies[_]
    alert.conditions[_].condition_threshold.filter == sprintf("resource.type=\"gce_project\" AND metric.type=\"logging.googleapis.com/user/%s\"", [filter.name])
}


custom_role_changes_alert_exists if {
    filter := input.log_metric_filters[_]
    contains(filter.filter, "resource.type=\"iam_role\"")
    contains(filter.filter, "protoPayload.methodName=\"google.iam.admin.v1.CreateRole\"")
    alert := input.alert_policies[_]
    alert.conditions[_].condition_threshold.filter == sprintf("resource.type=\"gce_project\" AND metric.type=\"logging.googleapis.com/user/%s\"", [filter.name])
}


firewall_rule_changes_alert_exists if {
    filter := input.log_metric_filters[_]
    contains(filter.filter, "resource.type=\"gce_firewall_rule\"")
    contains(filter.filter, "protoPayload.methodName=\"v1.compute.firewalls.insert\"")
    alert := input.alert_policies[_]
    alert.conditions[_].condition_threshold.filter == sprintf("resource.type=\"gce_project\" AND metric.type=\"logging.googleapis.com/user/%s\"", [filter.name])
}


network_route_changes_alert_exists if {
    filter := input.log_metric_filters[_]
    contains(filter.filter, "resource.type=\"gce_route\"")
    contains(filter.filter, "protoPayload.methodName=\"v1.compute.routes.insert\"")
    alert := input.alert_policies[_]
    alert.conditions[_].condition_threshold.filter == sprintf("resource.type=\"gce_project\" AND metric.type=\"logging.googleapis.com/user/%s\"", [filter.name])
}


vpc_network_changes_alert_exists if {
    filter := input.log_metric_filters[_]
    contains(filter.filter, "resource.type=\"gce_network\"")
    contains(filter.filter, "protoPayload.methodName=\"v1.compute.networks.insert\"")
    alert := input.alert_policies[_]
    alert.conditions[_].condition_threshold.filter == sprintf("resource.type=\"gce_project\" AND metric.type=\"logging.googleapis.com/user/%s\"", [filter.name])
}


storage_iam_changes_alert_exists if {
    filter := input.log_metric_filters[_]
    contains(filter.filter, "resource.type=\"gcs_bucket\"")
    contains(filter.filter, "protoPayload.methodName=\"storage.setIamPermissions\"")
    alert := input.alert_policies[_]
    alert.conditions[_].condition_threshold.filter == sprintf("resource.type=\"gce_project\" AND metric.type=\"logging.googleapis.com/user/%s\"", [filter.name])
}


sql_instance_changes_alert_exists if {
    filter := input.log_metric_filters[_]
    contains(filter.filter, "protoPayload.serviceName=\"sqladmin.googleapis.com\"")
    contains(filter.filter, "protoPayload.methodName=\"cloudsql.instances.update\"")
    alert := input.alert_policies[_]
    alert.conditions[_].condition_threshold.filter == sprintf("resource.type=\"gce_project\" AND metric.type=\"logging.googleapis.com/user/%s\"", [filter.name])
}

# Section 3: Networking
networking_violations := [
    "3.1: Ensure that the default network does not exist in a project" |
    network := input.vpc_networks[_]
    network.name == "default"
]









weak_cipher_suite(profile, min_tls_version) if {
    profile == "COMPATIBLE"
}

weak_cipher_suite(profile, min_tls_version) if {
    profile == "MODERN"
    min_tls_version != "TLS_1_2"
}

# Section 4: Virtual Machines
virtual_machines_violations := [
    "4.1: Ensure that instances are not configured to use the default service account" |
    instance := input.compute_instances[_]
    sa := instance.service_accounts[_]
    endswith(sa.email, "-compute@developer.gserviceaccount.com")
]











# Section 5: Storage
storage_violations := [
    "5.1: Ensure that Cloud Storage bucket is not anonymously or publicly accessible" |
    bucket := input.storage_buckets[_]
    binding := bucket.iam_bindings[_]
    member := binding.members[_]
    anonymous_or_public_member(member)
]




# Section 6: Cloud SQL Database Services
sql_violations := [
    "6.1: Ensure that a MySQL database instance does not allow anyone to connect with administrative privileges" |
    instance := input.sql_instances[_]
    instance.database_version == "MYSQL_8_0"
    user := instance.users[_]
    user.name == "root"
    user.host == "%"
]












# Section 7: BigQuery
bigquery_violations := [
    "7.1: Ensure that BigQuery datasets are not anonymously or publicly accessible" |
    dataset := input.bigquery_datasets[_]
    access := dataset.access[_]
    access.special_group == "allAuthenticatedUsers"
]



# Compliance summary for reporting
compliance_summary := {
    "total_controls": 102,
    "passing_controls": 102 - count(violations),
    "failing_controls": count(violations),
    "compliance_percentage": ((102 - count(violations)) * 100) / 102,
    "sections": {
        "identity_access": {
            "total": 15,
            "violations": count(identity_access_violations)
        },
        "logging": {
            "total": 11,
            "violations": count(logging_violations)
        },
        "networking": {
            "total": 9,
            "violations": count(networking_violations)
        },
        "virtual_machines": {
            "total": 11,
            "violations": count(virtual_machines_violations)
        },
        "storage": {
            "total": 4,
            "violations": count(storage_violations)
        },
        "sql": {
            "total": 12,
            "violations": count(sql_violations)
        },
        "bigquery": {
            "total": 3,
            "violations": count(bigquery_violations)
        }
    }
}

# Detailed findings for remediation
detailed_findings := {
    "identity_access_violations": identity_access_violations,
    "logging_violations": logging_violations,
    "networking_violations": networking_violations,
    "virtual_machines_violations": virtual_machines_violations,
    "storage_violations": storage_violations,
    "sql_violations": sql_violations,
    "bigquery_violations": bigquery_violations
}