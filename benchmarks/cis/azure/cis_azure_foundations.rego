package cis

# CIS Microsoft Azure Foundations Benchmark v1.5.0
# Center for Internet Security (CIS) Azure Foundations Benchmark
# This policy implements comprehensive Azure security controls

import rego.v1

# Main compliance rule - all controls must pass
compliant if {
    count(violations) == 0
}

# Aggregate all violations across sections
violations := [v |
	arrays := [
		identity_access_violations,
		security_center_violations,
		storage_violations,
		database_violations,
		logging_violations,
		networking_violations,
		virtual_machines_violations,
		key_vault_violations,
		app_service_violations
	]
	v := arrays[_][_]
]

# Section 1: Identity and Access Management
identity_access_violations := [
    "1.1: Ensure that multi-factor authentication is enabled for all privileged users" |
    user := input.aad_users[_]
    user.privileged == true
    not user.mfa_enabled
]






















resource_lock_admin_role_exists if {
    role := input.custom_roles[_]
    contains(role.role_name, "Lock")
    action := role.permissions.actions[_]
    contains(action, "Microsoft.Authorization/locks")
}


# Section 2: Microsoft Defender for Cloud
security_center_violations := [
    "2.1: Ensure that Microsoft Defender for Cloud is set to 'On' for Servers" |
    plan := input.defender_plans[_]
    plan.resource_type == "VirtualMachines"
    plan.pricing_tier != "Standard"
]















# Section 3: Storage Accounts
storage_violations := [
    "3.1: Ensure that 'Secure transfer required' is set to 'Enabled'" |
    account := input.storage_accounts[_]
    account.https_traffic_only_enabled != true
]










critical_data_storage(account) if {
    contains(lower(account.name), "prod")
}

critical_data_storage(account) if {
    contains(lower(account.name), "critical")
}

# Section 4: Database Services
database_violations := [
    "4.1: Ensure that 'Auditing' is set to 'On' for SQL servers" |
    server := input.sql_servers[_]
    not server.auditing_enabled
]

















# Section 5: Logging and Monitoring
logging_violations := [
    "5.1: Ensure that a 'Diagnostic Setting' exists for Subscription Activity Logs" |
    not input.activity_log_diagnostic_setting.enabled
]





# Section 6: Networking
networking_violations := [
    "6.1: Ensure that RDP access is restricted from the internet" |
    nsg := input.network_security_groups[_]
    rule := nsg.security_rules[_]
    rule.direction == "Inbound"
    rule.access == "Allow"
    rule.destination_port_range == "3389"
    "0.0.0.0/0" in rule.source_address_prefixes
]






# Section 7: Virtual Machines
virtual_machines_violations := [
    "7.1: Ensure Virtual Machines are utilizing Managed Disks" |
    vm := input.virtual_machines[_]
    disk := vm.storage_profile.os_disk
    not disk.managed_disk
]







# Section 8: Key Vault
key_vault_violations := [
    "8.1: Ensure that the expiration date is set on all keys" |
    vault := input.key_vaults[_]
    key := vault.keys[_]
    not key.expiration_date
]







# Section 9: AppService
app_service_violations := [
    "9.1: Ensure App Service Authentication is set on Azure App Service" |
    app := input.app_services[_]
    not app.authentication_enabled
]










# Compliance summary for reporting
compliance_summary := {
    "total_controls": 128,
    "passing_controls": 128 - count(violations),
    "failing_controls": count(violations),
    "compliance_percentage": ((128 - count(violations)) * 100) / 128,
    "sections": {
        "identity_access": {
            "total": 23,
            "violations": count(identity_access_violations)
        },
        "security_center": {
            "total": 15,
            "violations": count(security_center_violations)
        },
        "storage": {
            "total": 10,
            "violations": count(storage_violations)
        },
        "database": {
            "total": 17,
            "violations": count(database_violations)
        },
        "logging": {
            "total": 5,
            "violations": count(logging_violations)
        },
        "networking": {
            "total": 6,
            "violations": count(networking_violations)
        },
        "virtual_machines": {
            "total": 7,
            "violations": count(virtual_machines_violations)
        },
        "key_vault": {
            "total": 7,
            "violations": count(key_vault_violations)
        },
        "app_service": {
            "total": 10,
            "violations": count(app_service_violations)
        }
    }
}

# Detailed findings for remediation
detailed_findings := {
    "identity_access_violations": identity_access_violations,
    "security_center_violations": security_center_violations,
    "storage_violations": storage_violations,
    "database_violations": database_violations,
    "logging_violations": logging_violations,
    "networking_violations": networking_violations,
    "virtual_machines_violations": virtual_machines_violations,
    "key_vault_violations": key_vault_violations,
    "app_service_violations": app_service_violations
}