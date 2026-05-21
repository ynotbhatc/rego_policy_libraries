package cis_azure.l2

# CIS Microsoft Azure Foundations Benchmark v3.0.0 - Level 2 Additional Controls
# Level 2 extends Level 1 with stricter controls for regulated cloud workloads.
# Intended for: FedRAMP High, PCI-DSS, HIPAA, HITRUST, DoD IL4/IL5.

import rego.v1

default compliant := false

compliant if { count(violations) == 0 }

# ---------------------------------------------------------------------------
# Section 1 - Identity and Access Management (L2)
# ---------------------------------------------------------------------------

violations contains "CIS L2 1.1.1: Ensure Security Defaults is enabled on Azure Active Directory" if {
	not input.aad.security_defaults_enabled
}

violations contains "CIS L2 1.1.4: Ensure Guest Users Are Reviewed on a Regular Basis" if {
	some user in input.aad.guest_users
	user.days_since_last_review > 90
}

violations contains "CIS L2 1.2.1: Ensure that Microsoft Authenticator is configured to show geographic location" if {
	not input.aad.mfa.authenticator_show_location
}

violations contains "CIS L2 1.2.2: Ensure that multi-factor authentication is required for all users" if {
	some user in input.aad.users
	not user.mfa_enabled
	not user.service_account
}

violations contains "CIS L2 1.3.2: Ensure that 'Users can add gallery apps to My Apps' is set to 'No'" if {
	input.aad.users_can_add_gallery_apps
}

violations contains "CIS L2 1.4.1: Ensure that 'Restrict access to Azure AD administration portal' is set to 'Yes'" if {
	not input.aad.restrict_admin_portal_access
}

violations contains "CIS L2 1.5.1: Ensure that 'Number of methods required to reset' is set to '2'" if {
	input.aad.sspr_methods_required < 2
}

violations contains "CIS L2 1.6.1: Ensure Privileged Identity Management is used to manage role assignments" if {
	not input.aad.pim_enabled
}

violations contains "CIS L2 1.7: Ensure that Custom Subscription Administrator Roles are not created" if {
	some role in input.rbac.custom_roles
	contains_owner_actions(role.permissions)
}

contains_owner_actions(permissions) if {
	some perm in permissions
	perm.actions[_] == "*"
}

violations contains "CIS L2 1.8: Ensure that external users with Owner role are removed" if {
	some assignment in input.rbac.role_assignments
	assignment.role == "Owner"
	contains(assignment.principal_type, "Guest")
}

# ---------------------------------------------------------------------------
# Section 2 - Microsoft Defender for Cloud (L2)
# ---------------------------------------------------------------------------

violations contains "CIS L2 2.1.1: Ensure Microsoft Defender for Servers is set to 'On'" if {
	not input.defender.servers_enabled
}

violations contains "CIS L2 2.1.2: Ensure Microsoft Defender for Databases is set to 'On'" if {
	not input.defender.databases_enabled
}

violations contains "CIS L2 2.1.3: Ensure Microsoft Defender for Azure SQL is set to 'On'" if {
	not input.defender.azure_sql_enabled
}

violations contains "CIS L2 2.1.4: Ensure Microsoft Defender for SQL Servers is set to 'On'" if {
	not input.defender.sql_servers_on_machines_enabled
}

violations contains "CIS L2 2.1.5: Ensure Microsoft Defender for Storage is set to 'On'" if {
	not input.defender.storage_enabled
}

violations contains "CIS L2 2.1.6: Ensure Microsoft Defender for Containers is set to 'On'" if {
	not input.defender.containers_enabled
}

violations contains "CIS L2 2.1.7: Ensure Microsoft Defender for Key Vault is set to 'On'" if {
	not input.defender.key_vault_enabled
}

violations contains "CIS L2 2.2.1: Ensure Defender for Cloud's auto-provisioning of Log Analytics agent is enabled" if {
	not input.defender.auto_provision_log_analytics
}

violations contains "CIS L2 2.10: Ensure that Microsoft Defender for Cloud integration with Microsoft Defender for Endpoint is selected" if {
	not input.defender.mde_integration_enabled
}

# ---------------------------------------------------------------------------
# Section 3 - Storage Accounts (L2)
# ---------------------------------------------------------------------------

violations contains "CIS L2 3.1.1: Ensure that 'Secure transfer required' is set to 'Enabled'" if {
	some account in input.storage.accounts
	not account.https_traffic_only
}

violations contains "CIS L2 3.1.2: Ensure that storage account access keys are periodically regenerated" if {
	some account in input.storage.accounts
	account.key_age_days > 90
}

violations contains "CIS L2 3.1.3: Ensure Storage logging is enabled for Queue service read/write/delete requests" if {
	some account in input.storage.accounts
	not account.queue_logging_enabled
}

violations contains "CIS L2 3.1.4: Ensure that shared access signature tokens expire within an hour" if {
	some account in input.storage.accounts
	account.sas_max_expiry_hours > 1
}

violations contains "CIS L2 3.1.6: Ensure that 'Public access level' is set to Private for blob containers" if {
	some container in input.storage.blob_containers
	container.public_access != "None"
}

violations contains "CIS L2 3.2.1: Ensure soft-delete is enabled for Azure Blobs" if {
	some account in input.storage.accounts
	not account.blob_soft_delete_enabled
}

violations contains "CIS L2 3.2.2: Ensure soft-delete is enabled for Azure File Shares" if {
	some account in input.storage.accounts
	not account.file_soft_delete_enabled
}

# ---------------------------------------------------------------------------
# Section 4 - Database Services (L2)
# ---------------------------------------------------------------------------

violations contains "CIS L2 4.1.1: Ensure 'Auditing' is set to 'On' for Azure SQL Server" if {
	some server in input.sql.servers
	not server.auditing_enabled
}

violations contains "CIS L2 4.1.2: Ensure that 'Data encryption' is set to 'On' for SQL Server" if {
	some db in input.sql.databases
	not db.transparent_data_encryption_enabled
}

violations contains "CIS L2 4.1.3: Ensure that 'Threat Detection' is set to 'On' for SQL Server" if {
	some server in input.sql.servers
	not server.threat_detection_enabled
}

violations contains "CIS L2 4.2.1: Ensure 'Enforce SSL connection' is enabled for PostgreSQL" if {
	some server in input.postgresql.servers
	not server.ssl_enforcement_enabled
}

violations contains "CIS L2 4.3.1: Ensure 'Enforce SSL connection' is enabled for MySQL" if {
	some server in input.mysql.servers
	not server.ssl_enforcement_enabled
}

# ---------------------------------------------------------------------------
# Section 5 - Logging and Monitoring (L2)
# ---------------------------------------------------------------------------

violations contains "CIS L2 5.1.1: Ensure audit profile captures all activities" if {
	not input.monitor.audit_profile.captures_all_categories
}

violations contains "CIS L2 5.1.2: Ensure diagnostic logging retention policy is set to 365 days or more" if {
	input.monitor.log_retention_days < 365
}

violations contains "CIS L2 5.2.1: Ensure activity log alert exists for Create Policy Assignment" if {
	not input.monitor.alerts.create_policy_assignment
}

violations contains "CIS L2 5.2.2: Ensure activity log alert exists for Delete Policy Assignment" if {
	not input.monitor.alerts.delete_policy_assignment
}

violations contains "CIS L2 5.2.4: Ensure activity log alert exists for Create or Update Network Security Group" if {
	not input.monitor.alerts.create_update_nsg
}

violations contains "CIS L2 5.2.5: Ensure activity log alert exists for Delete Network Security Group" if {
	not input.monitor.alerts.delete_nsg
}

violations contains "CIS L2 5.2.7: Ensure activity log alert exists for Create or Update Security Solution" if {
	not input.monitor.alerts.create_update_security_solution
}

# ---------------------------------------------------------------------------
# Section 6 - Networking (L2)
# ---------------------------------------------------------------------------

violations contains "CIS L2 6.3: Ensure that Network Watcher is 'Enabled'" if {
	some region in input.network.regions_without_network_watcher
	region != ""
}

violations contains "CIS L2 6.4: Ensure that Network Security Group Flow Log retention is greater than 90 days" if {
	some nsg in input.network.nsgs
	nsg.flow_log_retention_days < 90
}

violations contains "CIS L2 6.5: Ensure that Network Security Group Flow logs are captured and sent to Log Analytics" if {
	some nsg in input.network.nsgs
	not nsg.flow_logs_sent_to_log_analytics
}

# ---------------------------------------------------------------------------
# Section 7 - Virtual Machines (L2)
# ---------------------------------------------------------------------------

violations contains "CIS L2 7.1: Ensure Virtual Machines are utilizing Managed Disks" if {
	some vm in input.compute.virtual_machines
	not vm.uses_managed_disks
}

violations contains "CIS L2 7.2: Ensure that 'OS disk' are encrypted with Customer Managed Key (CMK)" if {
	some vm in input.compute.virtual_machines
	not vm.os_disk_cmk_encrypted
}

violations contains "CIS L2 7.3: Ensure that 'Data disks' are encrypted with Customer Managed Key (CMK)" if {
	some disk in input.compute.managed_disks
	not disk.cmk_encrypted
}

# ---------------------------------------------------------------------------
# Compliance report
# ---------------------------------------------------------------------------

l2_total_controls := 44

compliance_report := {
	"profile":           "level2",
	"benchmark":         "CIS Microsoft Azure Foundations Benchmark v3.0.0",
	"l2_controls":       l2_total_controls,
	"l2_violations":     count(violations),
	"l2_compliant":      compliant,
	"l2_violation_list": [v | some v in violations],
	"note": "Level 2 controls supplement Level 1. Intended for regulated Azure workloads (FedRAMP High, PCI-DSS, HIPAA, HITRUST).",
}
