# METADATA
# title: "CIS Microsoft Azure Foundations Benchmark v3.0.0 - Level 2 Additional Controls"
# custom:
#   class: security
#   framework: cis_azure
#   source: cis
#   domains: [cloud, azure]
#   coverage:
#     checks: 44
#     cited: 44
#     density: sized
#     basis: size
#     tested: true
#     entrypoint: compliance_report
#     guard: self
#     as_of: v2.4.1
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

violations contains "CIS L2 1.1.1: Security Defaults must be turned on on Azure Active Directory" if {
	not input.aad.security_defaults_enabled
}

violations contains "CIS L2 1.1.4: Guest Users must be Reviewed on a Regular Basis" if {
	some user in input.aad.guest_users
	user.days_since_last_review > 90
}

violations contains "CIS L2 1.2.1: Microsoft Authenticator must be explicitly configured to show geographic location" if {
	not input.aad.mfa.authenticator_show_location
}

violations contains "CIS L2 1.2.2: multi-factor authentication must be required for all users" if {
	some user in input.aad.users
	not user.mfa_enabled
	not user.service_account
}

violations contains "CIS L2 1.3.2: required value of 'Users can add gallery apps to My Apps' is 'No'" if {
	input.aad.users_can_add_gallery_apps
}

violations contains "CIS L2 1.4.1: required value of 'Restrict access to Azure AD administration portal' is 'Yes'" if {
	not input.aad.restrict_admin_portal_access
}

violations contains "CIS L2 1.5.1: required value of 'Number of methods required to reset' is '2'" if {
	input.aad.sspr_methods_required < 2
}

violations contains "CIS L2 1.6.1: Privileged Identity Management must be used to manage role assignments" if {
	not input.aad.pim_enabled
}

violations contains "CIS L2 1.7: Custom Subscription Administrator Roles must be not created" if {
	some role in input.rbac.custom_roles
	contains_owner_actions(role.permissions)
}

contains_owner_actions(permissions) if {
	some perm in permissions
	perm.actions[_] == "*"
}

violations contains "CIS L2 1.8: external users with Owner role must be removed" if {
	some assignment in input.rbac.role_assignments
	assignment.role == "Owner"
	contains(assignment.principal_type, "Guest")
}

# ---------------------------------------------------------------------------
# Section 2 - Microsoft Defender for Cloud (L2)
# ---------------------------------------------------------------------------

violations contains "CIS L2 2.1.1: required value of Microsoft Defender for Servers is 'On'" if {
	not input.defender.servers_enabled
}

violations contains "CIS L2 2.1.2: required value of Microsoft Defender for Databases is 'On'" if {
	not input.defender.databases_enabled
}

violations contains "CIS L2 2.1.3: required value of Microsoft Defender for Azure SQL is 'On'" if {
	not input.defender.azure_sql_enabled
}

violations contains "CIS L2 2.1.4: required value of Microsoft Defender for SQL Servers is 'On'" if {
	not input.defender.sql_servers_on_machines_enabled
}

violations contains "CIS L2 2.1.5: required value of Microsoft Defender for Storage is 'On'" if {
	not input.defender.storage_enabled
}

violations contains "CIS L2 2.1.6: required value of Microsoft Defender for Containers is 'On'" if {
	not input.defender.containers_enabled
}

violations contains "CIS L2 2.1.7: required value of Microsoft Defender for Key Vault is 'On'" if {
	not input.defender.key_vault_enabled
}

violations contains "CIS L2 2.2.1: Defender for Cloud's auto-provisioning of Log Analytics agent must be turned on" if {
	not input.defender.auto_provision_log_analytics
}

violations contains "CIS L2 2.10: Microsoft Defender for Cloud integration with Microsoft Defender for Endpoint must be selected" if {
	not input.defender.mde_integration_enabled
}

# ---------------------------------------------------------------------------
# Section 3 - Storage Accounts (L2)
# ---------------------------------------------------------------------------

violations contains "CIS L2 3.1.1: required value of 'Secure transfer required' is 'Enabled'" if {
	some account in input.storage.accounts
	not account.https_traffic_only
}

violations contains "CIS L2 3.1.2: storage account access keys must be periodically regenerated" if {
	some account in input.storage.accounts
	account.key_age_days > 90
}

violations contains "CIS L2 3.1.3: Storage logging must be turned on for Queue service read/write/delete requests" if {
	some account in input.storage.accounts
	not account.queue_logging_enabled
}

violations contains "CIS L2 3.1.4: checked condition — shared access signature tokens expire within an hour" if {
	some account in input.storage.accounts
	account.sas_max_expiry_hours > 1
}

violations contains "CIS L2 3.1.6: required value of 'Public access level' is Private for blob containers" if {
	some container in input.storage.blob_containers
	container.public_access != "None"
}

violations contains "CIS L2 3.2.1: soft-delete must be turned on for Azure Blobs" if {
	some account in input.storage.accounts
	not account.blob_soft_delete_enabled
}

violations contains "CIS L2 3.2.2: soft-delete must be turned on for Azure File Shares" if {
	some account in input.storage.accounts
	not account.file_soft_delete_enabled
}

# ---------------------------------------------------------------------------
# Section 4 - Database Services (L2)
# ---------------------------------------------------------------------------

violations contains "CIS L2 4.1.1: required value of 'Auditing' is 'On' for Azure SQL Server" if {
	some server in input.sql.servers
	not server.auditing_enabled
}

violations contains "CIS L2 4.1.2: required value of 'Data encryption' is 'On' for SQL Server" if {
	some db in input.sql.databases
	not db.transparent_data_encryption_enabled
}

violations contains "CIS L2 4.1.3: required value of 'Threat Detection' is 'On' for SQL Server" if {
	some server in input.sql.servers
	not server.threat_detection_enabled
}

violations contains "CIS L2 4.2.1: 'Enforce SSL connection' must be turned on for PostgreSQL" if {
	some server in input.postgresql.servers
	not server.ssl_enforcement_enabled
}

violations contains "CIS L2 4.3.1: 'Enforce SSL connection' must be turned on for MySQL" if {
	some server in input.mysql.servers
	not server.ssl_enforcement_enabled
}

# ---------------------------------------------------------------------------
# Section 5 - Logging and Monitoring (L2)
# ---------------------------------------------------------------------------

violations contains "CIS L2 5.1.1: checked condition — audit profile captures all activities" if {
	not input.monitor.audit_profile.captures_all_categories
}

violations contains "CIS L2 5.1.2: required value of diagnostic logging retention policy is 365 days or more" if {
	input.monitor.log_retention_days < 365
}

violations contains "CIS L2 5.2.1: checked condition — activity log alert exists for Create Policy Assignment" if {
	not input.monitor.alerts.create_policy_assignment
}

violations contains "CIS L2 5.2.2: checked condition — activity log alert exists for Delete Policy Assignment" if {
	not input.monitor.alerts.delete_policy_assignment
}

violations contains "CIS L2 5.2.4: checked condition — activity log alert exists for Create or Update Network Security Group" if {
	not input.monitor.alerts.create_update_nsg
}

violations contains "CIS L2 5.2.5: checked condition — activity log alert exists for Delete Network Security Group" if {
	not input.monitor.alerts.delete_nsg
}

violations contains "CIS L2 5.2.7: checked condition — activity log alert exists for Create or Update Security Solution" if {
	not input.monitor.alerts.create_update_security_solution
}

# ---------------------------------------------------------------------------
# Section 6 - Networking (L2)
# ---------------------------------------------------------------------------

violations contains "CIS L2 6.3: required value of Network Watcher is 'Enabled'" if {
	some region in input.network.regions_without_network_watcher
	region != ""
}

violations contains "CIS L2 6.4: Network Security Group Flow Log retention must be greater than 90 days" if {
	some nsg in input.network.nsgs
	nsg.flow_log_retention_days < 90
}

violations contains "CIS L2 6.5: Network Security Group Flow logs must be captured and sent to Log Analytics" if {
	some nsg in input.network.nsgs
	not nsg.flow_logs_sent_to_log_analytics
}

# ---------------------------------------------------------------------------
# Section 7 - Virtual Machines (L2)
# ---------------------------------------------------------------------------

violations contains "CIS L2 7.1: Virtual Machines must be utilizing Managed Disks" if {
	some vm in input.compute.virtual_machines
	not vm.uses_managed_disks
}

violations contains "CIS L2 7.2: 'OS disk' must be encrypted with Customer Managed Key (CMK)" if {
	some vm in input.compute.virtual_machines
	not vm.os_disk_cmk_encrypted
}

violations contains "CIS L2 7.3: 'Data disks' must be encrypted with Customer Managed Key (CMK)" if {
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
