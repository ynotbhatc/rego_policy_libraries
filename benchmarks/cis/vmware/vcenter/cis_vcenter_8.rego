package cis_vcenter_8

import rego.v1

default compliant := false

violations := array.concat(
	vcenter_server_violations,
	array.concat(
		sso_violations,
		array.concat(
			vsphere_client_violations,
			array.concat(
				inventory_service_violations,
				array.concat(
					lookup_service_violations,
					array.concat(
						postgresql_violations,
						array.concat(
							photon_os_violations,
							performance_charts_violations
						)
					)
				)
			)
		)
	)
)

compliant if {
	count(violations) == 0
}

vcenter_server_violations := [msg |
	msgs := [
		{"msg": "1.1 Ensure vCenter Server service account is configured correctly", "condition": vcenter_service_account_secure},
		{"msg": "1.2 Ensure vCenter Server logging is configured appropriately", "condition": vcenter_logging_configured},
		{"msg": "1.3 Ensure vCenter Server session timeout is configured", "condition": vcenter_session_timeout_configured},
		{"msg": "1.4 Ensure vCenter Server password policies are enforced", "condition": vcenter_password_policy_enforced},
		{"msg": "1.5 Ensure vCenter Server SSL certificates are properly configured", "condition": vcenter_ssl_certificates_secure},
		{"msg": "1.6 Ensure vCenter Server network security is properly configured", "condition": vcenter_network_security_configured},
		{"msg": "1.7 Ensure vCenter Server backup and recovery procedures are in place", "condition": vcenter_backup_procedures_configured},
		{"msg": "1.8 Ensure vCenter Server database security is properly configured", "condition": vcenter_database_security_configured},
		{"msg": "1.9 Ensure vCenter Server access control is properly configured", "condition": vcenter_access_control_configured},
		{"msg": "1.10 Ensure vCenter Server audit logging is enabled", "condition": vcenter_audit_logging_enabled},
		{"msg": "1.11 Ensure vCenter Server management interfaces are secured", "condition": vcenter_management_interfaces_secured},
		{"msg": "1.12 Ensure vCenter Server time synchronization is configured", "condition": vcenter_time_sync_configured},
		{"msg": "1.13 Ensure vCenter Server SNMP is configured securely", "condition": vcenter_snmp_secure},
		{"msg": "1.14 Ensure vCenter Server performance monitoring is secured", "condition": vcenter_performance_monitoring_secure},
		{"msg": "1.15 Ensure vCenter Server update and patch management is configured", "condition": vcenter_patch_management_configured},
		{"msg": "1.16 Ensure vCenter Server high availability is properly configured", "condition": vcenter_ha_configured},
		{"msg": "1.17 Ensure vCenter Server disaster recovery is configured", "condition": vcenter_dr_configured},
		{"msg": "1.18 Ensure vCenter Server inventory management is secured", "condition": vcenter_inventory_management_secure},
		{"msg": "1.19 Ensure vCenter Server API access is properly secured", "condition": vcenter_api_access_secure},
		{"msg": "1.20 Ensure vCenter Server licensing is properly managed", "condition": vcenter_licensing_managed}
	]
	m := msgs[_]
	not m.condition
	msg := m.msg
]

sso_violations := [msg |
	msgs := [
		{"msg": "2.1 Ensure SSO password policy is configured securely", "condition": sso_password_policy_secure},
		{"msg": "2.2 Ensure SSO lockout policy is configured appropriately", "condition": sso_lockout_policy_configured},
		{"msg": "2.3 Ensure SSO identity sources are configured securely", "condition": sso_identity_sources_secure},
		{"msg": "2.4 Ensure SSO token policy is configured appropriately", "condition": sso_token_policy_configured},
		{"msg": "2.5 Ensure SSO certificate management is secure", "condition": sso_certificate_management_secure},
		{"msg": "2.6 Ensure SSO domain join operations are secured", "condition": sso_domain_join_secure},
		{"msg": "2.7 Ensure SSO service accounts have minimal privileges", "condition": sso_service_accounts_minimal_privileges},
		{"msg": "2.8 Ensure SSO audit logging is enabled and configured", "condition": sso_audit_logging_enabled},
		{"msg": "2.9 Ensure SSO global permissions are reviewed and minimized", "condition": sso_global_permissions_minimized},
		{"msg": "2.10 Ensure SSO solution user certificates are managed properly", "condition": sso_solution_user_certs_managed},
		{"msg": "2.11 Ensure SSO IdP discovery is configured securely", "condition": sso_idp_discovery_secure},
		{"msg": "2.12 Ensure SSO smart card authentication is configured properly", "condition": sso_smart_card_auth_configured}
	]
	m := msgs[_]
	not m.condition
	msg := m.msg
]

vsphere_client_violations := [msg |
	msgs := [
		{"msg": "3.1 Ensure vSphere Client session timeout is configured", "condition": vsphere_client_session_timeout_configured},
		{"msg": "3.2 Ensure vSphere Client SSL/TLS configuration is secure", "condition": vsphere_client_ssl_secure},
		{"msg": "3.3 Ensure vSphere Client access logging is enabled", "condition": vsphere_client_access_logging_enabled},
		{"msg": "3.4 Ensure vSphere Client plugin security is configured", "condition": vsphere_client_plugin_security_configured},
		{"msg": "3.5 Ensure vSphere Client content security policy is configured", "condition": vsphere_client_csp_configured},
		{"msg": "3.6 Ensure vSphere Client HTTP security headers are configured", "condition": vsphere_client_security_headers_configured},
		{"msg": "3.7 Ensure vSphere Client authentication mechanisms are secure", "condition": vsphere_client_auth_secure},
		{"msg": "3.8 Ensure vSphere Client cookie security is configured", "condition": vsphere_client_cookie_security_configured}
	]
	m := msgs[_]
	not m.condition
	msg := m.msg
]

inventory_service_violations := [msg |
	msgs := [
		{"msg": "4.1 Ensure Inventory Service logging is configured appropriately", "condition": inventory_service_logging_configured},
		{"msg": "4.2 Ensure Inventory Service access controls are properly configured", "condition": inventory_service_access_controls_configured},
		{"msg": "4.3 Ensure Inventory Service SSL/TLS configuration is secure", "condition": inventory_service_ssl_secure},
		{"msg": "4.4 Ensure Inventory Service database connections are secured", "condition": inventory_service_database_secure},
		{"msg": "4.5 Ensure Inventory Service performance monitoring is configured", "condition": inventory_service_performance_monitoring_configured},
		{"msg": "4.6 Ensure Inventory Service backup procedures are in place", "condition": inventory_service_backup_configured}
	]
	m := msgs[_]
	not m.condition
	msg := m.msg
]

lookup_service_violations := [msg |
	msgs := [
		{"msg": "5.1 Ensure Lookup Service SSL/TLS configuration is secure", "condition": lookup_service_ssl_secure},
		{"msg": "5.2 Ensure Lookup Service logging is configured appropriately", "condition": lookup_service_logging_configured},
		{"msg": "5.3 Ensure Lookup Service registration security is configured", "condition": lookup_service_registration_secure},
		{"msg": "5.4 Ensure Lookup Service access controls are properly configured", "condition": lookup_service_access_controls_configured},
		{"msg": "5.5 Ensure Lookup Service endpoint security is configured", "condition": lookup_service_endpoint_security_configured}
	]
	m := msgs[_]
	not m.condition
	msg := m.msg
]

postgresql_violations := [msg |
	msgs := [
		{"msg": "6.1 Ensure PostgreSQL authentication is configured securely", "condition": postgresql_auth_secure},
		{"msg": "6.2 Ensure PostgreSQL logging is configured appropriately", "condition": postgresql_logging_configured},
		{"msg": "6.3 Ensure PostgreSQL connection security is configured", "condition": postgresql_connection_security_configured},
		{"msg": "6.4 Ensure PostgreSQL access controls are properly configured", "condition": postgresql_access_controls_configured},
		{"msg": "6.5 Ensure PostgreSQL SSL/TLS configuration is secure", "condition": postgresql_ssl_secure},
		{"msg": "6.6 Ensure PostgreSQL backup and recovery procedures are in place", "condition": postgresql_backup_configured},
		{"msg": "6.7 Ensure PostgreSQL performance monitoring is configured", "condition": postgresql_performance_monitoring_configured},
		{"msg": "6.8 Ensure PostgreSQL audit logging is enabled", "condition": postgresql_audit_logging_enabled}
	]
	m := msgs[_]
	not m.condition
	msg := m.msg
]

photon_os_violations := [msg |
	msgs := [
		{"msg": "7.1 Ensure Photon OS firewall is configured appropriately", "condition": photon_firewall_configured},
		{"msg": "7.2 Ensure Photon OS system logging is configured", "condition": photon_logging_configured},
		{"msg": "7.3 Ensure Photon OS access controls are properly configured", "condition": photon_access_controls_configured},
		{"msg": "7.4 Ensure Photon OS network security is configured", "condition": photon_network_security_configured},
		{"msg": "7.5 Ensure Photon OS time synchronization is configured", "condition": photon_time_sync_configured},
		{"msg": "7.6 Ensure Photon OS package management is secure", "condition": photon_package_management_secure},
		{"msg": "7.7 Ensure Photon OS user account security is configured", "condition": photon_user_account_security_configured},
		{"msg": "7.8 Ensure Photon OS audit logging is enabled", "condition": photon_audit_logging_enabled},
		{"msg": "7.9 Ensure Photon OS kernel security parameters are configured", "condition": photon_kernel_security_configured},
		{"msg": "7.10 Ensure Photon OS filesystem security is configured", "condition": photon_filesystem_security_configured}
	]
	m := msgs[_]
	not m.condition
	msg := m.msg
]

performance_charts_violations := [msg |
	msgs := [
		{"msg": "8.1 Ensure Performance Charts service logging is configured", "condition": performance_charts_logging_configured},
		{"msg": "8.2 Ensure Performance Charts service SSL/TLS is configured securely", "condition": performance_charts_ssl_secure},
		{"msg": "8.3 Ensure Performance Charts service access controls are configured", "condition": performance_charts_access_controls_configured},
		{"msg": "8.4 Ensure Performance Charts service database security is configured", "condition": performance_charts_database_secure}
	]
	m := msgs[_]
	not m.condition
	msg := m.msg
]

# vCenter Server Security Controls
vcenter_service_account_secure if {
	input.vcenter.service_account.name != "root"
	input.vcenter.service_account.privileges_minimal == true
}

vcenter_logging_configured if {
	input.vcenter.logging.enabled == true
	input.vcenter.logging.level in ["info", "warn", "error"]
	input.vcenter.logging.rotation_enabled == true
}

vcenter_session_timeout_configured if {
	input.vcenter.session.timeout_minutes <= 30
	input.vcenter.session.timeout_minutes > 0
}

vcenter_password_policy_enforced if {
	policy := input.vcenter.password_policy
	policy.min_length >= 8
	policy.complexity_required == true
	policy.max_age_days <= 90
}

vcenter_ssl_certificates_secure if {
	ssl := input.vcenter.ssl
	ssl.certificate_valid == true
	ssl.certificate_not_expired == true
	ssl.strong_cipher_suites == true
	ssl.weak_protocols_disabled == true
}

vcenter_network_security_configured if {
	network := input.vcenter.network
	network.firewall_enabled == true
	network.unnecessary_services_disabled == true
	network.secure_protocols_only == true
}

vcenter_backup_procedures_configured if {
	backup := input.vcenter.backup
	backup.scheduled == true
	backup.tested_regularly == true
	backup.secure_storage == true
}

vcenter_database_security_configured if {
	db := input.vcenter.database
	db.authentication_secure == true
	db.encryption_enabled == true
	db.access_controls_configured == true
}

vcenter_access_control_configured if {
	access := input.vcenter.access_control
	access.rbac_enabled == true
	access.least_privilege == true
	access.regular_review == true
}

vcenter_audit_logging_enabled if {
	audit := input.vcenter.audit
	audit.enabled == true
	audit.comprehensive_coverage == true
	audit.log_retention_configured == true
}

vcenter_management_interfaces_secured if {
	mgmt := input.vcenter.management_interfaces
	mgmt.ssh_disabled == true
	mgmt.console_access_restricted == true
	mgmt.remote_access_secured == true
}

vcenter_time_sync_configured if {
	time := input.vcenter.time_sync
	time.ntp_enabled == true
	time.secure_time_sources == true
}

vcenter_snmp_secure if {
	snmp := input.vcenter.snmp
	snmp.v3_only == true
	snmp.community_strings_secure == true
}

vcenter_performance_monitoring_secure if {
	performance := input.vcenter.performance_monitoring
	performance.secure_access == true
	performance.data_retention_configured == true
}

vcenter_patch_management_configured if {
	patch := input.vcenter.patch_management
	patch.automated_updates == true
	patch.testing_procedures == true
}

vcenter_ha_configured if {
	ha := input.vcenter.high_availability
	ha.enabled == true
	ha.properly_configured == true
}

vcenter_dr_configured if {
	dr := input.vcenter.disaster_recovery
	dr.procedures_documented == true
	dr.tested_regularly == true
}

vcenter_inventory_management_secure if {
	inventory := input.vcenter.inventory_management
	inventory.access_controlled == true
	inventory.changes_audited == true
}

vcenter_api_access_secure if {
	api := input.vcenter.api_access
	api.authentication_required == true
	api.authorization_enforced == true
	api.rate_limiting_enabled == true
}

vcenter_licensing_managed if {
	licensing := input.vcenter.licensing
	licensing.properly_configured == true
	licensing.compliance_monitored == true
}

# SSO Security Controls
sso_password_policy_secure if {
	policy := input.vcenter.sso.password_policy
	policy.min_length >= 8
	policy.complexity_required == true
	policy.max_age_days <= 90
	policy.lockout_threshold <= 5
}

sso_lockout_policy_configured if {
	lockout := input.vcenter.sso.lockout_policy
	lockout.failed_attempts_threshold <= 5
	lockout.lockout_duration_minutes >= 15
}

sso_identity_sources_secure if {
	sources := input.vcenter.sso.identity_sources
	sources.secure_connections == true
	sources.certificate_validation == true
}

sso_token_policy_configured if {
	token := input.vcenter.sso.token_policy
	token.max_lifetime_hours <= 24
	token.renewal_count_limited == true
}

sso_certificate_management_secure if {
	certs := input.vcenter.sso.certificates
	certs.valid == true
	certs.not_expired == true
	certs.strong_key_length == true
}

sso_domain_join_secure if {
	domain := input.vcenter.sso.domain_join
	domain.secure_protocols == true
	domain.service_account_minimal_privileges == true
}

sso_service_accounts_minimal_privileges if {
	accounts := input.vcenter.sso.service_accounts
	accounts.minimal_privileges == true
	accounts.regular_review == true
}

sso_audit_logging_enabled if {
	audit := input.vcenter.sso.audit_logging
	audit.enabled == true
	audit.comprehensive_events == true
}

sso_global_permissions_minimized if {
	permissions := input.vcenter.sso.global_permissions
	permissions.minimized == true
	permissions.regularly_reviewed == true
}

sso_solution_user_certs_managed if {
	solution_users := input.vcenter.sso.solution_users
	solution_users.certificates_managed == true
	solution_users.rotation_scheduled == true
}

sso_idp_discovery_secure if {
	idp := input.vcenter.sso.idp_discovery
	idp.secure_configuration == true
}

sso_smart_card_auth_configured if {
	smart_card := input.vcenter.sso.smart_card_auth
	smart_card.properly_configured == true
}

# vSphere Client Security Controls
vsphere_client_session_timeout_configured if {
	client := input.vcenter.vsphere_client
	client.session_timeout_minutes <= 30
	client.session_timeout_minutes > 0
}

vsphere_client_ssl_secure if {
	ssl := input.vcenter.vsphere_client.ssl
	ssl.strong_protocols_only == true
	ssl.strong_cipher_suites == true
}

vsphere_client_access_logging_enabled if {
	logging := input.vcenter.vsphere_client.logging
	logging.access_logs_enabled == true
	logging.error_logs_enabled == true
}

vsphere_client_plugin_security_configured if {
	plugins := input.vcenter.vsphere_client.plugins
	plugins.security_validated == true
	plugins.unauthorized_disabled == true
}

vsphere_client_csp_configured if {
	csp := input.vcenter.vsphere_client.content_security_policy
	csp.enabled == true
	csp.properly_configured == true
}

vsphere_client_security_headers_configured if {
	headers := input.vcenter.vsphere_client.security_headers
	headers.hsts_enabled == true
	headers.xss_protection_enabled == true
	headers.content_type_nosniff_enabled == true
}

vsphere_client_auth_secure if {
	auth := input.vcenter.vsphere_client.authentication
	auth.strong_mechanisms == true
	auth.multi_factor_supported == true
}

vsphere_client_cookie_security_configured if {
	cookies := input.vcenter.vsphere_client.cookies
	cookies.secure_flag == true
	cookies.httponly_flag == true
}

# Inventory Service Security Controls
inventory_service_logging_configured if {
	logging := input.vcenter.inventory_service.logging
	logging.enabled == true
	logging.appropriate_level == true
}

inventory_service_access_controls_configured if {
	access := input.vcenter.inventory_service.access_controls
	access.authentication_required == true
	access.authorization_enforced == true
}

inventory_service_ssl_secure if {
	ssl := input.vcenter.inventory_service.ssl
	ssl.enabled == true
	ssl.strong_configuration == true
}

inventory_service_database_secure if {
	db := input.vcenter.inventory_service.database
	db.secure_connections == true
	db.access_controls == true
}

inventory_service_performance_monitoring_configured if {
	monitoring := input.vcenter.inventory_service.performance_monitoring
	monitoring.enabled == true
	monitoring.secure_access == true
}

inventory_service_backup_configured if {
	backup := input.vcenter.inventory_service.backup
	backup.scheduled == true
	backup.tested == true
}

# Lookup Service Security Controls
lookup_service_ssl_secure if {
	ssl := input.vcenter.lookup_service.ssl
	ssl.enabled == true
	ssl.strong_configuration == true
}

lookup_service_logging_configured if {
	logging := input.vcenter.lookup_service.logging
	logging.enabled == true
	logging.appropriate_level == true
}

lookup_service_registration_secure if {
	registration := input.vcenter.lookup_service.registration
	registration.secure_protocols == true
	registration.authentication_required == true
}

lookup_service_access_controls_configured if {
	access := input.vcenter.lookup_service.access_controls
	access.properly_configured == true
}

lookup_service_endpoint_security_configured if {
	endpoints := input.vcenter.lookup_service.endpoints
	endpoints.secure_configuration == true
}

# PostgreSQL Security Controls
postgresql_auth_secure if {
	auth := input.vcenter.postgresql.authentication
	auth.strong_mechanisms == true
	auth.no_trust_authentication == true
}

postgresql_logging_configured if {
	logging := input.vcenter.postgresql.logging
	logging.enabled == true
	logging.comprehensive == true
}

postgresql_connection_security_configured if {
	connections := input.vcenter.postgresql.connections
	connections.ssl_required == true
	connections.limits_configured == true
}

postgresql_access_controls_configured if {
	access := input.vcenter.postgresql.access_controls
	access.role_based == true
	access.least_privilege == true
}

postgresql_ssl_secure if {
	ssl := input.vcenter.postgresql.ssl
	ssl.enabled == true
	ssl.strong_configuration == true
}

postgresql_backup_configured if {
	backup := input.vcenter.postgresql.backup
	backup.automated == true
	backup.tested == true
}

postgresql_performance_monitoring_configured if {
	monitoring := input.vcenter.postgresql.performance_monitoring
	monitoring.enabled == true
}

postgresql_audit_logging_enabled if {
	audit := input.vcenter.postgresql.audit_logging
	audit.enabled == true
}

# Photon OS Security Controls
photon_firewall_configured if {
	firewall := input.vcenter.photon_os.firewall
	firewall.enabled == true
	firewall.rules_configured == true
}

photon_logging_configured if {
	logging := input.vcenter.photon_os.logging
	logging.centralized == true
	logging.secure_transport == true
}

photon_access_controls_configured if {
	access := input.vcenter.photon_os.access_controls
	access.sudo_configured == true
	access.unnecessary_accounts_removed == true
}

photon_network_security_configured if {
	network := input.vcenter.photon_os.network_security
	network.secure_protocols == true
	network.unnecessary_services_disabled == true
}

photon_time_sync_configured if {
	time := input.vcenter.photon_os.time_sync
	time.ntp_enabled == true
	time.secure_servers == true
}

photon_package_management_secure if {
	packages := input.vcenter.photon_os.package_management
	packages.signed_only == true
	packages.updates_automated == true
}

photon_user_account_security_configured if {
	users := input.vcenter.photon_os.user_accounts
	users.strong_passwords == true
	users.unnecessary_accounts_removed == true
}

photon_audit_logging_enabled if {
	audit := input.vcenter.photon_os.audit_logging
	audit.enabled == true
	audit.comprehensive == true
}

photon_kernel_security_configured if {
	kernel := input.vcenter.photon_os.kernel_security
	kernel.hardening_enabled == true
	kernel.modules_restricted == true
}

photon_filesystem_security_configured if {
	filesystem := input.vcenter.photon_os.filesystem_security
	filesystem.permissions_secure == true
	filesystem.mount_options_secure == true
}

# Performance Charts Security Controls
performance_charts_logging_configured if {
	logging := input.vcenter.performance_charts.logging
	logging.enabled == true
	logging.appropriate_level == true
}

performance_charts_ssl_secure if {
	ssl := input.vcenter.performance_charts.ssl
	ssl.enabled == true
	ssl.strong_configuration == true
}

performance_charts_access_controls_configured if {
	access := input.vcenter.performance_charts.access_controls
	access.authentication_required == true
	access.authorization_enforced == true
}

performance_charts_database_secure if {
	db := input.vcenter.performance_charts.database
	db.secure_connections == true
	db.access_restricted == true
}

findings := [{
	"title": "VMware vCenter Server 8.0 Security Configuration Assessment",
	"description": "Comprehensive security assessment of VMware vCenter Server 8.0 including vCenter Server, SSO, vSphere Client, Inventory Service, Lookup Service, PostgreSQL, Photon OS, and Performance Charts components",
	"severity": "HIGH",
	"details": sprintf("Found %d configuration violations across vCenter security domains", [count(violations)]),
	"violations": violations,
	"remediation": "Review and implement the recommended VMware vCenter security configurations including proper service account management, SSL/TLS hardening, authentication and authorization controls, comprehensive logging and monitoring, database security, operating system hardening, and performance monitoring security"
}]