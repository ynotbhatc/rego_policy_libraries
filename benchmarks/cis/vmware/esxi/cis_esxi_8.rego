# METADATA
# title: "Cis Esxi 8"
# custom:
#   class: security
#   framework: cis_vmware
#   source: cis
#   domains: [virtualization, vmware]
#   coverage:
#     checks: 96
#     cited: 96
#     density: sized
#     basis: size
#     tested: true
#     entrypoint: none
#     guard: self
#     as_of: v2.4.2
package cis_esxi_8

import rego.v1

default compliant := false

violations := array.concat(
	host_configuration_violations,
	array.concat(
		network_security_violations,
		array.concat(
			storage_security_violations,
			array.concat(
				vm_security_violations,
				array.concat(
					access_control_violations,
					array.concat(
						logging_audit_violations,
						array.concat(
							system_hardening_violations,
							compliance_monitoring_violations,
						),
					),
				),
			),
		),
	),
)

compliant if {
	# fail-closed: no facts, no compliance
	input.esxi
	count(violations) == 0
}

host_configuration_violations := [msg |
	msgs := [
		{"msg": "1.1 ESXi host must be explicitly configured with appropriate time synchronization", "condition": host_time_sync_configured},
		{"msg": "1.2 ESXi host SSH service must be explicitly configured securely", "condition": host_ssh_service_secure},
		{"msg": "1.3 ESXi host firewall must be explicitly configured appropriately", "condition": host_firewall_configured},
		{"msg": "1.4 ESXi host certificate management must be explicitly configured securely", "condition": host_certificate_management_secure},
		{"msg": "1.5 ESXi host password policies must be enforced", "condition": host_password_policies_enforced},
		{"msg": "1.6 ESXi host account lockout policies must be explicitly configured", "condition": host_account_lockout_configured},
		{"msg": "1.7 ESXi host session timeout must be explicitly configured appropriately", "condition": host_session_timeout_configured},
		{"msg": "1.8 ESXi host console access must be properly secured", "condition": host_console_access_secured},
		{"msg": "1.9 ESXi host SNMP configuration must be secure", "condition": host_snmp_configuration_secure},
		{"msg": "1.10 ESXi host syslog must be explicitly configured appropriately", "condition": host_syslog_configured},
		{"msg": "1.11 ESXi host kernel modules must be restricted", "condition": host_kernel_modules_restricted},
		{"msg": "1.12 ESXi host hypervisor scheduler must be explicitly configured securely", "condition": host_hypervisor_scheduler_secure},
		{"msg": "1.13 ESXi host memory management must be explicitly configured securely", "condition": host_memory_management_secure},
		{"msg": "1.14 ESXi host CPU resource management must be explicitly configured", "condition": host_cpu_management_configured},
		{"msg": "1.15 ESXi host power management must be explicitly configured appropriately", "condition": host_power_management_configured},
		{"msg": "1.16 ESXi host hardware monitoring must be explicitly configured", "condition": host_hardware_monitoring_configured},
		{"msg": "1.17 ESXi host update and patch management must be explicitly configured", "condition": host_patch_management_configured},
		{"msg": "1.18 ESXi host backup and recovery procedures must be in place", "condition": host_backup_procedures_configured},
		{"msg": "1.19 ESXi host disaster recovery must be explicitly configured", "condition": host_disaster_recovery_configured},
		{"msg": "1.20 ESXi host compliance monitoring must be turned on", "condition": host_compliance_monitoring_enabled},
	]
	m := msgs[_]
	not m.condition
	msg := m.msg
]

network_security_violations := [msg |
	msgs := [
		{"msg": "2.1 network redundancy must be explicitly configured for critical traffic", "condition": network_redundancy_configured},
		{"msg": "2.2 network security policies must be implemented", "condition": network_security_policies_implemented},
		{"msg": "2.3 checked condition — VLAN configuration follows security best practices", "condition": vlan_configuration_secure},
		{"msg": "2.4 virtual switch security policies must be explicitly configured", "condition": vswitch_security_policies_configured},
		{"msg": "2.5 port group security policies must be explicitly configured", "condition": portgroup_security_policies_configured},
		{"msg": "2.6 network I/O control must be explicitly configured appropriately", "condition": network_io_control_configured},
		{"msg": "2.7 network traffic shaping must be explicitly configured", "condition": network_traffic_shaping_configured},
		{"msg": "2.8 network security and monitoring must be explicitly configured", "condition": network_security_monitoring_configured},
		{"msg": "2.9 network access control must match the approved configuration", "condition": network_access_control_configured},
		{"msg": "2.10 network encryption must be turned on where appropriate", "condition": network_encryption_enabled},
		{"msg": "2.11 network segmentation must be properly implemented", "condition": network_segmentation_implemented},
		{"msg": "2.12 virtual networking security features must be turned on", "condition": virtual_networking_security_enabled},
		{"msg": "2.13 network intrusion detection must be explicitly configured", "condition": network_intrusion_detection_configured},
		{"msg": "2.14 network performance monitoring must be explicitly configured", "condition": network_performance_monitoring_configured},
	]
	m := msgs[_]
	not m.condition
	msg := m.msg
]

storage_security_violations := [msg |
	msgs := [
		{"msg": "3.1 storage access control must match the approved configuration", "condition": storage_access_control_configured},
		{"msg": "3.2 storage encryption must be turned on where appropriate", "condition": storage_encryption_enabled},
		{"msg": "3.3 storage multipathing must be explicitly configured securely", "condition": storage_multipathing_secure},
		{"msg": "3.4 storage performance monitoring must be explicitly configured", "condition": storage_performance_monitoring_configured},
		{"msg": "3.5 storage backup and recovery procedures must be in place", "condition": storage_backup_procedures_configured},
		{"msg": "3.6 storage array integration must be secure", "condition": storage_array_integration_secure},
		{"msg": "3.7 storage I/O control must be explicitly configured appropriately", "condition": storage_io_control_configured},
		{"msg": "3.8 storage security policies must be implemented", "condition": storage_security_policies_implemented},
		{"msg": "3.9 storage audit logging must be turned on", "condition": storage_audit_logging_enabled},
		{"msg": "3.10 storage compliance monitoring must be explicitly configured", "condition": storage_compliance_monitoring_configured},
	]
	m := msgs[_]
	not m.condition
	msg := m.msg
]

vm_security_violations := [msg |
	msgs := [
		{"msg": "4.1 VM configuration security must be enforced", "condition": vm_configuration_security_enforced},
		{"msg": "4.2 VM resource allocation must be properly controlled", "condition": vm_resource_allocation_controlled},
		{"msg": "4.3 VM security policies must be implemented", "condition": vm_security_policies_implemented},
		{"msg": "4.4 VM network security must be explicitly configured", "condition": vm_network_security_configured},
		{"msg": "4.5 VM storage security must be explicitly configured", "condition": vm_storage_security_configured},
		{"msg": "4.6 VM access control must match the approved configuration", "condition": vm_access_control_configured},
		{"msg": "4.7 VM monitoring and logging must be explicitly configured", "condition": vm_monitoring_logging_configured},
		{"msg": "4.8 VM backup and recovery procedures must be in place", "condition": vm_backup_procedures_configured},
		{"msg": "4.9 VM compliance monitoring must be turned on", "condition": vm_compliance_monitoring_enabled},
		{"msg": "4.10 VM security scanning must be explicitly configured", "condition": vm_security_scanning_configured},
		{"msg": "4.11 VM vulnerability management must be implemented", "condition": vm_vulnerability_management_implemented},
		{"msg": "4.12 VM patch management must be explicitly configured", "condition": vm_patch_management_configured},
		{"msg": "4.13 VM antivirus and anti-malware protection must be explicitly configured", "condition": vm_antivirus_protection_configured},
		{"msg": "4.14 VM data loss prevention must be explicitly configured", "condition": vm_data_loss_prevention_configured},
	]
	m := msgs[_]
	not m.condition
	msg := m.msg
]

access_control_violations := [msg |
	msgs := [
		{"msg": "5.1 role-based access control must be implemented", "condition": rbac_implemented},
		{"msg": "5.2 user account management must match the approved configuration", "condition": user_account_management_configured},
		{"msg": "5.3 service account management must be secure", "condition": service_account_management_secure},
		{"msg": "5.4 privileged access management must be implemented", "condition": privileged_access_management_implemented},
		{"msg": "5.5 authentication mechanisms must be secure", "condition": authentication_mechanisms_secure},
		{"msg": "5.6 authorization policies must match the approved configuration", "condition": authorization_policies_configured},
		{"msg": "5.7 access review procedures must be in place", "condition": access_review_procedures_configured},
		{"msg": "5.8 access provisioning and deprovisioning must be automated", "condition": access_provisioning_automated},
		{"msg": "5.9 access monitoring and alerting must be explicitly configured", "condition": access_monitoring_configured},
		{"msg": "5.10 emergency access procedures must be documented", "condition": emergency_access_procedures_documented},
	]
	m := msgs[_]
	not m.condition
	msg := m.msg
]

logging_audit_violations := [msg |
	msgs := [
		{"msg": "6.1 comprehensive audit logging must be turned on", "condition": comprehensive_audit_logging_enabled},
		{"msg": "6.2 log forwarding must be explicitly configured securely", "condition": log_forwarding_configured_securely},
		{"msg": "6.3 log retention policies must be implemented", "condition": log_retention_policies_implemented},
		{"msg": "6.4 log monitoring and alerting must be explicitly configured", "condition": log_monitoring_alerting_configured},
		{"msg": "6.5 log integrity protection must be turned on", "condition": log_integrity_protection_enabled},
		{"msg": "6.6 security event correlation must be explicitly configured", "condition": security_event_correlation_configured},
		{"msg": "6.7 incident response procedures must be documented", "condition": incident_response_procedures_documented},
		{"msg": "6.8 forensic analysis capabilities must be available", "condition": forensic_analysis_capabilities_available},
		{"msg": "6.9 compliance reporting must be automated", "condition": compliance_reporting_automated},
		{"msg": "6.10 audit trail review procedures must be in place", "condition": audit_trail_review_procedures_configured},
	]
	m := msgs[_]
	not m.condition
	msg := m.msg
]

system_hardening_violations := [msg |
	msgs := [
		{"msg": "7.1 system hardening standards must be applied", "condition": system_hardening_standards_applied},
		{"msg": "7.2 security patches must be applied timely", "condition": security_patches_applied_timely},
		{"msg": "7.3 vulnerability scanning must be explicitly configured", "condition": vulnerability_scanning_configured},
		{"msg": "7.4 penetration testing must be performed regularly", "condition": penetration_testing_performed_regularly},
		{"msg": "7.5 security baseline compliance must be monitored", "condition": security_baseline_compliance_monitored},
		{"msg": "7.6 configuration drift detection must be turned on", "condition": configuration_drift_detection_enabled},
		{"msg": "7.7 security automation must be implemented", "condition": security_automation_implemented},
		{"msg": "7.8 threat intelligence integration must be explicitly configured", "condition": threat_intelligence_integration_configured},
		{"msg": "7.9 security metrics and KPIs must be tracked", "condition": security_metrics_kpis_tracked},
		{"msg": "7.10 continuous security improvement processes must be in place", "condition": continuous_security_improvement_processes_configured},
	]
	m := msgs[_]
	not m.condition
	msg := m.msg
]

compliance_monitoring_violations := [msg |
	msgs := [
		{"msg": "8.1 compliance framework alignment must be documented", "condition": compliance_framework_alignment_documented},
		{"msg": "8.2 regulatory compliance monitoring must be explicitly configured", "condition": regulatory_compliance_monitoring_configured},
		{"msg": "8.3 compliance reporting must be automated", "condition": compliance_reporting_automated_comprehensive},
		{"msg": "8.4 compliance audit trails must be maintained", "condition": compliance_audit_trails_maintained},
		{"msg": "8.5 compliance exception management must be implemented", "condition": compliance_exception_management_implemented},
		{"msg": "8.6 compliance training and awareness programs must be in place", "condition": compliance_training_awareness_programs_configured},
		{"msg": "8.7 compliance risk assessment must be performed regularly", "condition": compliance_risk_assessment_performed_regularly},
		{"msg": "8.8 compliance governance processes must be documented", "condition": compliance_governance_processes_documented},
	]
	m := msgs[_]
	not m.condition
	msg := m.msg
]

# Host Configuration Security Controls
default host_time_sync_configured := false

host_time_sync_configured if {
	time_sync := input.esxi.host.time_sync
	time_sync.ntp_enabled == true
	time_sync.secure_time_sources == true
}

default host_ssh_service_secure := false

host_ssh_service_secure if {
	ssh := input.esxi.host.ssh
	ssh.disabled == true
}

host_ssh_service_secure if {
	ssh := input.esxi.host.ssh
	ssh.enabled == true
	ssh.secure_configuration == true
	ssh.key_based_auth == true
	ssh.root_login_disabled == true
}

default host_firewall_configured := false

host_firewall_configured if {
	firewall := input.esxi.host.firewall
	firewall.enabled == true
	firewall.default_deny == true
	firewall.rules_reviewed == true
}

default host_certificate_management_secure := false

host_certificate_management_secure if {
	certs := input.esxi.host.certificates
	certs.valid == true
	certs.not_expired == true
	certs.ca_signed == true
}

default host_password_policies_enforced := false

host_password_policies_enforced if {
	password := input.esxi.host.password_policy
	password.complexity_required == true
	password.min_length >= 8
	password.max_age_days <= 90
}

default host_account_lockout_configured := false

host_account_lockout_configured if {
	lockout := input.esxi.host.account_lockout
	lockout.enabled == true
	lockout.threshold <= 5
	lockout.duration_minutes >= 15
}

default host_session_timeout_configured := false

host_session_timeout_configured if {
	session := input.esxi.host.session
	session.timeout_minutes <= 30
	session.timeout_minutes > 0
}

default host_console_access_secured := false

host_console_access_secured if {
	console := input.esxi.host.console_access
	console.restricted == true
	console.timeout_configured == true
}

default host_snmp_configuration_secure := false

host_snmp_configuration_secure if {
	snmp := input.esxi.host.snmp
	snmp.v3_only == true
	snmp.community_strings_removed == true
}

default host_syslog_configured := false

host_syslog_configured if {
	syslog := input.esxi.host.syslog
	syslog.enabled == true
	syslog.remote_logging == true
	syslog.secure_transport == true
}

default host_kernel_modules_restricted := false

host_kernel_modules_restricted if {
	kernel := input.esxi.host.kernel_modules
	kernel.unauthorized_modules_blocked == true
	kernel.module_loading_restricted == true
}

default host_hypervisor_scheduler_secure := false

host_hypervisor_scheduler_secure if {
	scheduler := input.esxi.host.hypervisor_scheduler
	scheduler.secure_configuration == true
}

default host_memory_management_secure := false

host_memory_management_secure if {
	memory := input.esxi.host.memory_management
	memory.secure_configuration == true
	memory.isolation_enabled == true
}

default host_cpu_management_configured := false

host_cpu_management_configured if {
	cpu := input.esxi.host.cpu_management
	cpu.resource_allocation_controlled == true
	cpu.hyperthreading_configured_securely == true
}

default host_power_management_configured := false

host_power_management_configured if {
	power := input.esxi.host.power_management
	power.appropriate_policy == true
}

default host_hardware_monitoring_configured := false

host_hardware_monitoring_configured if {
	hardware := input.esxi.host.hardware_monitoring
	hardware.health_monitoring == true
	hardware.alerting_configured == true
}

default host_patch_management_configured := false

host_patch_management_configured if {
	patch := input.esxi.host.patch_management
	patch.automated_updates == true
	patch.testing_procedures == true
}

default host_backup_procedures_configured := false

host_backup_procedures_configured if {
	backup := input.esxi.host.backup_procedures
	backup.scheduled == true
	backup.tested_regularly == true
}

default host_disaster_recovery_configured := false

host_disaster_recovery_configured if {
	dr := input.esxi.host.disaster_recovery
	dr.procedures_documented == true
	dr.tested_regularly == true
}

default host_compliance_monitoring_enabled := false

host_compliance_monitoring_enabled if {
	compliance := input.esxi.host.compliance_monitoring
	compliance.enabled == true
	compliance.reporting_configured == true
}

# Network Security Controls
default network_redundancy_configured := false

network_redundancy_configured if {
	redundancy := input.esxi.network.redundancy
	redundancy.configured == true
	redundancy.critical_traffic_protected == true
}

default network_security_policies_implemented := false

network_security_policies_implemented if {
	policies := input.esxi.network.security_policies
	policies.implemented == true
	policies.regularly_reviewed == true
}

default vlan_configuration_secure := false

vlan_configuration_secure if {
	vlan := input.esxi.network.vlan
	vlan.properly_configured == true
	vlan.isolated_appropriately == true
}

default vswitch_security_policies_configured := false

vswitch_security_policies_configured if {
	vswitch := input.esxi.network.vswitch
	vswitch.security_policies_configured == true
	vswitch.promiscuous_mode_disabled == true
	vswitch.mac_address_changes_rejected == true
	vswitch.forged_transmits_rejected == true
}

default portgroup_security_policies_configured := false

portgroup_security_policies_configured if {
	portgroup := input.esxi.network.portgroup
	portgroup.security_policies_configured == true
	portgroup.access_controls_implemented == true
}

default network_io_control_configured := false

network_io_control_configured if {
	io_control := input.esxi.network.io_control
	io_control.enabled == true
	io_control.properly_configured == true
}

default network_traffic_shaping_configured := false

network_traffic_shaping_configured if {
	traffic_shaping := input.esxi.network.traffic_shaping
	traffic_shaping.configured == true
}

default network_security_monitoring_configured := false

network_security_monitoring_configured if {
	monitoring := input.esxi.network.security_monitoring
	monitoring.enabled == true
	monitoring.alerting_configured == true
}

default network_access_control_configured := false

network_access_control_configured if {
	access_control := input.esxi.network.access_control
	access_control.implemented == true
	access_control.regularly_reviewed == true
}

default network_encryption_enabled := false

network_encryption_enabled if {
	encryption := input.esxi.network.encryption
	encryption.enabled_where_appropriate == true
}

default network_segmentation_implemented := false

network_segmentation_implemented if {
	segmentation := input.esxi.network.segmentation
	segmentation.properly_implemented == true
}

default virtual_networking_security_enabled := false

virtual_networking_security_enabled if {
	virtual_security := input.esxi.network.virtual_security
	virtual_security.features_enabled == true
}

default network_intrusion_detection_configured := false

network_intrusion_detection_configured if {
	ids := input.esxi.network.intrusion_detection
	ids.configured == true
}

default network_performance_monitoring_configured := false

network_performance_monitoring_configured if {
	performance := input.esxi.network.performance_monitoring
	performance.configured == true
}

# Storage Security Controls
default storage_access_control_configured := false

storage_access_control_configured if {
	access_control := input.esxi.storage.access_control
	access_control.properly_configured == true
	access_control.regularly_reviewed == true
}

default storage_encryption_enabled := false

storage_encryption_enabled if {
	encryption := input.esxi.storage.encryption
	encryption.enabled_where_appropriate == true
}

default storage_multipathing_secure := false

storage_multipathing_secure if {
	multipathing := input.esxi.storage.multipathing
	multipathing.configured_securely == true
}

default storage_performance_monitoring_configured := false

storage_performance_monitoring_configured if {
	performance := input.esxi.storage.performance_monitoring
	performance.configured == true
}

default storage_backup_procedures_configured := false

storage_backup_procedures_configured if {
	backup := input.esxi.storage.backup_procedures
	backup.in_place == true
	backup.tested_regularly == true
}

default storage_array_integration_secure := false

storage_array_integration_secure if {
	array_integration := input.esxi.storage.array_integration
	array_integration.secure == true
}

default storage_io_control_configured := false

storage_io_control_configured if {
	io_control := input.esxi.storage.io_control
	io_control.configured_appropriately == true
}

default storage_security_policies_implemented := false

storage_security_policies_implemented if {
	policies := input.esxi.storage.security_policies
	policies.implemented == true
}

default storage_audit_logging_enabled := false

storage_audit_logging_enabled if {
	audit := input.esxi.storage.audit_logging
	audit.enabled == true
}

default storage_compliance_monitoring_configured := false

storage_compliance_monitoring_configured if {
	compliance := input.esxi.storage.compliance_monitoring
	compliance.configured == true
}

# VM Security Controls
default vm_configuration_security_enforced := false

vm_configuration_security_enforced if {
	vm_config := input.esxi.vm.configuration_security
	vm_config.enforced == true
}

default vm_resource_allocation_controlled := false

vm_resource_allocation_controlled if {
	resource_allocation := input.esxi.vm.resource_allocation
	resource_allocation.properly_controlled == true
}

default vm_security_policies_implemented := false

vm_security_policies_implemented if {
	policies := input.esxi.vm.security_policies
	policies.implemented == true
}

default vm_network_security_configured := false

vm_network_security_configured if {
	network_security := input.esxi.vm.network_security
	network_security.configured == true
}

default vm_storage_security_configured := false

vm_storage_security_configured if {
	storage_security := input.esxi.vm.storage_security
	storage_security.configured == true
}

default vm_access_control_configured := false

vm_access_control_configured if {
	access_control := input.esxi.vm.access_control
	access_control.properly_configured == true
}

default vm_monitoring_logging_configured := false

vm_monitoring_logging_configured if {
	monitoring := input.esxi.vm.monitoring_logging
	monitoring.configured == true
}

default vm_backup_procedures_configured := false

vm_backup_procedures_configured if {
	backup := input.esxi.vm.backup_procedures
	backup.in_place == true
}

default vm_compliance_monitoring_enabled := false

vm_compliance_monitoring_enabled if {
	compliance := input.esxi.vm.compliance_monitoring
	compliance.enabled == true
}

default vm_security_scanning_configured := false

vm_security_scanning_configured if {
	security_scanning := input.esxi.vm.security_scanning
	security_scanning.configured == true
}

default vm_vulnerability_management_implemented := false

vm_vulnerability_management_implemented if {
	vulnerability_mgmt := input.esxi.vm.vulnerability_management
	vulnerability_mgmt.implemented == true
}

default vm_patch_management_configured := false

vm_patch_management_configured if {
	patch_mgmt := input.esxi.vm.patch_management
	patch_mgmt.configured == true
}

default vm_antivirus_protection_configured := false

vm_antivirus_protection_configured if {
	antivirus := input.esxi.vm.antivirus_protection
	antivirus.configured == true
}

default vm_data_loss_prevention_configured := false

vm_data_loss_prevention_configured if {
	dlp := input.esxi.vm.data_loss_prevention
	dlp.configured == true
}

# Access Control Security Controls
default rbac_implemented := false

rbac_implemented if {
	rbac := input.esxi.access_control.rbac
	rbac.implemented == true
	rbac.regularly_reviewed == true
}

default user_account_management_configured := false

user_account_management_configured if {
	user_mgmt := input.esxi.access_control.user_account_management
	user_mgmt.properly_configured == true
}

default service_account_management_secure := false

service_account_management_secure if {
	service_mgmt := input.esxi.access_control.service_account_management
	service_mgmt.secure == true
}

default privileged_access_management_implemented := false

privileged_access_management_implemented if {
	pam := input.esxi.access_control.privileged_access_management
	pam.implemented == true
}

default authentication_mechanisms_secure := false

authentication_mechanisms_secure if {
	auth := input.esxi.access_control.authentication_mechanisms
	auth.secure == true
}

default authorization_policies_configured := false

authorization_policies_configured if {
	authz := input.esxi.access_control.authorization_policies
	authz.properly_configured == true
}

default access_review_procedures_configured := false

access_review_procedures_configured if {
	review := input.esxi.access_control.access_review_procedures
	review.configured == true
}

default access_provisioning_automated := false

access_provisioning_automated if {
	provisioning := input.esxi.access_control.access_provisioning
	provisioning.automated == true
}

default access_monitoring_configured := false

access_monitoring_configured if {
	monitoring := input.esxi.access_control.access_monitoring
	monitoring.configured == true
}

default emergency_access_procedures_documented := false

emergency_access_procedures_documented if {
	emergency := input.esxi.access_control.emergency_access_procedures
	emergency.documented == true
}

# Logging and Audit Security Controls
default comprehensive_audit_logging_enabled := false

comprehensive_audit_logging_enabled if {
	audit := input.esxi.logging_audit.comprehensive_audit_logging
	audit.enabled == true
}

default log_forwarding_configured_securely := false

log_forwarding_configured_securely if {
	forwarding := input.esxi.logging_audit.log_forwarding
	forwarding.configured_securely == true
}

default log_retention_policies_implemented := false

log_retention_policies_implemented if {
	retention := input.esxi.logging_audit.log_retention_policies
	retention.implemented == true
}

default log_monitoring_alerting_configured := false

log_monitoring_alerting_configured if {
	monitoring := input.esxi.logging_audit.log_monitoring_alerting
	monitoring.configured == true
}

default log_integrity_protection_enabled := false

log_integrity_protection_enabled if {
	integrity := input.esxi.logging_audit.log_integrity_protection
	integrity.enabled == true
}

default security_event_correlation_configured := false

security_event_correlation_configured if {
	correlation := input.esxi.logging_audit.security_event_correlation
	correlation.configured == true
}

default incident_response_procedures_documented := false

incident_response_procedures_documented if {
	incident_response := input.esxi.logging_audit.incident_response_procedures
	incident_response.documented == true
}

default forensic_analysis_capabilities_available := false

forensic_analysis_capabilities_available if {
	forensic := input.esxi.logging_audit.forensic_analysis_capabilities
	forensic.available == true
}

default compliance_reporting_automated := false

compliance_reporting_automated if {
	reporting := input.esxi.logging_audit.compliance_reporting
	reporting.automated == true
}

default audit_trail_review_procedures_configured := false

audit_trail_review_procedures_configured if {
	review := input.esxi.logging_audit.audit_trail_review_procedures
	review.configured == true
}

# System Hardening Security Controls
default system_hardening_standards_applied := false

system_hardening_standards_applied if {
	hardening := input.esxi.system_hardening.hardening_standards
	hardening.applied == true
}

default security_patches_applied_timely := false

security_patches_applied_timely if {
	patches := input.esxi.system_hardening.security_patches
	patches.applied_timely == true
}

default vulnerability_scanning_configured := false

vulnerability_scanning_configured if {
	vuln_scan := input.esxi.system_hardening.vulnerability_scanning
	vuln_scan.configured == true
}

default penetration_testing_performed_regularly := false

penetration_testing_performed_regularly if {
	pen_test := input.esxi.system_hardening.penetration_testing
	pen_test.performed_regularly == true
}

default security_baseline_compliance_monitored := false

security_baseline_compliance_monitored if {
	baseline := input.esxi.system_hardening.security_baseline_compliance
	baseline.monitored == true
}

default configuration_drift_detection_enabled := false

configuration_drift_detection_enabled if {
	drift := input.esxi.system_hardening.configuration_drift_detection
	drift.enabled == true
}

default security_automation_implemented := false

security_automation_implemented if {
	automation := input.esxi.system_hardening.security_automation
	automation.implemented == true
}

default threat_intelligence_integration_configured := false

threat_intelligence_integration_configured if {
	threat_intel := input.esxi.system_hardening.threat_intelligence_integration
	threat_intel.configured == true
}

default security_metrics_kpis_tracked := false

security_metrics_kpis_tracked if {
	metrics := input.esxi.system_hardening.security_metrics_kpis
	metrics.tracked == true
}

default continuous_security_improvement_processes_configured := false

continuous_security_improvement_processes_configured if {
	improvement := input.esxi.system_hardening.continuous_security_improvement_processes
	improvement.configured == true
}

# Compliance Monitoring Security Controls
default compliance_framework_alignment_documented := false

compliance_framework_alignment_documented if {
	framework := input.esxi.compliance_monitoring.compliance_framework_alignment
	framework.documented == true
}

default regulatory_compliance_monitoring_configured := false

regulatory_compliance_monitoring_configured if {
	regulatory := input.esxi.compliance_monitoring.regulatory_compliance_monitoring
	regulatory.configured == true
}

default compliance_reporting_automated_comprehensive := false

compliance_reporting_automated_comprehensive if {
	reporting := input.esxi.compliance_monitoring.compliance_reporting
	reporting.automated_comprehensive == true
}

default compliance_audit_trails_maintained := false

compliance_audit_trails_maintained if {
	audit_trails := input.esxi.compliance_monitoring.compliance_audit_trails
	audit_trails.maintained == true
}

default compliance_exception_management_implemented := false

compliance_exception_management_implemented if {
	exception_mgmt := input.esxi.compliance_monitoring.compliance_exception_management
	exception_mgmt.implemented == true
}

default compliance_training_awareness_programs_configured := false

compliance_training_awareness_programs_configured if {
	training := input.esxi.compliance_monitoring.compliance_training_awareness_programs
	training.configured == true
}

default compliance_risk_assessment_performed_regularly := false

compliance_risk_assessment_performed_regularly if {
	risk_assessment := input.esxi.compliance_monitoring.compliance_risk_assessment
	risk_assessment.performed_regularly == true
}

default compliance_governance_processes_documented := false

compliance_governance_processes_documented if {
	governance := input.esxi.compliance_monitoring.compliance_governance_processes
	governance.documented == true
}

findings := [{
	"title": "VMware ESXi 8.0 Host Security Configuration Assessment",
	"description": "Comprehensive security assessment of VMware ESXi 8.0 hypervisor including host configuration, network security, storage security, virtual machine security, access control, logging and audit, system hardening, and compliance monitoring",
	"severity": "HIGH",
	"details": sprintf("Found %d configuration violations across ESXi security domains", [count(violations)]),
	"violations": violations,
	"remediation": "Review and implement the recommended VMware ESXi security configurations including proper host hardening, network security policies, storage access controls, virtual machine security settings, comprehensive access control mechanisms, audit logging, system hardening standards, and compliance monitoring procedures",
}]
