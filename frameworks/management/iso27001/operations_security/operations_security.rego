package iso27001.operations_security

import rego.v1

# ISO 27001:2022 - A.12 Operations Security
# Technical controls for secure day-to-day IT operations

# =============================================================================
# A.12.1 - Operational Procedures and Responsibilities
# =============================================================================

# A.12.1.1 - Documented operating procedures
operating_procedures_documented if {
	input.operational_procedures.documented == true
	input.operational_procedures.approved == true
	input.operational_procedures.accessible_to_staff == true
	input.operational_procedures.regularly_reviewed == true
	input.operational_procedures.version_controlled == true

	# Procedures cover required areas
	input.operational_procedures.covers.system_startup_shutdown == true
	input.operational_procedures.covers.backup_procedures == true
	input.operational_procedures.covers.error_handling == true
	input.operational_procedures.covers.incident_management == true
	input.operational_procedures.covers.escalation_paths == true
}

# A.12.1.2 - Change management
change_management if {
	input.change_management.formal_process == true
	input.change_management.approval_required == true
	input.change_management.testing_required == true
	input.change_management.rollback_procedures == true
	input.change_management.documentation_required == true
	input.change_management.impact_assessment == true

	# Change advisory board
	input.change_management.cab.exists == true
	input.change_management.cab.security_represented == true
	input.change_management.cab.regular_meetings == true

	# Emergency change procedures
	input.change_management.emergency.defined == true
	input.change_management.emergency.post_implementation_review == true
}

# A.12.1.3 - Capacity management
capacity_management if {
	input.capacity_management.monitoring_enabled == true
	input.capacity_management.forecasting_performed == true
	input.capacity_management.thresholds_defined == true
	input.capacity_management.alerts_configured == true
	input.capacity_management.tuning_performed == true

	# Resource monitoring
	input.capacity_management.resources.cpu_monitored == true
	input.capacity_management.resources.memory_monitored == true
	input.capacity_management.resources.storage_monitored == true
	input.capacity_management.resources.network_monitored == true
}

# A.12.1.4 - Separation of development, testing and operational environments
environment_separation if {
	input.environments.development_separated == true
	input.environments.testing_separated == true
	input.environments.production_separated == true
	input.environments.access_controls_different == true
	input.environments.data_not_copied_without_authorization == true
	input.environments.compilers_restricted_in_production == true
}

# =============================================================================
# A.12.2 - Protection from Malware
# =============================================================================

# A.12.2.1 - Controls against malware
malware_protection if {
	# Antivirus/antimalware
	input.malware_protection.antivirus.deployed == true
	input.malware_protection.antivirus.real_time_enabled == true
	input.malware_protection.antivirus.signatures_current == true
	input.malware_protection.antivirus.scheduled_scans == true
	input.malware_protection.antivirus.coverage_percentage >= 95

	# Signature currency
	input.malware_protection.antivirus.signature_age_days <= 3

	# Additional controls
	input.malware_protection.email_scanning == true
	input.malware_protection.web_filtering == true
	input.malware_protection.application_whitelisting == true
	input.malware_protection.removable_media_scanning == true

	# User awareness
	input.malware_protection.user_awareness_training == true
	input.malware_protection.phishing_training == true
}

# =============================================================================
# A.12.3 - Backup
# =============================================================================

# A.12.3.1 - Information backup
backup_management if {
	input.backup.policy.documented == true
	input.backup.policy.approved == true
	input.backup.policy.regularly_tested == true

	# Backup coverage
	input.backup.coverage.critical_systems == true
	input.backup.coverage.databases == true
	input.backup.coverage.configuration_files == true
	input.backup.coverage.application_data == true

	# Backup frequency
	input.backup.frequency.daily_incremental == true
	input.backup.frequency.weekly_full == true

	# Backup security
	input.backup.security.encrypted == true
	input.backup.security.offsite_copy == true
	input.backup.security.access_controlled == true
	input.backup.security.integrity_verified == true

	# Retention
	input.backup.retention.defined == true
	input.backup.retention.minimum_days >= 30

	# Restore testing
	input.backup.testing.restore_tests_performed == true
	input.backup.testing.frequency_days <= 90
}

# =============================================================================
# A.12.4 - Logging and Monitoring
# =============================================================================

# A.12.4.1 - Event logging
event_logging if {
	input.logging.events.user_activities == true
	input.logging.events.exceptions == true
	input.logging.events.faults == true
	input.logging.events.security_events == true
	input.logging.events.privileged_operations == true
	input.logging.events.system_access == true
	input.logging.events.authentication_attempts == true

	# Log retention
	input.logging.retention.enabled == true
	input.logging.retention.minimum_days >= 90

	# Log integrity
	input.logging.integrity.tamper_protection == true
	input.logging.integrity.checksum_verification == true
	input.logging.integrity.immutable_storage == true
}

# A.12.4.2 - Protection of log information
log_protection if {
	input.log_protection.access_restricted == true
	input.log_protection.centralized_storage == true
	input.log_protection.encryption_enabled == true
	input.log_protection.deletion_prevention == true
	input.log_protection.backup_enabled == true
	input.log_protection.siem_integrated == true
}

# A.12.4.3 - Administrator and operator logs
admin_logs if {
	input.admin_logging.privileged_commands_logged == true
	input.admin_logging.sudo_usage_logged == true
	input.admin_logging.root_access_logged == true
	input.admin_logging.configuration_changes_logged == true
	input.admin_logging.service_account_activity_logged == true
	input.admin_logging.logs_reviewed_regularly == true
}

# A.12.4.4 - Clock synchronisation
clock_synchronization if {
	input.clock_sync.ntp_configured == true
	input.clock_sync.authoritative_source == true
	input.clock_sync.all_systems_synchronized == true
	input.clock_sync.drift_monitored == true

	# Maximum drift threshold
	input.clock_sync.max_drift_seconds <= 1
}

# =============================================================================
# A.12.5 - Control of Operational Software
# =============================================================================

# A.12.5.1 - Installation of software on operational systems
software_installation_control if {
	input.software_control.installation.policy_defined == true
	input.software_control.installation.approved_software_list == true
	input.software_control.installation.unauthorized_installation_prevented == true
	input.software_control.installation.admin_rights_required == true
	input.software_control.installation.approval_process == true

	# Software inventory
	input.software_control.inventory.maintained == true
	input.software_control.inventory.regularly_reviewed == true
	input.software_control.inventory.unauthorized_software_detected == true
}

# =============================================================================
# A.12.6 - Technical Vulnerability Management
# =============================================================================

# A.12.6.1 - Management of technical vulnerabilities
vulnerability_management if {
	input.vulnerability_management.scanning.regular_scans == true
	input.vulnerability_management.scanning.frequency_days <= 30
	input.vulnerability_management.scanning.authenticated_scans == true
	input.vulnerability_management.scanning.covers_all_systems == true

	# Patch management
	input.vulnerability_management.patching.policy_defined == true
	input.vulnerability_management.patching.critical_patch_sla_days <= 7
	input.vulnerability_management.patching.high_patch_sla_days <= 30
	input.vulnerability_management.patching.testing_required == true
	input.vulnerability_management.patching.automated_where_possible == true

	# Vulnerability tracking
	input.vulnerability_management.tracking.risk_register == true
	input.vulnerability_management.tracking.remediation_tracked == true
	input.vulnerability_management.tracking.management_reporting == true
}

# A.12.6.2 - Restrictions on software installation
software_restriction if {
	input.software_restriction.standard_builds_enforced == true
	input.software_restriction.application_whitelisting == true
	input.software_restriction.unapproved_software_blocked == true
	input.software_restriction.code_signing_required == true
	input.software_restriction.exceptions_documented == true
}

# =============================================================================
# A.12.7 - Information Systems Audit Considerations
# =============================================================================

# A.12.7.1 - Information systems audit controls
audit_controls if {
	input.audit_controls.requirements_agreed == true
	input.audit_controls.scope_controlled == true
	input.audit_controls.audit_tools_protected == true
	input.audit_controls.audit_access_restricted == true
	input.audit_controls.production_disruption_minimized == true

	# Audit scheduling
	input.audit_controls.scheduling.planned_in_advance == true
	input.audit_controls.scheduling.maintenance_window_preferred == true
	input.audit_controls.scheduling.stakeholders_notified == true

	# Audit logging
	input.audit_controls.logging.audit_activities_logged == true
	input.audit_controls.logging.audit_log_protected == true
}

# =============================================================================
# Overall compliance
# =============================================================================

operational_procedures if {
	operating_procedures_documented
	change_management
	capacity_management
	environment_separation
}

logging_monitoring if {
	event_logging
	log_protection
	admin_logs
	clock_synchronization
}

compliant if {
	operational_procedures
	malware_protection
	backup_management
	logging_monitoring
	software_installation_control
	vulnerability_management
}

# Detailed compliance reporting
compliance_details := {
	"operational_procedures": {
		"documented_procedures": operating_procedures_documented,
		"change_management": change_management,
		"capacity_management": capacity_management,
		"environment_separation": environment_separation,
	},
	"malware_protection": malware_protection,
	"backup_management": backup_management,
	"logging_monitoring": {
		"event_logging": event_logging,
		"log_protection": log_protection,
		"admin_logs": admin_logs,
		"clock_synchronization": clock_synchronization,
	},
	"operational_software_control": {
		"installation_control": software_installation_control,
		"software_restriction": software_restriction,
	},
	"vulnerability_management": vulnerability_management,
	"audit_considerations": audit_controls,
	"overall_compliant": compliant,
}
