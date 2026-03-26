package iso27001.communications_security

import rego.v1

# ISO 27001:2022 - A.13 Communications Security
# Technical controls for protecting information in networks and information transfer

# =============================================================================
# A.13.1 - Network Security Management
# =============================================================================

# A.13.1.1 - Network controls
network_controls if {
	input.network_security.controls.firewalls_deployed == true
	input.network_security.controls.intrusion_detection == true
	input.network_security.controls.network_monitoring == true
	input.network_security.controls.access_control_lists == true
	input.network_security.controls.policy_documented == true
	input.network_security.controls.responsibility_assigned == true
}

# A.13.1.2 - Security of network services
network_services_secure if {
	input.network_services.security_features_identified == true
	input.network_services.service_agreements_documented == true
	input.network_services.service_levels_monitored == true
	input.network_services.managed_security_services == true

	# Third-party network service security
	input.network_services.third_party.security_requirements_defined == true
	input.network_services.third_party.compliance_monitored == true
	input.network_services.third_party.contracts_include_security == true
}

# A.13.1.3 - Segregation in networks
network_segregation if {
	input.network_segregation.zones_defined == true
	input.network_segregation.vlans_configured == true
	input.network_segregation.dmz_implemented == true
	input.network_segregation.internal_external_separated == true

	# Perimeter security
	input.network_segregation.perimeter.firewall_rules_documented == true
	input.network_segregation.perimeter.egress_filtering == true
	input.network_segregation.perimeter.ingress_filtering == true

	# Wireless network segregation
	input.network_segregation.wireless.guest_network_isolated == true
	input.network_segregation.wireless.corporate_separate == true
}

# =============================================================================
# A.13.2 - Information Transfer
# =============================================================================

# A.13.2.1 - Information transfer policies and procedures
transfer_policies if {
	input.information_transfer.policy.documented == true
	input.information_transfer.policy.approved == true
	input.information_transfer.policy.communicated == true
	input.information_transfer.policy.acceptable_use_defined == true

	# Transfer controls
	input.information_transfer.controls.encryption_required == true
	input.information_transfer.controls.integrity_checking == true
	input.information_transfer.controls.data_classification_applied == true
	input.information_transfer.controls.unauthorized_interception_prevented == true
}

# A.13.2.2 - Agreements on information transfer
transfer_agreements if {
	input.information_transfer.agreements.formal_agreements_required == true
	input.information_transfer.agreements.security_requirements_defined == true
	input.information_transfer.agreements.responsibilities_defined == true
	input.information_transfer.agreements.classification_labeling_required == true

	# Third-party transfer agreements
	input.information_transfer.agreements.third_party.nda_required == true
	input.information_transfer.agreements.third_party.data_handling_procedures == true
	input.information_transfer.agreements.third_party.breach_notification_required == true
	input.information_transfer.agreements.third_party.audit_rights_reserved == true
}

# A.13.2.3 - Electronic messaging security
electronic_messaging_secure if {
	input.electronic_messaging.encryption.emails_encrypted == true
	input.electronic_messaging.encryption.sensitive_content_protected == true
	input.electronic_messaging.anti_malware.email_scanning == true
	input.electronic_messaging.anti_malware.attachment_filtering == true
	input.electronic_messaging.anti_spam.enabled == true
	input.electronic_messaging.dlp.enabled == true
	input.electronic_messaging.dlp.sensitive_data_blocked == true

	# Email authentication
	input.electronic_messaging.authentication.spf_configured == true
	input.electronic_messaging.authentication.dkim_enabled == true
	input.electronic_messaging.authentication.dmarc_configured == true
}

# A.13.2.4 - Confidentiality or non-disclosure agreements
nda_requirements if {
	input.nda.required_for_staff == true
	input.nda.required_for_contractors == true
	input.nda.required_for_partners == true
	input.nda.legally_reviewed == true
	input.nda.regularly_reviewed == true
	input.nda.signed_before_access == true

	# NDA enforcement
	input.nda.enforcement.records_maintained == true
	input.nda.enforcement.expiry_tracked == true
	input.nda.enforcement.renewal_process == true
}

# =============================================================================
# Additional Network Security Controls
# =============================================================================

# Remote access security
remote_access_secure if {
	input.remote_access.vpn.required == true
	input.remote_access.vpn.strong_encryption == true
	input.remote_access.vpn.multi_factor_auth == true
	input.remote_access.vpn.session_timeout_configured == true

	# Remote session controls
	input.remote_access.sessions.logging_enabled == true
	input.remote_access.sessions.activity_monitored == true
	input.remote_access.sessions.idle_timeout_minutes <= 30

	# Endpoint requirements
	input.remote_access.endpoints.compliance_check == true
	input.remote_access.endpoints.antivirus_required == true
	input.remote_access.endpoints.patch_level_verified == true
}

# Network monitoring and detection
network_monitoring if {
	input.network_monitoring.ids_ips_deployed == true
	input.network_monitoring.traffic_analysis == true
	input.network_monitoring.anomaly_detection == true
	input.network_monitoring.siem_integrated == true
	input.network_monitoring.alert_thresholds_configured == true

	# Log retention
	input.network_monitoring.log_retention_days >= 90
}

# DNS security
dns_security if {
	input.dns_security.dnssec_enabled == true
	input.dns_security.internal_external_separated == true
	input.dns_security.recursive_queries_restricted == true
	input.dns_security.response_rate_limiting == true
	input.dns_security.monitoring_enabled == true
}

# Network management security
network_management_secure if {
	input.network_management.out_of_band_management == true
	input.network_management.management_vlan_separate == true
	input.network_management.snmp_v3_only == true
	input.network_management.management_access_restricted == true
	input.network_management.configuration_backups == true
	input.network_management.change_management_applied == true
}

# =============================================================================
# Overall compliance
# =============================================================================

network_security_management if {
	network_controls
	network_services_secure
	network_segregation
	network_monitoring
	network_management_secure
}

information_transfer if {
	transfer_policies
	transfer_agreements
	electronic_messaging_secure
	nda_requirements
}

compliant if {
	network_security_management
	information_transfer
	remote_access_secure
}

# Detailed compliance reporting
compliance_details := {
	"network_security_management": {
		"network_controls": network_controls,
		"network_services": network_services_secure,
		"network_segregation": network_segregation,
		"network_monitoring": network_monitoring,
		"network_management": network_management_secure,
	},
	"information_transfer": {
		"transfer_policies": transfer_policies,
		"transfer_agreements": transfer_agreements,
		"electronic_messaging": electronic_messaging_secure,
		"nda_requirements": nda_requirements,
	},
	"remote_access": remote_access_secure,
	"dns_security": dns_security,
	"overall_compliant": compliant,
}
