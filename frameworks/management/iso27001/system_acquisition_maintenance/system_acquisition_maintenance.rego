package iso27001.system_acquisition_maintenance

import rego.v1

# ISO 27001:2022 - A.14 System Acquisition, Development and Maintenance
# Technical controls for building security into information systems

# =============================================================================
# A.14.1 - Security Requirements of Information Systems
# =============================================================================

# A.14.1.1 - Information security requirements analysis and specification
security_requirements_defined if {
	input.system_requirements.security_requirements.documented == true
	input.system_requirements.security_requirements.included_in_specifications == true
	input.system_requirements.security_requirements.reviewed_before_procurement == true
	input.system_requirements.security_requirements.stakeholders_approved == true

	# Requirements categorization
	input.system_requirements.categorization.data_classification_considered == true
	input.system_requirements.categorization.regulatory_requirements_mapped == true
	input.system_requirements.categorization.risk_assessment_performed == true
}

# A.14.1.2 - Securing application services on public networks
public_network_services_secure if {
	input.public_services.authentication.strong_auth_required == true
	input.public_services.authentication.multi_factor_enabled == true
	input.public_services.encryption.tls_enforced == true
	input.public_services.encryption.minimum_tls_version >= "1.2"
	input.public_services.integrity.message_signing == true
	input.public_services.integrity.transaction_verification == true
	input.public_services.fraud_prevention.controls_implemented == true

	# Input validation
	input.public_services.input_validation.enabled == true
	input.public_services.input_validation.sanitization == true
	input.public_services.input_validation.parameterized_queries == true
}

# A.14.1.3 - Protecting application services transactions
transaction_protection if {
	input.transactions.integrity_verification == true
	input.transactions.non_repudiation == true
	input.transactions.confidentiality_protected == true
	input.transactions.routing_security == true
	input.transactions.audit_trail == true
	input.transactions.error_handling_secure == true
	input.transactions.timeout_configured == true
}

# =============================================================================
# A.14.2 - Security in Development and Support Processes
# =============================================================================

# A.14.2.1 - Secure development policy
secure_development_policy if {
	input.development.policy.documented == true
	input.development.policy.approved == true
	input.development.policy.communicated == true
	input.development.policy.enforced == true

	# Policy covers required areas
	input.development.policy.covers.coding_standards == true
	input.development.policy.covers.security_training == true
	input.development.policy.covers.secure_coding_guidelines == true
	input.development.policy.covers.vulnerability_testing == true
	input.development.policy.covers.peer_code_review == true
}

# A.14.2.2 - System change control procedures
change_control_procedures if {
	input.change_control.formal_process == true
	input.change_control.documentation_required == true
	input.change_control.impact_assessment == true
	input.change_control.approval_required == true
	input.change_control.testing_required == true
	input.change_control.rollback_plan == true
	input.change_control.post_change_review == true

	# Version control
	input.change_control.version_control.mandatory == true
	input.change_control.version_control.all_changes_tracked == true
	input.change_control.version_control.branch_protection == true
}

# A.14.2.3 - Technical review of applications after OS changes
os_change_review if {
	input.os_change_review.procedure_defined == true
	input.os_change_review.applications_tested_after_os_change == true
	input.os_change_review.compatibility_verified == true
	input.os_change_review.security_posture_validated == true
	input.os_change_review.change_management_notified == true
}

# A.14.2.4 - Restrictions on changes to software packages
software_package_control if {
	input.software_packages.modification_restricted == true
	input.software_packages.vendor_packages_preferred == true
	input.software_packages.modifications_tested == true
	input.software_packages.modifications_documented == true
	input.software_packages.vendor_notification_when_modified == true
}

# A.14.2.5 - Secure system engineering principles
secure_engineering_principles if {
	input.secure_engineering.threat_modeling == true
	input.secure_engineering.security_architecture_review == true
	input.secure_engineering.defense_in_depth == true
	input.secure_engineering.least_privilege == true
	input.secure_engineering.fail_secure == true
	input.secure_engineering.separation_of_duties == true

	# OWASP / secure coding
	input.secure_engineering.owasp_top10_mitigated == true
	input.secure_engineering.input_validation_implemented == true
	input.secure_engineering.output_encoding_implemented == true
	input.secure_engineering.authentication_centralized == true
	input.secure_engineering.session_management_secure == true
}

# A.14.2.6 - Secure development environment
secure_development_environment if {
	input.dev_environment.access_restricted == true
	input.dev_environment.separated_from_production == true
	input.dev_environment.security_controls_applied == true
	input.dev_environment.code_repository_protected == true
	input.dev_environment.secrets_management_implemented == true

	# Developer workstation security
	input.dev_environment.workstations.full_disk_encryption == true
	input.dev_environment.workstations.antivirus_deployed == true
	input.dev_environment.workstations.screen_lock_configured == true
	input.dev_environment.workstations.patching_current == true
}

# A.14.2.7 - Outsourced development
outsourced_development if {
	# If outsourcing is not used, this control is satisfied
	not input.outsourced_development.used
} else if {
	input.outsourced_development.contracts.security_requirements == true
	input.outsourced_development.contracts.code_ownership_defined == true
	input.outsourced_development.contracts.escrow_arrangements == true
	input.outsourced_development.contracts.audit_rights == true
	input.outsourced_development.code_review.performed == true
	input.outsourced_development.code_review.security_focused == true
	input.outsourced_development.background_checks.developers == true
	input.outsourced_development.ip_protection == true
}

# A.14.2.8 - System security testing
security_testing if {
	input.security_testing.policy.defined == true
	input.security_testing.types.unit_testing == true
	input.security_testing.types.integration_testing == true
	input.security_testing.types.penetration_testing == true
	input.security_testing.types.vulnerability_scanning == true
	input.security_testing.types.static_analysis == true

	# SAST / DAST
	input.security_testing.sast.enabled == true
	input.security_testing.sast.integrated_in_pipeline == true
	input.security_testing.dast.enabled == true

	# Dependency scanning
	input.security_testing.dependency_scanning.enabled == true
	input.security_testing.dependency_scanning.blocking_on_critical == true

	# Frequency
	input.security_testing.penetration_testing.frequency_days <= 365
}

# A.14.2.9 - System acceptance testing
acceptance_testing if {
	input.acceptance_testing.criteria_defined == true
	input.acceptance_testing.security_criteria_included == true
	input.acceptance_testing.formal_sign_off == true
	input.acceptance_testing.documentation_complete == true
	input.acceptance_testing.stakeholders_signed_off == true
}

# =============================================================================
# A.14.3 - Test Data
# =============================================================================

# A.14.3.1 - Protection of test data
data_protection_control if {
	# Production data should not be used in test environments
	input.test_data.production_data_not_used_for_testing == true

	# If production data is unavoidably used
	# (if input.test_data.production_data_used is true, additional controls required)
	test_data_controls_adequate
}

test_data_controls_adequate if {
	not input.test_data.production_data_used
} else if {
	input.test_data.production_data_used
	input.test_data.anonymization.applied == true
	input.test_data.anonymization.pii_masked == true
	input.test_data.anonymization.cardholder_data_masked == true
	input.test_data.authorization.formal_approval == true
	input.test_data.access_controls.restricted == true
	input.test_data.deletion.post_test_deletion == true
	input.test_data.logging.access_logged == true
}

# Test data generation
data_generation_control if {
	input.test_data.synthetic_data.available == true
	input.test_data.synthetic_data.realistic_for_testing == true
	input.test_data.generators.approved_tools == true
}

# =============================================================================
# Additional Controls - DevSecOps
# =============================================================================

# CI/CD pipeline security
cicd_security if {
	input.cicd.pipeline_as_code == true
	input.cicd.access_controlled == true
	input.cicd.secrets_management.vault_used == true
	input.cicd.secrets_management.no_plaintext_secrets == true
	input.cicd.artifact_signing == true
	input.cicd.container_scanning == true
	input.cicd.infrastructure_as_code_scanning == true

	# Deployment gates
	input.cicd.gates.security_scan_required == true
	input.cicd.gates.quality_checks_required == true
	input.cicd.gates.approval_required_for_production == true
}

# Software composition analysis
sca_controls if {
	input.sca.enabled == true
	input.sca.sbom_generated == true
	input.sca.license_compliance_checked == true
	input.sca.known_vulnerabilities_flagged == true
	input.sca.policy_enforcement == true
}

# =============================================================================
# Overall compliance
# =============================================================================

information_systems_security if {
	security_requirements_defined
	public_network_services_secure
	transaction_protection
}

security_in_development if {
	secure_development_policy
	change_control_procedures
	os_change_review
	software_package_control
	secure_engineering_principles
	secure_development_environment
	outsourced_development
	security_testing
	acceptance_testing
}

compliant if {
	information_systems_security
	security_in_development
	data_protection_control
}

# Detailed compliance reporting
compliance_details := {
	"information_systems_security": {
		"security_requirements": security_requirements_defined,
		"public_network_services": public_network_services_secure,
		"transaction_protection": transaction_protection,
	},
	"security_in_development": {
		"secure_development_policy": secure_development_policy,
		"change_control": change_control_procedures,
		"os_change_review": os_change_review,
		"software_package_control": software_package_control,
		"secure_engineering": secure_engineering_principles,
		"secure_dev_environment": secure_development_environment,
		"outsourced_development": outsourced_development,
		"security_testing": security_testing,
		"acceptance_testing": acceptance_testing,
	},
	"test_data": {
		"protection": data_protection_control,
		"generation": data_generation_control,
	},
	"devsecops": {
		"cicd_security": cicd_security,
		"sca_controls": sca_controls,
	},
	"overall_compliant": compliant,
}
