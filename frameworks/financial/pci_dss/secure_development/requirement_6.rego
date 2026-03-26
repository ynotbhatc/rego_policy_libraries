# PCI DSS v4.0 Requirement 6 - Develop and Maintain Secure Systems and Software

package pci_dss.secure_development.requirement_6

import rego.v1

# =================================================================
# 6.1 - Processes and mechanisms for secure systems and software
# =================================================================

secure_development_policies_established if {
	input.pci.secure_development.policies.documented == true
	input.pci.secure_development.policies.approved == true
	input.pci.secure_development.policies.current == true
	input.pci.secure_development.policies.reviewed_annually == true
}

secure_development_roles_defined if {
	input.pci.secure_development.roles.defined == true
	input.pci.secure_development.responsibilities.assigned == true
}

# =================================================================
# 6.2 - Bespoke and custom software are developed securely
# =================================================================

# Secure development lifecycle (SDLC) in place
secure_sdlc_implemented if {
	input.pci.sdlc.documented == true
	input.pci.sdlc.security_requirements.defined == true
	input.pci.sdlc.security_integrated_at_all_phases == true
	input.pci.sdlc.security_training.required_for_developers == true
}

# Developer security training
developer_security_training if {
	input.pci.developer_training.secure_coding.conducted == true
	input.pci.developer_training.frequency_months <= 12
	input.pci.developer_training.owasp_top10.covered == true
	input.pci.developer_training.records.maintained == true
}

# Pre-production testing
preproduction_security_testing if {
	input.pci.testing.preproduction.performed == true
	input.pci.testing.production_data_not_used == true
	input.pci.testing.test_accounts.removed_before_production == true
	input.pci.testing.custom_application_accounts.reviewed == true
}

# Code review for bespoke software
bespoke_code_review if {
	input.pci.code_review.performed == true
	input.pci.code_review.by_security_aware_personnel == true
	input.pci.code_review.all_code_changes_reviewed == true
	input.pci.code_review.vulnerabilities_corrected_before_release == true
}

# =================================================================
# 6.2.4 - Attacks on software are prevented
# =================================================================

# Injection attacks prevention (SQLi, command injection, LDAP injection, etc.)
injection_attacks_prevented if {
	input.pci.secure_coding.sql_injection.input_validation == true
	input.pci.secure_coding.sql_injection.parameterized_queries == true
	input.pci.secure_coding.command_injection.input_sanitization == true
	input.pci.secure_coding.ldap_injection.prevented == true
}

# XSS attack prevention
xss_attacks_prevented if {
	input.pci.secure_coding.xss.output_encoding == true
	input.pci.secure_coding.xss.input_validation == true
	input.pci.secure_coding.xss.csp_headers.implemented == true
}

# Authentication / session management attacks prevented
authentication_attacks_prevented if {
	input.pci.secure_coding.authentication.secure_session_management == true
	input.pci.secure_coding.authentication.session_fixation.prevented == true
	input.pci.secure_coding.authentication.brute_force.prevented == true
	input.pci.secure_coding.authentication.mfa.implemented == true
}

# Memory corruption attacks prevented
memory_corruption_prevented if {
	input.pci.secure_coding.memory.buffer_overflow.prevented == true
	input.pci.secure_coding.memory.heap_spray.mitigated == true
	input.pci.secure_coding.memory.secure_languages_preferred == true
}

# Insecure cryptography usage prevented
insecure_cryptography_prevented if {
	input.pci.secure_coding.cryptography.weak_algorithms.not_used == true
	input.pci.secure_coding.cryptography.approved_libraries.used == true
	input.pci.secure_coding.cryptography.random_number_generation.cryptographically_secure == true
}

# =================================================================
# 6.3 - Security vulnerabilities are identified and addressed
# =================================================================

# Security patch management
security_patch_management if {
	input.pci.patch_management.process.documented == true
	input.pci.patch_management.critical_patches.applied_within_30_days == true
	input.pci.patch_management.high_patches.applied_within_30_days == true
	input.pci.patch_management.testing.required_before_deployment == true
	input.pci.patch_management.rollback.procedures_defined == true
}

# Vulnerability identification for in-scope systems
vulnerability_identification if {
	input.pci.vulnerability_management.scanning.internal.performed == true
	input.pci.vulnerability_management.scanning.external.performed == true
	input.pci.vulnerability_management.scanning.frequency_days <= 30
	input.pci.vulnerability_management.cve_tracking.enabled == true
	input.pci.vulnerability_management.nvd.monitored == true
}

# =================================================================
# 6.3.2 - Inventory of bespoke and third-party software
# =================================================================

software_inventory_maintained if {
	input.pci.software_inventory.bespoke.documented == true
	input.pci.software_inventory.third_party.documented == true
	input.pci.software_inventory.versions.tracked == true
	input.pci.software_inventory.vulnerabilities.tracked == true
	input.pci.software_inventory.regularly_reviewed == true
}

# =================================================================
# 6.4 - Public-facing web applications are protected against attacks
# =================================================================

# Web Application Firewall (WAF) in place
waf_implemented if {
	# Only required if public-facing web apps are in scope
	not input.pci.public_web_apps.in_scope
} else if {
	input.pci.public_web_apps.in_scope
	input.pci.waf.implemented == true
	input.pci.waf.mode.blocking == true
	input.pci.waf.rules.pci_specific == true
	input.pci.waf.rules.owasp_crs.enabled == true
	input.pci.waf.logging.comprehensive == true
	input.pci.waf.monitoring.real_time == true
}

# Automated technical solution detects and prevents web-based attacks
automated_attack_detection if {
	not input.pci.public_web_apps.in_scope
} else if {
	input.pci.public_web_apps.in_scope
	input.pci.automated_detection.waf_or_vapt.implemented == true
	input.pci.automated_detection.active_blocking.enabled == true
	input.pci.automated_detection.logging.configured == true
}

# Penetration testing of web applications
web_app_pen_testing if {
	not input.pci.public_web_apps.in_scope
} else if {
	input.pci.public_web_apps.in_scope
	input.pci.penetration_testing.web_app.performed == true
	input.pci.penetration_testing.web_app.frequency_months <= 12
	input.pci.penetration_testing.web_app.owasp_top10.tested == true
	input.pci.penetration_testing.web_app.remediation.tracked == true
	input.pci.penetration_testing.web_app.qualified_personnel == true
}

# =================================================================
# Static and Dynamic Application Security Testing
# =================================================================

sast_dast_implemented if {
	input.pci.sast.enabled == true
	input.pci.sast.integrated_in_pipeline == true
	input.pci.sast.critical_findings.block_deployment == true
	input.pci.dast.enabled == true
	input.pci.dast.run_against_staging == true
}

software_composition_analysis if {
	input.pci.sca.enabled == true
	input.pci.sca.third_party_components.scanned == true
	input.pci.sca.known_vulnerabilities.flagged == true
	input.pci.sca.license_compliance.checked == true
}

# =================================================================
# Scoring
# =================================================================

pci_requirement_6_compliant if {
	secure_development_policies_established
	secure_development_roles_defined
	secure_sdlc_implemented
	developer_security_training
	preproduction_security_testing
	bespoke_code_review
	injection_attacks_prevented
	xss_attacks_prevented
	authentication_attacks_prevented
	security_patch_management
	vulnerability_identification
	software_inventory_maintained
	waf_implemented
}

pci_requirement_6_score := score if {
	controls := [
		secure_development_policies_established,
		secure_development_roles_defined,
		secure_sdlc_implemented,
		developer_security_training,
		preproduction_security_testing,
		bespoke_code_review,
		injection_attacks_prevented,
		xss_attacks_prevented,
		authentication_attacks_prevented,
		memory_corruption_prevented,
		insecure_cryptography_prevented,
		security_patch_management,
		vulnerability_identification,
		software_inventory_maintained,
		waf_implemented,
		web_app_pen_testing,
		sast_dast_implemented,
		software_composition_analysis,
	]
	passed := count([c | some c in controls; c == true])
	total := count(controls)
	score := (passed / total) * 100
}

pci_requirement_6_findings := {
	"requirement_6_1": {
		"policies_established": secure_development_policies_established,
		"roles_defined": secure_development_roles_defined,
	},
	"requirement_6_2": {
		"secure_sdlc": secure_sdlc_implemented,
		"developer_training": developer_security_training,
		"preproduction_testing": preproduction_security_testing,
		"code_review": bespoke_code_review,
	},
	"requirement_6_2_4_attack_prevention": {
		"injection_prevented": injection_attacks_prevented,
		"xss_prevented": xss_attacks_prevented,
		"auth_attacks_prevented": authentication_attacks_prevented,
		"memory_corruption_prevented": memory_corruption_prevented,
		"insecure_crypto_prevented": insecure_cryptography_prevented,
	},
	"requirement_6_3": {
		"patch_management": security_patch_management,
		"vulnerability_identification": vulnerability_identification,
		"software_inventory": software_inventory_maintained,
	},
	"requirement_6_4": {
		"waf_implemented": waf_implemented,
		"automated_attack_detection": automated_attack_detection,
		"web_app_pen_testing": web_app_pen_testing,
	},
	"enhanced_controls": {
		"sast_dast": sast_dast_implemented,
		"software_composition_analysis": software_composition_analysis,
	},
	"overall_score": pci_requirement_6_score,
	"overall_compliant": pci_requirement_6_compliant,
}
