# PCI DSS v4.0.1 Requirement 6 - Develop and Maintain Secure Systems and Software

# METADATA
# title: "PCI DSS v4.0.1 Requirement 6 - Develop and Maintain Secure Systems and Software"
# custom:
#   class: compliance
#   framework: pci_dss
#   source: pci-ssc
#   domains: [financial, payment-cards]
#   coverage:
#     checks: 21
#     cited: 6
#     density: sized
#     basis: size
#     tested: true
#     entrypoint: none
#     guard: n/a
#     as_of: v2.4.2
package pci_dss.secure_development.requirement_6

import rego.v1

# Parameters checked on 2026-11-17 against PCI SSC's public SAQ D for Service Providers (v4.0) rows 6.1.1-6.5.6
# and FAQ 1593 (6.4.1 superseded by 6.4.2). The 6.3.3 critical-only window follows v4.0.1 per secondary
# sources and is used only to relax. Implementation choices the standard does not require (WAF rule sets,
# SAST/DAST, SCA licence checks, a 30-day scan cadence, specific coding techniques) do not gate
# pci_requirement_6_compliant; they remain as informational rules (audit 2026-11-17 follow-up).

_num_le(x, n) if {
	is_number(x)
	x <= n
}

# =================================================================
# 6.1 - Processes and mechanisms for secure systems and software
# =================================================================

# x.1.1: documented, kept up to date (current), in use (approved). No annual review is part of x.1.1; the
# annual review is 12.1.2 for the information security policy (audit 2026-11-17 follow-up).
secure_development_policies_established if {
	input.pci.secure_development.policies.documented == true
	input.pci.secure_development.policies.approved == true
	input.pci.secure_development.policies.current == true
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
	_num_le(input.pci.developer_training.frequency_months, 12) # 6.2.2 at least once every 12 months
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
# 6.2.4: techniques or other methods are defined and in use for this attack class; the listed techniques are
# one way, input.pci.secure_coding.injection.techniques_defined_and_in_use the other.
injection_attacks_prevented if input.pci.secure_coding.injection.techniques_defined_and_in_use == true

injection_attacks_prevented if {
	input.pci.secure_coding.sql_injection.input_validation == true
	input.pci.secure_coding.sql_injection.parameterized_queries == true
	input.pci.secure_coding.command_injection.input_sanitization == true
	input.pci.secure_coding.ldap_injection.prevented == true
}

# XSS attack prevention
# 6.2.4: techniques or other methods are defined and in use for this attack class; the listed techniques are
# one way, input.pci.secure_coding.xss.techniques_defined_and_in_use the other.
xss_attacks_prevented if input.pci.secure_coding.xss.techniques_defined_and_in_use == true

xss_attacks_prevented if {
	input.pci.secure_coding.xss.output_encoding == true
	input.pci.secure_coding.xss.input_validation == true
	input.pci.secure_coding.xss.csp_headers.implemented == true
}

# Authentication / session management attacks prevented
# 6.2.4: techniques or other methods are defined and in use for this attack class; the listed techniques are
# one way, input.pci.secure_coding.authentication.techniques_defined_and_in_use the other.
authentication_attacks_prevented if input.pci.secure_coding.authentication.techniques_defined_and_in_use == true

authentication_attacks_prevented if {
	input.pci.secure_coding.authentication.secure_session_management == true
	input.pci.secure_coding.authentication.session_fixation.prevented == true
	input.pci.secure_coding.authentication.brute_force.prevented == true
	input.pci.secure_coding.authentication.mfa.implemented == true
}

# Memory corruption attacks prevented
# 6.2.4: techniques or other methods are defined and in use for this attack class; the listed techniques are
# one way, input.pci.secure_coding.memory.techniques_defined_and_in_use the other.
memory_corruption_prevented if input.pci.secure_coding.memory.techniques_defined_and_in_use == true

memory_corruption_prevented if {
	input.pci.secure_coding.memory.buffer_overflow.prevented == true
	input.pci.secure_coding.memory.heap_spray.mitigated == true
	input.pci.secure_coding.memory.secure_languages_preferred == true
}

# Insecure cryptography usage prevented
# 6.2.4: techniques or other methods are defined and in use for this attack class; the listed techniques are
# one way, input.pci.secure_coding.cryptography.techniques_defined_and_in_use the other.
insecure_cryptography_prevented if input.pci.secure_coding.cryptography.techniques_defined_and_in_use == true

insecure_cryptography_prevented if {
	input.pci.secure_coding.cryptography.weak_algorithms.not_used == true
	input.pci.secure_coding.cryptography.approved_libraries.used == true
	input.pci.secure_coding.cryptography.random_number_generation.cryptographically_secure == true
}

# =================================================================
# 6.3 - Security vulnerabilities are identified and addressed
# =================================================================

# Security patch management (6.3.3). PCI DSS v4.0.1 limits the one-month installation window to patches for
# critical vulnerabilities (v4.0 also named high-security patches); all other applicable patches are
# installed within a time frame the entity determines. Either the former high-within-30-days evidence or
# evidence that the entity-defined time frame is met satisfies the second condition.
_other_patches_timely if input.pci.patch_management.high_patches.applied_within_30_days == true

_other_patches_timely if input.pci.patch_management.other_patches.entity_defined_timeframe.met == true

security_patch_management if {
	input.pci.patch_management.process.documented == true
	input.pci.patch_management.critical_patches.applied_within_30_days == true
	_other_patches_timely
	input.pci.patch_management.testing.required_before_deployment == true
	input.pci.patch_management.rollback.procedures_defined == true
}

# Vulnerability identification for in-scope systems
# 6.3.1: new vulnerabilities identified from industry-recognised sources (CERT alerts among them) and given a
# risk ranking that identifies at least high-risk and critical ones. Scanning cadence is 11.3 (every three
# months), not 6.3.1; the former 30-day scan check no longer gates this control.
_industry_sources_monitored if input.pci.vulnerability_management.industry_sources.monitored == true

_industry_sources_monitored if {
	input.pci.vulnerability_management.cve_tracking.enabled == true
	input.pci.vulnerability_management.nvd.monitored == true
}

vulnerability_identification if {
	_industry_sources_monitored
	input.pci.vulnerability_management.risk_ranking.assigned == true
}

# =================================================================
# 6.3.2 - Inventory of bespoke and third-party software
# =================================================================

software_inventory_maintained if {
	input.pci.software_inventory.bespoke.documented == true
	input.pci.software_inventory.third_party.documented == true
}

# =================================================================
# 6.4 - Public-facing web applications are protected against attacks
# =================================================================

# Web Application Firewall (WAF) with specific rule sets: one way to meet 6.4.2, not a requirement. Reported
# for information; it does not gate requirement 6.
waf_implemented if {
	# Only required if public-facing web apps are in scope
	input.pci.public_web_apps.in_scope == false
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
	input.pci.public_web_apps.in_scope == false
} else if {
	input.pci.public_web_apps.in_scope
	input.pci.automated_detection.waf_or_vapt.implemented == true
	_blocks_or_alerts
	input.pci.automated_detection.logging.configured == true
}

# 6.4.2: configured to block web-based attacks OR to alert with immediate investigation.
_blocks_or_alerts if input.pci.automated_detection.active_blocking.enabled == true

_blocks_or_alerts if input.pci.automated_detection.alerts.immediately_investigated == true

# Penetration testing / review of web applications: the 6.4.1 "review or automated solution" path,
# superseded by 6.4.2 after 31 March 2025 (PCI SSC FAQ 1593). Reported for information only; it no longer
# gates pci_requirement_6_compliant or counts in the score. 6.4.2 is automated_attack_detection above.
web_app_pen_testing if {
	input.pci.public_web_apps.in_scope == false
} else if {
	input.pci.public_web_apps.in_scope
	input.pci.penetration_testing.web_app.performed == true
	_num_le(input.pci.penetration_testing.web_app.frequency_months, 12)
	input.pci.penetration_testing.web_app.owasp_top10.tested == true
	input.pci.penetration_testing.web_app.remediation.tracked == true
	input.pci.penetration_testing.web_app.qualified_personnel == true
}

# =================================================================
# Static and Dynamic Application Security Testing, software composition analysis: not PCI DSS requirements
# (6.2.3 code review and 6.3.2 inventory are). Informational; they do not gate requirement 6.
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

# Every control referenced by the score, findings and roll-up has a default so a failing
# control reports false instead of making the whole score/findings undefined.
default secure_development_policies_established := false

default secure_development_roles_defined := false

default secure_sdlc_implemented := false

default developer_security_training := false

default preproduction_security_testing := false

default bespoke_code_review := false

default injection_attacks_prevented := false

default xss_attacks_prevented := false

default authentication_attacks_prevented := false

default memory_corruption_prevented := false

default automated_attack_detection := false

default insecure_cryptography_prevented := false

default security_patch_management := false

default vulnerability_identification := false

default software_inventory_maintained := false

default waf_implemented := false

default web_app_pen_testing := false

default sast_dast_implemented := false

default software_composition_analysis := false

default pci_requirement_6_compliant := false

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
	memory_corruption_prevented
	insecure_cryptography_prevented
	security_patch_management
	vulnerability_identification
	software_inventory_maintained
	automated_attack_detection
}

default pci_requirement_6_score := 0

default pci_requirement_6_findings := {}

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
		automated_attack_detection,
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
		"automated_attack_detection": automated_attack_detection,
		"web_app_pen_testing_6_4_1_superseded": web_app_pen_testing,
	},
	"informational_not_required": {
		"waf_with_rule_sets": waf_implemented,
		"sast_dast": sast_dast_implemented,
		"software_composition_analysis": software_composition_analysis,
	},
	"overall_score": pci_requirement_6_score,
	"overall_compliant": pci_requirement_6_compliant,
}
