# PCI DSS v4.0.1 Requirement 11 - Test Security of Systems and Networks Regularly

# METADATA
# title: "PCI DSS v4.0.1 Requirement 11 - Test Security of Systems and Networks Regularly"
# custom:
#   class: compliance
#   framework: pci_dss
#   source: pci-ssc
#   domains: [financial, payment-cards]
#   coverage:
#     checks: 9
#     cited: 6
#     density: section
#     basis: role
#     tested: true
#     entrypoint: none
#     guard: n/a
#     as_of: v2.5.0
package pci_dss.security_testing.requirement_11

import rego.v1

# Frequencies were checked on 2026-11-17 against PCI SSC's public SAQ D for Service Providers (v4.0) rows
# 11.2.1, 11.3.1, 11.3.1.1, 11.3.2, 11.4.2-11.4.6, 11.5.1, 11.5.2 and 11.6.1, and the v4.0 -> v4.0.1
# change to 6.3.3 (one-month installation applies to critical patches only). The standard's text is
# licensed and is not reproduced; ids and parameter values are facts. "Every three months" is checked as at
# most 90 days: PCI SSC FAQ 1087 (July 2023) treats three months, or 90 days, as the maximum time between
# quarterly scans (the 90-92 day figure seen elsewhere is secondary and not used). Numbers are compared only when they
# are numbers (OPA orders every string above every number).

_num_le(x, n) if {
	is_number(x)
	x <= n
}

# =================================================================
# 11.1 - Processes and mechanisms for testing security
# =================================================================

# x.1.1: documented, kept up to date (current), in use (approved). No annual review is part of x.1.1; the
# annual review is 12.1.2 for the information security policy (audit 2026-11-17 follow-up).
security_testing_policies_established if {
	input.pci.security_testing.policies.documented == true
	input.pci.security_testing.policies.approved == true
	input.pci.security_testing.policies.current == true
}

security_testing_roles_defined if {
	input.pci.security_testing.roles.defined == true
	input.pci.security_testing.responsibilities.assigned == true
}

# =================================================================
# 11.2 - Wireless access points managed and tested
# =================================================================

wireless_access_point_testing if {
	input.pci.wireless.authorized_access_points.inventoried == true
	input.pci.wireless.rogue_detection.implemented == true
	_num_le(input.pci.wireless.rogue_detection.frequency_days, 90)
	input.pci.wireless.unauthorized_access_points.alerts.configured == true
	input.pci.wireless.unauthorized_access_points.response.documented == true
}

# =================================================================
# 11.3 - External and internal vulnerabilities regularly identified, prioritized and addressed
# =================================================================

# Internal vulnerability scanning
internal_vulnerability_scanning if {
	input.pci.vuln_scanning.internal.performed == true
	_num_le(input.pci.vuln_scanning.internal.frequency_days, 90)
	input.pci.vuln_scanning.internal.qualified_personnel == true
	input.pci.vuln_scanning.internal.after_significant_changes == true
	input.pci.vuln_scanning.internal.high_and_critical.remediated == true
	input.pci.vuln_scanning.internal.rescans.performed == true
}

# 11.3.1.2 (future-dated in v4.0, in force since 31 March 2025): internal scans are authenticated. Systems that
# cannot accept credentials are documented, sufficient privileges are used, and scan accounts that can log in
# interactively are managed per 8.2.2 (or cannot log in interactively).
_scan_accounts_ok if input.pci.vuln_scanning.internal.authenticated.scan_accounts.managed_per_8_2_2 == true

_scan_accounts_ok if input.pci.vuln_scanning.internal.authenticated.scan_accounts.interactive_login_possible == false

authenticated_internal_scanning if {
	input.pci.vuln_scanning.internal.authenticated.performed == true
	input.pci.vuln_scanning.internal.authenticated.non_credentialed_systems_documented == true
	input.pci.vuln_scanning.internal.authenticated.sufficient_privileges == true
	_scan_accounts_ok
}

# External vulnerability scanning by ASV
external_vulnerability_scanning if {
	input.pci.vuln_scanning.external.performed == true
	_num_le(input.pci.vuln_scanning.external.frequency_days, 90)
	input.pci.vuln_scanning.external.asv.approved == true
	input.pci.vuln_scanning.external.passing_scan.achieved == true
	input.pci.vuln_scanning.external.after_significant_changes == true
}

# Vulnerability scan remediation: 11.3.1 high-risk and critical vulnerabilities are resolved and rescans
# confirm it (no fixed number of days; resolving within 30 days is evidence of it), 11.3.1.1 all others
# addressed per the entity's targeted risk analysis.
_resolved(sev) if input.pci.vuln_remediation[sev].resolved == true

_resolved(sev) if input.pci.vuln_remediation[sev].within_30_days == true

vulnerability_remediation if {
	_resolved("critical")
	_resolved("high")
	input.pci.vuln_remediation.medium.risk_based_timeline == true
	input.pci.vuln_remediation.tracking.implemented == true
	input.pci.vuln_remediation.verification.rescan_after_fix == true
}

# =================================================================
# 11.4 - External and internal penetration testing regularly performed
# =================================================================

penetration_testing if {
	input.pci.pen_testing.performed == true
	_num_le(input.pci.pen_testing.frequency_months, 12)
	input.pci.pen_testing.after_significant_infrastructure_changes == true
	input.pci.pen_testing.qualified.independent_tester == true
	input.pci.pen_testing.scope.network_layer == true
	input.pci.pen_testing.scope.application_layer == true
	input.pci.pen_testing.scope.includes_cde_perimeter == true
	input.pci.pen_testing.scope.includes_critical_systems == true
}

# Penetration test remediation
pen_test_remediation if {
	input.pci.pen_testing.exploitable_vulnerabilities.corrected == true
	input.pci.pen_testing.retesting.performed_after_fixes == true
	input.pci.pen_testing.results.retained == true
}

# Segmentation testing: only where segmentation is used to isolate the CDE. 11.4.5 at least every 12
# months; 11.4.6 (service providers only) at least every six months. A 6-month cadence meets both, so it
# passes without the entity type; a 7-12 month cadence needs input.pci.entity.service_provider == false.
_segmentation_frequency_ok if _num_le(input.pci.segmentation_testing.frequency_months, 6)

_segmentation_frequency_ok if {
	_num_le(input.pci.segmentation_testing.frequency_months, 12)
	input.pci.entity.service_provider == false
}

segmentation_testing if input.pci.segmentation_testing.segmentation_used == false

segmentation_testing if {
	input.pci.segmentation_testing.performed == true
	_segmentation_frequency_ok
	input.pci.segmentation_testing.penetration_testing_method == true
	input.pci.segmentation_testing.confirms_isolation == true
	input.pci.segmentation_testing.after_segmentation_changes == true
}

# =================================================================
# 11.5 - Network intrusion and unexpected file changes detected
# =================================================================

# Intrusion detection and prevention
ids_ips_deployed if {
	input.pci.ids_ips.deployed == true
	input.pci.ids_ips.coverage.all_cde_network_traffic == true
	input.pci.ids_ips.signatures.current == true
	input.pci.ids_ips.alerts.configured == true
	input.pci.ids_ips.personnel.responds_to_alerts == true
}

# File integrity monitoring (FIM)
file_integrity_monitoring if {
	input.pci.fim.deployed == true
	input.pci.fim.critical_files.covered == true
	input.pci.fim.os_files.covered == true
	input.pci.fim.application_files.covered == true
	input.pci.fim.configuration_files.covered == true
	input.pci.fim.alerts.immediate == true
	input.pci.fim.comparison.against_baseline == true
	_num_le(input.pci.fim.frequency_days, 7)
}

# =================================================================
# 11.6 - Unauthorized changes to payment pages detected and responded to
# =================================================================

payment_page_integrity if {
	# Only required if e-commerce with hosted payment pages
	input.pci.ecommerce.payment_pages.in_scope == false
} else if {
	input.pci.ecommerce.payment_pages.in_scope == true
	input.pci.ecommerce.payment_pages.integrity_monitoring == true
	input.pci.ecommerce.payment_pages.change_detection.implemented == true
	_payment_page_frequency_ok
	input.pci.ecommerce.payment_pages.script_inventory.maintained == true
	input.pci.ecommerce.payment_pages.alerts.configured == true
}

# 11.6.1 runs at least once every seven days OR at the frequency of the entity's targeted risk analysis.
# (A content security policy is one technique, not a requirement, and no longer gates this control.)
_payment_page_frequency_ok if _num_le(input.pci.ecommerce.payment_pages.change_detection.frequency_days, 7)

_payment_page_frequency_ok if input.pci.ecommerce.payment_pages.change_detection.tra_frequency_met == true

# Every control referenced by the score, findings and roll-up has a default so a failing
# control reports false instead of making the whole score/findings undefined.
default security_testing_policies_established := false

default security_testing_roles_defined := false

default wireless_access_point_testing := false

default internal_vulnerability_scanning := false

default external_vulnerability_scanning := false

default authenticated_internal_scanning := false

default vulnerability_remediation := false

default penetration_testing := false

default pen_test_remediation := false

default segmentation_testing := false

default ids_ips_deployed := false

default file_integrity_monitoring := false

default payment_page_integrity := false

default pci_requirement_11_compliant := false

# =================================================================
# Scoring
# =================================================================

pci_requirement_11_compliant if {
	security_testing_policies_established
	security_testing_roles_defined
	wireless_access_point_testing
	internal_vulnerability_scanning
	authenticated_internal_scanning
	external_vulnerability_scanning
	vulnerability_remediation
	penetration_testing
	pen_test_remediation
	segmentation_testing
	ids_ips_deployed
	file_integrity_monitoring
	payment_page_integrity
}

default pci_requirement_11_score := 0

default pci_requirement_11_findings := {}

pci_requirement_11_score := score if {
	controls := [
		security_testing_policies_established,
		security_testing_roles_defined,
		wireless_access_point_testing,
		internal_vulnerability_scanning,
		authenticated_internal_scanning,
		external_vulnerability_scanning,
		vulnerability_remediation,
		penetration_testing,
		pen_test_remediation,
		segmentation_testing,
		ids_ips_deployed,
		file_integrity_monitoring,
		payment_page_integrity,
	]
	passed := count([c | some c in controls; c == true])
	total := count(controls)
	score := (passed / total) * 100
}

pci_requirement_11_findings := {
	"requirement_11_1": {
		"policies_established": security_testing_policies_established,
		"roles_defined": security_testing_roles_defined,
	},
	"requirement_11_2": {"wireless_ap_testing": wireless_access_point_testing},
	"requirement_11_3": {
		"internal_scanning": internal_vulnerability_scanning,
		"authenticated_internal_scanning": authenticated_internal_scanning,
		"external_scanning_asv": external_vulnerability_scanning,
		"vulnerability_remediation": vulnerability_remediation,
	},
	"requirement_11_4": {
		"penetration_testing": penetration_testing,
		"pen_test_remediation": pen_test_remediation,
		"segmentation_testing": segmentation_testing,
	},
	"requirement_11_5": {
		"ids_ips": ids_ips_deployed,
		"file_integrity_monitoring": file_integrity_monitoring,
	},
	"requirement_11_6": {"payment_page_integrity": payment_page_integrity},
	"overall_score": pci_requirement_11_score,
	"overall_compliant": pci_requirement_11_compliant,
}

# BEGIN evidence_spec (generated by scripts/gen_pci_dss_evidence_spec.py; do not edit by hand)
# The facts each check that gates pci_requirement_11_compliant reads, for pci_dss.main: a failing check is
# "evidence missing" when no alternative holds a present, non-compliant fact and some fact is absent or of
# the wrong type. Term tests are described in the generator's docstring.
evidence_spec := {
	"security_testing_policies_established": {
		"passed": security_testing_policies_established,
		"alternatives": [
			[["pci.security_testing.policies.documented", "true"], ["pci.security_testing.policies.approved", "true"], ["pci.security_testing.policies.current", "true"]],
		],
	},
	"security_testing_roles_defined": {
		"passed": security_testing_roles_defined,
		"alternatives": [
			[["pci.security_testing.roles.defined", "true"], ["pci.security_testing.responsibilities.assigned", "true"]],
		],
	},
	"wireless_access_point_testing": {
		"passed": wireless_access_point_testing,
		"alternatives": [
			[["pci.wireless.authorized_access_points.inventoried", "true"], ["pci.wireless.rogue_detection.implemented", "true"], ["pci.wireless.rogue_detection.frequency_days", "le", 90], ["pci.wireless.unauthorized_access_points.alerts.configured", "true"], ["pci.wireless.unauthorized_access_points.response.documented", "true"]],
		],
	},
	"internal_vulnerability_scanning": {
		"passed": internal_vulnerability_scanning,
		"alternatives": [
			[["pci.vuln_scanning.internal.performed", "true"], ["pci.vuln_scanning.internal.frequency_days", "le", 90], ["pci.vuln_scanning.internal.qualified_personnel", "true"], ["pci.vuln_scanning.internal.after_significant_changes", "true"], ["pci.vuln_scanning.internal.high_and_critical.remediated", "true"], ["pci.vuln_scanning.internal.rescans.performed", "true"]],
		],
	},
	"authenticated_internal_scanning": {
		"passed": authenticated_internal_scanning,
		"alternatives": [
			[["pci.vuln_scanning.internal.authenticated.performed", "true"], ["pci.vuln_scanning.internal.authenticated.non_credentialed_systems_documented", "true"], ["pci.vuln_scanning.internal.authenticated.sufficient_privileges", "true"], ["pci.vuln_scanning.internal.authenticated.scan_accounts.managed_per_8_2_2", "true"]],
			[["pci.vuln_scanning.internal.authenticated.performed", "true"], ["pci.vuln_scanning.internal.authenticated.non_credentialed_systems_documented", "true"], ["pci.vuln_scanning.internal.authenticated.sufficient_privileges", "true"], ["pci.vuln_scanning.internal.authenticated.scan_accounts.interactive_login_possible", "false"]],
		],
	},
	"external_vulnerability_scanning": {
		"passed": external_vulnerability_scanning,
		"alternatives": [
			[["pci.vuln_scanning.external.performed", "true"], ["pci.vuln_scanning.external.frequency_days", "le", 90], ["pci.vuln_scanning.external.asv.approved", "true"], ["pci.vuln_scanning.external.passing_scan.achieved", "true"], ["pci.vuln_scanning.external.after_significant_changes", "true"]],
		],
	},
	"vulnerability_remediation": {
		"passed": vulnerability_remediation,
		"alternatives": [
			[["pci.vuln_remediation.critical.resolved", "true"], ["pci.vuln_remediation.high.resolved", "true"], ["pci.vuln_remediation.medium.risk_based_timeline", "true"], ["pci.vuln_remediation.tracking.implemented", "true"], ["pci.vuln_remediation.verification.rescan_after_fix", "true"]],
			[["pci.vuln_remediation.critical.resolved", "true"], ["pci.vuln_remediation.high.within_30_days", "true"], ["pci.vuln_remediation.medium.risk_based_timeline", "true"], ["pci.vuln_remediation.tracking.implemented", "true"], ["pci.vuln_remediation.verification.rescan_after_fix", "true"]],
			[["pci.vuln_remediation.critical.within_30_days", "true"], ["pci.vuln_remediation.high.resolved", "true"], ["pci.vuln_remediation.medium.risk_based_timeline", "true"], ["pci.vuln_remediation.tracking.implemented", "true"], ["pci.vuln_remediation.verification.rescan_after_fix", "true"]],
			[["pci.vuln_remediation.critical.within_30_days", "true"], ["pci.vuln_remediation.high.within_30_days", "true"], ["pci.vuln_remediation.medium.risk_based_timeline", "true"], ["pci.vuln_remediation.tracking.implemented", "true"], ["pci.vuln_remediation.verification.rescan_after_fix", "true"]],
		],
	},
	"penetration_testing": {
		"passed": penetration_testing,
		"alternatives": [
			[["pci.pen_testing.performed", "true"], ["pci.pen_testing.frequency_months", "le", 12], ["pci.pen_testing.after_significant_infrastructure_changes", "true"], ["pci.pen_testing.qualified.independent_tester", "true"], ["pci.pen_testing.scope.network_layer", "true"], ["pci.pen_testing.scope.application_layer", "true"], ["pci.pen_testing.scope.includes_cde_perimeter", "true"], ["pci.pen_testing.scope.includes_critical_systems", "true"]],
		],
	},
	"pen_test_remediation": {
		"passed": pen_test_remediation,
		"alternatives": [
			[["pci.pen_testing.exploitable_vulnerabilities.corrected", "true"], ["pci.pen_testing.retesting.performed_after_fixes", "true"], ["pci.pen_testing.results.retained", "true"]],
		],
	},
	"segmentation_testing": {
		"passed": segmentation_testing,
		"alternatives": [
			[["pci.segmentation_testing.segmentation_used", "false"]],
			[["pci.segmentation_testing.performed", "true"], ["pci.segmentation_testing.frequency_months", "le", 6], ["pci.segmentation_testing.penetration_testing_method", "true"], ["pci.segmentation_testing.confirms_isolation", "true"], ["pci.segmentation_testing.after_segmentation_changes", "true"]],
			[["pci.segmentation_testing.performed", "true"], ["pci.segmentation_testing.frequency_months", "le", 12], ["pci.entity.service_provider", "false"], ["pci.segmentation_testing.penetration_testing_method", "true"], ["pci.segmentation_testing.confirms_isolation", "true"], ["pci.segmentation_testing.after_segmentation_changes", "true"]],
		],
	},
	"ids_ips_deployed": {
		"passed": ids_ips_deployed,
		"alternatives": [
			[["pci.ids_ips.deployed", "true"], ["pci.ids_ips.coverage.all_cde_network_traffic", "true"], ["pci.ids_ips.signatures.current", "true"], ["pci.ids_ips.alerts.configured", "true"], ["pci.ids_ips.personnel.responds_to_alerts", "true"]],
		],
	},
	"file_integrity_monitoring": {
		"passed": file_integrity_monitoring,
		"alternatives": [
			[["pci.fim.deployed", "true"], ["pci.fim.critical_files.covered", "true"], ["pci.fim.os_files.covered", "true"], ["pci.fim.application_files.covered", "true"], ["pci.fim.configuration_files.covered", "true"], ["pci.fim.alerts.immediate", "true"], ["pci.fim.comparison.against_baseline", "true"], ["pci.fim.frequency_days", "le", 7]],
		],
	},
	"payment_page_integrity": {
		"passed": payment_page_integrity,
		"alternatives": [
			[["pci.ecommerce.payment_pages.in_scope", "false"]],
			[["pci.ecommerce.payment_pages.in_scope", "true"], ["pci.ecommerce.payment_pages.integrity_monitoring", "true"], ["pci.ecommerce.payment_pages.change_detection.implemented", "true"], ["pci.ecommerce.payment_pages.change_detection.frequency_days", "le", 7], ["pci.ecommerce.payment_pages.script_inventory.maintained", "true"], ["pci.ecommerce.payment_pages.alerts.configured", "true"]],
			[["pci.ecommerce.payment_pages.in_scope", "true"], ["pci.ecommerce.payment_pages.integrity_monitoring", "true"], ["pci.ecommerce.payment_pages.change_detection.implemented", "true"], ["pci.ecommerce.payment_pages.change_detection.tra_frequency_met", "true"], ["pci.ecommerce.payment_pages.script_inventory.maintained", "true"], ["pci.ecommerce.payment_pages.alerts.configured", "true"]],
		],
	},
}

# END evidence_spec
