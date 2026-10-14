# METADATA
# title: "NIST SP 800-171 Rev 3 - Configuration Management (CM) Requirements"
# custom:
#   class: compliance
#   framework: nist_sp_800_171
#   source: nist
#   domains: [us-federal, security-controls]
#   coverage:
#     checks: 16
#     cited: 7
#     expected: 7
#     found: 16
#     scope: module
#     density: full
#     basis: declared-total
#     tested: true
#     entrypoint: compliance_report
#     guard: self
#     as_of: v2.4.2
package nist.sp800_171.configuration_management

import rego.v1

# NIST SP 800-171 Rev 3 - Configuration Management (CM) Requirements
#
# Ids are NIST SP 800-171 Rev 3 element identifiers from the NIST CPRT export
# (https://csrc.nist.gov/extensions/nudp/services/json/nudp/framework/version/SP_800_171_3_0_0/export/json?element=all, sha256 19d18ef88700e468..., retrieved 2026-10-13).
# The fact checks below were written against the Rev 2 statements; each is re-keyed to the Rev 3
# requirement that carries its Rev 2 slot. A Rev 2 slot withdrawn in Rev 3 with "Incorporated into"
# is keyed to the incorporating requirement(s); one withdrawn as "Addressed by", recategorized as
# NCO, technology-specific or for consistency with SP 800-53 is retired: its rule is kept for lineage
# but it emits no violation and is not a Rev 3 control. Rev 3 status per requirement (attestation
# plus these facts) is computed by nist_800_171_main.rego (package nist_800_171.main).
# Family: 03.04 Configuration Management — Protecting Controlled Unclassified Information (CUI)

# 03.04.01 Baseline Configuration (Rev 2 3.4.1): Establish and maintain baseline configurations and inventories of organizational
#         systems throughout the respective system development life cycles
default baseline_configurations := false

baseline_configurations if {
	input.nist_800_171.configuration_management.baselines.documented == true
	input.nist_800_171.configuration_management.baselines.inventory_maintained == true
	input.nist_800_171.configuration_management.baselines.includes_all_components == true
	input.nist_800_171.configuration_management.baselines.reviewed_periodically == true
}

# 03.04.02 Configuration Settings (Rev 2 3.4.2): Establish and enforce security configuration settings for information technology
#         products employed in organizational systems
default security_configuration_settings := false

security_configuration_settings if {
	input.nist_800_171.configuration_management.security_settings.settings_defined == true
	input.nist_800_171.configuration_management.security_settings.enforcement_automated == true
	input.nist_800_171.configuration_management.security_settings.deviations_approved == true
}

# 03.04.03 Configuration Change Control (Rev 2 3.4.3): Track, review, approve, and log changes to organizational systems
default change_control := false

change_control if {
	input.nist_800_171.configuration_management.change_control.change_tracking == true
	input.nist_800_171.configuration_management.change_control.review_process == true
	input.nist_800_171.configuration_management.change_control.approval_required == true
	input.nist_800_171.configuration_management.change_control.changes_logged == true
}

# 03.04.04 Impact Analyses (Rev 2 3.4.4): Analyze the security impact of changes prior to implementation
default security_impact_analysis := false

security_impact_analysis if {
	input.nist_800_171.configuration_management.impact_analysis.performed_before_implementation == true
	input.nist_800_171.configuration_management.impact_analysis.security_team_involved == true
	input.nist_800_171.configuration_management.impact_analysis.results_documented == true
}

# 03.04.05 Access Restrictions for Change (Rev 2 3.4.5): Define, document, approve, and enforce physical and logical access restrictions
#         associated with changes to organizational systems
default change_access_restrictions := false

change_access_restrictions if {
	input.nist_800_171.configuration_management.change_access.physical_restrictions_defined == true
	input.nist_800_171.configuration_management.change_access.logical_restrictions_defined == true
	input.nist_800_171.configuration_management.change_access.approval_documented == true
	input.nist_800_171.configuration_management.change_access.enforcement_implemented == true
}

# 03.04.06 Least Functionality (Rev 2 3.4.6): Employ the principle of least functionality by configuring organizational systems
#         to provide only essential capabilities
default least_functionality := false

least_functionality if {
	input.nist_800_171.configuration_management.least_functionality.unnecessary_functions_disabled == true
	input.nist_800_171.configuration_management.least_functionality.reviewed_periodically == true
	input.nist_800_171.configuration_management.least_functionality.documented_rationale == true
}

# 03.04.06/03.04.08 (Rev 2 3.4.7, withdrawn in Rev 3: Incorporated into 03.04.06 and 03.04.08.): Restrict, disable, or prevent the use of nonessential programs, functions, ports,
#         protocols, and services
default nonessential_services_restricted := false

nonessential_services_restricted if {
	input.nist_800_171.configuration_management.nonessential.ports_restricted == true
	input.nist_800_171.configuration_management.nonessential.protocols_restricted == true
	input.nist_800_171.configuration_management.nonessential.services_restricted == true
	input.nist_800_171.configuration_management.nonessential.programs_restricted == true
}

# 03.04.08 Authorized Software – Allow by Exception (Rev 2 3.4.8): Apply deny-by-exception (blacklisting) policy to prevent use of unauthorized software
default deny_by_exception_policy := false

deny_by_exception_policy if {
	input.nist_800_171.configuration_management.software_policy.deny_by_exception_implemented == true
	input.nist_800_171.configuration_management.software_policy.authorized_software_list == true
	input.nist_800_171.configuration_management.software_policy.enforcement_automated == true
}

# RETIRED, not a Rev 3 control (Rev 2 3.4.9, withdrawn in Rev 3: Addressed by 03.01.05, 03.01.06, 03.01.07, 03.04.08, and 03.12.03.): Control and monitor user-installed software
default user_installed_software_controlled := false

user_installed_software_controlled if {
	input.nist_800_171.configuration_management.user_software.installation_restricted == true
	input.nist_800_171.configuration_management.user_software.monitoring_implemented == true
	input.nist_800_171.configuration_management.user_software.policy_documented == true
}

# Violations set
violations contains msg if {
	not baseline_configurations
	msg := "NIST SP 800-171 03.04.01: Baseline configurations and system inventories must be established, documented, and maintained"
}

violations contains msg if {
	not security_configuration_settings
	msg := "NIST SP 800-171 03.04.02: Security configuration settings must be established and enforced for all IT products"
}

violations contains msg if {
	not change_control
	msg := "NIST SP 800-171 03.04.03: Changes to organizational systems must be tracked, reviewed, approved, and logged"
}

violations contains msg if {
	not security_impact_analysis
	msg := "NIST SP 800-171 03.04.04: Security impact analysis must be performed and documented before implementing system changes"
}

violations contains msg if {
	not change_access_restrictions
	msg := "NIST SP 800-171 03.04.05: Physical and logical access restrictions for system changes must be defined, approved, and enforced"
}

violations contains msg if {
	not least_functionality
	msg := "NIST SP 800-171 03.04.06: Systems must be configured for least functionality with unnecessary functions disabled and reviewed periodically"
}

violations contains msg if {
	not nonessential_services_restricted
	msg := "NIST SP 800-171 03.04.06/03.04.08 (Rev 2 3.4.7, withdrawn in Rev 3: Incorporated into 03.04.06 and 03.04.08.): Nonessential programs, ports, protocols, and services must be restricted, disabled, or prevented"
}

violations contains msg if {
	not deny_by_exception_policy
	msg := "NIST SP 800-171 03.04.08: A deny-by-exception policy must be implemented with an authorized software list and automated enforcement"
}

# Compliance aggregation
default compliant := false

compliant if count(violations) == 0

compliance_report := {
	"family": "03.04 Configuration Management",
	"standard": "NIST SP 800-171 Rev 3",
	"total_controls": 7,
	"violations": violations,
	"compliant": compliant,
	"retired_rev2_checks": {"rev2_3.4.9_user_installed_software_controlled": user_installed_software_controlled},
	"controls": {
		"03.04.01_baseline_configurations": baseline_configurations,
		"03.04.02_security_configuration_settings": security_configuration_settings,
		"03.04.03_change_control": change_control,
		"03.04.04_security_impact_analysis": security_impact_analysis,
		"03.04.05_change_access_restrictions": change_access_restrictions,
		"03.04.06_least_functionality": least_functionality,
		"03.04.06_nonessential_services_restricted": nonessential_services_restricted,
		"03.04.08_deny_by_exception_policy": deny_by_exception_policy,
	},
}
