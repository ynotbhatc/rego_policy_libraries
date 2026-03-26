# PCI DSS v4.0 Requirement 7 - Restrict Access to System Components and Cardholder Data
# by Business Need to Know

package pci_dss.access_control.requirement_7

import rego.v1

# =================================================================
# 7.1 - Processes and mechanisms for restricting access
# =================================================================

access_control_policies_established if {
	input.pci.access_control.policies.documented == true
	input.pci.access_control.policies.approved == true
	input.pci.access_control.policies.current == true
	input.pci.access_control.policies.reviewed_annually == true
}

access_control_roles_defined if {
	input.pci.access_control.roles.defined == true
	input.pci.access_control.responsibilities.assigned == true
	input.pci.access_control.accountability.established == true
}

# =================================================================
# 7.2 - Access to system components and data is appropriately defined and assigned
# =================================================================

# Access model based on least privilege and need to know
least_privilege_access_model if {
	input.pci.access_model.least_privilege.implemented == true
	input.pci.access_model.need_to_know.enforced == true
	input.pci.access_model.default_deny.configured == true
	input.pci.access_model.access_rules.documented == true
}

# Role-based access control implemented
rbac_implemented if {
	input.pci.rbac.enabled == true
	input.pci.rbac.roles.defined == true
	input.pci.rbac.roles.cde_access.restricted == true
	input.pci.rbac.privilege_assignment.approved == true
	input.pci.rbac.conflicting_duties.prevented == true
}

# Access to all system components based on individual job function
job_function_based_access if {
	input.pci.access_assignment.job_functions.documented == true
	input.pci.access_assignment.access_required.justified == true
	input.pci.access_assignment.approval_required == true
	input.pci.access_assignment.manager_approval == true
}

# Privileged user access managed
privileged_access_managed if {
	input.pci.privileged_access.inventory.maintained == true
	input.pci.privileged_access.assignment.approved == true
	input.pci.privileged_access.separation_from_normal.enforced == true
	input.pci.privileged_access.just_in_time.available == true
	input.pci.privileged_access.monitoring.enabled == true
}

# Third-party access managed
third_party_access_managed if {
	input.pci.third_party_access.inventory.maintained == true
	input.pci.third_party_access.need_to_know.enforced == true
	input.pci.third_party_access.time_limited == true
	input.pci.third_party_access.mfa.required == true
	input.pci.third_party_access.monitoring.enabled == true
}

# =================================================================
# 7.2.4 - All user accounts reviewed at least every 6 months
# =================================================================

user_access_reviews if {
	input.pci.access_review.performed == true
	input.pci.access_review.frequency_months <= 6
	input.pci.access_review.all_accounts.included == true
	input.pci.access_review.privileged_accounts.reviewed_quarterly == true
	input.pci.access_review.results.documented == true
	input.pci.access_review.inappropriate_access.removed == true
}

# =================================================================
# 7.2.5 - Application and system accounts managed
# =================================================================

application_system_accounts_managed if {
	input.pci.system_accounts.inventory.maintained == true
	input.pci.system_accounts.access.limited_to_functions_needed == true
	input.pci.system_accounts.interactive_login.disabled_unless_needed == true
	input.pci.system_accounts.review.annually == true
}

# =================================================================
# 7.3 - Access to system components and data managed via an access control system
# =================================================================

access_control_system if {
	input.pci.acs.implemented == true
	input.pci.acs.all_cde_system_components.covered == true
	input.pci.acs.default_deny.configured == true
	input.pci.acs.settings.restriction_unless_specifically_allowed == true
}

# =================================================================
# Scoring
# =================================================================

pci_requirement_7_compliant if {
	access_control_policies_established
	access_control_roles_defined
	least_privilege_access_model
	rbac_implemented
	job_function_based_access
	privileged_access_managed
	third_party_access_managed
	user_access_reviews
	application_system_accounts_managed
	access_control_system
}

pci_requirement_7_score := score if {
	controls := [
		access_control_policies_established,
		access_control_roles_defined,
		least_privilege_access_model,
		rbac_implemented,
		job_function_based_access,
		privileged_access_managed,
		third_party_access_managed,
		user_access_reviews,
		application_system_accounts_managed,
		access_control_system,
	]
	passed := count([c | some c in controls; c == true])
	total := count(controls)
	score := (passed / total) * 100
}

pci_requirement_7_findings := {
	"requirement_7_1": {
		"policies_established": access_control_policies_established,
		"roles_defined": access_control_roles_defined,
	},
	"requirement_7_2": {
		"least_privilege": least_privilege_access_model,
		"rbac": rbac_implemented,
		"job_function_access": job_function_based_access,
		"privileged_access": privileged_access_managed,
		"third_party_access": third_party_access_managed,
		"user_access_reviews": user_access_reviews,
		"system_accounts": application_system_accounts_managed,
	},
	"requirement_7_3": {
		"access_control_system": access_control_system,
	},
	"overall_score": pci_requirement_7_score,
	"overall_compliant": pci_requirement_7_compliant,
}
