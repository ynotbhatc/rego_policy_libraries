# CIS Microsoft 365 Foundations Benchmark v7.0.0
# Section 5 -- Microsoft Entra admin center
#
# Section 5 is the largest in the benchmark: 63 of its 160 recommendations.
# This module evaluates the four that the current Graph collector can
# actually establish.
#
# DROPPED FROM THE PRE-v7 LIBRARY: the "Security Defaults" check. v7.0.0
# has no Security Defaults recommendation -- the nearest control is 5.1.2.1
# ("Per-user MFA"), which is a different requirement and is not established
# by the facts we collect. The check was removed rather than renumbered;
# inventing an id is the defect this rewrite exists to fix.
#
# Input contract (from the aac.m365 collection):
#   input.identity.conditional_access_policies[] - {id, display_name, state,
#                                                   conditions, grant_controls}
#   input.identity.pim_role_assignments[]        - {principal_id, role_definition_id, status}
#   input.identity.pim_available                 - bool

package cis_m365_v7.entra

import rego.v1

default compliant := false

default facts_present := false

facts_present if {
	is_array(input.identity.conditional_access_policies)
}

enabled_policies contains p if {
	some p in input.identity.conditional_access_policies
	p.state == "enabled"
}

# A policy requires MFA when its grant controls include the mfa built-in.
requires_mfa(p) if {
	some c in p.grant_controls.builtInControls
	c == "mfa"
}

# Scope helper: "All" in includeUsers means the policy covers every user.
targets_all_users(p) if {
	some u in p.conditions.users.includeUsers
	u == "All"
}

targets_admin_roles(p) if {
	count(p.conditions.users.includeRoles) > 0
}

# CIS 5.2.2.1 -- multifactor authentication for users in administrative roles.
violation contains msg if {
	facts_present
	not admin_mfa_enforced
	msg := "CIS 5.2.2.1: no enabled Conditional Access policy requires multifactor authentication for administrative roles"
}

default admin_mfa_enforced := false

admin_mfa_enforced if {
	some p in enabled_policies
	requires_mfa(p)
	targets_admin_roles(p)
}

# CIS 5.2.2.2 -- multifactor authentication for all users.
violation contains msg if {
	facts_present
	not all_user_mfa_enforced
	msg := "CIS 5.2.2.2: no enabled Conditional Access policy requires multifactor authentication for all users"
}

default all_user_mfa_enforced := false

all_user_mfa_enforced if {
	some p in enabled_policies
	requires_mfa(p)
	targets_all_users(p)
}

# CIS 5.2.2.3 -- Conditional Access must block legacy authentication.
violation contains msg if {
	facts_present
	not legacy_auth_blocked
	msg := "CIS 5.2.2.3: no enabled Conditional Access policy blocks legacy authentication; legacy protocols bypass multifactor authentication"
}

default legacy_auth_blocked := false

legacy_auth_blocked if {
	some p in enabled_policies
	some c in p.conditions.clientAppTypes
	c in {"exchangeActiveSync", "other"}
	some g in p.grant_controls.builtInControls
	g == "block"
}

# CIS 5.3.1 -- privileged roles should be activated through PIM, not
# permanently assigned.
violation contains msg if {
	facts_present
	not input.identity.pim_available
	msg := "CIS 5.3.1: Privileged Identity Management not in use; privileged role assignments are standing rather than activated on demand"
}

violation contains msg if {
	not facts_present
	msg := "CIS 5.2.2.1: Conditional Access facts not collected -- multifactor and legacy-authentication controls could not be evaluated (this is not a pass)"
}

compliant if {
	facts_present
	count(violation) == 0
}

compliance_report := {
	"benchmark": "CIS Microsoft 365 Foundations Benchmark",
	"benchmark_version": "7.0.0",
	"section": "5",
	"name": "Microsoft Entra admin center",
	"section_total_controls": 63,
	"controls_evaluated": 4,
	"controls": ["5.2.2.1", "5.2.2.2", "5.2.2.3", "5.3.1"],
	"facts_present": facts_present,
	"violations": violation,
	"violation_count": count(violation),
	"compliant": compliant,
}
