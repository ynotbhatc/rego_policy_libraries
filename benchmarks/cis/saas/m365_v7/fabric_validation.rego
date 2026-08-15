# CIS Microsoft 365 Foundations Benchmark v7.0.0
# Section 9 -- Microsoft Fabric
#
# All 12 of section 9's recommendations are Fabric tenant settings.
# Microsoft Graph does not expose them; they come from the Fabric /
# Power BI admin API, a third authentication surface for this collection.
#
# The settingName for each control is taken from the benchmark's own
# audit procedure, not inferred from the control title.
#
# TWO WAYS A SETTING PASSES: most of these settings are not simple
# booleans. Fabric lets a setting be enabled but scoped to named security
# groups, which is what the benchmark accepts for several controls -- the
# question is not "is it off" but "is it off, or restricted to a defined
# group". Treating enabled-with-scoping as a violation would flood a
# correctly-configured tenant with false findings.
#
# Input contract (aac.m365.m365_fabric_admin_facts):
#   input.fabric.settings[<settingName>] - {enabled,
#                                           can_specify_security_groups,
#                                           enabled_security_groups[], ...}
#   input.fabric.unavailable             - {key: reason}

package cis_m365_v7.fabric

import rego.v1

default compliant := false

default unavailable := {}

unavailable := input.fabric.unavailable

default collected := false

collected if {
	input.fabric.collected == true
}

settings := object.get(input, ["fabric", "settings"], {})

available(name) if {
	collected
	not unavailable[name]
	not unavailable.tenant_settings
	_ := settings[name]
}

# A setting is adequately restricted when it is off outright, or on but
# limited to explicitly named security groups.
restricted(name) if {
	settings[name].enabled == false
}

restricted(name) if {
	settings[name].enabled == true
	count(object.get(settings[name], "enabled_security_groups", [])) > 0
}

SETTING_CONTROLS := {
	"AllowGuestUserToAccessSharedContent": "9.1.1",
	"ExternalSharingV2": "9.1.2",
	"ElevatedGuestsTenant": "9.1.3",
	"PublishToWeb": "9.1.4",
	"RScriptVisual": "9.1.5",
	"ShareLinkToEntireOrg": "9.1.7",
	"EnableDatasetInPlaceSharing": "9.1.8",
	"ServicePrincipalAccessPermissionAPIs": "9.1.10",
	"AllowServicePrincipalsCreateAndUseProfiles": "9.1.11",
	"ServicePrincipalAccessGlobalAPIs": "9.1.12",
}

SETTING_SUBJECTS := {
	"AllowGuestUserToAccessSharedContent": "guest user access to Fabric is not restricted",
	"ExternalSharingV2": "external user invitations are not restricted",
	"ElevatedGuestsTenant": "guest access to content is not restricted",
	"PublishToWeb": "'Publish to web' is not restricted, so reports can be exposed publicly",
	"RScriptVisual": "interact with and share R and Python visuals is not disabled",
	"ShareLinkToEntireOrg": "shareable links are not restricted -- links can be issued to the entire organization",
	"EnableDatasetInPlaceSharing": "enabling of external data sharing is not restricted",
	"ServicePrincipalAccessPermissionAPIs": "access to APIs by service principals is not restricted",
	"AllowServicePrincipalsCreateAndUseProfiles": "service principals can create and use profiles",
	"ServicePrincipalAccessGlobalAPIs": "service principals ability to create workspaces and connections is not restricted",
}

# ── The permissive settings: off, or scoped to a named group ─────────
violation contains msg if {
	some name, control in SETTING_CONTROLS
	available(name)
	not restricted(name)
	msg := sprintf("CIS %s: %s (Fabric tenant setting '%s' is enabled for the whole organization)", [control, SETTING_SUBJECTS[name], name])
}

# ── CIS 9.1.6 -- sensitivity labels must be ENABLED, not restricted ───
# The inverse of the settings above: this one is a protection, so the
# benchmark wants it on rather than off.
violation contains msg if {
	available("EimInformationProtectionEdit")
	settings.EimInformationProtectionEdit.enabled == false
	msg := "CIS 9.1.6: 'Allow users to apply sensitivity labels for content' is disabled, so Fabric content cannot be classified"
}

# ── CIS 9.1.9 -- ResourceKey authentication must be BLOCKED ───────────
violation contains msg if {
	available("BlockResourceKeyAuthentication")
	settings.BlockResourceKeyAuthentication.enabled == false
	msg := "CIS 9.1.9: 'Block ResourceKey Authentication' is not enabled, so streaming datasets can be pushed with a resource key instead of an identity"
}

# ── Fail closed ───────────────────────────────────────────────────────
ALL_SETTING_CONTROLS := object.union(SETTING_CONTROLS, {
	"EimInformationProtectionEdit": "9.1.6",
	"BlockResourceKeyAuthentication": "9.1.9",
	"tenant_settings": "9.1.1",
})

violation contains msg if {
	some key, reason in unavailable
	control := object.get(ALL_SETTING_CONTROLS, key, "9.1.1")
	msg := sprintf("CIS %s: could not be evaluated -- %s (this is not a pass)", [control, reason])
}

violation contains msg if {
	not collected
	msg := "CIS 9.1.1: Fabric tenant settings were not collected, so whether guest user access is restricted could not be established -- section 9 was not evaluated (this is not a pass)"
}

compliant if {
	collected
	count(violation) == 0
}

compliance_report := {
	"benchmark": "CIS Microsoft 365 Foundations Benchmark",
	"benchmark_version": "7.0.0",
	"section": "9",
	"name": "Microsoft Fabric",
	"section_total_controls": 12,
	"controls_evaluated": 12,
	"controls": [
		"9.1.1", "9.1.2", "9.1.3", "9.1.4", "9.1.5", "9.1.6",
		"9.1.7", "9.1.8", "9.1.9", "9.1.10", "9.1.11", "9.1.12",
	],
	"facts_present": collected,
	"unavailable_facts": unavailable,
	"evidence_strength": {
		"section": "collected from the Fabric admin API. CIS documents these as portal steps plus a CIS-supplied helper function; the API returns the same tenantSettings the portal displays. A setting that is enabled but scoped to named security groups is treated as restricted, which is what the benchmark accepts.",
	},
	"violations": violation,
	"violation_count": count(violation),
	"compliant": compliant,
}
