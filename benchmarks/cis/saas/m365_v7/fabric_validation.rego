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

# METADATA
# title: "CIS Microsoft 365 Foundations Benchmark v7.0.0"
# custom:
#   class: security
#   framework: cis_saas
#   source: cis
#   domains: [saas, m365]
#   coverage:
#     checks: 16
#     cited: 13
#     density: sized
#     basis: size
#     tested: true
#     entrypoint: compliance_report
#     guard: self
#     as_of: v2.4.2
package cis_m365_v7.fabric

import rego.v1

default compliant := false

default unavailable := {}

unavailable := input.fabric.unavailable if is_object(input.fabric.unavailable)

default collected := false

collected if {
	input.fabric.collected == true
}

default settings := {}

settings := input.fabric.settings if is_object(input.fabric.settings)

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
	count(_groups(settings[name])) > 0
}

# the security groups a setting is scoped to: absent or null means none (the
# API omits the list for a setting that applies to the whole organisation);
# any other non-list value is not read
_groups(s) := object.get(s, "enabled_security_groups", []) if is_array(object.get(s, "enabled_security_groups", []))

_groups(s) := [] if object.get(s, "enabled_security_groups", []) == null

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
	is_boolean(settings[name].enabled)
	is_array(_groups(settings[name]))
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

# every setting this module reads, with its control
ALL_SETTING_CONTROLS := object.union(SETTING_CONTROLS, {
	"EimInformationProtectionEdit": "9.1.6",
	"BlockResourceKeyAuthentication": "9.1.9",
	"tenant_settings": "9.1.1",
})

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
	"evidence_strength": {"section": "collected from the Fabric admin API. CIS documents these as portal steps plus a CIS-supplied helper function; the API returns the same tenantSettings the portal displays. A setting that is enabled but scoped to named security groups is treated as restricted, which is what the benchmark accepts."},
	"violations": violation,
	"violation_count": count(violation),
	"compliant": compliant,
}

# ── Per-control results ──────────────────────────────────────────────
# `decidable` holds the controls of this section whose facts were all
# collected; CONTROL_EVIDENCE names the input paths each one reads ("[]"
# = every element of a list). The main report marks a control that is not
# decidable "evidence_missing" even where no violation above names it: an
# absent fact must never read as a pass. Each gate restates the condition
# of its rule above; change them together.
CONTROL_EVIDENCE := {id: paths |
	some name, id in ALL_SETTING_CONTROLS
	name != "tenant_settings"
	paths := _setting_paths(name)
}

# the ten settings judged by restricted() also read the security-group scope
_setting_paths(name) := [concat(".", ["fabric", "settings", name, "enabled"]), concat(".", ["fabric", "settings", name, "enabled_security_groups"])] if SETTING_CONTROLS[name]

_setting_paths(name) := [concat(".", ["fabric", "settings", name, "enabled"])] if not SETTING_CONTROLS[name]

decidable contains id if {
	some name, id in ALL_SETTING_CONTROLS
	name != "tenant_settings"
	available(name)
	is_boolean(settings[name].enabled)
	_scope_readable(name)
}

_scope_readable(name) if not SETTING_CONTROLS[name]

_scope_readable(name) if {
	SETTING_CONTROLS[name]
	is_array(_groups(settings[name]))
}

# ── Evidence gaps, reported by control id ─────────────────────────────
# A gap names every control it blocks ("tenant_settings" blocks all twelve),
# so the per-control results and an exporter reading the ids agree on what was
# not evaluated. An unavailable key that is neither "tenant_settings" nor a
# setting read here is reported on its own, attributed to no control.
FACT_CONTROLS := object.union(
	{name: [id] |
		some name, id in ALL_SETTING_CONTROLS
		name != "tenant_settings"
	},
	{"tenant_settings": _section_controls},
)

_section_controls := _natural_sort(object.keys(CONTROL_EVIDENCE))

# ids in benchmark order (9.1.2 before 9.1.10)
_natural_sort(ids) := [pair[1] | some pair in sort([[key, id] |
	some id in ids
	parts := split(id, ".")
	key := concat(".", [sprintf("%03d", [to_number(x)]) | some x in parts])
])]

_gap(ids, why) := sprintf("CIS %s: evidence missing -- %s (this is not a pass)", [concat("/", ids), why])

_source_gaps contains [_section_controls, "Fabric tenant settings were not collected (fabric.collected is not true)"] if not collected

_source_gaps contains [FACT_CONTROLS[key], sprintf("fabric.unavailable.%s: %v", [key, reason])] if {
	collected
	some key, reason in unavailable
}

_gap_ids contains id if {
	some g in _source_gaps
	some id in g[0]
}

# a source gap names each control it leaves undecided in a message of its own, so the
# violation count is never smaller than the number of controls that are not a pass
_evidence_gaps contains _gap([id], concat("; ", sort(whys))) if {
	some id in _gap_ids
	not id in decidable
	whys := {g[1] | some g in _source_gaps; id in g[0]}
}

_evidence_gaps contains msg if {
	some key, reason in unavailable
	not FACT_CONTROLS[key]
	msg := sprintf("M365 section 9 (Fabric): unrecognised unavailable key '%s' (%v) -- this module reads no setting of that name, so it is attributed to no control (this is not a pass)", [key, reason])
}

_evidence_gaps contains _gap([id], why) if {
	some id, paths in CONTROL_EVIDENCE
	not id in decidable
	not id in _gap_ids
	why := sprintf("%s not collected or not of the expected type", [concat(", ", paths)])
}

violation contains msg if some msg in _evidence_gaps
