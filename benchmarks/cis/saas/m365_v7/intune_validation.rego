# CIS Microsoft 365 Foundations Benchmark v7.0.0
# Section 4 -- Microsoft Intune admin center
#
# Section 4 has exactly 2 recommendations and uses TWO-level control ids
# (4.1, 4.2) where every other section uses three or four. That is the
# benchmark's own numbering, not a typo.
#
# Both are reachable from Microsoft Graph, but only with the
# DeviceManagementConfiguration.Read.All application permission, which is
# an ADDITION to what the other collectors need. Without it both controls
# report as unevaluable rather than passing.
#
# Input contract (aac.m365.m365_intune_facts):
#   input.intune.secure_by_default                  - bool
#   input.intune.enrollment_platform_restrictions[] - {display_name, platforms{}}
#   input.intune.unavailable                        - {fact_key: reason}

package cis_m365_v7.intune

import rego.v1

default compliant := false

# `default` matters here: with no input at all (a bare `opa eval`, or a
# collector that never ran) a top-level object.get(input, ...) is
# undefined, which collapses compliance_report to {} at the endpoint.
default unavailable := {}

unavailable := input.intune.unavailable

default collected := false

collected if {
	input.intune.collected == true
}

available(key) if {
	collected
	not unavailable[key]
}

# ── CIS 4.1 -- devices without a compliance policy are 'not compliant' ─
# Intune calls this "secure by default". When false, a device that no
# compliance policy targets is treated as compliant, so Conditional
# Access admits it.
violation contains msg if {
	available("device_management_settings")
	input.intune.secure_by_default == false
	msg := "CIS 4.1: devices not targeted by a compliance policy are marked compliant rather than 'not compliant' -- an unmanaged device satisfies device-compliance Conditional Access by default"
}

# ── CIS 4.2 -- block enrollment of personally owned devices ───────────
violation contains msg if {
	available("enrollment_configurations")
	count(input.intune.enrollment_platform_restrictions) == 0
	msg := "CIS 4.2: no platform enrollment restriction is configured, so device enrollment for personally owned devices is not blocked by default"
}

violation contains msg if {
	available("enrollment_configurations")
	some r in input.intune.enrollment_platform_restrictions
	some platform, settings in r.platforms
	settings.personal_device_enrollment_blocked == false
	msg := sprintf("CIS 4.2: enrollment restriction '%s' permits personally owned %s devices; personal device enrollment should be blocked by default", [r.display_name, platform])
}

# ── Fail closed ───────────────────────────────────────────────────────
FACT_CONTROLS := {
	"device_management_settings": "4.1",
	"enrollment_configurations": "4.2",
}

violation contains msg if {
	some key, reason in unavailable
	control := object.get(FACT_CONTROLS, key, "4.1")
	msg := sprintf("CIS %s: could not be evaluated -- %s (this is not a pass)", [control, reason])
}

violation contains msg if {
	not collected
	msg := "CIS 4.1: Intune facts were not collected, so whether devices without a compliance policy are marked 'not compliant' could not be established -- section 4 was not evaluated (this is not a pass). Requires the DeviceManagementConfiguration.Read.All application permission."
}

compliant if {
	collected
	count(violation) == 0
}

compliance_report := {
	"benchmark": "CIS Microsoft 365 Foundations Benchmark",
	"benchmark_version": "7.0.0",
	"section": "4",
	"name": "Microsoft Intune admin center",
	"section_total_controls": 2,
	"controls_evaluated": 2,
	"controls": ["4.1", "4.2"],
	"facts_present": collected,
	"unavailable_facts": unavailable,
	"violations": violation,
	"violation_count": count(violation),
	"compliant": compliant,
}
