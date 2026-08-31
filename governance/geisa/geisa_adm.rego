package governance.geisa.adm

import rego.v1

# ─── GEISA ADM Pillar — Application/Device Management via LwM2M ───────────────
# Validates that a GEISA application was properly deployed and managed via
# OMA LwM2M (Object 9 — Software Management). Checks registration, version,
# and post-install object state.
#
# Input schema:
#   input.manifest.applicationId               — app identity (must match pkg_name)
#   input.lwm2m.registered                     — boolean
#   input.lwm2m.version                        — string "1.1" or higher
#   input.lwm2m.registered_objects             — array of URI strings (e.g. "/9/0")
#   input.lwm2m.object9.pkg_name               — installed package name
#   input.lwm2m.object9.update_state           — 4 = Installed
#   input.lwm2m.object9.update_result          — 1 = Success
#   input.lwm2m.object9.activation_state       — 1 = Active
#
# Authors: Tim Coulter, Claude (Anthropic)
# ─────────────────────────────────────────────────────────────────────────────

default compliant := false

_lwm2m := input.lwm2m

_obj9 := input.lwm2m.object9

# LwM2M version comparison: "1.1" >= "1.1" and "1.2" >= "1.1"
_lwm2m_version_ok if {
	parts := split(_lwm2m.version, ".")
	to_number(parts[0]) > 1
}

_lwm2m_version_ok if {
	parts := split(_lwm2m.version, ".")
	to_number(parts[0]) == 1
	to_number(parts[1]) >= 1
}

# ─── Violations ──────────────────────────────────────────────────────────────

violations contains "ADM: lwm2m input missing or not an object" if {
	not is_object(input.lwm2m)
}

violations contains "ADM: device is not registered with LwM2M server" if {
	is_object(_lwm2m)
	not _lwm2m.registered == true
}

violations contains sprintf("ADM: LwM2M version must be >= 1.1, got '%s'", [_lwm2m.version]) if {
	is_object(_lwm2m)
	is_string(_lwm2m.version)
	not _lwm2m_version_ok
}

violations contains "ADM: Object /9 (Software Management) must be registered" if {
	is_object(_lwm2m)
	is_array(_lwm2m.registered_objects)
	not "/9/0" in _lwm2m.registered_objects
}

violations contains "ADM: lwm2m.object9 missing or not an object" if {
	is_object(_lwm2m)
	not is_object(input.lwm2m.object9)
}

violations contains sprintf("ADM: update_result must be 1 (Success), got %v", [_obj9.update_result]) if {
	is_object(_obj9)
	_obj9.update_result != 1
}

violations contains sprintf("ADM: update_state must be 4 (Installed), got %v", [_obj9.update_state]) if {
	is_object(_obj9)
	_obj9.update_state != 4
}

violations contains "ADM: activation_state must be 1 (Active)" if {
	is_object(_obj9)
	_obj9.activation_state != 1
}

violations contains sprintf("ADM: Object9 pkg_name '%s' does not match manifest applicationId '%s'", [_obj9.pkg_name, input.manifest.applicationId]) if {
	is_object(_obj9)
	is_string(input.manifest.applicationId)
	_obj9.pkg_name != input.manifest.applicationId
}

# ─── Output ──────────────────────────────────────────────────────────────────

compliant if { count(violations) == 0 }

compliance_report := {
	"pillar": "ADM",
	"compliant": compliant,
	"violation_count": count(violations),
	"violations": violations,
	"lwm2m_version": object.get(input, ["lwm2m", "version"], "unknown"),
	"registered": object.get(input, ["lwm2m", "registered"], false),
	"registered_objects": object.get(input, ["lwm2m", "registered_objects"], []),
	"object9": object.get(input, ["lwm2m", "object9"], {}),
}
