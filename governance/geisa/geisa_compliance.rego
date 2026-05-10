package governance.geisa.compliance

import rego.v1

# ─── GEISA Runtime Compliance Orchestrator ────────────────────────────────────
# Aggregates all four GEISA pillar compliance checks (API, ADM, LEE, VEE) into
# a single compliance assessment. The `compliant` rule is true only when every
# applicable pillar passes.
#
# Usage (OPA):
#   POST /v1/data/governance/geisa/compliance
#   Body: { "input": <geisa_runtime_facts> }
#
# Required input schema:
#   input.manifest
#     .applicationId          — reverse-DNS app identifier
#     .version                — semantic version string
#     .geisa.uses             — array of GEISA services used
#     .permissions.mqtt.{publish,subscribe} — MQTT topic declarations
#   input.discovery_response
#     .status_code            — 1 = OK
#     .geisa_version          — {major, minor, patch}
#     .pillars                — {api, adm, lee, vee}
#   input.lwm2m
#     .registered             — boolean
#     .version                — "1.1" or higher
#     .registered_objects     — array of LwM2M object URIs
#     .object9                — {pkg_name, update_state, update_result, activation_state}
#   input.container
#     .runtime                — container runtime identifier
#     .runtime_version        — version string
#     .isolated               — boolean
#     .network_mode           — network configuration description
#
# Authors: Tim Coulter, Claude (Anthropic)
# ─────────────────────────────────────────────────────────────────────────────

import data.governance.geisa.api
import data.governance.geisa.adm
import data.governance.geisa.lee
import data.governance.geisa.vee

default compliant := false

# ─── Aggregate violations ─────────────────────────────────────────────────────

all_violations := array.concat(
	array.concat(
		array.concat(
			[v | some v in api.violations],
			[v | some v in adm.violations],
		),
		[v | some v in lee.violations],
	),
	[v | some v in vee.violations],
)

# ─── Overall compliance ───────────────────────────────────────────────────────

compliant if {
	api.compliant
	adm.compliant
	lee.compliant
	vee.compliant
}

# ─── Pillar summary ───────────────────────────────────────────────────────────

_pillar_status(name, is_compliant) := {"pillar": name, "compliant": is_compliant, "violation_count": count([v | some v in all_violations; startswith(v, concat("", [name, ":"]))])}

_pillars := [
	{"pillar": "API", "compliant": api.compliant, "violation_count": count(api.violations)},
	{"pillar": "ADM", "compliant": adm.compliant, "violation_count": count(adm.violations)},
	{"pillar": "LEE", "compliant": lee.compliant, "violation_count": count(lee.violations)},
	{"pillar": "VEE", "compliant": vee.compliant, "violation_count": count(vee.violations)},
]

# ─── Compliance report ────────────────────────────────────────────────────────

compliance_report := {
	"compliant": compliant,
	"app_id": input.manifest.applicationId,
	"app_version": input.manifest.version,
	"total_violations": count(all_violations),
	"pillars": _pillars,
	"violations": all_violations,
	"details": {
		"api": api.compliance_report,
		"adm": adm.compliance_report,
		"lee": lee.compliance_report,
		"vee": vee.compliance_report,
	},
}
