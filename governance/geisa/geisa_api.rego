package governance.geisa.api

import rego.v1

# ─── GEISA API Pillar — Platform Discovery Compliance ─────────────────────────
# Validates that a deployed GEISA application successfully completed Platform
# Discovery and that its MQTT topic naming follows the GEISA spec invariant:
#
#   Publish topic:   geisa/api/platform/discovery/req/<applicationId>
#   Subscribe topic: geisa/api/platform/discovery/rsp/<applicationId>
#
# Input schema:
#   input.manifest.applicationId   — reverse-DNS app identifier
#   input.manifest.geisa.uses      — array of GEISA service names used
#   input.manifest.permissions.mqtt.publish   — declared MQTT publish topics
#   input.manifest.permissions.mqtt.subscribe — declared MQTT subscribe topics
#   input.discovery_response.status_code      — 1 = OK
#   input.discovery_response.geisa_version    — {major, minor, patch}
#   input.discovery_response.pillars.api      — boolean
#
# Authors: Tim Coulter, Claude (Anthropic)
# ─────────────────────────────────────────────────────────────────────────────

default compliant := false

_app_id := input.manifest.applicationId

_discovery := input.discovery_response

_uses := input.manifest.geisa.uses

_mqtt_pub := input.manifest.permissions.mqtt.publish

_mqtt_sub := input.manifest.permissions.mqtt.subscribe

# ─── Helpers ─────────────────────────────────────────────────────────────────

_expected_pub_topic := sprintf("geisa/api/platform/discovery/req/%s", [_app_id])

_expected_sub_topic := sprintf("geisa/api/platform/discovery/rsp/%s", [_app_id])

# ─── Violations ──────────────────────────────────────────────────────────────

violations contains "API: platform discovery response missing or not an object" if {
	not is_object(input.discovery_response)
}

violations contains sprintf("API: platform discovery status_code must be 1 (OK), got %v", [_discovery.status_code]) if {
	is_object(_discovery)
	_discovery.status_code != 1
}

violations contains "API: GEISA version must be >= 1.0" if {
	is_object(_discovery)
	is_object(_discovery.geisa_version)
	_discovery.geisa_version.major < 1
}

violations contains "API: discovery_response.pillars.api must be true" if {
	is_object(_discovery)
	is_object(_discovery.pillars)
	not _discovery.pillars.api == true
}

violations contains "API: manifest.geisa.uses must include 'platform-discovery'" if {
	is_array(_uses)
	not "platform-discovery" in _uses
}

violations contains sprintf("API: manifest must declare publish topic '%s'", [_expected_pub_topic]) if {
	is_array(_mqtt_pub)
	not _expected_pub_topic in _mqtt_pub
}

violations contains sprintf("API: manifest must declare subscribe topic '%s'", [_expected_sub_topic]) if {
	is_array(_mqtt_sub)
	not _expected_sub_topic in _mqtt_sub
}

violations contains "API: manifest.applicationId must be set" if {
	not is_string(input.manifest.applicationId)
}

violations contains "API: manifest.applicationId must be non-empty" if {
	is_string(input.manifest.applicationId)
	count(input.manifest.applicationId) == 0
}

# ─── Output ──────────────────────────────────────────────────────────────────

compliant if { count(violations) == 0 }

compliance_report := {
	"pillar": "API",
	"compliant": compliant,
	"violation_count": count(violations),
	"violations": violations,
	"app_id": _app_id,
	"geisa_version": _discovery.geisa_version,
	"platform_discovery_status": _discovery.status_code,
}
