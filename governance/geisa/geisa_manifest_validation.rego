package governance.geisa.manifest_validation

import rego.v1

# ─── GEISA Application Manifest Validator ─────────────────────────────────────
# Validates a GEISA App Manifest document against the rules defined in the
# GEISA Application Manifest Schema v1.0.0.
#
# Schema source:
#   https://github.com/geisa/schemas/blob/main/geisa-application-manifest-schema.json
#
# Usage (OPA):
#   POST /v1/data/governance/geisa/manifest_validation
#   Body: { "input": <manifest-json> }
#
# Key output rules:
#   valid              — true if no violations found
#   violations         — set of violation messages
#   validation_report  — structured report with summary
# ─────────────────────────────────────────────────────────────────────────────

default valid := false

# ─── Convenience aliases ──────────────────────────────────────────────────────

_top := input["geisa-application-manifest"]

_manifest := input["geisa-application-manifest"]["manifest"]

# ─── Key existence helper ─────────────────────────────────────────────────────
# OPA's "x in obj" checks VALUES, not keys.
# Use object.keys() to correctly test for key presence.

_has_key(obj, key) if { key in object.keys(obj) }

# ─── Type / format helpers ────────────────────────────────────────────────────

# SHA-256: exactly 64 hexadecimal characters
_valid_sha256(s) if {
	is_string(s)
	count(s) == 64
	regex.match(`^[0-9A-Fa-f]+$`, s)
}

# Fixed version: X.Y.Z (no suffix)
_valid_fixed_version(v) if {
	is_string(v)
	regex.match(`^[0-9]+\.[0-9]+\.[0-9]+$`, v)
}

# Fixed version or null (GEISA-LEE / GEISA-VEE)
_valid_fixed_version_or_null(v) if { _valid_fixed_version(v) }

_valid_fixed_version_or_null(v) if { v == null }

# Application version: X.Y.Z with optional suffix (e.g. "1.0.0-beta")
_valid_app_version(v) if {
	is_string(v)
	regex.match(`^[0-9]+\.[0-9]+\.[0-9]+(\b.*)?$`, v)
}

# transport:address:port tuple
_valid_tap(s) if {
	is_string(s)
	regex.match(`^([Tt][Cc][Pp]:|[Uu][Dd][Pp]:|)([0-9A-Fa-f:\.]+|\[[0-9A-Fa-f:\.]+\]|)(:[0-9]+)$`, s)
}

# String with min / max length bounds
_valid_string_min(val, min) if {
	is_string(val)
	count(val) >= min
}

_valid_string_range(val, min, max) if {
	is_string(val)
	count(val) >= min
	count(val) <= max
}

# Integer with bounds
_valid_int_min(val, min) if {
	is_number(val)
	val >= min
}

_valid_int_range(val, min, max) if {
	is_number(val)
	val >= min
	val <= max
}

# ═══════════════════════════════════════════════════════════════════════════════
# Section 1 — Top-level structure
# ═══════════════════════════════════════════════════════════════════════════════

# 1.1 Root key must exist
violations contains "Missing required top-level key: 'geisa-application-manifest'" if {
	not _has_key(input, "geisa-application-manifest")
}

# 1.2 geisa-application-manifest must be an object
violations contains "geisa-application-manifest: must be an object" if {
	_has_key(input, "geisa-application-manifest")
	not is_object(input["geisa-application-manifest"])
}

# 1.3 manifest key required
violations contains "geisa-application-manifest: missing required field 'manifest'" if {
	is_object(_top)
	not _has_key(_top, "manifest")
}

# 1.4 manifest must be an object
violations contains "geisa-application-manifest.manifest: must be an object" if {
	is_object(_top)
	_has_key(_top, "manifest")
	not is_object(_top["manifest"])
}

# 1.5 Top-level signature required
violations contains "geisa-application-manifest: missing required field 'signature'" if {
	is_object(_top)
	not _has_key(_top, "signature")
}

# 1.6 Top-level signature must be a valid SHA-256
violations contains sprintf("geisa-application-manifest.signature: must be a 64-character hex string, got %d characters", [count(_top["signature"])]) if {
	is_object(_top)
	_has_key(_top, "signature")
	not _valid_sha256(_top["signature"])
}

# ═══════════════════════════════════════════════════════════════════════════════
# Section 2 — manifest required fields (presence checks)
# ═══════════════════════════════════════════════════════════════════════════════

_required_manifest_fields := {
	"api-access",
	"app-id",
	"app-version",
	"artifacts",
	"author",
	"communication",
	"compatibility",
	"default-configuration",
	"default-launch-strategy",
	"description",
	"external-dependencies",
	"manifest-version",
	"name",
	"resources",
}

violations contains sprintf("manifest: missing required field '%s'", [field]) if {
	is_object(_manifest)
	some field in _required_manifest_fields
	not _has_key(_manifest, field)
}

# ═══════════════════════════════════════════════════════════════════════════════
# Section 3 — manifest scalar field value validation
# ═══════════════════════════════════════════════════════════════════════════════

# 3.1 app-id: string, minLength 4
violations contains "manifest.app-id: must be a string with at least 4 characters" if {
	is_object(_manifest)
	_has_key(_manifest, "app-id")
	not _valid_string_min(_manifest["app-id"], 4)
}

# 3.2 author: string, minLength 4
violations contains "manifest.author: must be a string with at least 4 characters" if {
	is_object(_manifest)
	_has_key(_manifest, "author")
	not _valid_string_min(_manifest["author"], 4)
}

# 3.3 name: string, minLength 4
violations contains "manifest.name: must be a string with at least 4 characters" if {
	is_object(_manifest)
	_has_key(_manifest, "name")
	not _valid_string_min(_manifest["name"], 4)
}

# 3.4 description: must be a string
violations contains "manifest.description: must be a string" if {
	is_object(_manifest)
	_has_key(_manifest, "description")
	not is_string(_manifest["description"])
}

# 3.5 app-version: string matching X.Y.Z pattern
violations contains sprintf("manifest.app-version: '%s' does not match required version pattern (X.Y.Z)", [_manifest["app-version"]]) if {
	is_object(_manifest)
	_has_key(_manifest, "app-version")
	not _valid_app_version(_manifest["app-version"])
}

# 3.6 manifest-version: must be exactly "1.0.0"
violations contains sprintf("manifest.manifest-version: must be '1.0.0', got '%s'", [_manifest["manifest-version"]]) if {
	is_object(_manifest)
	_has_key(_manifest, "manifest-version")
	_manifest["manifest-version"] != "1.0.0"
}

# 3.7 api-access: must be an object
violations contains "manifest.api-access: must be an object" if {
	is_object(_manifest)
	_has_key(_manifest, "api-access")
	not is_object(_manifest["api-access"])
}

# 3.8 api-access fields must be boolean if present
_api_access_fields := {"actuator", "messaging", "instantaneous", "sensor", "waveform"}

violations contains sprintf("manifest.api-access.%s: must be a boolean", [field]) if {
	is_object(_manifest)
	is_object(_manifest["api-access"])
	some field in _api_access_fields
	_has_key(_manifest["api-access"], field)
	not is_boolean(_manifest["api-access"][field])
}

# 3.9 artifacts: must be an array with at least 1 item
violations contains "manifest.artifacts: must be an array" if {
	is_object(_manifest)
	_has_key(_manifest, "artifacts")
	not is_array(_manifest["artifacts"])
}

violations contains "manifest.artifacts: must contain at least 1 item" if {
	is_object(_manifest)
	is_array(_manifest["artifacts"])
	count(_manifest["artifacts"]) < 1
}

# 3.10 external-dependencies: must be an array
violations contains "manifest.external-dependencies: must be an array" if {
	is_object(_manifest)
	_has_key(_manifest, "external-dependencies")
	not is_array(_manifest["external-dependencies"])
}

# 3.11 external-dependencies items must be strings
violations contains sprintf("manifest.external-dependencies[%d]: must be a string", [i]) if {
	is_object(_manifest)
	is_array(_manifest["external-dependencies"])
	some i, dep in _manifest["external-dependencies"]
	not is_string(dep)
}

# 3.12 default-configuration: must be an object
violations contains "manifest.default-configuration: must be an object" if {
	is_object(_manifest)
	_has_key(_manifest, "default-configuration")
	not is_object(_manifest["default-configuration"])
}

# ═══════════════════════════════════════════════════════════════════════════════
# Section 4 — compatibility validation
# ═══════════════════════════════════════════════════════════════════════════════

_compat := _manifest["compatibility"]

# 4.1 compatibility must be an object
violations contains "manifest.compatibility: must be an object" if {
	is_object(_manifest)
	_has_key(_manifest, "compatibility")
	not is_object(_manifest["compatibility"])
}

# 4.2 GEISA-API: fixedVersion X.Y.Z
violations contains sprintf("manifest.compatibility.GEISA-API: '%v' is not a valid fixed version (X.Y.Z)", [_compat["GEISA-API"]]) if {
	is_object(_manifest)
	is_object(_compat)
	_has_key(_compat, "GEISA-API")
	not _valid_fixed_version(_compat["GEISA-API"])
}

# 4.3 GEISA-LEE: fixedVersion or null
violations contains sprintf("manifest.compatibility.GEISA-LEE: '%v' must be a valid fixed version (X.Y.Z) or null", [_compat["GEISA-LEE"]]) if {
	is_object(_manifest)
	is_object(_compat)
	_has_key(_compat, "GEISA-LEE")
	not _valid_fixed_version_or_null(_compat["GEISA-LEE"])
}

# 4.4 GEISA-VEE: fixedVersion or null
violations contains sprintf("manifest.compatibility.GEISA-VEE: '%v' must be a valid fixed version (X.Y.Z) or null", [_compat["GEISA-VEE"]]) if {
	is_object(_manifest)
	is_object(_compat)
	_has_key(_compat, "GEISA-VEE")
	not _valid_fixed_version_or_null(_compat["GEISA-VEE"])
}

# 4.5 toolchain-id: string, minLength 4, maxLength 256
violations contains "manifest.compatibility.toolchain-id: must be a string between 4 and 256 characters" if {
	is_object(_manifest)
	is_object(_compat)
	_has_key(_compat, "toolchain-id")
	not _valid_string_range(_compat["toolchain-id"], 4, 256)
}

# 4.6 toolchain-version: fixedVersion X.Y.Z
violations contains sprintf("manifest.compatibility.toolchain-version: '%v' is not a valid fixed version (X.Y.Z)", [_compat["toolchain-version"]]) if {
	is_object(_manifest)
	is_object(_compat)
	_has_key(_compat, "toolchain-version")
	not _valid_fixed_version(_compat["toolchain-version"])
}

# ═══════════════════════════════════════════════════════════════════════════════
# Section 5 — resources validation
# ═══════════════════════════════════════════════════════════════════════════════

_resources := _manifest["resources"]

# 5.1 resources must be an object
violations contains "manifest.resources: must be an object" if {
	is_object(_manifest)
	_has_key(_manifest, "resources")
	not is_object(_manifest["resources"])
}

# 5.2 app-ram: integer >= 1
violations contains "manifest.resources.app-ram: must be an integer >= 1" if {
	is_object(_manifest)
	is_object(_resources)
	_has_key(_resources, "app-ram")
	not _valid_int_min(_resources["app-ram"], 1)
}

# 5.3 storage-persistent: integer >= 0
violations contains "manifest.resources.storage-persistent: must be an integer >= 0" if {
	is_object(_manifest)
	is_object(_resources)
	_has_key(_resources, "storage-persistent")
	not _valid_int_min(_resources["storage-persistent"], 0)
}

# 5.4 storage-nonpersistent: integer >= 0
violations contains "manifest.resources.storage-nonpersistent: must be an integer >= 0" if {
	is_object(_manifest)
	is_object(_resources)
	_has_key(_resources, "storage-nonpersistent")
	not _valid_int_min(_resources["storage-nonpersistent"], 0)
}

# 5.5 app-cpu (optional): integer >= 1 if present
violations contains "manifest.resources.app-cpu: must be an integer >= 1" if {
	is_object(_manifest)
	is_object(_resources)
	_has_key(_resources, "app-cpu")
	not _valid_int_min(_resources["app-cpu"], 1)
}

# 5.6 threads (optional): integer >= 1 if present
violations contains "manifest.resources.threads: must be an integer >= 1" if {
	is_object(_manifest)
	is_object(_resources)
	_has_key(_resources, "threads")
	not _valid_int_min(_resources["threads"], 1)
}

# ═══════════════════════════════════════════════════════════════════════════════
# Section 6 — default-launch-strategy validation
# ═══════════════════════════════════════════════════════════════════════════════

_launch := _manifest["default-launch-strategy"]

# 6.1 must be an object
violations contains "manifest.default-launch-strategy: must be an object" if {
	is_object(_manifest)
	_has_key(_manifest, "default-launch-strategy")
	not is_object(_manifest["default-launch-strategy"])
}

# 6.2 max-restarts: integer >= 0
violations contains "manifest.default-launch-strategy.max-restarts: must be an integer >= 0" if {
	is_object(_manifest)
	is_object(_launch)
	_has_key(_launch, "max-restarts")
	not _valid_int_min(_launch["max-restarts"], 0)
}

# 6.3 restart-period: integer >= 0
violations contains "manifest.default-launch-strategy.restart-period: must be an integer >= 0" if {
	is_object(_manifest)
	is_object(_launch)
	_has_key(_launch, "restart-period")
	not _valid_int_min(_launch["restart-period"], 0)
}

# 6.4 start-timeout: integer 0–60
violations contains sprintf("manifest.default-launch-strategy.start-timeout: must be an integer 0-60, got %v", [_launch["start-timeout"]]) if {
	is_object(_manifest)
	is_object(_launch)
	_has_key(_launch, "start-timeout")
	not _valid_int_range(_launch["start-timeout"], 0, 60)
}

# 6.5 stop-timeout: integer 0–60
violations contains sprintf("manifest.default-launch-strategy.stop-timeout: must be an integer 0-60, got %v", [_launch["stop-timeout"]]) if {
	is_object(_manifest)
	is_object(_launch)
	_has_key(_launch, "stop-timeout")
	not _valid_int_range(_launch["stop-timeout"], 0, 60)
}

# 6.6 notify-timeout: integer 0–120
violations contains sprintf("manifest.default-launch-strategy.notify-timeout: must be an integer 0-120, got %v", [_launch["notify-timeout"]]) if {
	is_object(_manifest)
	is_object(_launch)
	_has_key(_launch, "notify-timeout")
	not _valid_int_range(_launch["notify-timeout"], 0, 120)
}

# 6.7 auto-restart (optional): boolean
violations contains "manifest.default-launch-strategy.auto-restart: must be a boolean" if {
	is_object(_manifest)
	is_object(_launch)
	_has_key(_launch, "auto-restart")
	not is_boolean(_launch["auto-restart"])
}

# 6.8 start-background (optional): boolean
violations contains "manifest.default-launch-strategy.start-background: must be a boolean" if {
	is_object(_manifest)
	is_object(_launch)
	_has_key(_launch, "start-background")
	not is_boolean(_launch["start-background"])
}

# 6.9 watchdog (optional): boolean
violations contains "manifest.default-launch-strategy.watchdog: must be a boolean" if {
	is_object(_manifest)
	is_object(_launch)
	_has_key(_launch, "watchdog")
	not is_boolean(_launch["watchdog"])
}

# 6.10 start-string (optional): string
violations contains "manifest.default-launch-strategy.start-string: must be a string" if {
	is_object(_manifest)
	is_object(_launch)
	_has_key(_launch, "start-string")
	not is_string(_launch["start-string"])
}

# 6.11 stop-string (optional): string
violations contains "manifest.default-launch-strategy.stop-string: must be a string" if {
	is_object(_manifest)
	is_object(_launch)
	_has_key(_launch, "stop-string")
	not is_string(_launch["stop-string"])
}

# ═══════════════════════════════════════════════════════════════════════════════
# Section 7 — artifacts validation (per item)
# ═══════════════════════════════════════════════════════════════════════════════

_artifact_required_fields := {"image-name", "image-type", "image-size", "uncompressed-size", "signature"}

# 7.1 Required fields presence
violations contains sprintf("manifest.artifacts[%d]: missing required field '%s'", [i, field]) if {
	is_object(_manifest)
	is_array(_manifest["artifacts"])
	some i, art in _manifest["artifacts"]
	some field in _artifact_required_fields
	not _has_key(art, field)
}

# 7.2 image-name: string, length 4–256
violations contains sprintf("manifest.artifacts[%d].image-name: must be a string between 4 and 256 characters", [i]) if {
	is_object(_manifest)
	is_array(_manifest["artifacts"])
	some i, art in _manifest["artifacts"]
	_has_key(art, "image-name")
	not _valid_string_range(art["image-name"], 4, 256)
}

# 7.3 image-type: must be "appoverlay"
violations contains sprintf("manifest.artifacts[%d].image-type: must be 'appoverlay', got '%v'", [i, art["image-type"]]) if {
	is_object(_manifest)
	is_array(_manifest["artifacts"])
	some i, art in _manifest["artifacts"]
	_has_key(art, "image-type")
	art["image-type"] != "appoverlay"
}

# 7.4 image-size: integer >= 1
violations contains sprintf("manifest.artifacts[%d].image-size: must be an integer >= 1", [i]) if {
	is_object(_manifest)
	is_array(_manifest["artifacts"])
	some i, art in _manifest["artifacts"]
	_has_key(art, "image-size")
	not _valid_int_min(art["image-size"], 1)
}

# 7.5 uncompressed-size: integer >= 1
violations contains sprintf("manifest.artifacts[%d].uncompressed-size: must be an integer >= 1", [i]) if {
	is_object(_manifest)
	is_array(_manifest["artifacts"])
	some i, art in _manifest["artifacts"]
	_has_key(art, "uncompressed-size")
	not _valid_int_min(art["uncompressed-size"], 1)
}

# 7.6 artifact signature: valid SHA-256
violations contains sprintf("manifest.artifacts[%d].signature: must be a 64-character hex string", [i]) if {
	is_object(_manifest)
	is_array(_manifest["artifacts"])
	some i, art in _manifest["artifacts"]
	_has_key(art, "signature")
	not _valid_sha256(art["signature"])
}

# ═══════════════════════════════════════════════════════════════════════════════
# Section 8 — communication validation (optional fields validated if present)
# ═══════════════════════════════════════════════════════════════════════════════

_comm := _manifest["communication"]

# 8.1 communication must be an object
violations contains "manifest.communication: must be an object" if {
	is_object(_manifest)
	_has_key(_manifest, "communication")
	not is_object(_manifest["communication"])
}

# 8.2 FAN (optional): boolean
violations contains "manifest.communication.FAN: must be a boolean" if {
	is_object(_manifest)
	is_object(_comm)
	_has_key(_comm, "FAN")
	not is_boolean(_comm["FAN"])
}

# 8.3 HAN (optional): boolean
violations contains "manifest.communication.HAN: must be a boolean" if {
	is_object(_manifest)
	is_object(_comm)
	_has_key(_comm, "HAN")
	not is_boolean(_comm["HAN"])
}

# 8.4 messaging.daily-messages: required if messaging present, integer >= 0
violations contains "manifest.communication.messaging: missing required field 'daily-messages'" if {
	is_object(_manifest)
	is_object(_comm)
	_has_key(_comm, "messaging")
	is_object(_comm["messaging"])
	not _has_key(_comm["messaging"], "daily-messages")
}

violations contains "manifest.communication.messaging.daily-messages: must be an integer >= 0" if {
	is_object(_manifest)
	is_object(_comm)
	_has_key(_comm, "messaging")
	is_object(_comm["messaging"])
	_has_key(_comm["messaging"], "daily-messages")
	not _valid_int_min(_comm["messaging"]["daily-messages"], 0)
}

# 8.5 networkAccessRequirements — operator / internet / local
_net_ifaces := {"operator", "internet", "local"}

violations contains sprintf("manifest.communication.%s: missing required field 'daily-volume'", [iface]) if {
	is_object(_manifest)
	is_object(_comm)
	some iface in _net_ifaces
	_has_key(_comm, iface)
	is_object(_comm[iface])
	not _has_key(_comm[iface], "daily-volume")
}

violations contains sprintf("manifest.communication.%s.daily-volume: must be an integer >= 0", [iface]) if {
	is_object(_manifest)
	is_object(_comm)
	some iface in _net_ifaces
	_has_key(_comm, iface)
	is_object(_comm[iface])
	_has_key(_comm[iface], "daily-volume")
	not _valid_int_min(_comm[iface]["daily-volume"], 0)
}

violations contains sprintf("manifest.communication.%s: must have at least one of 'inbound' or 'outbound'", [iface]) if {
	is_object(_manifest)
	is_object(_comm)
	some iface in _net_ifaces
	_has_key(_comm, iface)
	is_object(_comm[iface])
	not _has_key(_comm[iface], "inbound")
	not _has_key(_comm[iface], "outbound")
}

violations contains sprintf("manifest.communication.%s.inbound: '%s' does not match transport:address:port pattern", [iface, tap]) if {
	is_object(_manifest)
	is_object(_comm)
	some iface in _net_ifaces
	_has_key(_comm, iface)
	is_object(_comm[iface])
	_has_key(_comm[iface], "inbound")
	some tap in _comm[iface]["inbound"]
	not _valid_tap(tap)
}

violations contains sprintf("manifest.communication.%s.outbound: '%s' does not match transport:address:port pattern", [iface, tap]) if {
	is_object(_manifest)
	is_object(_comm)
	some iface in _net_ifaces
	_has_key(_comm, iface)
	is_object(_comm[iface])
	_has_key(_comm[iface], "outbound")
	some tap in _comm[iface]["outbound"]
	not _valid_tap(tap)
}

# ═══════════════════════════════════════════════════════════════════════════════
# Output
# ═══════════════════════════════════════════════════════════════════════════════

valid if { count(violations) == 0 }

validation_report := {
	"valid": valid,
	"violation_count": count(violations),
	"violations": violations,
	"app_id": _manifest["app-id"],
	"app_name": _manifest["name"],
	"author": _manifest["author"],
	"app_version": _manifest["app-version"],
	"manifest_version": _manifest["manifest-version"],
}
