package governance.geisa.lee

import rego.v1

# ─── GEISA LEE Pillar — Lightweight Execution Environment ─────────────────────
# Validates that the GEISA application runs inside a recognized container/LEE
# runtime. GEISA-LEE ensures applications execute in an isolated environment
# with defined resource boundaries.
#
# Input schema:
#   input.container.runtime          — string: "lxc", "docker", "podman", "wasm"
#   input.container.runtime_version  — version string (X.Y.Z)
#   input.container.isolated         — boolean: filesystem/process isolation
#   input.container.network_mode     — string: describes network configuration
#   input.discovery_response.pillars.lee — boolean: server declares LEE support
#
# Authors: Tim Coulter, Claude (Anthropic)
# ─────────────────────────────────────────────────────────────────────────────

default compliant := false

_container := input.container

_recognized_runtimes := {"lxc", "docker", "podman", "containerd", "wasm", "kata", "firecracker"}

# ─── Violations ──────────────────────────────────────────────────────────────

violations contains "LEE: container input missing or not an object" if {
	not is_object(input.container)
}

violations contains "LEE: container.runtime must be set" if {
	is_object(_container)
	not is_string(_container.runtime)
}

violations contains "LEE: container.runtime must be non-empty" if {
	is_object(_container)
	is_string(_container.runtime)
	count(_container.runtime) == 0
}

violations contains sprintf("LEE: container.runtime '%s' is not a recognized GEISA-LEE runtime", [_container.runtime]) if {
	is_object(_container)
	is_string(_container.runtime)
	count(_container.runtime) > 0
	not _container.runtime in _recognized_runtimes
}

violations contains "LEE: container.isolated must be true" if {
	is_object(_container)
	not _container.isolated == true
}

violations contains "LEE: discovery_response must declare lee pillar as true" if {
	is_object(input.discovery_response)
	is_object(input.discovery_response.pillars)
	not input.discovery_response.pillars.lee == true
}

# ─── Output ──────────────────────────────────────────────────────────────────

compliant if { count(violations) == 0 }

compliance_report := {
	"pillar": "LEE",
	"compliant": compliant,
	"violation_count": count(violations),
	"violations": violations,
	"runtime": object.get(input, ["container", "runtime"], "unknown"),
	"runtime_version": object.get(input, ["container", "runtime_version"], "unknown"),
	"isolated": object.get(input, ["container", "isolated"], false),
	"network_mode": object.get(input, ["container", "network_mode"], "unknown"),
}
