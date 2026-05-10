package governance.geisa.vee

import rego.v1

# ─── GEISA VEE Pillar — Virtual Execution Environment ─────────────────────────
# Validates VEE compliance when the device and/or manifest declare VEE support.
# VEE extends LEE with hardware-level virtualization (hypervisor, TEE, etc.).
# This check is CONDITIONAL — if discovery_response.pillars.vee == false and the
# manifest does not declare VEE usage, no violations are raised.
#
# Input schema:
#   input.discovery_response.pillars.vee  — boolean: server declares VEE support
#   input.container.runtime               — must be a VEE-capable runtime if vee=true
#   input.container.vee_type              — optional: "hypervisor", "tee", "unikernel"
#
# Authors: Tim Coulter, Claude (Anthropic)
# ─────────────────────────────────────────────────────────────────────────────

default compliant := false

_pillars := input.discovery_response.pillars

_container := input.container

_vee_capable_runtimes := {"kata", "firecracker", "qemu", "xen", "tee-ta"}

# VEE is not required if the server advertises vee=false
default _vee_required := false

_vee_required if {
	is_object(_pillars)
	_pillars.vee == true
}

# ─── Violations (only when VEE is required) ───────────────────────────────────

violations contains "VEE: discovery_response.pillars.vee is true but container.runtime is not VEE-capable" if {
	_vee_required
	is_object(_container)
	is_string(_container.runtime)
	not _container.runtime in _vee_capable_runtimes
}

violations contains "VEE: discovery_response.pillars.vee is true but container input is missing" if {
	_vee_required
	not is_object(input.container)
}

# ─── Output ──────────────────────────────────────────────────────────────────

# When VEE is not required, the pillar trivially passes.
compliant if {
	not _vee_required
}

compliant if {
	_vee_required
	count(violations) == 0
}

_vee_status := "not_required" if { not _vee_required }

_vee_status := "required_and_compliant" if { _vee_required; count(violations) == 0 }

_vee_status := "required_and_non_compliant" if { _vee_required; count(violations) > 0 }

compliance_report := {
	"pillar": "VEE",
	"compliant": compliant,
	"vee_required": _vee_required,
	"vee_status": _vee_status,
	"violation_count": count(violations),
	"violations": violations,
}
