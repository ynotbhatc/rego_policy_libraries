# METADATA
# title: "GEISA VEE Pillar — Virtual Execution Environment"
# custom:
#   class: governance
#   framework: geisa
#   source: geisa
#   domains: [ot, energy, smart-grid]
#   coverage:
#     checks: 3
#     cited: 0
#     density: sparse
#     basis: size
#     tested: true
#     entrypoint: compliance_report
#     guard: self
#     as_of: v2.4.1
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
	not is_object(object.get(input, "container", null))
}

# ─── Output ──────────────────────────────────────────────────────────────────

# When VEE is not required, the pillar trivially passes.
# Fail-closed: without the facts this module keys on, it reports a violation rather than silence.
violations contains "GEISA: FAIL-CLOSED - facts 'input.container' were not supplied; this module cannot be evaluated and is reported non-compliant" if {
	not input.container
}

compliant if {
	# "VEE not required" is only knowable from a discovery response; without one the module cannot be evaluated
	input.discovery_response
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
