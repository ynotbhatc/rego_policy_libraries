# METADATA
# title: "NIST SP 800-53 Rev 5 — System and Communications Protection (SC) Family"
# custom:
#   class: compliance
#   framework: nist_sp_800_53
#   source: nist
#   domains: [us-federal, security-controls]
#   coverage:
#     checks: 64
#     cited: 62
#     density: sized
#     basis: size
#     tested: true
#     entrypoint: compliance_report
#     guard: self
#     as_of: v2.5.0
package nist.sp800_53.system_communications

import rego.v1

# NIST SP 800-53 Rev 5 — System and Communications Protection (SC) Family
# Boundary protection, transmission confidentiality/integrity, key management.
#
# Control ids and titles checked against the NIST OSCAL catalog, SP 800-53 Rev 5 release 5.2.0.
# Evaluated: 62 ids (SC-7(24) is the Privacy-baseline enhancement), listed in evaluated_controls at the end. The 28 Low/Moderate ids (SP 800-53B; SC-4,
# SC-7(3), SC-7(4), SC-7(5), SC-7(7), SC-7(8), SC-22 and SC-39 are the Moderate additions) plus the High-baseline
# enhancements SC-7(10), SC-7(12), SC-7(18), SC-7(20), SC-7(21), SC-12(1) and the remaining active base controls
# SC-6, SC-11, SC-16, SC-24 to SC-27, SC-29 to SC-32, SC-34 to SC-38, SC-40 to SC-44 and SC-46 to SC-51
# (SC-33 is withdrawn into SC-8). SC-19 (Voice over Internet Protocol) is WITHDRAWN in Rev 5
# ("Technology-specific; addressed as any other technology or protocol") and is not assessed.
#
# SC-8 and SC-28 protect "the [Selection: confidentiality; integrity]" of information: the selection is an
# organization-defined parameter and the mechanism is the organisation's choice. Cryptography is the
# enhancement SC-8(1) / SC-28(1), evaluated as its own control.

_sc := object.get(input, "sc_controls", {})

_root := "sc_controls"

# ---------------------------------------------------------------------------------------------------------
# Evidence helpers. Every value is read with object.get(..., null).
# ---------------------------------------------------------------------------------------------------------

_val(path) := object.get(input, array.concat([_root], path), null)

_p(path) := concat(".", array.concat(["input", _root], path))

# Boolean checks pass only on `== true` (strict since 2026-11-19; a truthy "yes", 1 or object no longer passes):
# false keeps the original text, any non-boolean (or a path through a non-object) is evidence missing.
_strict(path, text) := text if {
	is_boolean(_val(path))
} else := sprintf("evidence missing — %s not collected", [_p(path)])

# Leading "evidence missing — ... not collected; " when some facts behind a finding were not collected.
_ev_prefix(m) := "" if {
	count(m) == 0
} else := sprintf("evidence missing — %s not collected; ", [concat(", ", sort(m))])

# Booleans: reqs maps a fact key to the text reported when that fact is false. Only `true` passes.
_bool_missing(sec, reqs) := {_p(array.concat(sec, [k])) | some k, _ in reqs; not is_boolean(_val(array.concat(sec, [k])))}

_bool_unmet(sec, reqs) := {d | some k, d in reqs; _val(array.concat(sec, [k])) == false}

# Organization-defined frequency: observed <sec>.days_since_last against <sec>.odp.frequency_days.
_freq_keys := [["days_since_last"], ["odp", "frequency_days"]]

_freq_missing(sec) := {_p(array.concat(sec, k)) | some k in _freq_keys; not is_number(_val(array.concat(sec, k)))}

_freq_unmet(sec, what) := {d |
	obs := _val(array.concat(sec, ["days_since_last"]))
	odp := _val(array.concat(sec, ["odp", "frequency_days"]))
	is_number(obs)
	is_number(odp)
	obs > odp
	d := sprintf("%s last %v days ago; the organization-defined frequency is %v days", [what, obs, odp])
}

# Counts that must be zero. A value that is not a non-negative whole number is missing evidence.
# A count: a non-negative whole number. Anything else (absent, null, "1", a negative or a fractional number) is
# evidence missing.
_count_ok(x) if {
	is_number(x)
	x >= 0
	floor(x) == x
}

_zero_missing(sec, k) := {_p(array.concat(sec, [k])) | not _count_ok(_val(array.concat(sec, [k])))}

_zero_unmet(sec, k, what) := {d |
	n := _val(array.concat(sec, [k]))
	is_number(n)
	_count_ok(n)
	n > 0
	d := sprintf("%v %s", [n, what])
}

# One finding text: the missing evidence first, then every unmet requirement.
_mpart(m) := [] if {
	count(m) == 0
} else := [sprintf("evidence missing — %s not collected", [concat(", ", sort(m))])]

_detail(m, u) := concat("; ", array.concat(_mpart(m), sort(u)))

_valid_properties := {"confidentiality", "integrity"}

# The organisation's SC-8 selection, when supplied as a non-empty list of confidentiality / integrity.
_sc8_selection := {p | some p in object.get(_sc, ["transmission_protection", "odp", "properties"], [])}

_sc8_selection_valid if {
	count(_sc8_selection) > 0
	every p in _sc8_selection {
		p in _valid_properties
	}
}

# Without a valid selection both properties are required: protecting both satisfies any selection.
default sc8_required_properties := {"confidentiality", "integrity"}

sc8_required_properties := _sc8_selection if _sc8_selection_valid

_sc8_protected contains "confidentiality" if object.get(_sc, ["transmission_confidentiality", "protected"], false) == true

_sc8_protected contains "confidentiality" if object.get(_sc, ["transmission_confidentiality", "encrypted"], false) == true

_sc8_protected contains "integrity" if object.get(_sc, ["transmission_integrity", "protected"], false) == true

_sc8_protected contains "integrity" if object.get(_sc, ["transmission_integrity", "cryptographic"], false) == true

_sc8_1_crypto contains "confidentiality" if object.get(_sc, ["transmission_confidentiality", "encrypted"], false) == true

_sc8_1_crypto contains "integrity" if object.get(_sc, ["transmission_integrity", "cryptographic"], false) == true

sc8_unprotected := sc8_required_properties - _sc8_protected

sc8_1_uncovered := sc8_required_properties - _sc8_1_crypto

# The facts behind each property; a property whose facts are all non-boolean was not collected.
_sc8_facts := {
	"confidentiality": [["transmission_confidentiality", "protected"], ["transmission_confidentiality", "encrypted"]],
	"integrity": [["transmission_integrity", "protected"], ["transmission_integrity", "cryptographic"]],
}

_sc8_1_facts := {"confidentiality": [["transmission_confidentiality", "encrypted"]], "integrity": [["transmission_integrity", "cryptographic"]]}

_none_boolean(paths) if {
	every f in paths {
		not is_boolean(_val(f))
	}
}

_sc8_missing := {_p(f) | some prop in sc8_unprotected; _none_boolean(_sc8_facts[prop]); some f in _sc8_facts[prop]}

_sc8_1_missing := {_p(f) | some prop in sc8_1_uncovered; _none_boolean(_sc8_1_facts[prop]); some f in _sc8_1_facts[prop]}

_sc28 := object.get(_sc, "protection_of_info_at_rest", {})

# SC-28 base: protection by the organisation's chosen mechanism (protected) or by encryption (encrypted).
sc28_protected if object.get(_sc28, "protected", false) == true

sc28_protected if object.get(_sc28, "encrypted", false) == true

default compliant := false

violation contains msg if {
	not _val(["policy", "documented"]) == true
	msg := sprintf("NIST SC-1: %s", [_strict(["policy", "documented"], "System and communications protection policy not documented")])
}

violation contains msg if {
	not _val(["app_partitioning", "separated"]) == true
	msg := sprintf("NIST SC-2: %s", [_strict(["app_partitioning", "separated"], "User functionality is not separated from system management functionality")])
}

violation contains msg if {
	not _val(["security_function_isolation", "implemented"]) == true
	msg := sprintf("NIST SC-3: %s", [_strict(["security_function_isolation", "implemented"], "Security functions not isolated from non-security functions")])
}

violation contains msg if {
	not _val(["denial_of_service", "protections"]) == true
	msg := sprintf("NIST SC-5: %s", [_strict(["denial_of_service", "protections"], "Denial-of-service protections not in place")])
}

violation contains msg if {
	not _val(["boundary_protection", "deployed"]) == true
	msg := sprintf("NIST SC-7: %s", [_strict(["boundary_protection", "deployed"], "System boundary protection not deployed at managed interfaces")])
}

violation contains msg if {
	count(sc8_unprotected) > 0
	msg := sprintf(
		"NIST SC-8: %sTransmission confidentiality and integrity — selected properties %v not evidenced as protected (unprotected or not collected: %v; selection from input.sc_controls.transmission_protection.odp.properties, both when not supplied)",
		[_ev_prefix(_sc8_missing), sort(sc8_required_properties), sort(sc8_unprotected)],
	)
}

violation contains msg if {
	count(sc8_1_uncovered) > 0
	msg := sprintf(
		"NIST SC-8(1): %sCryptographic protection — cryptographic mechanisms not evidenced for transmitted-information properties %v (confidentiality: input.sc_controls.transmission_confidentiality.encrypted; integrity: input.sc_controls.transmission_integrity.cryptographic)",
		[_ev_prefix(_sc8_1_missing), sort(sc8_1_uncovered)],
	)
}

violation contains msg if {
	not _val(["network_disconnect", "timeout_configured"]) == true
	msg := sprintf("NIST SC-10: %s", [_strict(["network_disconnect", "timeout_configured"], "Network session disconnect timeout not configured")])
}

violation contains msg if {
	not _val(["cryptographic_key_mgmt", "documented"]) == true
	msg := sprintf("NIST SC-12: %s", [_strict(["cryptographic_key_mgmt", "documented"], "Cryptographic key management process not documented")])
}

# SC-13: the organisation determines the cryptographic uses and the types of cryptography required for
# each (ODP). NIST does not fix FIPS validation in the catalog text; FedRAMP's parameter does, and that
# lives in the FedRAMP module. Here every organization-required standard must be evidenced as implemented.
_sc13 := object.get(_sc, "cryptographic_protection", {})

_sc13_missing contains "input.sc_controls.cryptographic_protection.odp.required_standards (organization-defined types of cryptography)" if {
	not _nonempty_array(object.get(_sc13, ["odp", "required_standards"], null))
}

_sc13_missing contains "input.sc_controls.cryptographic_protection.standards_implemented" if {
	not is_array(object.get(_sc13, "standards_implemented", null))
}

_nonempty_array(x) if {
	is_array(x)
	count(x) > 0
}

sc13_unmet contains s if {
	count(_sc13_missing) == 0
	some s in _sc13.odp.required_standards
	not s in _sc13.standards_implemented
}

violation contains msg if {
	count(_sc13_missing) > 0
	msg := sprintf("NIST SC-13: evidence missing — %s not collected", [concat(", ", sort(_sc13_missing))])
}

violation contains msg if {
	count(sc13_unmet) > 0
	msg := sprintf("NIST SC-13: Organization-required cryptography not implemented: %v", [sort(sc13_unmet)])
}

violation contains msg if {
	not _val(["collaborative_devices", "disabled_when_unused"]) == true
	msg := sprintf("NIST SC-15: %s", [_strict(["collaborative_devices", "disabled_when_unused"], "Collaborative computing devices (mic/camera) not disabled when unused")])
}

violation contains msg if {
	not _val(["public_key_infrastructure", "certificates_managed"]) == true
	msg := sprintf("NIST SC-17: %s", [_strict(["public_key_infrastructure", "certificates_managed"], "Public key certificates not issued/managed by authorized PKI")])
}

violation contains msg if {
	not _val(["mobile_code", "controls_enforced"]) == true
	msg := sprintf("NIST SC-18: %s", [_strict(["mobile_code", "controls_enforced"], "Mobile code controls (allow/deny lists) not enforced")])
}

violation contains msg if {
	not _val(["secure_dns", "dnssec_enforced"]) == true
	msg := sprintf("NIST SC-20: %s", [_strict(["secure_dns", "dnssec_enforced"], "Authoritative name resolution does not provide origin authentication and integrity artifacts (DNSSEC signing not evidenced: input.sc_controls.secure_dns.dnssec_enforced)")])
}

violation contains msg if {
	not _val(["secure_dns", "dnssec_enforced"]) == true
	msg := sprintf("NIST SC-21: %s", [_strict(["secure_dns", "dnssec_enforced"], "Recursive or caching resolver does not validate origin and integrity of responses (DNSSEC validation not evidenced: input.sc_controls.secure_dns.dnssec_enforced)")])
}

violation contains msg if {
	not _val(["session_authenticity", "protected"]) == true
	msg := sprintf("NIST SC-23: %s", [_strict(["session_authenticity", "protected"], "Session authenticity not protected (session ID randomness, timeouts)")])
}

_sc28_collected if is_boolean(object.get(_sc28, "protected", null))

_sc28_collected if is_boolean(object.get(_sc28, "encrypted", null))

violation contains msg if {
	not sc28_protected
	_sc28_collected
	msg := "NIST SC-28: Information at rest is not protected by the organization-chosen mechanism (input.sc_controls.protection_of_info_at_rest.protected) or by encryption (.encrypted)"
}

violation contains msg if {
	not sc28_protected
	not _sc28_collected
	msg := "NIST SC-28: evidence missing — protection of information at rest not evidenced by the organization-chosen mechanism (input.sc_controls.protection_of_info_at_rest.protected) or by encryption (.encrypted)"
}

violation contains msg if {
	object.get(_sc28, "encrypted", false) != true
	msg := sprintf("NIST SC-28(1): %s", [_strict(["protection_of_info_at_rest", "encrypted"], "Cryptographic protection of information at rest not evidenced (input.sc_controls.protection_of_info_at_rest.encrypted is not true)")])
}

compliant if count(violation) == 0

# SC-45 System Time Synchronization and SC-45(1) Synchronization with Authoritative Time Source (SC-45(1)
# is where Rev 5 moved the withdrawn AU-8(1)).
violation contains msg if {
	not object.get(_sc, ["time_synchronization", "clocks_synchronized"], false) == true
	msg := sprintf("NIST SC-45: %s", [_strict(["time_synchronization", "clocks_synchronized"], "System clocks not synchronized within and between systems and components (input.sc_controls.time_synchronization.clocks_synchronized)")])
}

violation contains msg if {
	not object.get(_sc, ["time_synchronization", "authoritative_source_synchronized"], false) == true
	msg := sprintf("NIST SC-45(1): %s", [_strict(["time_synchronization", "authoritative_source_synchronized"], "Internal clocks not compared with and synchronized to an authoritative time source (input.sc_controls.time_synchronization.authoritative_source_synchronized)")])
}

# ---------------------------------------------------------------------------------------------------------
# Moderate-baseline ids (SP 800-53B). Boundary-protection enhancements nest under boundary_protection.
# ---------------------------------------------------------------------------------------------------------

# SC-4 Information in Shared System Resources: input.sc_controls.shared_resources.residual_information_protected,
# true when shared resources (memory, storage, caches) are cleared or isolated before reallocation so no
# information passes between users or processes through them (object reuse protection).
violation contains msg if {
	sec := ["shared_resources"]
	b := {"residual_information_protected": "unauthorized and unintended information transfer via shared system resources is not prevented"}
	m := _bool_missing(sec, b)
	u := _bool_unmet(sec, b)
	count(m) + count(u) > 0
	msg := sprintf("NIST SC-4: %s", [_detail(m, u)])
}

# SC-7(3) Access Points: input.sc_controls.boundary_protection.access_points.{external_connections,
# odp.max_external_connections}: the observed number of external network connections against the
# organization-approved limit.
_sc7_3 := ["boundary_protection", "access_points"]

_sc7_3_missing := {_p(array.concat(_sc7_3, k)) | some k in [["external_connections"], ["odp", "max_external_connections"]]; not is_number(_val(array.concat(_sc7_3, k)))}

_sc7_3_unmet := {d |
	n := _val(array.concat(_sc7_3, ["external_connections"]))
	limit := _val(array.concat(_sc7_3, ["odp", "max_external_connections"]))
	is_number(n)
	is_number(limit)
	n > limit
	d := sprintf("%v external network connections; the organization-approved limit is %v", [n, limit])
}

violation contains msg if {
	count(_sc7_3_missing) + count(_sc7_3_unmet) > 0
	msg := sprintf("NIST SC-7(3): %s", [_detail(_sc7_3_missing, _sc7_3_unmet)])
}

# SC-7(4) External Telecommunications Services: input.sc_controls.boundary_protection.external_telecom.
# {services_without_managed_interface, interfaces_without_flow_policy, unprotected_interfaces,
# undocumented_exceptions, control_plane_traffic_controlled} and
# input.sc_controls.boundary_protection.external_telecom.exception_review.{days_since_last, odp.frequency_days}.
# The counts are external telecommunication services with no managed interface, managed interfaces with no
# traffic flow policy, interfaces not protecting the confidentiality and integrity of transmitted information,
# and flow-policy exceptions without a documented mission need and duration. control_plane_traffic_controlled
# is true when unauthorized control plane traffic is prevented outbound, filtered inbound, and the information
# remote networks need to detect it is published.
_sc7_4_zero := {
	"services_without_managed_interface": "external telecommunication services have no managed interface",
	"interfaces_without_flow_policy": "managed interfaces have no traffic flow policy",
	"unprotected_interfaces": "managed interfaces do not protect the confidentiality and integrity of transmitted information",
	"undocumented_exceptions": "traffic flow policy exceptions lack a documented mission or business need and duration",
}

violation contains msg if {
	sec := ["boundary_protection", "external_telecom"]
	b := {"control_plane_traffic_controlled": "unauthorized control plane traffic is not prevented, published for detection and filtered"}
	zm := {p | some k, _ in _sc7_4_zero; some p in _zero_missing(sec, k)}
	zu := {d | some k, t in _sc7_4_zero; some d in _zero_unmet(sec, k, t)}
	m := (_bool_missing(sec, b) | zm) | _freq_missing(array.concat(sec, ["exception_review"]))
	u := (_bool_unmet(sec, b) | zu) | _freq_unmet(array.concat(sec, ["exception_review"]), "traffic flow policy exceptions reviewed")
	count(m) + count(u) > 0
	msg := sprintf("NIST SC-7(4): %s", [_detail(m, u)])
}

# SC-7(5) Deny by Default — Allow by Exception: input.sc_controls.boundary_protection.deny_by_default.
# interfaces_allowing_by_default, the number of managed interfaces (or organization-defined systems) whose
# filter rule set does not end in a default deny.
violation contains msg if {
	sec := ["boundary_protection", "deny_by_default"]
	m := _zero_missing(sec, "interfaces_allowing_by_default")
	u := _zero_unmet(sec, "interfaces_allowing_by_default", "managed interfaces do not deny network traffic by default and allow it by exception")
	count(m) + count(u) > 0
	msg := sprintf("NIST SC-7(5): %s", [_detail(m, u)])
}

# SC-7(7) Split Tunneling for Remote Devices: input.sc_controls.boundary_protection.split_tunneling.
# unsafe_profiles, the number of remote-access (VPN) profiles that permit split tunneling without the
# organization-defined safeguards.
violation contains msg if {
	sec := ["boundary_protection", "split_tunneling"]
	m := _zero_missing(sec, "unsafe_profiles")
	u := _zero_unmet(sec, "unsafe_profiles", "remote-access profiles permit split tunneling without the organization-defined safeguards")
	count(m) + count(u) > 0
	msg := sprintf("NIST SC-7(7): %s", [_detail(m, u)])
}

# SC-7(8) Route Traffic to Authenticated Proxy Servers: input.sc_controls.boundary_protection.proxy.
# authenticated_proxy_enforced, true when the organization-defined internal traffic to the organization-defined
# external networks can leave only through authenticated proxy servers at managed interfaces.
violation contains msg if {
	sec := ["boundary_protection", "proxy"]
	b := {"authenticated_proxy_enforced": "internal traffic to external networks is not routed through authenticated proxy servers at managed interfaces"}
	m := _bool_missing(sec, b)
	u := _bool_unmet(sec, b)
	count(m) + count(u) > 0
	msg := sprintf("NIST SC-7(8): %s", [_detail(m, u)])
}

# SC-22 Architecture and Provisioning for Name/Address Resolution Service:
# input.sc_controls.name_resolution_architecture.{fault_tolerant, role_separation}. fault_tolerant is true when
# each zone is served by at least two name servers in separate network locations; role_separation is true when
# internal and external (authoritative and recursive) roles run on separate servers.
_sc22 := {
	"fault_tolerant": "the name/address resolution servers are not fault-tolerant",
	"role_separation": "the name/address resolution servers do not separate internal and external roles",
}

violation contains msg if {
	sec := ["name_resolution_architecture"]
	m := _bool_missing(sec, _sc22)
	u := _bool_unmet(sec, _sc22)
	count(m) + count(u) > 0
	msg := sprintf("NIST SC-22: %s", [_detail(m, u)])
}

# SC-39 Process Isolation: input.sc_controls.process_isolation.separate_execution_domains, true when each
# executing process has its own execution domain (separate address spaces enforced by the OS or hypervisor).
violation contains msg if {
	sec := ["process_isolation"]
	b := {"separate_execution_domains": "a separate execution domain is not maintained for each executing process"}
	m := _bool_missing(sec, b)
	u := _bool_unmet(sec, b)
	count(m) + count(u) > 0
	msg := sprintf("NIST SC-39: %s", [_detail(m, u)])
}

# ---------------------------------------------------------------------------------------------------------
# High-baseline ids and the remaining base controls.
# ---------------------------------------------------------------------------------------------------------

# Organization-defined lists: every item in <sec>.odp.<odp_key> must appear in <sec>.<obs_key>. A missing or
# empty ODP list, or an observed value that is not an array, is evidence missing.
_list_missing(sec, odp_key, obs_key) := {p |
	not _nonempty_array(_val(array.concat(sec, ["odp", odp_key])))
	p := _p(array.concat(sec, ["odp", odp_key]))
} | {p |
	not is_array(_val(array.concat(sec, [obs_key])))
	p := _p(array.concat(sec, [obs_key]))
}

_list_unmet(sec, odp_key, obs_key, what) := {d |
	req := _val(array.concat(sec, ["odp", odp_key]))
	obs := _val(array.concat(sec, [obs_key]))
	is_array(req)
	is_array(obs)
	missing := [x | some x in req; not x in obs]
	count(missing) > 0
	d := sprintf("%s: %v", [what, sort(missing)])
}

# Attestation for requirements no configuration or tool output can evidence: <sec>.attestation must be
# {attested: true, by: <non-empty string>, date: <non-empty string>}. attested false names the requirement as
# not attested; anything else that is not a complete attestation is evidence missing.
_attested(sec) if {
	a := _val(array.concat(sec, ["attestation"]))
	is_object(a)
	object.get(a, "attested", null) == true
	_nonempty_string(object.get(a, "by", null))
	_nonempty_string(object.get(a, "date", null))
}

_nonempty_string(x) if {
	is_string(x)
	x != ""
}

_attest_msg(sec, what) := sprintf("%s not attested (%s.attested is false)", [what, _p(array.concat(sec, ["attestation"]))]) if {
	a := _val(array.concat(sec, ["attestation"]))
	is_object(a)
	object.get(a, "attested", null) == false
} else := sprintf("evidence missing — %s {attested: true, by, date} not collected; %s not attested", [_p(array.concat(sec, ["attestation"])), what])

# SC-6 Resource Availability: input.sc_controls.resource_availability.resources_without_allocation, the number
# of organization-defined resources (CPU, memory, storage, bandwidth) with no priority, quota or other
# allocation control configured.
violation contains msg if {
	sec := ["resource_availability"]
	m := _zero_missing(sec, "resources_without_allocation")
	u := _zero_unmet(sec, "resources_without_allocation", "organization-defined resources are not allocated by priority, quota or other controls")
	count(m) + count(u) > 0
	msg := sprintf("NIST SC-6: %s", [_detail(m, u)])
}

# SC-7(10) Prevent Exfiltration: input.sc_controls.boundary_protection.exfiltration.prevention_enforced (true
# when data-loss / egress controls prevent exfiltration at the boundary) and
# input.sc_controls.boundary_protection.exfiltration.testing.{days_since_last, odp.frequency_days}: the age of
# the last exfiltration test against the organization-defined frequency.
violation contains msg if {
	sec := ["boundary_protection", "exfiltration"]
	b := {"prevention_enforced": "exfiltration of information is not prevented at the boundary"}
	m := _bool_missing(sec, b) | _freq_missing(array.concat(sec, ["testing"]))
	u := _bool_unmet(sec, b) | _freq_unmet(array.concat(sec, ["testing"]), "exfiltration tests conducted")
	count(m) + count(u) > 0
	msg := sprintf("NIST SC-7(10): %s", [_detail(m, u)])
}

# SC-7(12) Host-based Protection: input.sc_controls.boundary_protection.host_based.components_without_protection,
# the number of organization-defined system components without the host-based boundary protection mechanism
# (host firewall, host IPS) running.
violation contains msg if {
	sec := ["boundary_protection", "host_based"]
	m := _zero_missing(sec, "components_without_protection")
	u := _zero_unmet(sec, "components_without_protection", "organization-defined system components lack host-based boundary protection")
	count(m) + count(u) > 0
	msg := sprintf("NIST SC-7(12): %s", [_detail(m, u)])
}

# SC-7(18) Fail Secure: input.sc_controls.boundary_protection.fail_secure.devices_fail_open, the number of
# boundary protection devices configured to fail open (pass traffic unfiltered) on an operational failure.
violation contains msg if {
	sec := ["boundary_protection", "fail_secure"]
	m := _zero_missing(sec, "devices_fail_open")
	u := _zero_unmet(sec, "devices_fail_open", "boundary protection devices fail open rather than to a secure state")
	count(m) + count(u) > 0
	msg := sprintf("NIST SC-7(18): %s", [_detail(m, u)])
}

# SC-7(20) Dynamic Isolation and Segregation: input.sc_controls.boundary_protection.dynamic_isolation.
# components_without_capability, the number of organization-defined system components that cannot be
# isolated dynamically (quarantine VLAN, micro-segmentation policy, NAC isolation) from other components.
violation contains msg if {
	sec := ["boundary_protection", "dynamic_isolation"]
	m := _zero_missing(sec, "components_without_capability")
	u := _zero_unmet(sec, "components_without_capability", "organization-defined system components cannot be dynamically isolated from other components")
	count(m) + count(u) > 0
	msg := sprintf("NIST SC-7(20): %s", [_detail(m, u)])
}

# SC-7(21) Isolation of System Components: input.sc_controls.boundary_protection.component_isolation.
# components_not_isolated, the number of organization-defined components supporting the organization-defined
# missions or business functions that no boundary protection mechanism isolates.
violation contains msg if {
	sec := ["boundary_protection", "component_isolation"]
	m := _zero_missing(sec, "components_not_isolated")
	u := _zero_unmet(sec, "components_not_isolated", "organization-defined system components are not isolated by boundary protection mechanisms")
	count(m) + count(u) > 0
	msg := sprintf("NIST SC-7(21): %s", [_detail(m, u)])
}

# SC-11 Trusted Path: input.sc_controls.trusted_path.{isolated_path_provided, user_invocable}. isolated_path_provided
# is true when an isolated (physically or logically, per the ODP) trusted communications path to the trusted
# components exists (e.g. a secure attention sequence); user_invocable is true when users can invoke it for the
# organization-defined security functions, at least authentication and re-authentication.
_sc11 := {
	"isolated_path_provided": "no isolated trusted communications path to the trusted system components is provided",
	"user_invocable": "users cannot invoke the trusted path for authentication, re-authentication and the organization-defined security functions",
}

violation contains msg if {
	sec := ["trusted_path"]
	m := _bool_missing(sec, _sc11)
	u := _bool_unmet(sec, _sc11)
	count(m) + count(u) > 0
	msg := sprintf("NIST SC-11: %s", [_detail(m, u)])
}

# SC-12(1) Availability: input.sc_controls.cryptographic_key_mgmt.availability.key_recovery_enabled, true when
# keys are escrowed or backed up so information stays available if users lose their keys.
violation contains msg if {
	sec := ["cryptographic_key_mgmt", "availability"]
	b := {"key_recovery_enabled": "information availability is not maintained when users lose cryptographic keys (no key escrow or backup)"}
	m := _bool_missing(sec, b)
	u := _bool_unmet(sec, b)
	count(m) + count(u) > 0
	msg := sprintf("NIST SC-12(1): %s", [_detail(m, u)])
}

# SC-16 Transmission of Security and Privacy Attributes: input.sc_controls.attribute_transmission.
# {odp.attributes, attributes_associated}: every organization-defined security and privacy attribute must be
# among the attributes observed bound to information exchanged between systems and components.
violation contains msg if {
	sec := ["attribute_transmission"]
	m := _list_missing(sec, "attributes", "attributes_associated")
	u := _list_unmet(sec, "attributes", "attributes_associated", "organization-defined security and privacy attributes not associated with exchanged information")
	count(m) + count(u) > 0
	msg := sprintf("NIST SC-16: %s", [_detail(m, u)])
}

# SC-24 Fail in Known State: input.sc_controls.fail_in_known_state.failure_types_without_known_state, the number
# of organization-defined failure types (on the indicated components) for which the component is not configured
# and tested to fail to the organization-defined known state while preserving the state information.
violation contains msg if {
	sec := ["fail_in_known_state"]
	m := _zero_missing(sec, "failure_types_without_known_state")
	u := _zero_unmet(sec, "failure_types_without_known_state", "organization-defined failure types do not fail to a known state preserving system state information")
	count(m) + count(u) > 0
	msg := sprintf("NIST SC-24: %s", [_detail(m, u)])
}

# SC-25 Thin Nodes: input.sc_controls.thin_nodes.components_exceeding_minimal, the number of organization-defined
# thin-node components with functionality or local information storage beyond the minimal profile.
violation contains msg if {
	sec := ["thin_nodes"]
	m := _zero_missing(sec, "components_exceeding_minimal")
	u := _zero_unmet(sec, "components_exceeding_minimal", "organization-defined components exceed minimal functionality and information storage")
	count(m) + count(u) > 0
	msg := sprintf("NIST SC-25: %s", [_detail(m, u)])
}

# SC-26 Decoys: input.sc_controls.decoys.deployed, true when the asset inventory shows components (honeypots,
# honeynets, honeytokens) designed to be the target of attacks for detecting, deflecting and analysing them.
violation contains msg if {
	sec := ["decoys"]
	b := {"deployed": "no decoy components are deployed to detect, deflect and analyse attacks"}
	m := _bool_missing(sec, b)
	u := _bool_unmet(sec, b)
	count(m) + count(u) > 0
	msg := sprintf("NIST SC-26: %s", [_detail(m, u)])
}

# SC-27 Platform-independent Applications: input.sc_controls.platform_independent_applications.
# {odp.applications, included}: every organization-defined platform-independent application must be included.
violation contains msg if {
	sec := ["platform_independent_applications"]
	m := _list_missing(sec, "applications", "included")
	u := _list_unmet(sec, "applications", "included", "organization-defined platform-independent applications not included")
	count(m) + count(u) > 0
	msg := sprintf("NIST SC-27: %s", [_detail(m, u)])
}

# SC-29 Heterogeneity: input.sc_controls.heterogeneity.components_single_technology, the number of
# organization-defined system components implemented with a single technology (one vendor or product) where a
# diverse set is required.
violation contains msg if {
	sec := ["heterogeneity"]
	m := _zero_missing(sec, "components_single_technology")
	u := _zero_unmet(sec, "components_single_technology", "organization-defined system components do not use a diverse set of information technologies")
	count(m) + count(u) > 0
	msg := sprintf("NIST SC-29: %s", [_detail(m, u)])
}

# SC-30 Concealment and Misdirection: input.sc_controls.concealment_misdirection.{odp.techniques,
# techniques_employed}: every organization-defined concealment and misdirection technique must be observed in
# use on the organization-defined systems. The "time periods" ODP (when the techniques apply) is a description,
# not an interval, so it is not compared; the collector reports a technique as employed only within it.
violation contains msg if {
	sec := ["concealment_misdirection"]
	m := _list_missing(sec, "techniques", "techniques_employed")
	u := _list_unmet(sec, "techniques", "techniques_employed", "organization-defined concealment and misdirection techniques not employed")
	count(m) + count(u) > 0
	msg := sprintf("NIST SC-30: %s", [_detail(m, u)])
}

# SC-31 Covert Channel Analysis: input.sc_controls.covert_channel_analysis.attestation. A covert storage/timing
# channel analysis with maximum-bandwidth estimates is an engineering study; no configuration evidences it.
violation contains msg if {
	sec := ["covert_channel_analysis"]
	not _attested(sec)
	msg := sprintf("NIST SC-31: %s", [_attest_msg(sec, "a covert channel analysis identifying covert channels and estimating their maximum bandwidth is")])
}

# SC-32 System Partitioning: input.sc_controls.system_partitioning.components_not_separated, the number of
# organization-defined system components not residing in their own physical or logical domain as the
# organization-defined circumstances require.
violation contains msg if {
	sec := ["system_partitioning"]
	m := _zero_missing(sec, "components_not_separated")
	u := _zero_unmet(sec, "components_not_separated", "organization-defined system components do not reside in separate physical or logical domains")
	count(m) + count(u) > 0
	msg := sprintf("NIST SC-32: %s", [_detail(m, u)])
}

# SC-34 Non-modifiable Executable Programs: input.sc_controls.non_modifiable_executables.
# {operating_environment_read_only, applications_not_read_only}. operating_environment_read_only is true when
# the organization-defined components load and execute the operating environment from hardware-enforced
# read-only media; applications_not_read_only counts organization-defined applications that do not.
violation contains msg if {
	sec := ["non_modifiable_executables"]
	b := {"operating_environment_read_only": "the operating environment is not loaded and executed from hardware-enforced read-only media"}
	m := _bool_missing(sec, b) | _zero_missing(sec, "applications_not_read_only")
	u := _bool_unmet(sec, b) | _zero_unmet(sec, "applications_not_read_only", "organization-defined applications are not loaded and executed from hardware-enforced read-only media")
	count(m) + count(u) > 0
	msg := sprintf("NIST SC-34: %s", [_detail(m, u)])
}

# SC-35 External Malicious Code Identification: input.sc_controls.external_malicious_code_identification.
# seeking_components_deployed, true when components (honeyclients, web crawlers) proactively seek out
# network-based malicious code or malicious websites.
violation contains msg if {
	sec := ["external_malicious_code_identification"]
	b := {"seeking_components_deployed": "no system components proactively seek to identify network-based malicious code or malicious websites"}
	m := _bool_missing(sec, b)
	u := _bool_unmet(sec, b)
	count(m) + count(u) > 0
	msg := sprintf("NIST SC-35: %s", [_detail(m, u)])
}

# SC-36 Distributed Processing and Storage: input.sc_controls.distributed_processing.components_single_location,
# the number of organization-defined processing and storage components not distributed across multiple
# physical locations or logical domains.
violation contains msg if {
	sec := ["distributed_processing"]
	m := _zero_missing(sec, "components_single_location")
	u := _zero_unmet(sec, "components_single_location", "organization-defined processing and storage components are not distributed across multiple locations or domains")
	count(m) + count(u) > 0
	msg := sprintf("NIST SC-36: %s", [_detail(m, u)])
}

# SC-37 Out-of-band Channels: input.sc_controls.out_of_band_channels.attestation. Physical delivery or
# electronic transmission of keys, tokens or authenticators over a separate channel is a procedure.
violation contains msg if {
	sec := ["out_of_band_channels"]
	not _attested(sec)
	msg := sprintf("NIST SC-37: %s", [_attest_msg(sec, "use of the organization-defined out-of-band channels for delivering the organization-defined information, components or devices is")])
}

# SC-38 Operations Security: input.sc_controls.operations_security.attestation. OPSEC controls over key
# organizational information throughout the system development life cycle are practices, not settings.
violation contains msg if {
	sec := ["operations_security"]
	not _attested(sec)
	msg := sprintf("NIST SC-38: %s", [_attest_msg(sec, "employment of the organization-defined operations security controls throughout the system development life cycle is")])
}

# SC-40 Wireless Link Protection: input.sc_controls.wireless_link_protection.unprotected_links, the number of
# organization-defined wireless links not protected against the organization-defined signal parameter attacks.
violation contains msg if {
	sec := ["wireless_link_protection"]
	m := _zero_missing(sec, "unprotected_links")
	u := _zero_unmet(sec, "unprotected_links", "organization-defined wireless links are not protected from signal parameter attacks")
	count(m) + count(u) > 0
	msg := sprintf("NIST SC-40: %s", [_detail(m, u)])
}

# SC-41 Port and I/O Device Access: input.sc_controls.port_io_access.enabled_prohibited_ports, the number of
# organization-defined connection ports or I/O devices (USB, FireWire, Thunderbolt, Bluetooth) still enabled on
# the organization-defined systems or components.
violation contains msg if {
	sec := ["port_io_access"]
	m := _zero_missing(sec, "enabled_prohibited_ports")
	u := _zero_unmet(sec, "enabled_prohibited_ports", "organization-defined connection ports or I/O devices are not disabled or removed")
	count(m) + count(u) > 0
	msg := sprintf("NIST SC-41: %s", [_detail(m, u)])
}

# SC-42 Sensor Capability and Data: input.sc_controls.sensor_capability.{remote_activation_prohibited,
# use_indicated}. remote_activation_prohibited is true when the prohibited use or remote activation of
# environmental sensors (microphones, cameras, GPS) is blocked outside the organization-defined exceptions;
# use_indicated is true when an explicit indication of sensor use is shown to the organization-defined users.
_sc42 := {
	"remote_activation_prohibited": "the organization-prohibited use or remote activation of environmental sensing capabilities is not blocked",
	"use_indicated": "no explicit indication of sensor use is provided to the organization-defined users",
}

violation contains msg if {
	sec := ["sensor_capability"]
	m := _bool_missing(sec, _sc42)
	u := _bool_unmet(sec, _sc42)
	count(m) + count(u) > 0
	msg := sprintf("NIST SC-42: %s", [_detail(m, u)])
}

# SC-43 Usage Restrictions: input.sc_controls.usage_restrictions.{restrictions_established, use_controlled}.
# restrictions_established is true when usage restrictions and implementation guidelines exist for the
# organization-defined components; use_controlled is true when their use is authorized, monitored and controlled.
_sc43 := {
	"restrictions_established": "usage restrictions and implementation guidelines are not established for the organization-defined components",
	"use_controlled": "use of the organization-defined components is not authorized, monitored and controlled",
}

violation contains msg if {
	sec := ["usage_restrictions"]
	m := _bool_missing(sec, _sc43)
	u := _bool_unmet(sec, _sc43)
	count(m) + count(u) > 0
	msg := sprintf("NIST SC-43: %s", [_detail(m, u)])
}

# SC-44 Detonation Chambers: input.sc_controls.detonation_chamber.deployed, true when a detonation chamber
# (sandbox) analyses suspicious attachments, files and URLs within the organization-defined system, component
# or location.
violation contains msg if {
	sec := ["detonation_chamber"]
	b := {"deployed": "no detonation chamber capability is employed"}
	m := _bool_missing(sec, b)
	u := _bool_unmet(sec, b)
	count(m) + count(u) > 0
	msg := sprintf("NIST SC-44: %s", [_detail(m, u)])
}

# SC-46 Cross Domain Policy Enforcement: input.sc_controls.cross_domain.interfaces_without_enforcement, the
# number of interfaces between connecting security domains with no (physical or logical) policy enforcement
# mechanism.
violation contains msg if {
	sec := ["cross_domain"]
	m := _zero_missing(sec, "interfaces_without_enforcement")
	u := _zero_unmet(sec, "interfaces_without_enforcement", "interfaces between connecting security domains have no policy enforcement mechanism")
	count(m) + count(u) > 0
	msg := sprintf("NIST SC-46: %s", [_detail(m, u)])
}

# SC-47 Alternate Communications Paths: input.sc_controls.alternate_communications_paths.{odp.paths,
# established}: every organization-defined alternate communication path for command and control must be
# observed as established.
violation contains msg if {
	sec := ["alternate_communications_paths"]
	m := _list_missing(sec, "paths", "established")
	u := _list_unmet(sec, "paths", "established", "organization-defined alternate communication paths for command and control not established")
	count(m) + count(u) > 0
	msg := sprintf("NIST SC-47: %s", [_detail(m, u)])
}

# SC-48 Sensor Relocation: input.sc_controls.sensor_relocation.attestation. Relocating sensors and monitoring
# capabilities under organization-defined conditions is an operational capability exercised on demand.
violation contains msg if {
	sec := ["sensor_relocation"]
	not _attested(sec)
	msg := sprintf("NIST SC-48: %s", [_attest_msg(sec, "the capability to relocate the organization-defined sensors and monitoring capabilities under the organization-defined conditions is")])
}

# SC-49 Hardware-enforced Separation and Policy Enforcement: input.sc_controls.hardware_separation.
# boundaries_without_enforcement, the number of boundaries between organization-defined security domains with
# no hardware-enforced separation and policy enforcement mechanism.
violation contains msg if {
	sec := ["hardware_separation"]
	m := _zero_missing(sec, "boundaries_without_enforcement")
	u := _zero_unmet(sec, "boundaries_without_enforcement", "boundaries between organization-defined security domains lack hardware-enforced separation and policy enforcement")
	count(m) + count(u) > 0
	msg := sprintf("NIST SC-49: %s", [_detail(m, u)])
}

# SC-50 Software-enforced Separation and Policy Enforcement: input.sc_controls.software_separation.
# boundaries_without_enforcement, the number of boundaries between organization-defined security domains with
# no software-enforced separation and policy enforcement mechanism.
violation contains msg if {
	sec := ["software_separation"]
	m := _zero_missing(sec, "boundaries_without_enforcement")
	u := _zero_unmet(sec, "boundaries_without_enforcement", "boundaries between organization-defined security domains lack software-enforced separation and policy enforcement")
	count(m) + count(u) > 0
	msg := sprintf("NIST SC-50: %s", [_detail(m, u)])
}

# SC-51 Hardware-based Protection: input.sc_controls.hardware_write_protect.{firmware_unprotected,
# procedures_documented}. firmware_unprotected counts organization-defined firmware components without
# hardware-based write-protect; procedures_documented is true when procedures exist for the organization-defined
# authorized individuals to disable write-protect for firmware changes and re-enable it before operation.
violation contains msg if {
	sec := ["hardware_write_protect"]
	b := {"procedures_documented": "procedures to manually disable and re-enable hardware write-protect for firmware modifications are not documented"}
	m := _bool_missing(sec, b) | _zero_missing(sec, "firmware_unprotected")
	u := _bool_unmet(sec, b) | _zero_unmet(sec, "firmware_unprotected", "organization-defined firmware components lack hardware-based write-protect")
	count(m) + count(u) > 0
	msg := sprintf("NIST SC-51: %s", [_detail(m, u)])
}

# ---------------------------------------------------------------------------------------------------------
# NIST SP 800-53B Privacy-baseline enhancements. Each is its own requirement; its base control never fails for it.
# ---------------------------------------------------------------------------------------------------------

# SC-7(24) Personally Identifiable Information: for systems that process PII, the organization-defined processing
# rules are applied to PII data elements, permitted processing is monitored at the external interfaces and key
# internal boundaries, each processing exception is documented, and exceptions no longer supported are removed.
# Facts (input.sc_controls.boundary_protection.pii_processing): odp.processing_rules (non-empty list) and
# rules_enforced (list of the rules the boundary devices or data-loss controls enforce); monitored_at_external_interfaces,
# monitored_at_internal_boundaries (booleans); undocumented_exceptions, unsupported_exceptions (counts: exceptions
# with no documentation, and exceptions whose justification has lapsed but are still in place).
_sc7_24_bools := {
	"monitored_at_external_interfaces": "permitted PII processing is not monitored at the system's external interfaces",
	"monitored_at_internal_boundaries": "permitted PII processing is not monitored at key internal boundaries",
}

_sc7_24_zeros := {
	"undocumented_exceptions": "PII processing exceptions are not documented",
	"unsupported_exceptions": "PII processing exceptions no longer supported have not been removed",
}

violation contains msg if {
	sec := ["boundary_protection", "pii_processing"]
	m := (_list_missing(sec, "processing_rules", "rules_enforced") | _bool_missing(sec, _sc7_24_bools)) | {p | some k, _ in _sc7_24_zeros; some p in _zero_missing(sec, k)}
	u := (_list_unmet(sec, "processing_rules", "rules_enforced", "organization-defined PII processing rules not applied") | _bool_unmet(sec, _sc7_24_bools)) | {d | some k, what in _sc7_24_zeros; some d in _zero_unmet(sec, k, what)}
	count(m) + count(u) > 0
	msg := sprintf("NIST SC-7(24): %s", [_detail(m, u)])
}

# The control and enhancement ids this family evaluates; each has exactly one finding when it fails.
evaluated_controls := {
	"SC-1", "SC-2", "SC-3", "SC-4", "SC-5", "SC-6", "SC-7", "SC-7(3)", "SC-7(4)", "SC-7(5)", "SC-7(7)", "SC-7(8)",
	"SC-7(10)", "SC-7(12)", "SC-7(18)", "SC-7(20)", "SC-7(21)", "SC-8", "SC-8(1)", "SC-10", "SC-11", "SC-12",
	"SC-12(1)", "SC-13", "SC-15", "SC-16", "SC-17", "SC-18", "SC-20", "SC-21", "SC-22", "SC-23", "SC-24",
	"SC-25", "SC-26", "SC-27", "SC-28", "SC-28(1)", "SC-29", "SC-30", "SC-31", "SC-32", "SC-34", "SC-35",
	"SC-36", "SC-37", "SC-38", "SC-39", "SC-40", "SC-41", "SC-42", "SC-43", "SC-44", "SC-45", "SC-45(1)",
	"SC-46", "SC-47", "SC-48", "SC-49", "SC-50", "SC-51",
	"SC-7(24)",
}

compliance_report := {
	"family": "SC",
	"name": "System and Communications Protection",
	"controls_evaluated": count(evaluated_controls),
	"violations": violation,
	"violation_count": count(violation),
	"compliant": compliant,
}
