# METADATA
# title: "NIST SP 800-53 Rev 5 — System and Communications Protection (SC) Family"
# custom:
#   class: compliance
#   framework: nist_sp_800_53
#   source: nist
#   domains: [us-federal, security-controls]
#   coverage:
#     checks: 30
#     cited: 12
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
# Evaluated: SC-1, SC-2, SC-3, SC-4, SC-5, SC-7, SC-7(3), SC-7(4), SC-7(5), SC-7(7), SC-7(8), SC-8, SC-8(1),
# SC-10, SC-12, SC-13, SC-15, SC-17, SC-18, SC-20, SC-21, SC-22, SC-23, SC-28, SC-28(1), SC-39, SC-45, SC-45(1)
# (28 ids; SC-4, SC-7(3), SC-7(4), SC-7(5), SC-7(7), SC-7(8), SC-22 and SC-39 are the Moderate-baseline ids
# added from SP 800-53B). SC-19 (Voice over Internet Protocol) is WITHDRAWN in Rev 5
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

_missing_msg(id, paths) := sprintf("NIST %s: evidence missing — %s not collected", [id, concat(", ", sort(paths))])

# The original boolean checks keep their pass condition (`not input.sc_controls.<path>`: only an absent fact or
# false fails). The finding says which: false keeps the original text; an absent fact (or a path through a
# non-object) is evidence missing.
_legacy(id, path, text) := sprintf("NIST %s: %s", [id, text]) if {
	_val(path) == false
} else := _missing_msg(id, {_p(path)})

# Checks that pass only on `== true`: false keeps the original text, any non-boolean is evidence missing.
_strict(id, path, text) := sprintf("NIST %s: %s", [id, text]) if {
	is_boolean(_val(path))
} else := _missing_msg(id, {_p(path)})

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

# Counts that must be zero. A non-number is missing evidence.
_zero_missing(sec, k) := {_p(array.concat(sec, [k])) | not is_number(_val(array.concat(sec, [k])))}

_zero_unmet(sec, k, what) := {d |
	n := _val(array.concat(sec, [k]))
	is_number(n)
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
	not input.sc_controls.policy.documented
	msg := _legacy("SC-1", ["policy", "documented"], "System and communications protection policy not documented")
}

violation contains msg if {
	not input.sc_controls.app_partitioning.separated
	msg := _legacy("SC-2", ["app_partitioning", "separated"], "User functionality is not separated from system management functionality")
}

violation contains msg if {
	not input.sc_controls.security_function_isolation.implemented
	msg := _legacy("SC-3", ["security_function_isolation", "implemented"], "Security functions not isolated from non-security functions")
}

violation contains msg if {
	not input.sc_controls.denial_of_service.protections
	msg := _legacy("SC-5", ["denial_of_service", "protections"], "Denial-of-service protections not in place")
}

violation contains msg if {
	not input.sc_controls.boundary_protection.deployed
	msg := _legacy("SC-7", ["boundary_protection", "deployed"], "System boundary protection not deployed at managed interfaces")
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
	not input.sc_controls.network_disconnect.timeout_configured
	msg := _legacy("SC-10", ["network_disconnect", "timeout_configured"], "Network session disconnect timeout not configured")
}

violation contains msg if {
	not input.sc_controls.cryptographic_key_mgmt.documented
	msg := _legacy("SC-12", ["cryptographic_key_mgmt", "documented"], "Cryptographic key management process not documented")
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
	not input.sc_controls.collaborative_devices.disabled_when_unused
	msg := _legacy("SC-15", ["collaborative_devices", "disabled_when_unused"], "Collaborative computing devices (mic/camera) not disabled when unused")
}

violation contains msg if {
	not input.sc_controls.public_key_infrastructure.certificates_managed
	msg := _legacy("SC-17", ["public_key_infrastructure", "certificates_managed"], "Public key certificates not issued/managed by authorized PKI")
}

violation contains msg if {
	not input.sc_controls.mobile_code.controls_enforced
	msg := _legacy("SC-18", ["mobile_code", "controls_enforced"], "Mobile code controls (allow/deny lists) not enforced")
}

violation contains msg if {
	not input.sc_controls.secure_dns.dnssec_enforced
	msg := _legacy("SC-20", ["secure_dns", "dnssec_enforced"], "Authoritative name resolution does not provide origin authentication and integrity artifacts (DNSSEC signing not evidenced: input.sc_controls.secure_dns.dnssec_enforced)")
}

violation contains msg if {
	not input.sc_controls.secure_dns.dnssec_enforced
	msg := _legacy("SC-21", ["secure_dns", "dnssec_enforced"], "Recursive or caching resolver does not validate origin and integrity of responses (DNSSEC validation not evidenced: input.sc_controls.secure_dns.dnssec_enforced)")
}

violation contains msg if {
	not input.sc_controls.session_authenticity.protected
	msg := _legacy("SC-23", ["session_authenticity", "protected"], "Session authenticity not protected (session ID randomness, timeouts)")
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
	msg := _strict("SC-28(1)", ["protection_of_info_at_rest", "encrypted"], "Cryptographic protection of information at rest not evidenced (input.sc_controls.protection_of_info_at_rest.encrypted is not true)")
}

compliant if count(violation) == 0

# SC-45 System Time Synchronization and SC-45(1) Synchronization with Authoritative Time Source (SC-45(1)
# is where Rev 5 moved the withdrawn AU-8(1)).
violation contains msg if {
	not object.get(_sc, ["time_synchronization", "clocks_synchronized"], false) == true
	msg := _strict("SC-45", ["time_synchronization", "clocks_synchronized"], "System clocks not synchronized within and between systems and components (input.sc_controls.time_synchronization.clocks_synchronized)")
}

violation contains msg if {
	not object.get(_sc, ["time_synchronization", "authoritative_source_synchronized"], false) == true
	msg := _strict("SC-45(1)", ["time_synchronization", "authoritative_source_synchronized"], "Internal clocks not compared with and synchronized to an authoritative time source (input.sc_controls.time_synchronization.authoritative_source_synchronized)")
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

# The control and enhancement ids this family evaluates; each has exactly one finding when it fails.
evaluated_controls := {
	"SC-1", "SC-2", "SC-3", "SC-4", "SC-5", "SC-7", "SC-7(3)", "SC-7(4)", "SC-7(5)", "SC-7(7)", "SC-7(8)",
	"SC-8", "SC-8(1)", "SC-10", "SC-12", "SC-13", "SC-15", "SC-17", "SC-18", "SC-20", "SC-21", "SC-22",
	"SC-23", "SC-28", "SC-28(1)", "SC-39", "SC-45", "SC-45(1)",
}

compliance_report := {
	"family": "SC",
	"name": "System and Communications Protection",
	"controls_evaluated": count(evaluated_controls),
	"violations": violation,
	"violation_count": count(violation),
	"compliant": compliant,
}
