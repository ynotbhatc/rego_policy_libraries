# METADATA
# title: "NIST SP 800-171 Rev 3 - System and Communications Protection (SC) Requirements"
# custom:
#   class: compliance
#   framework: nist_sp_800_171
#   source: nist
#   domains: [us-federal, security-controls]
#   coverage:
#     checks: 28
#     cited: 10
#     expected: 10
#     found: 28
#     scope: module
#     density: full
#     basis: declared-total
#     tested: true
#     entrypoint: compliance_report
#     guard: self
#     as_of: v2.4.2
package nist.sp800_171.system_communications

import rego.v1

# NIST SP 800-171 Rev 3 - System and Communications Protection (SC) Requirements
#
# Ids are NIST SP 800-171 Rev 3 element identifiers from the NIST CPRT export
# (https://csrc.nist.gov/extensions/nudp/services/json/nudp/framework/version/SP_800_171_3_0_0/export/json?element=all, sha256 19d18ef88700e468..., retrieved 2026-10-13).
# The fact checks below were written against the Rev 2 statements; each is re-keyed to the Rev 3
# requirement that carries its Rev 2 slot. A Rev 2 slot withdrawn in Rev 3 with "Incorporated into"
# is keyed to the incorporating requirement(s); one withdrawn as "Addressed by", recategorized as
# NCO, technology-specific or for consistency with SP 800-53 is retired: its rule is kept for lineage
# but it emits no violation and is not a Rev 3 control. Rev 3 status per requirement (attestation
# plus these facts) is computed by nist_800_171_main.rego (package nist_800_171.main).
# Family: 03.13 System and Communications Protection — Protecting Controlled Unclassified Information (CUI)

# 03.13.01 Boundary Protection (Rev 2 3.13.1): Monitor, control, and protect communications (transmissions) at the external
#          boundaries and key internal boundaries of organizational systems
default boundary_protection := false

boundary_protection if {
	input.nist_800_171.system_communications.boundary.external_boundaries_monitored == true
	input.nist_800_171.system_communications.boundary.key_internal_boundaries_monitored == true
	input.nist_800_171.system_communications.boundary.communications_controlled == true
}

# RETIRED, not a Rev 3 control (Rev 2 3.13.2, withdrawn in Rev 3: Recategorized as NCO.): Employ architectural designs, software development techniques, and systems
#          engineering principles that promote effective information security
default security_engineering_principles := false

security_engineering_principles if {
	input.nist_800_171.system_communications.engineering.security_by_design == true
	input.nist_800_171.system_communications.engineering.secure_sdlc == true
	input.nist_800_171.system_communications.engineering.principles_documented == true
}

# RETIRED, not a Rev 3 control (Rev 2 3.13.3, withdrawn in Rev 3: Addressed by 03.01.01, 03.01.02, 03.01.03, 03.01.04, 03.01.05, 03.01.06, and 03.01.07.): Separate user functionality from system management functionality
default functionality_separation := false

functionality_separation if {
	input.nist_800_171.system_communications.separation.user_mgmt_separated == true
	input.nist_800_171.system_communications.separation.technical_controls_implemented == true
	input.nist_800_171.system_communications.separation.admin_interfaces_distinct == true
}

# 03.13.04 Information in Shared System Resources (Rev 2 3.13.4): Prevent unauthorized and unintended information transfer via shared system resources
default shared_resource_control := false

shared_resource_control if {
	input.nist_800_171.system_communications.shared_resources.unauthorized_transfer_prevented == true
	input.nist_800_171.system_communications.shared_resources.resource_isolation == true
	input.nist_800_171.system_communications.shared_resources.controls_documented == true
}

# 03.13.01 (Rev 2 3.13.5, withdrawn in Rev 3: Incorporated into 03.13.01.): Implement subnetworks for publicly accessible system components that are
#          physically or logically separated from internal networks
default dmz_implementation := false

dmz_implementation if {
	input.nist_800_171.system_communications.dmz.public_components_separated == true
	input.nist_800_171.system_communications.dmz.physical_or_logical_separation == true
	input.nist_800_171.system_communications.dmz.internal_network_protected == true
}

# 03.13.06 Network Communications – Deny by Default – Allow by Exception (Rev 2 3.13.6): Deny network communications traffic by default and allow network communications
#          traffic by exception (deny all, permit by exception)
default deny_all_permit_exception := false

deny_all_permit_exception if {
	input.nist_800_171.system_communications.deny_all.default_deny_implemented == true
	input.nist_800_171.system_communications.deny_all.permit_by_exception == true
	input.nist_800_171.system_communications.deny_all.exceptions_documented == true
}

# RETIRED, not a Rev 3 control (Rev 2 3.13.7, withdrawn in Rev 3: Addressed by 03.01.12, 03.04.02 and 03.04.06.): Prevent remote devices from simultaneously using non-remote access to
#          organizational systems and using another connection to resources in other
#          networks (split tunneling)
default split_tunneling_prevention := false

split_tunneling_prevention if {
	input.nist_800_171.system_communications.split_tunneling.prevention_implemented == true
	input.nist_800_171.system_communications.split_tunneling.vpn_configured_correctly == true
	input.nist_800_171.system_communications.split_tunneling.policy_enforced == true
}

# 03.13.08 Transmission and Storage Confidentiality (Rev 2 3.13.8): Implement cryptographic mechanisms to prevent unauthorized disclosure of CUI
#          during transmission unless otherwise protected by alternative physical safeguards
default transmission_encryption := false

transmission_encryption if {
	input.nist_800_171.system_communications.transmission.encryption_implemented == true
	input.nist_800_171.system_communications.transmission.approved_algorithms == true
	input.nist_800_171.system_communications.transmission.covers_all_cui_transmission == true
}

# 03.13.09 Network Disconnect (Rev 2 3.13.9): Terminate network connections associated with communications sessions after a
#          defined period of inactivity
default session_termination_inactivity := false

session_termination_inactivity if {
	input.nist_800_171.system_communications.session_timeout.inactivity_timeout_defined == true
	input.nist_800_171.system_communications.session_timeout.automatic_termination == true
	input.nist_800_171.system_communications.session_timeout.all_connection_types_covered == true
}

# 03.13.10 Cryptographic Key Establishment and Management (Rev 2 3.13.10): Establish and manage cryptographic keys for required cryptography employed in
#           organizational systems
default cryptographic_key_management := false

cryptographic_key_management if {
	input.nist_800_171.system_communications.key_management.key_generation_documented == true
	input.nist_800_171.system_communications.key_management.key_distribution_secured == true
	input.nist_800_171.system_communications.key_management.key_rotation_policy == true
	input.nist_800_171.system_communications.key_management.key_destruction_procedures == true
}

# 03.13.11 Cryptographic Protection (Rev 2 3.13.11): Employ FIPS-validated cryptography when used to protect the confidentiality of CUI
default fips_validated_cryptography := false

fips_validated_cryptography if {
	input.nist_800_171.system_communications.fips.fips_validated_modules == true
	input.nist_800_171.system_communications.fips.covers_cui_protection == true
	input.nist_800_171.system_communications.fips.inventory_maintained == true
}

# 03.13.12 Collaborative Computing Devices and Applications (Rev 2 3.13.12): Prohibit remote activation of collaborative computing devices and provide
#           indication of use to users physically present
default collaborative_device_control := false

collaborative_device_control if {
	input.nist_800_171.system_communications.collaborative_devices.remote_activation_prohibited == true
	input.nist_800_171.system_communications.collaborative_devices.presence_indicator == true
	input.nist_800_171.system_communications.collaborative_devices.policy_documented == true
}

# 03.13.13 Mobile Code (Rev 2 3.13.13): Control and monitor the use of mobile code
default mobile_code_control := false

mobile_code_control if {
	input.nist_800_171.system_communications.mobile_code.usage_policy_defined == true
	input.nist_800_171.system_communications.mobile_code.technical_controls == true
	input.nist_800_171.system_communications.mobile_code.monitoring_implemented == true
}

# RETIRED, not a Rev 3 control (Rev 2 3.13.14, withdrawn in Rev 3: Technology-specific.): Control and monitor the use of Voice over Internet Protocol (VoIP) technologies
default voip_control := false

voip_control if {
	input.nist_800_171.system_communications.voip.usage_policy_defined == true
	input.nist_800_171.system_communications.voip.technical_controls == true
	input.nist_800_171.system_communications.voip.monitoring_implemented == true
}

# 03.13.15 Session Authenticity (Rev 2 3.13.15): Protect the authenticity of communications sessions
default session_authenticity := false

session_authenticity if {
	input.nist_800_171.system_communications.authenticity.session_authentication == true
	input.nist_800_171.system_communications.authenticity.replay_protection == true
	input.nist_800_171.system_communications.authenticity.mechanisms_documented == true
}

# 03.13.08 (Rev 2 3.13.16, withdrawn in Rev 3: Incorporated into 03.13.08.): Protect the confidentiality of CUI at rest
default cui_at_rest_protection := false

cui_at_rest_protection if {
	input.nist_800_171.system_communications.data_at_rest.encryption_implemented == true
	input.nist_800_171.system_communications.data_at_rest.approved_algorithms == true
	input.nist_800_171.system_communications.data_at_rest.covers_all_cui_storage == true
}

# Violations set
violations contains msg if {
	not boundary_protection
	msg := "NIST SP 800-171 03.13.01: Communications must be monitored, controlled, and protected at external boundaries and key internal boundaries"
}

violations contains msg if {
	not shared_resource_control
	msg := "NIST SP 800-171 03.13.04: Unauthorized and unintended information transfer via shared system resources must be prevented through resource isolation"
}

violations contains msg if {
	not dmz_implementation
	msg := "NIST SP 800-171 03.13.01 (Rev 2 3.13.5, withdrawn in Rev 3: Incorporated into 03.13.01.): Publicly accessible system components must be in subnetworks physically or logically separated from internal networks"
}

violations contains msg if {
	not deny_all_permit_exception
	msg := "NIST SP 800-171 03.13.06: Network communications must default to deny-all with permit-by-exception; all exceptions must be documented"
}

violations contains msg if {
	not transmission_encryption
	msg := "NIST SP 800-171 03.13.08: FIPS-approved cryptographic mechanisms must protect CUI confidentiality during all transmission"
}

violations contains msg if {
	not session_termination_inactivity
	msg := "NIST SP 800-171 03.13.09: Network connections must be automatically terminated after a defined period of inactivity across all connection types"
}

violations contains msg if {
	not cryptographic_key_management
	msg := "NIST SP 800-171 03.13.10: Cryptographic keys must be managed with documented generation, secured distribution, rotation policy, and destruction procedures"
}

violations contains msg if {
	not fips_validated_cryptography
	msg := "NIST SP 800-171 03.13.11: FIPS-validated cryptographic modules must be employed for protecting CUI with an inventory maintained"
}

violations contains msg if {
	not collaborative_device_control
	msg := "NIST SP 800-171 03.13.12: Remote activation of collaborative computing devices must be prohibited with presence indicators for users"
}

violations contains msg if {
	not mobile_code_control
	msg := "NIST SP 800-171 03.13.13: Mobile code use must be controlled with defined policy, technical controls, and active monitoring"
}

violations contains msg if {
	not session_authenticity
	msg := "NIST SP 800-171 03.13.15: The authenticity of communications sessions must be protected with session authentication and replay protection"
}

violations contains msg if {
	not cui_at_rest_protection
	msg := "NIST SP 800-171 03.13.08 (Rev 2 3.13.16, withdrawn in Rev 3: Incorporated into 03.13.08.): CUI at rest must be protected with FIPS-approved encryption across all CUI storage locations"
}

# Compliance aggregation
default compliant := false

compliant if count(violations) == 0

compliance_report := {
	"family": "03.13 System and Communications Protection",
	"standard": "NIST SP 800-171 Rev 3",
	"total_controls": 10,
	"violations": violations,
	"compliant": compliant,
	"retired_rev2_checks": {
		"rev2_3.13.2_security_engineering_principles": security_engineering_principles,
		"rev2_3.13.3_functionality_separation": functionality_separation,
		"rev2_3.13.7_split_tunneling_prevention": split_tunneling_prevention,
		"rev2_3.13.14_voip_control": voip_control,
	},
	"controls": {
		"03.13.01_boundary_protection": boundary_protection,
		"03.13.04_shared_resource_control": shared_resource_control,
		"03.13.01_dmz_implementation": dmz_implementation,
		"03.13.06_deny_all_permit_exception": deny_all_permit_exception,
		"03.13.08_transmission_encryption": transmission_encryption,
		"03.13.09_session_termination_inactivity": session_termination_inactivity,
		"03.13.10_cryptographic_key_management": cryptographic_key_management,
		"03.13.11_fips_validated_cryptography": fips_validated_cryptography,
		"03.13.12_collaborative_device_control": collaborative_device_control,
		"03.13.13_mobile_code_control": mobile_code_control,
		"03.13.15_session_authenticity": session_authenticity,
		"03.13.08_cui_at_rest_protection": cui_at_rest_protection,
	},
}
