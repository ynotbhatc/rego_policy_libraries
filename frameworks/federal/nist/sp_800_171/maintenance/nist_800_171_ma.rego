# METADATA
# title: "NIST SP 800-171 Rev 3 - Maintenance (MA) Requirements"
# custom:
#   class: compliance
#   framework: nist_sp_800_171
#   source: nist
#   domains: [us-federal, security-controls]
#   coverage:
#     checks: 10
#     cited: 3
#     expected: 4
#     found: 10
#     scope: module
#     density: full
#     basis: declared-total
#     tested: true
#     entrypoint: compliance_report
#     guard: self
#     as_of: v2.4.2
package nist.sp800_171.maintenance

import rego.v1

# NIST SP 800-171 Rev 3 - Maintenance (MA) Requirements
#
# Ids are NIST SP 800-171 Rev 3 element identifiers from the NIST CPRT export
# (https://csrc.nist.gov/extensions/nudp/services/json/nudp/framework/version/SP_800_171_3_0_0/export/json?element=all, sha256 19d18ef88700e468..., retrieved 2026-10-13).
# The fact checks below were written against the Rev 2 statements; each is re-keyed to the Rev 3
# requirement that carries its Rev 2 slot. A Rev 2 slot withdrawn in Rev 3 with "Incorporated into"
# is keyed to the incorporating requirement(s); one withdrawn as "Addressed by", recategorized as
# NCO, technology-specific or for consistency with SP 800-53 is retired: its rule is kept for lineage
# but it emits no violation and is not a Rev 3 control. Rev 3 status per requirement (attestation
# plus these facts) is computed by nist_800_171_main.rego (package nist_800_171.main).
# Family: 03.07 Maintenance — Protecting Controlled Unclassified Information (CUI)

# RETIRED, not a Rev 3 control (Rev 2 3.7.1, withdrawn in Rev 3: Recategorized as NCO.): Perform maintenance on organizational systems
default maintenance_performed := false

maintenance_performed if {
	input.nist_800_171.maintenance.maintenance_schedule.schedule_documented == true
	input.nist_800_171.maintenance.maintenance_schedule.performed_regularly == true
	input.nist_800_171.maintenance.maintenance_schedule.records_maintained == true
}

# 03.07.04/03.07.06 (Rev 2 3.7.2, withdrawn in Rev 3: Incorporated into 03.07.04 and 03.07.06.): Provide controls on the tools, techniques, mechanisms, and personnel that perform
#         maintenance on organizational systems
default maintenance_controls := false

maintenance_controls if {
	input.nist_800_171.maintenance.controls.approved_tools == true
	input.nist_800_171.maintenance.controls.approved_techniques == true
	input.nist_800_171.maintenance.controls.authorized_personnel_only == true
	input.nist_800_171.maintenance.controls.controls_documented == true
}

# 03.08.03 (Rev 2 3.7.3, withdrawn in Rev 3: Incorporated into 03.08.03.): Ensure equipment removed for off-site maintenance is sanitized of any CUI
default equipment_sanitization := false

equipment_sanitization if {
	input.nist_800_171.maintenance.sanitization.removed_equipment_sanitized == true
	input.nist_800_171.maintenance.sanitization.sanitization_verified == true
	input.nist_800_171.maintenance.sanitization.process_documented == true
}

# 03.07.04 Maintenance Tools (Rev 2 3.7.4): Check media containing diagnostic programs for malicious code before use
default diagnostic_media_checked := false

diagnostic_media_checked if {
	input.nist_800_171.maintenance.diagnostic_media.scanned_before_use == true
	input.nist_800_171.maintenance.diagnostic_media.approved_scanning_tool == true
	input.nist_800_171.maintenance.diagnostic_media.results_documented == true
}

# 03.07.05 Nonlocal Maintenance (Rev 2 3.7.5): Require MFA to establish nonlocal (remote) maintenance sessions via external
#         networks and terminate such connections when nonlocal maintenance is complete
default remote_maintenance_mfa := false

remote_maintenance_mfa if {
	input.nist_800_171.maintenance.remote_maintenance.mfa_required == true
	input.nist_800_171.maintenance.remote_maintenance.session_terminated_after == true
	input.nist_800_171.maintenance.remote_maintenance.connections_monitored == true
}

# 03.07.06 Maintenance Personnel (Rev 2 3.7.6): Supervise maintenance activities of maintenance personnel without required
#         access authorization
default maintenance_supervision := false

maintenance_supervision if {
	input.nist_800_171.maintenance.supervision.unauthorized_personnel_supervised == true
	input.nist_800_171.maintenance.supervision.supervisor_has_required_access == true
	input.nist_800_171.maintenance.supervision.supervision_documented == true
}

# Violations set
violations contains msg if {
	not maintenance_controls
	msg := "NIST SP 800-171 03.07.04/03.07.06 (Rev 2 3.7.2, withdrawn in Rev 3: Incorporated into 03.07.04 and 03.07.06.): Controls must be established for maintenance tools, techniques, mechanisms, and authorized personnel"
}

violations contains msg if {
	not equipment_sanitization
	msg := "NIST SP 800-171 03.08.03 (Rev 2 3.7.3, withdrawn in Rev 3: Incorporated into 03.08.03.): Equipment removed for off-site maintenance must be sanitized of CUI and sanitization must be verified"
}

violations contains msg if {
	not diagnostic_media_checked
	msg := "NIST SP 800-171 03.07.04: Media containing diagnostic programs must be scanned for malicious code before use in maintenance"
}

violations contains msg if {
	not remote_maintenance_mfa
	msg := "NIST SP 800-171 03.07.05: MFA must be required for remote maintenance sessions and connections must be terminated when complete"
}

violations contains msg if {
	not maintenance_supervision
	msg := "NIST SP 800-171 03.07.06: Maintenance personnel without required access authorization must be supervised by authorized individuals"
}

# Compliance aggregation
default compliant := false

compliant if count(violations) == 0

compliance_report := {
	"family": "03.07 Maintenance",
	"standard": "NIST SP 800-171 Rev 3",
	"total_controls": 4,
	"violations": violations,
	"compliant": compliant,
	"retired_rev2_checks": {"rev2_3.7.1_maintenance_performed": maintenance_performed},
	"controls": {
		"03.07.04_maintenance_controls": maintenance_controls,
		"03.08.03_equipment_sanitization": equipment_sanitization,
		"03.07.04_diagnostic_media_checked": diagnostic_media_checked,
		"03.07.05_remote_maintenance_mfa": remote_maintenance_mfa,
		"03.07.06_maintenance_supervision": maintenance_supervision,
	},
}
