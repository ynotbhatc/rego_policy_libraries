# METADATA
# title: "NIST Special Publication 800-82 Revision 3"
# custom:
#   class: ot
#   framework: nist_800_82
#   source: nist
#   domains: [ot, industrial]
#   coverage:
#     checks: 36
#     cited: 24
#     expected: 32
#     found: 36
#     scope: directory
#     density: full
#     basis: declared-total
#     tested: true
#     entrypoint: compliance_report
#     guard: self
#     as_of: v2.4.2
package nist_800_82.main

import rego.v1

# NIST Special Publication 800-82 Revision 3
# "Guide to Operational Technology (OT) Security"
# Published: September 2023
#
# Covers: ICS, SCADA, DCS, PLC, RTU, HMI, and other OT systems
# Natural companion to NERC-CIP for utility and critical infrastructure operators
#
# Mapped to NIST SP 800-53 Rev 5 control families with OT-specific overlays:
#   AC  — Access Control
#   AU  — Audit and Accountability
#   CA  — Assessment, Authorization, Monitoring
#   CM  — Configuration Management
#   CP  — Contingency Planning
#   IA  — Identification and Authentication
#   IR  — Incident Response
#   MA  — Maintenance
#   MP  — Media Protection
#   PE  — Physical and Environmental Protection
#   PL  — Planning
#   PM  — Program Management
#   RA  — Risk Assessment
#   SA  — System and Services Acquisition
#   SC  — System and Communications Protection
#   SI  — System and Information Integrity
#
# OPA endpoint: POST http://<host>:8183/v1/data/nist_800_82/main/compliance_report
#
# OT overlay profile gate (Appendix F) — input.nist_800_82.target_impact:
#   "low" | "moderate" | "high". Absent evaluates "high" (the largest baseline).
#   Any other value is itself a violation and evaluates "high". The gate selects
#   which overlay baseline the report summarises (ot_overlay_selected); the 35
#   checks above are evaluated unchanged at every impact level.
#   The full overlay table is exposed as data.nist_800_82.main.ot_overlay for the
#   orchestrator's coverage bridge (transcription notes above the table).
#
# OT overlay source record:
#   Document: NIST SP 800-82 Rev. 3 (September 2023)
#   URL:      https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-82r3.pdf
#   sha256:   608f554514d381853e24e0b33123b7080fbd757826f460032690aade63394616
#   Read:     2026-10-13
#   Table:    Appendix F "OT Overlay", F.3 Table 22 "Control baselines",
#             printed pp. 215-223, cross-checked against the F.7 detailed
#             control tables (pp. 227-298). Appendix G is the change log.
#   Could not read: 0 rows.

default compliant := false

compliant if {
	count(violations) == 0
}

# ── OT-Specific Risk Assessment ───────────────────────────────────────────────

violations contains msg if {
	not input.risk_assessment.ot_specific.conducted
	msg := "NIST 800-82 RA-3(OT): OT-specific risk assessment not conducted — must account for safety, availability, and process integrity impacts"
}

violations contains msg if {
	not input.risk_assessment.consequence_analysis.life_safety
	msg := "NIST 800-82 RA-3(OT): Risk assessment does not evaluate life-safety consequences of cyber events"
}

violations contains msg if {
	not input.risk_assessment.consequence_analysis.environmental
	msg := "NIST 800-82 RA-3(OT): Risk assessment does not evaluate environmental impact consequences of cyber events"
}

violations contains msg if {
	not input.risk_assessment.asset_inventory.ot_systems
	msg := "NIST 800-82 CM-8(OT): OT asset inventory not maintained (PLCs, RTUs, HMIs, historians, engineering workstations)"
}

# ── Network Architecture and Segmentation ────────────────────────────────────

violations contains msg if {
	not input.network.ot_it_segmentation.implemented
	msg := "NIST 800-82 SC-7(OT): OT network not segmented from IT/corporate network using firewall or DMZ"
}

violations contains msg if {
	not input.network.demilitarized_zone.exists
	msg := "NIST 800-82 SC-7(OT): DMZ not established between OT and IT networks for data exchange"
}

violations contains msg if {
	not input.network.wireless.ot_wireless_restricted
	msg := "NIST 800-82 SC-8(OT): Wireless access to OT networks not restricted and controlled"
}

violations contains msg if {
	not input.network.remote_access.ot_specific_controls
	msg := "NIST 800-82 AC-17(OT): Remote access to OT systems not controlled with OT-specific security controls"
}

violations contains msg if {
	not input.network.dial_up.disabled_or_controlled
	msg := "NIST 800-82 SC-7(OT): Dial-up modems connected to OT systems not disabled or controlled"
}

violations contains msg if {
	not input.network.data_flows.documented
	msg := "NIST 800-82 SC-7(OT): Data flows between OT zones and to IT/internet not documented"
}

# ── Access Control ────────────────────────────────────────────────────────────

violations contains msg if {
	not input.access_control.ot_accounts.managed
	msg := "NIST 800-82 AC-2(OT): OT system accounts not formally managed — shared accounts common but must be documented"
}

violations contains msg if {
	not input.access_control.privileged_access.ot.controlled
	msg := "NIST 800-82 AC-6(OT): Privileged access to OT engineering workstations and HMIs not controlled"
}

violations contains msg if {
	not input.access_control.vendor_remote.managed
	msg := "NIST 800-82 AC-17(OT): Vendor and third-party remote access to OT systems not controlled and monitored"
}

violations contains msg if {
	not input.access_control.physical_ot_access.controlled
	msg := "NIST 800-82 PE-3(OT): Physical access to OT components (field devices, control panels) not controlled"
}

# ── Configuration Management ──────────────────────────────────────────────────

violations contains msg if {
	not input.configuration.ot_baseline.established
	msg := "NIST 800-82 CM-2(OT): Secure baseline configuration not established for OT systems"
}

violations contains msg if {
	not input.configuration.change_management.ot_process
	msg := "NIST 800-82 CM-3(OT): Change management process not established for OT system changes — must consider safety impacts"
}

violations contains msg if {
	not input.configuration.removable_media.controlled
	msg := "NIST 800-82 MP-7(OT): Removable media (USB drives, laptops) not controlled when connecting to OT systems"
}

violations contains msg if {
	not input.configuration.software.authorized_only
	msg := "NIST 800-82 CM-7(OT): Only authorized software permitted to execute on OT systems — whitelisting required"
}

# ── Patch Management (OT-Specific Challenges) ────────────────────────────────

violations contains msg if {
	not input.patch_management.ot.policy_exists
	msg := "NIST 800-82 SI-2(OT): OT-specific patch management policy not established — must account for vendor approval requirements"
}

violations contains msg if {
	not input.patch_management.ot.compensating_controls
	msg := "NIST 800-82 SI-2(OT): Compensating controls not in place for OT systems that cannot be immediately patched"
}

violations contains msg if {
	not input.patch_management.ot.vendor_coordination
	msg := "NIST 800-82 SI-2(OT): Vendor coordination process not established for OT software updates"
}

# ── Incident Response ─────────────────────────────────────────────────────────

violations contains msg if {
	not input.incident_response.ot_specific.plan_exists
	msg := "NIST 800-82 IR-4(OT): OT-specific incident response plan not established — must include safety system recovery"
}

violations contains msg if {
	not input.incident_response.ot_specific.coordination_with_safety
	msg := "NIST 800-82 IR-4(OT): Incident response plan does not coordinate with safety and engineering teams"
}

violations contains msg if {
	not input.incident_response.ot_specific.forensics_consideration
	msg := "NIST 800-82 IR-4(OT): OT incident response does not address forensic evidence collection without disrupting operations"
}

violations contains msg if {
	not input.incident_response.reporting.ics_cert
	msg := "NIST 800-82 IR-6(OT): Process not established to report OT incidents to ICS-CERT / CISA"
}

# ── Audit and Monitoring ──────────────────────────────────────────────────────

violations contains msg if {
	not input.monitoring.ot_network.continuous
	msg := "NIST 800-82 AU-2(OT): Continuous monitoring not implemented for OT network traffic"
}

violations contains msg if {
	not input.monitoring.ot_network.protocol_aware
	msg := "NIST 800-82 AU-2(OT): OT network monitoring not protocol-aware (Modbus, DNP3, IEC 61850, etc.)"
}

violations contains msg if {
	not input.monitoring.historian.log_integrity
	msg := "NIST 800-82 AU-9(OT): Process historian logs not protected from tampering"
}

# ── System Integrity ──────────────────────────────────────────────────────────

violations contains msg if {
	not input.system_integrity.malware_protection.ot_appropriate
	msg := "NIST 800-82 SI-3(OT): OT-appropriate malware protection not deployed — must not impact real-time operations"
}

violations contains msg if {
	not input.system_integrity.firmware.integrity_verified
	msg := "NIST 800-82 SI-7(OT): Firmware integrity verification not performed for critical OT devices"
}

# ── Contingency Planning ──────────────────────────────────────────────────────

violations contains msg if {
	not input.contingency.backup.ot_configurations
	msg := "NIST 800-82 CP-9(OT): OT system configurations (PLC programs, HMI screens, historian data) not backed up"
}

violations contains msg if {
	not input.contingency.recovery.ot_rto_defined
	msg := "NIST 800-82 CP-2(OT): Recovery Time Objectives not defined for OT systems — must balance safety with cyber recovery"
}

violations contains msg if {
	not input.contingency.manual_operations.procedures_documented
	msg := "NIST 800-82 CP-2(OT): Manual/degraded operations procedures not documented for OT systems"
}

# ── Supply Chain (OT Equipment) ───────────────────────────────────────────────

violations contains msg if {
	not input.supply_chain.ot_equipment.vendor_assessment
	msg := "NIST 800-82 SR-3(OT): OT equipment vendor security assessment not performed"
}

violations contains msg if {
	not input.supply_chain.ot_equipment.counterfeit_protection
	msg := "NIST 800-82 SR-4(OT): Process not established to detect counterfeit OT hardware components"
}

# ── Compliance Report ────────────────────────────────────────────────────────

# Defaults — without these, an undefined input field makes the
# entire compliance_report object undefined (Rego v1 behavior).
default assessment_date := "unknown"

assessment_date := input.assessment_date

default entity_name := "unknown"

entity_name := input.entity_name

default ot_system_type := "unknown"

ot_system_type := input.ot_system_type

default sector := "unknown"

sector := input.sector

compliance_report := {
	"framework": "NIST Special Publication 800-82 Rev 3",
	"title": "Guide to Operational Technology (OT) Security",
	"published": "September 2023",
	"entity_name": entity_name,
	"ot_system_type": ot_system_type,
	"sector": sector,
	"assessed_at": assessment_date,
	"compliant": compliant,
	"total_controls": 32,
	"violations": violations,
	"violation_count": count(violations),
	"ot_overlay": {
		"source": "NIST SP 800-82 Rev. 3, Appendix F, Table 22 (Control baselines)",
		"target_impact": target_impact,
		"target_impact_defaulted": target_impact_defaulted,
		"control_counts": ot_overlay_counts,
		"selected_control_count": count(ot_overlay_selected),
		"org_wide_pm_count": count(_ot_org_wide),
	},
	"control_family_summary": {
		"risk_assessment": [v | some v in violations; contains(v, "RA-")],
		"network_architecture": array.concat([v | some v in violations; contains(v, "SC-7")], [v | some v in violations; contains(v, "SC-8")]),
		"access_control": array.concat([v | some v in violations; contains(v, "AC-")], [v | some v in violations; contains(v, "PE-")]),
		"configuration_mgmt": array.concat([v | some v in violations; contains(v, "CM-")], [v | some v in violations; contains(v, "MP-")]),
		"patch_management": [v | some v in violations; contains(v, "SI-2")],
		"incident_response": [v | some v in violations; contains(v, "IR-")],
		"monitoring": [v | some v in violations; contains(v, "AU-")],
		"system_integrity": array.concat([v | some v in violations; contains(v, "SI-3")], [v | some v in violations; contains(v, "SI-7")]),
		"contingency_planning": [v | some v in violations; contains(v, "CP-")],
		"supply_chain": [v | some v in violations; contains(v, "SR-")],
	},
}

# ── OT overlay profile gate ───────────────────────────────────────────────────

_impacts := {"low", "moderate", "high"}

# Absent target_impact evaluates the HIGH baseline (largest, fail-closed).
default target_impact := "high"

target_impact := input.nist_800_82.target_impact if input.nist_800_82.target_impact in _impacts

default target_impact_defaulted := true

target_impact_defaulted := false if input.nist_800_82.target_impact in _impacts

violations contains msg if {
	v := input.nist_800_82.target_impact
	not v in _impacts
	msg := sprintf("NIST 800-82 Appendix F: unrecognized input.nist_800_82.target_impact %v, must be low, moderate or high (evaluated at high)", [v])
}

# ── OT overlay table (Appendix F, Table 22) ───────────────────────────────────
#
# Source:  NIST SP 800-82 Rev. 3, "Guide to Operational Technology (OT) Security",
#          September 2023, Appendix F "OT Overlay", section F.3, Table 22
#          "Control baselines" (printed pp. 215-223).
# URL:     https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-82r3.pdf
# sha256:  608f554514d381853e24e0b33123b7080fbd757826f460032690aade63394616
# Read:    2026-10-13
# Note:    in Rev. 3 the OT overlay is Appendix F; Appendix G is the change log.
#
# Transcription rules:
#   - Keys are SP 800-53 Rev. 5 ids in OSCAL token form (AC-2 -> ac-2,
#     AC-2 (1) -> ac-2.1). A cell "AC-2 (1) (2)" selects AC-2, AC-2(1) and
#     AC-2(2) in that baseline; low / moderate / high are true where the cell
#     lists the control and it is not struck through.
#   - Underline (control added to that baseline by the overlay, compared with
#     SP 800-53B) is recorded in _ot_added; strikethrough (removed compared with
#     SP 800-53B) in _ot_removed, with the boolean for that baseline false. The
#     three struck entries (CA-8(1) HIGH; SC-10 MODERATE and HIGH; SI-8(2)
#     MODERATE and HIGH) are kept as rows so the removal is visible.
#   - PM-1 .. PM-32: Table 22 prints them in a single cell merged across LOW,
#     MOD and HIGH, and F.7.13 says program management controls "are not
#     associated with control baselines and are independent of any system
#     impact level". Encoded as true at all three levels and listed in
#     _ot_org_wide (row field org_wide), so a consumer can drop them.
#   - Table 22 gives no per-row tailoring note text; the tailoring it shows is
#     the underline / strikethrough marking above. The per-control OT
#     discussions and rationales in F.7 are not transcribed.
#   - Underline and strikethrough do not survive text extraction; they were read
#     from the line segments drawn on each page (underline at the glyph
#     baseline, strikethrough at mid-height). Cross-check: every non-PM row
#     agrees with the Select / Add / Remove cells of the F.7 detailed control
#     tables (390 of 390 rows, 0 differences; F.7.13 PM tables carry no
#     baseline columns).
#   - Could not read: 0 rows.
#
# Measured (rows marked true): 424 keys; low 194, moderate 338, high 421,
# of which 34 are the org-wide PM rows (160 / 304 / 387 without them).
# Subtracting the 11 / 19 / 20 overlay additions and adding back the 0 / 2 / 3
# removals gives 149 / 287 / 370, the SP 800-53B security baseline sizes.
# The profiles are nested: every low control is in moderate, every moderate
# control is in high.

# [token, low, moderate, high]
_ot_overlay_rows := [
	# Table 22, p. 215
	["ac-1", true, true, true],
	["ac-2", true, true, true],
	["ac-2.1", false, true, true],
	["ac-2.2", false, true, true],
	["ac-2.3", false, true, true],
	["ac-2.4", false, true, true],
	["ac-2.5", false, true, true],
	["ac-2.11", false, false, true],
	["ac-2.12", false, false, true],
	["ac-2.13", false, true, true],
	["ac-3", true, true, true],
	["ac-3.11", false, false, true],
	["ac-4", false, true, true],
	["ac-4.4", false, false, true],
	["ac-5", false, true, true],
	["ac-6", false, true, true],
	["ac-6.1", false, true, true],
	["ac-6.2", false, true, true],
	["ac-6.3", false, false, true],
	["ac-6.5", false, true, true],
	["ac-6.7", false, true, true],
	["ac-6.9", false, true, true],
	["ac-6.10", false, true, true],
	["ac-7", true, true, true],
	["ac-8", true, true, true],
	["ac-10", false, false, true],
	["ac-11", false, true, true],
	["ac-11.1", false, true, true],
	["ac-12", false, true, true],
	["ac-14", true, true, true],
	["ac-17", true, true, true],
	["ac-17.1", false, true, true],
	["ac-17.2", false, true, true],
	["ac-17.3", false, true, true],
	["ac-17.4", false, true, true],
	["ac-17.9", true, true, true],
	["ac-17.10", false, true, true],
	["ac-18", true, true, true],
	["ac-18.1", false, true, true],
	["ac-18.3", false, true, true],
	["ac-18.4", false, false, true],
	["ac-18.5", false, false, true],
	["ac-19", true, true, true],
	["ac-19.5", false, true, true],
	["ac-20", true, true, true],
	["ac-20.1", false, true, true],
	["ac-20.2", false, true, true],
	["ac-21", false, true, true],
	["ac-22", true, true, true],
	["at-1", true, true, true],
	["at-2", true, true, true],
	["at-2.2", true, true, true],
	["at-2.3", false, true, true],
	["at-2.4", false, true, true],
	["at-3", true, true, true],
	["at-4", true, true, true],
	["au-1", true, true, true],
	["au-2", true, true, true],
	["au-3", true, true, true],
	["au-3.1", false, true, true],
	# Table 22, p. 216
	["au-4", true, true, true],
	["au-4.1", true, true, true],
	["au-5", true, true, true],
	["au-5.1", false, false, true],
	["au-5.2", false, false, true],
	["au-6", true, true, true],
	["au-6.1", false, true, true],
	["au-6.3", false, true, true],
	["au-6.5", false, false, true],
	["au-6.6", false, false, true],
	["au-7", false, true, true],
	["au-7.1", false, true, true],
	["au-8", true, true, true],
	["au-9", true, true, true],
	["au-9.2", false, false, true],
	["au-9.3", false, false, true],
	["au-9.4", false, true, true],
	["au-10", false, false, true],
	["au-11", true, true, true],
	["au-12", true, true, true],
	["au-12.1", false, false, true],
	["au-12.3", false, false, true],
	["ca-1", true, true, true],
	["ca-2", true, true, true],
	["ca-2.1", false, true, true],
	["ca-2.2", false, false, true],
	["ca-3", true, true, true],
	["ca-3.6", false, false, true],
	["ca-5", true, true, true],
	["ca-6", true, true, true],
	["ca-7", true, true, true],
	["ca-7.1", false, true, true],
	["ca-7.4", true, true, true],
	["ca-8", false, false, true],
	["ca-8.1", false, false, false],
	["ca-9", true, true, true],
	["cm-1", true, true, true],
	["cm-2", true, true, true],
	["cm-2.2", false, true, true],
	["cm-2.3", false, true, true],
	["cm-2.7", false, true, true],
	["cm-3", false, true, true],
	["cm-3.1", false, false, true],
	["cm-3.2", false, true, true],
	["cm-3.4", false, true, true],
	["cm-3.6", false, false, true],
	["cm-4", true, true, true],
	["cm-4.1", false, false, true],
	["cm-4.2", false, true, true],
	["cm-5", true, true, true],
	["cm-5.1", false, false, true],
	["cm-6", true, true, true],
	["cm-6.1", false, false, true],
	["cm-6.2", false, false, true],
	["cm-7", true, true, true],
	["cm-7.1", false, true, true],
	["cm-7.2", false, true, true],
	["cm-7.5", false, true, true],
	["cm-8", true, true, true],
	["cm-8.1", false, true, true],
	["cm-8.2", false, false, true],
	["cm-8.3", false, true, true],
	["cm-8.4", false, false, true],
	["cm-9", false, true, true],
	# Table 22, p. 217
	["cm-10", true, true, true],
	["cm-11", true, true, true],
	["cm-12", false, true, true],
	["cm-12.1", false, true, true],
	["cp-1", true, true, true],
	["cp-2", true, true, true],
	["cp-2.1", false, true, true],
	["cp-2.2", false, false, true],
	["cp-2.3", false, true, true],
	["cp-2.5", false, false, true],
	["cp-2.8", false, true, true],
	["cp-3", true, true, true],
	["cp-3.1", false, false, true],
	["cp-4", true, true, true],
	["cp-4.1", false, true, true],
	["cp-4.2", false, false, true],
	["cp-6", false, true, true],
	["cp-6.1", false, true, true],
	["cp-6.2", false, false, true],
	["cp-6.3", false, true, true],
	["cp-7", false, true, true],
	["cp-7.1", false, true, true],
	["cp-7.2", false, true, true],
	["cp-7.3", false, true, true],
	["cp-7.4", false, false, true],
	["cp-8", false, true, true],
	["cp-8.1", false, true, true],
	["cp-8.2", false, true, true],
	["cp-8.3", false, false, true],
	["cp-8.4", false, false, true],
	["cp-9", true, true, true],
	["cp-9.1", false, true, true],
	["cp-9.2", false, false, true],
	["cp-9.3", false, false, true],
	["cp-9.5", false, false, true],
	["cp-9.8", false, true, true],
	["cp-10", true, true, true],
	["cp-10.2", false, true, true],
	["cp-10.4", false, false, true],
	["cp-10.6", false, true, true],
	["cp-12", true, true, true],
	["ia-1", true, true, true],
	["ia-2", true, true, true],
	["ia-2.1", true, true, true],
	["ia-2.2", true, true, true],
	["ia-2.5", false, false, true],
	["ia-2.8", true, true, true],
	["ia-2.12", true, true, true],
	["ia-3", true, true, true],
	["ia-4", true, true, true],
	["ia-4.4", false, true, true],
	["ia-5", true, true, true],
	["ia-5.1", true, true, true],
	["ia-5.2", false, true, true],
	["ia-5.6", false, true, true],
	["ia-6", true, true, true],
	["ia-7", true, true, true],
	["ia-8", true, true, true],
	["ia-8.1", true, true, true],
	["ia-8.2", true, true, true],
	["ia-8.4", true, true, true],
	["ia-11", true, true, true],
	["ia-12", false, true, true],
	["ia-12.1", false, false, true],
	["ia-12.2", false, true, true],
	["ia-12.3", false, true, true],
	["ia-12.4", false, false, true],
	["ia-12.5", false, true, true],
	["ir-1", true, true, true],
	["ir-2", true, true, true],
	["ir-2.1", false, false, true],
	["ir-2.2", false, false, true],
	["ir-3", false, true, true],
	["ir-3.2", false, true, true],
	# Table 22, p. 218
	["ir-4", true, true, true],
	["ir-4.1", false, true, true],
	["ir-4.4", false, false, true],
	["ir-4.11", false, false, true],
	["ir-5", true, true, true],
	["ir-5.1", false, false, true],
	["ir-6", true, true, true],
	["ir-6.1", false, true, true],
	["ir-6.3", false, true, true],
	["ir-7", true, true, true],
	["ir-7.1", false, true, true],
	["ir-8", true, true, true],
	["ma-1", true, true, true],
	["ma-2", true, true, true],
	["ma-2.2", false, false, true],
	["ma-3", false, true, true],
	["ma-3.1", false, true, true],
	["ma-3.2", false, true, true],
	["ma-3.3", false, true, true],
	["ma-4", true, true, true],
	["ma-4.1", false, true, true],
	["ma-4.3", false, false, true],
	["ma-5", true, true, true],
	["ma-5.1", false, false, true],
	["ma-6", false, true, true],
	["ma-7", true, true, true],
	["mp-1", true, true, true],
	["mp-2", true, true, true],
	["mp-3", false, true, true],
	["mp-4", false, true, true],
	["mp-5", false, true, true],
	["mp-6", true, true, true],
	["mp-6.1", false, false, true],
	["mp-6.2", false, false, true],
	["mp-6.3", false, false, true],
	["mp-7", true, true, true],
	["pe-1", true, true, true],
	["pe-2", true, true, true],
	["pe-3", true, true, true],
	["pe-3.1", false, false, true],
	["pe-4", false, true, true],
	["pe-5", false, true, true],
	["pe-6", true, true, true],
	["pe-6.1", false, true, true],
	["pe-6.4", false, true, true],
	["pe-8", true, true, true],
	["pe-8.1", false, false, true],
	["pe-9", false, true, true],
	# Table 22, p. 219
	["pe-10", false, true, true],
	["pe-11", false, true, true],
	["pe-11.1", false, false, true],
	["pe-12", true, true, true],
	["pe-13", true, true, true],
	["pe-13.1", false, true, true],
	["pe-13.2", false, false, true],
	["pe-14", true, true, true],
	["pe-15", true, true, true],
	["pe-15.1", false, false, true],
	["pe-16", true, true, true],
	["pe-17", false, true, true],
	["pe-18", false, false, true],
	["pe-22", false, true, true],
	["pl-1", true, true, true],
	["pl-2", true, true, true],
	["pl-4", true, true, true],
	["pl-4.1", true, true, true],
	["pl-8", false, true, true],
	["pl-10", true, true, true],
	["pl-11", true, true, true],
	["pm-1", true, true, true],
	["pm-2", true, true, true],
	["pm-3", true, true, true],
	["pm-4", true, true, true],
	["pm-5", true, true, true],
	["pm-6", true, true, true],
	["pm-7", true, true, true],
	["pm-8", true, true, true],
	["pm-9", true, true, true],
	["pm-10", true, true, true],
	["pm-11", true, true, true],
	# Table 22, p. 220
	["pm-12", true, true, true],
	["pm-13", true, true, true],
	["pm-14", true, true, true],
	["pm-15", true, true, true],
	["pm-16", true, true, true],
	["pm-17", true, true, true],
	["pm-18", true, true, true],
	["pm-19", true, true, true],
	["pm-20", true, true, true],
	["pm-20.1", true, true, true],
	["pm-21", true, true, true],
	["pm-22", true, true, true],
	["pm-23", true, true, true],
	["pm-24", true, true, true],
	["pm-25", true, true, true],
	["pm-26", true, true, true],
	["pm-27", true, true, true],
	["pm-28", true, true, true],
	["pm-29", true, true, true],
	["pm-30", true, true, true],
	["pm-30.1", true, true, true],
	["pm-31", true, true, true],
	["pm-32", true, true, true],
	["ps-1", true, true, true],
	["ps-2", true, true, true],
	["ps-3", true, true, true],
	["ps-4", true, true, true],
	["ps-4.2", false, false, true],
	["ps-5", true, true, true],
	# Table 22, p. 221
	["ps-6", true, true, true],
	["ps-7", true, true, true],
	["ps-8", true, true, true],
	["ps-9", true, true, true],
	["ra-1", true, true, true],
	["ra-2", true, true, true],
	["ra-3", true, true, true],
	["ra-3.1", true, true, true],
	["ra-5", true, true, true],
	["ra-5.2", true, true, true],
	["ra-5.4", false, false, true],
	["ra-5.5", false, true, true],
	["ra-5.11", true, true, true],
	["ra-7", true, true, true],
	["ra-9", false, true, true],
	["sa-1", true, true, true],
	["sa-2", true, true, true],
	["sa-3", true, true, true],
	["sa-4", true, true, true],
	["sa-4.1", false, true, true],
	["sa-4.2", false, true, true],
	["sa-4.5", false, false, true],
	["sa-4.9", false, true, true],
	["sa-4.10", true, true, true],
	["sa-4.12", true, true, true],
	["sa-5", true, true, true],
	["sa-8", true, true, true],
	["sa-9", true, true, true],
	["sa-9.2", false, true, true],
	["sa-10", false, true, true],
	["sa-11", false, true, true],
	["sa-15", false, true, true],
	["sa-15.3", false, true, true],
	["sa-16", false, false, true],
	["sa-17", false, false, true],
	["sa-21", false, false, true],
	["sa-22", true, true, true],
	["sc-1", true, true, true],
	["sc-2", false, true, true],
	["sc-3", false, false, true],
	# Table 22, p. 222
	["sc-4", false, true, true],
	["sc-5", true, true, true],
	["sc-7", true, true, true],
	["sc-7.3", false, true, true],
	["sc-7.4", false, true, true],
	["sc-7.5", false, true, true],
	["sc-7.7", false, true, true],
	["sc-7.8", false, true, true],
	["sc-7.18", false, true, true],
	["sc-7.21", false, false, true],
	["sc-7.28", true, true, true],
	["sc-7.29", true, true, true],
	["sc-8", false, true, true],
	["sc-8.1", false, true, true],
	["sc-10", false, false, false],
	["sc-12", true, true, true],
	["sc-12.1", false, false, true],
	["sc-13", true, true, true],
	["sc-15", true, true, true],
	["sc-17", false, true, true],
	["sc-18", false, true, true],
	["sc-20", true, true, true],
	["sc-21", true, true, true],
	["sc-22", true, true, true],
	["sc-23", false, true, true],
	["sc-24", false, true, true],
	["sc-28", false, true, true],
	["sc-28.1", false, true, true],
	["sc-39", true, true, true],
	["sc-41", true, true, true],
	["sc-45", true, true, true],
	["sc-47", false, false, true],
	["si-1", true, true, true],
	["si-2", true, true, true],
	["si-2.2", false, true, true],
	["si-3", true, true, true],
	["si-4", true, true, true],
	["si-4.2", false, true, true],
	["si-4.4", false, true, true],
	["si-4.5", false, true, true],
	["si-4.10", false, false, true],
	["si-4.12", false, false, true],
	["si-4.14", false, false, true],
	["si-4.20", false, false, true],
	["si-4.22", false, false, true],
	["si-5", true, true, true],
	["si-5.1", false, false, true],
	# Table 22, p. 223
	["si-6", false, false, true],
	["si-7", false, true, true],
	["si-7.1", false, true, true],
	["si-7.2", false, false, true],
	["si-7.5", false, false, true],
	["si-7.7", false, true, true],
	["si-7.15", false, false, true],
	["si-8", false, true, true],
	["si-8.2", false, false, false],
	["si-10", false, true, true],
	["si-11", false, true, true],
	["si-12", true, true, true],
	["si-13", false, false, true],
	["si-16", false, true, true],
	["si-17", true, true, true],
	["sr-1", true, true, true],
	["sr-2", true, true, true],
	["sr-2.1", true, true, true],
	["sr-3", true, true, true],
	["sr-5", true, true, true],
	["sr-5.1", false, true, true],
	["sr-6", false, true, true],
	["sr-8", true, true, true],
	["sr-9", false, false, true],
	["sr-9.1", false, false, true],
	["sr-10", true, true, true],
	["sr-11", true, true, true],
	["sr-11.1", true, true, true],
	["sr-11.2", true, true, true],
	["sr-12", true, true, true],
]

# Underlined in Table 22: [token, baselines the overlay added it to]
_ot_added := [
	["ac-3.11", ["high"]],
	["ac-17.9", ["low", "moderate", "high"]],
	["ac-17.10", ["moderate", "high"]],
	["at-2.4", ["moderate", "high"]],
	["au-4.1", ["low", "moderate", "high"]],
	["cp-10.6", ["moderate", "high"]],
	["cp-12", ["low", "moderate", "high"]],
	["ia-3", ["low"]],
	["ia-12.1", ["high"]],
	["ma-4.1", ["moderate", "high"]],
	["ma-7", ["low", "moderate", "high"]],
	["pe-6.4", ["moderate"]],
	["pe-22", ["moderate", "high"]],
	["sa-4.12", ["low", "moderate", "high"]],
	["sc-7.18", ["moderate"]],
	["sc-7.28", ["low", "moderate", "high"]],
	["sc-7.29", ["low", "moderate", "high"]],
	["sc-24", ["moderate"]],
	["sc-41", ["low", "moderate", "high"]],
	["sc-45", ["low", "moderate", "high"]],
	["sc-47", ["high"]],
	["si-13", ["high"]],
	["si-17", ["low", "moderate", "high"]],
	["sr-5.1", ["moderate", "high"]],
]

# Struck through in Table 22: [token, baselines the overlay removed it from]
_ot_removed := [
	["ca-8.1", ["high"]],
	["sc-10", ["moderate", "high"]],
	["si-8.2", ["moderate", "high"]],
]

# Merged LOW/MOD/HIGH cell; independent of impact level (F.7.13)
_ot_org_wide := {"pm-1", "pm-2", "pm-3", "pm-4", "pm-5", "pm-6", "pm-7", "pm-8", "pm-9", "pm-10", "pm-11", "pm-12", "pm-13", "pm-14", "pm-15", "pm-16", "pm-17", "pm-18", "pm-19", "pm-20", "pm-20.1", "pm-21", "pm-22", "pm-23", "pm-24", "pm-25", "pm-26", "pm-27", "pm-28", "pm-29", "pm-30", "pm-30.1", "pm-31", "pm-32"}

_ot_added_map := {r[0]: r[1] | some r in _ot_added}

_ot_removed_map := {r[0]: r[1] | some r in _ot_removed}

ot_overlay := {r[0]: row |
	some r in _ot_overlay_rows
	row := {
		"low": r[1],
		"moderate": r[2],
		"high": r[3],
		"added_to": object.get(_ot_added_map, r[0], []),
		"removed_from": object.get(_ot_removed_map, r[0], []),
		"org_wide": r[0] in _ot_org_wide,
	}
}

ot_overlay_counts := {lvl: n |
	some lvl in _impacts
	n := count([k | some k, row in ot_overlay; row[lvl]])
}

ot_overlay_selected := sort([k | some k, row in ot_overlay; row[target_impact]])
