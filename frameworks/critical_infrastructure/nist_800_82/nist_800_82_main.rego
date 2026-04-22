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

compliance_report := {
    "framework":       "NIST Special Publication 800-82 Rev 3",
    "title":           "Guide to Operational Technology (OT) Security",
    "published":       "September 2023",
    "entity_name":     input.entity_name,
    "ot_system_type":  input.ot_system_type,
    "sector":          input.sector,
    "assessed_at":     input.assessment_date,
    "compliant":       compliant,
    "total_controls":  32,
    "violations":      violations,
    "violation_count": count(violations),
    "control_family_summary": {
        "risk_assessment":      [v | some v in violations; contains(v, "RA-")],
        "network_architecture": array.concat([v | some v in violations; contains(v, "SC-7")], [v | some v in violations; contains(v, "SC-8")]),
        "access_control":       array.concat([v | some v in violations; contains(v, "AC-")], [v | some v in violations; contains(v, "PE-")]),
        "configuration_mgmt":   array.concat([v | some v in violations; contains(v, "CM-")], [v | some v in violations; contains(v, "MP-")]),
        "patch_management":     [v | some v in violations; contains(v, "SI-2")],
        "incident_response":    [v | some v in violations; contains(v, "IR-")],
        "monitoring":           [v | some v in violations; contains(v, "AU-")],
        "system_integrity":     array.concat([v | some v in violations; contains(v, "SI-3")], [v | some v in violations; contains(v, "SI-7")]),
        "contingency_planning": [v | some v in violations; contains(v, "CP-")],
        "supply_chain":         [v | some v in violations; contains(v, "SR-")],
    },
}
