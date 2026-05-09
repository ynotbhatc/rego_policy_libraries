package nist.sp800_171.physical_protection

import rego.v1

# NIST SP 800-171 Rev 3 - Physical Protection (PE) Requirements
# Family: 3.10 — Protecting Controlled Unclassified Information (CUI)

# 3.10.1: Limit physical access to organizational systems to authorized individuals
default physical_access_limited := false

physical_access_limited if {
    input.nist_800_171.physical_protection.access.authorized_individuals_only == true
    input.nist_800_171.physical_protection.access.access_controls_implemented == true
    input.nist_800_171.physical_protection.access.access_list_maintained == true
}

# 3.10.2: Protect and monitor the physical facility and support infrastructure for
#          organizational systems
default facility_monitoring := false

facility_monitoring if {
    input.nist_800_171.physical_protection.monitoring.facility_monitored == true
    input.nist_800_171.physical_protection.monitoring.support_infrastructure_monitored == true
    input.nist_800_171.physical_protection.monitoring.monitoring_continuous == true
}

# 3.10.3: Escort visitors and monitor visitor activity
default visitor_escort := false

visitor_escort if {
    input.nist_800_171.physical_protection.visitors.escort_required == true
    input.nist_800_171.physical_protection.visitors.activity_monitored == true
    input.nist_800_171.physical_protection.visitors.visitor_log_maintained == true
}

# 3.10.4: Maintain audit logs of physical access
default physical_access_logs := false

physical_access_logs if {
    input.nist_800_171.physical_protection.access_logs.logs_maintained == true
    input.nist_800_171.physical_protection.access_logs.covers_all_entry_points == true
    input.nist_800_171.physical_protection.access_logs.retention_period_days >= 90
    input.nist_800_171.physical_protection.access_logs.reviewed_periodically == true
}

# 3.10.5: Control and manage physical access devices such as keys, locks, combinations,
#          and card readers
default physical_access_devices_managed := false

physical_access_devices_managed if {
    input.nist_800_171.physical_protection.access_devices.inventory_maintained == true
    input.nist_800_171.physical_protection.access_devices.issuance_tracked == true
    input.nist_800_171.physical_protection.access_devices.revocation_procedures == true
    input.nist_800_171.physical_protection.access_devices.periodic_audit == true
}

# 3.10.6: Enforce safeguarding measures for CUI at alternate work sites
default alternate_work_site_safeguards := false

alternate_work_site_safeguards if {
    input.nist_800_171.physical_protection.alternate_sites.safeguards_defined == true
    input.nist_800_171.physical_protection.alternate_sites.safeguards_enforced == true
    input.nist_800_171.physical_protection.alternate_sites.includes_remote_work == true
}

# Violations set
violations contains msg if {
    not physical_access_limited
    msg := "NIST 800-171 3.10.1: Physical access to organizational systems must be limited to authorized individuals with maintained access lists"
}

violations contains msg if {
    not facility_monitoring
    msg := "NIST 800-171 3.10.2: Physical facilities and support infrastructure for organizational systems must be continuously protected and monitored"
}

violations contains msg if {
    not visitor_escort
    msg := "NIST 800-171 3.10.3: Visitors must be escorted and their activity monitored, with visitor logs maintained"
}

violations contains msg if {
    not physical_access_logs
    msg := "NIST 800-171 3.10.4: Audit logs of physical access must be maintained for all entry points, retained at least 90 days, and reviewed periodically"
}

violations contains msg if {
    not physical_access_devices_managed
    msg := "NIST 800-171 3.10.5: Physical access devices (keys, cards, PINs) must be inventoried, tracked, with revocation procedures and periodic audits"
}

violations contains msg if {
    not alternate_work_site_safeguards
    msg := "NIST 800-171 3.10.6: Safeguarding measures for CUI must be defined and enforced at alternate work sites including remote work locations"
}

# Compliance aggregation
default compliant := false

compliant if { count(violations) == 0 }

compliance_report := {
    "family": "3.10 Physical Protection",
    "standard": "NIST SP 800-171 Rev 3",
    "total_controls": 6,
    "violations": violations,
    "compliant": compliant,
    "controls": {
        "3.10.1_physical_access_limited": physical_access_limited,
        "3.10.2_facility_monitoring": facility_monitoring,
        "3.10.3_visitor_escort": visitor_escort,
        "3.10.4_physical_access_logs": physical_access_logs,
        "3.10.5_physical_access_devices_managed": physical_access_devices_managed,
        "3.10.6_alternate_work_site_safeguards": alternate_work_site_safeguards,
    },
}
