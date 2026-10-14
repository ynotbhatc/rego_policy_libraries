# METADATA
# title: "NIST SP 800-171 Rev 3 - Physical Protection (PE) Requirements"
# custom:
#   class: compliance
#   framework: nist_sp_800_171
#   source: nist
#   domains: [us-federal, security-controls]
#   coverage:
#     checks: 12
#     cited: 3
#     expected: 4
#     found: 12
#     scope: module
#     density: full
#     basis: declared-total
#     tested: true
#     entrypoint: compliance_report
#     guard: self
#     as_of: v2.4.2
package nist.sp800_171.physical_protection

import rego.v1

# NIST SP 800-171 Rev 3 - Physical Protection (PE) Requirements
#
# Ids are NIST SP 800-171 Rev 3 element identifiers from the NIST CPRT export
# (https://csrc.nist.gov/extensions/nudp/services/json/nudp/framework/version/SP_800_171_3_0_0/export/json?element=all, sha256 19d18ef88700e468..., retrieved 2026-10-13).
# The fact checks below were written against the Rev 2 statements; each is re-keyed to the Rev 3
# requirement that carries its Rev 2 slot. A Rev 2 slot withdrawn in Rev 3 with "Incorporated into"
# is keyed to the incorporating requirement(s); one withdrawn as "Addressed by", recategorized as
# NCO, technology-specific or for consistency with SP 800-53 is retired: its rule is kept for lineage
# but it emits no violation and is not a Rev 3 control. Rev 3 status per requirement (attestation
# plus these facts) is computed by nist_800_171_main.rego (package nist_800_171.main).
# Family: 03.10 Physical Protection — Protecting Controlled Unclassified Information (CUI)

# 03.10.01 Physical Access Authorizations (Rev 2 3.10.1): Limit physical access to organizational systems to authorized individuals
default physical_access_limited := false

physical_access_limited if {
	input.nist_800_171.physical_protection.access.authorized_individuals_only == true
	input.nist_800_171.physical_protection.access.access_controls_implemented == true
	input.nist_800_171.physical_protection.access.access_list_maintained == true
}

# 03.10.02 Monitoring Physical Access (Rev 2 3.10.2): Protect and monitor the physical facility and support infrastructure for
#          organizational systems
default facility_monitoring := false

facility_monitoring if {
	input.nist_800_171.physical_protection.monitoring.facility_monitored == true
	input.nist_800_171.physical_protection.monitoring.support_infrastructure_monitored == true
	input.nist_800_171.physical_protection.monitoring.monitoring_continuous == true
}

# 03.10.07 (Rev 2 3.10.3, withdrawn in Rev 3: Incorporated into 03.10.07.): Escort visitors and monitor visitor activity
default visitor_escort := false

visitor_escort if {
	input.nist_800_171.physical_protection.visitors.escort_required == true
	input.nist_800_171.physical_protection.visitors.activity_monitored == true
	input.nist_800_171.physical_protection.visitors.visitor_log_maintained == true
}

# 03.10.07 (Rev 2 3.10.4, withdrawn in Rev 3: Incorporated into 03.10.07.): Maintain audit logs of physical access
default physical_access_logs := false

physical_access_logs if {
	input.nist_800_171.physical_protection.access_logs.logs_maintained == true
	input.nist_800_171.physical_protection.access_logs.covers_all_entry_points == true
	input.nist_800_171.physical_protection.access_logs.retention_period_days >= 90
	input.nist_800_171.physical_protection.access_logs.reviewed_periodically == true
}

# 03.10.07 (Rev 2 3.10.5, withdrawn in Rev 3: Incorporated into 03.10.07.): Control and manage physical access devices such as keys, locks, combinations,
#          and card readers
default physical_access_devices_managed := false

physical_access_devices_managed if {
	input.nist_800_171.physical_protection.access_devices.inventory_maintained == true
	input.nist_800_171.physical_protection.access_devices.issuance_tracked == true
	input.nist_800_171.physical_protection.access_devices.revocation_procedures == true
	input.nist_800_171.physical_protection.access_devices.periodic_audit == true
}

# 03.10.06 Alternate Work Site (Rev 2 3.10.6): Enforce safeguarding measures for CUI at alternate work sites
default alternate_work_site_safeguards := false

alternate_work_site_safeguards if {
	input.nist_800_171.physical_protection.alternate_sites.safeguards_defined == true
	input.nist_800_171.physical_protection.alternate_sites.safeguards_enforced == true
	input.nist_800_171.physical_protection.alternate_sites.includes_remote_work == true
}

# Violations set
violations contains msg if {
	not physical_access_limited
	msg := "NIST SP 800-171 03.10.01: Physical access to organizational systems must be limited to authorized individuals with maintained access lists"
}

violations contains msg if {
	not facility_monitoring
	msg := "NIST SP 800-171 03.10.02: Physical facilities and support infrastructure for organizational systems must be continuously protected and monitored"
}

violations contains msg if {
	not visitor_escort
	msg := "NIST SP 800-171 03.10.07 (Rev 2 3.10.3, withdrawn in Rev 3: Incorporated into 03.10.07.): Visitors must be escorted and their activity monitored, with visitor logs maintained"
}

violations contains msg if {
	not physical_access_logs
	msg := "NIST SP 800-171 03.10.07 (Rev 2 3.10.4, withdrawn in Rev 3: Incorporated into 03.10.07.): Audit logs of physical access must be maintained for all entry points, retained at least 90 days, and reviewed periodically"
}

violations contains msg if {
	not physical_access_devices_managed
	msg := "NIST SP 800-171 03.10.07 (Rev 2 3.10.5, withdrawn in Rev 3: Incorporated into 03.10.07.): Physical access devices (keys, cards, PINs) must be inventoried, tracked, with revocation procedures and periodic audits"
}

violations contains msg if {
	not alternate_work_site_safeguards
	msg := "NIST SP 800-171 03.10.06: Safeguarding measures for CUI must be defined and enforced at alternate work sites including remote work locations"
}

# Compliance aggregation
default compliant := false

compliant if count(violations) == 0

compliance_report := {
	"family": "03.10 Physical Protection",
	"standard": "NIST SP 800-171 Rev 3",
	"total_controls": 4,
	"violations": violations,
	"compliant": compliant,
	"controls": {
		"03.10.01_physical_access_limited": physical_access_limited,
		"03.10.02_facility_monitoring": facility_monitoring,
		"03.10.07_visitor_escort": visitor_escort,
		"03.10.07_physical_access_logs": physical_access_logs,
		"03.10.07_physical_access_devices_managed": physical_access_devices_managed,
		"03.10.06_alternate_work_site_safeguards": alternate_work_site_safeguards,
	},
}
