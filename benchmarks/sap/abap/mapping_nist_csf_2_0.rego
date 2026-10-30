# METADATA
# title: "SAP ABAP Baseline → NIST CSF 2.0 subcategory view"
# custom:
#   class: security
#   framework: sap_abap_baseline
#   source: sap
#   domains: [sap, erp, crosswalk, us-federal]
#   coverage:
#     checks: 0
#     cited: 0
#     density: unrecognised
#     basis: role
#     tested: false
#     entrypoint: none
#     guard: n/a
#     as_of: v2.4.2
package sap_abap_baseline.mappings.nist_csf_2_0

import rego.v1

import data.sap_abap_baseline.registry

# NIST Cybersecurity Framework 2.0 (February 2024). The registry below is the complete set of 106 subcategory
# identifiers; titles are carried for the ones an SAP ABAP host assessment can inform. The requirement →
# subcategory assignment is this library's reading (DSAG's security guide organises SAP security along the
# CSF functions; SAP itself publishes no CSF crosswalk for the Baseline) and is data, not logic: change the
# table, not the rules.

framework := {
	"id": "nist_csf_2_0",
	"name": "NIST Cybersecurity Framework 2.0",
	"source": "NIST CSWP 29, February 2024",
	"mapping": "Baseline requirement → CSF 2.0 subcategory, this library's editorial assignment",
}

# Baseline requirement (the policy a check belongs to) → CSF 2.0 subcategories it gives evidence for.
by_requirement := {
	"PWDPOL-A": ["PR.AA-01", "PR.AA-03"],
	"STDUSR-A": ["PR.AA-01", "PR.AA-05"],
	"USRCTR-A": ["PR.AA-01", "PR.AA-05"],
	"USRTYP-A": ["PR.AA-01"],
	"USRCHAR-A": ["PR.AA-01"],
	"AUTHASSIGN-A": ["PR.AA-05"],
	"CRITAU-A": ["PR.AA-05"],
	"TRUST-A": ["PR.AA-03", "PR.AA-05"],
	"SSO-A": ["PR.AA-03"],
	"RFCGW-A": ["PR.IR-01", "PR.AA-05"],
	"MSGSRV-A": ["PR.IR-01"],
	"NETCF-A": ["PR.IR-01", "PR.PS-01"],
	"NETENC-A": ["PR.DS-02"],
	"AUDIT-A": ["PR.PS-04", "DE.CM-09"],
	"SECUPD-A": ["ID.RA-01", "PR.PS-02"],
	"CHANGE-A": ["PR.PS-01"],
	"DISCL-A": ["PR.PS-01", "PR.IR-01"],
	"FILE-A": ["PR.DS-01", "PR.PS-01"],
	"SCRIPT-A": ["PR.PS-05"],
	"SECSTO-A": ["PR.DS-01"],
	"OBSCNT-A": ["ID.AM-08"],
}

_titles := {
	"ID.AM-08": "Systems, hardware, software, services, and data are managed throughout their life cycles",
	"ID.RA-01": "Vulnerabilities in assets are identified, validated, and recorded",
	"PR.AA-01": "Identities and credentials for authorized users, services, and hardware are managed by the organization",
	"PR.AA-03": "Users, services, and hardware are authenticated",
	"PR.AA-05": "Access permissions, entitlements, and authorizations are defined in a policy, managed, enforced, and reviewed, and incorporate the principles of least privilege and separation of duties",
	"PR.DS-01": "The confidentiality, integrity, and availability of data-at-rest are protected",
	"PR.DS-02": "The confidentiality, integrity, and availability of data-in-transit are protected",
	"PR.PS-01": "Configuration management practices are established and applied",
	"PR.PS-02": "Software is maintained, replaced, and removed commensurate with risk",
	"PR.PS-04": "Log records are generated and made available for continuous monitoring",
	"PR.PS-05": "Installation and execution of unauthorized software are prevented",
	"PR.IR-01": "Networks and environments are protected from unauthorized logical access and usage",
	"DE.CM-09": "Computing hardware and software, runtime environments, and their data are monitored to find potentially adverse events",
}

_categories := {
	"GV.OC": "Organizational Context", "GV.RM": "Risk Management Strategy", "GV.RR": "Roles, Responsibilities, and Authorities",
	"GV.PO": "Policy", "GV.OV": "Oversight", "GV.SC": "Cybersecurity Supply Chain Risk Management",
	"ID.AM": "Asset Management", "ID.RA": "Risk Assessment", "ID.IM": "Improvement",
	"PR.AA": "Identity Management, Authentication, and Access Control", "PR.AT": "Awareness and Training",
	"PR.DS": "Data Security", "PR.PS": "Platform Security", "PR.IR": "Technology Infrastructure Resilience",
	"DE.CM": "Continuous Monitoring", "DE.AE": "Adverse Event Analysis",
	"RS.MA": "Incident Management", "RS.AN": "Incident Analysis", "RS.CO": "Incident Response Reporting and Communication",
	"RS.MI": "Incident Mitigation", "RC.RP": "Incident Recovery Plan Execution", "RC.CO": "Incident Recovery Communication",
}

# All 106 CSF 2.0 subcategories (CSWP 29, Appendix A), so the projection lists what the SAP assessment does
# not inform rather than hiding it.
_subcategories := [
	"GV.OC-01", "GV.OC-02", "GV.OC-03", "GV.OC-04", "GV.OC-05",
	"GV.RM-01", "GV.RM-02", "GV.RM-03", "GV.RM-04", "GV.RM-05", "GV.RM-06", "GV.RM-07",
	"GV.RR-01", "GV.RR-02", "GV.RR-03", "GV.RR-04",
	"GV.PO-01", "GV.PO-02",
	"GV.OV-01", "GV.OV-02", "GV.OV-03",
	"GV.SC-01", "GV.SC-02", "GV.SC-03", "GV.SC-04", "GV.SC-05", "GV.SC-06", "GV.SC-07", "GV.SC-08", "GV.SC-09", "GV.SC-10",
	"ID.AM-01", "ID.AM-02", "ID.AM-03", "ID.AM-04", "ID.AM-05", "ID.AM-07", "ID.AM-08",
	"ID.RA-01", "ID.RA-02", "ID.RA-03", "ID.RA-04", "ID.RA-05", "ID.RA-06", "ID.RA-07", "ID.RA-08", "ID.RA-09", "ID.RA-10",
	"ID.IM-01", "ID.IM-02", "ID.IM-03", "ID.IM-04",
	"PR.AA-01", "PR.AA-02", "PR.AA-03", "PR.AA-04", "PR.AA-05", "PR.AA-06",
	"PR.AT-01", "PR.AT-02",
	"PR.DS-01", "PR.DS-02", "PR.DS-10", "PR.DS-11",
	"PR.PS-01", "PR.PS-02", "PR.PS-03", "PR.PS-04", "PR.PS-05", "PR.PS-06",
	"PR.IR-01", "PR.IR-02", "PR.IR-03", "PR.IR-04",
	"DE.CM-01", "DE.CM-02", "DE.CM-03", "DE.CM-06", "DE.CM-09",
	"DE.AE-02", "DE.AE-03", "DE.AE-04", "DE.AE-06", "DE.AE-07", "DE.AE-08",
	"RS.MA-01", "RS.MA-02", "RS.MA-03", "RS.MA-04", "RS.MA-05",
	"RS.AN-03", "RS.AN-06", "RS.AN-07", "RS.AN-08",
	"RS.CO-02", "RS.CO-03",
	"RS.MI-01", "RS.MI-02",
	"RC.RP-01", "RC.RP-02", "RC.RP-03", "RC.RP-04", "RC.RP-05", "RC.RP-06",
	"RC.CO-03", "RC.CO-04",
]

_title(sc) := _titles[sc]

_title(sc) := sprintf("%s (%s)", [_categories[substring(sc, 0, 5)], sc]) if not _titles[sc]

# One pass over the registry, then a lookup per subcategory (not a scan per subcategory).
_by_subcategory[sc] contains id if {
	some id, c in registry.checks
	some sc in by_requirement[c.requirement]
}

_canonical(sc) := sort(_by_subcategory[sc])

_canonical(sc) := [] if not _by_subcategory[sc]

references := [ref |
	some sc in _subcategories
	ref := {
		"ref": sc,
		"title": _title(sc),
		"canonical": _canonical(sc),
	}
]
