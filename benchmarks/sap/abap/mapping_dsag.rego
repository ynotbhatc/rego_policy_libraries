# METADATA
# title: "SAP ABAP Baseline → DSAG S/4HANA audit guide (Prüfleitfaden) section view"
# custom:
#   class: security
#   framework: sap_abap_baseline
#   source: sap
#   domains: [sap, erp, crosswalk, germany]
#   coverage:
#     checks: 0
#     cited: 0
#     density: unrecognised
#     basis: role
#     tested: false
#     entrypoint: none
#     guard: n/a
#     as_of: v2.4.2
package sap_abap_baseline.mappings.dsag

import rego.v1

import data.sap_abap_baseline.registry

# DSAG Prüfleitfaden SAP S/4HANA, edition December 2022 (published May 2023), German, all rights reserved by
# DSAG e.V. This table carries the guide's SECTION NUMBERS and this library's own one-line English labels —
# none of the guide's text. The references are the guide's audit programmes ("Prüfprogramm") and its system
# parameter table (section 6.5); a section the Baseline gives no evidence for is listed with no canonical
# ids, so the DSAG projection says "not assessable" instead of staying silent.
#
# Two mapping sources, both data:
#   by_parameter    profile parameters the guide names, with the section(s) that name them (read from the
#                   guide's text at import time; the parameter names are SAP's, not DSAG's prose)
#   by_requirement  Baseline requirements whose subject a DSAG audit programme covers as a whole — this
#                   library's reading

framework := {
	"id": "dsag_s4hana_pruefleitfaden_2022_12",
	"name": "DSAG Prüfleitfaden SAP S/4HANA (Dec 2022 edition)",
	"source": "https://impulsant.dsag.de/formate/textbeitrag/sap-s-4hana-leitfaden (section numbers only)",
	"mapping": "parameter mentions per section + Baseline requirement → audit programme, this library's reading",
}

sections := [
	{"ref": "4.4", "title": "Authorization concept: documentation and standards"},
	{"ref": "4.5", "title": "Authorization concept: roles and authorizations"},
	{"ref": "4.6", "title": "Authorization concept: users and rights"},
	{"ref": "4.7", "title": "Authorization concept: sensitive functions"},
	{"ref": "4.8", "title": "Authorization concept: segregation of duties"},
	{"ref": "4.9", "title": "Authorization concept: processes and organisation"},
	{"ref": "4.10", "title": "Authorization concept: logs and parameters"},
	{"ref": "5.4", "title": "Change management: system and client change options, table logging, transports"},
	{"ref": "5.5", "title": "Change management: authentication and authorization"},
	{"ref": "6.4", "title": "S/4HANA on premise: authentication audit programme"},
	{"ref": "6.5", "title": "S/4HANA on premise: system parameters and security policies"},
	{"ref": "6.6", "title": "S/4HANA on premise: authorization audit programme"},
	{"ref": "6.7", "title": "S/4HANA on premise: change management with Solution Manager"},
	{"ref": "7.4", "title": "S/4HANA Cloud public edition: authentication"},
	{"ref": "7.5", "title": "S/4HANA Cloud public edition: authorization"},
	{"ref": "7.6", "title": "S/4HANA Cloud public edition: change management"},
	{"ref": "7.7", "title": "S/4HANA Cloud public edition: IT operations"},
	{"ref": "7.8", "title": "S/4HANA Cloud public edition: logs and parameters"},
	{"ref": "7.9", "title": "S/4HANA Cloud public edition: SOC 1 type 2 report analysis"},
	{"ref": "8.4", "title": "SAP HANA database: authentication"},
	{"ref": "8.5", "title": "SAP HANA database: authorization"},
	{"ref": "8.6", "title": "SAP HANA database: change management"},
	{"ref": "8.7", "title": "SAP HANA database: logs"},
	{"ref": "9.4", "title": "Operating system: Linux/Unix system integrity"},
	{"ref": "9.5", "title": "Operating system: Windows system integrity"},
	{"ref": "9.6", "title": "Operating system: logging and security monitoring"},
	{"ref": "9.7", "title": "Operating system: backup, recovery and deletion"},
]

# Profile parameters the guide names, by section. Read from the guide at import time (2026-10-29).
by_parameter := {
	"auth/no_check_in_some_cases": ["6.6"],
	"auth/object_disabling_active": ["6.6"],
	"auth/rfc_authority_check": ["6.6"],
	"login/accept_sso2_ticket": ["6.4", "6.5"],
	"login/disable_password_logon": ["6.4", "6.5"],
	"login/failed_user_auto_unlock": ["6.5"],
	"login/fails_to_user_lock": ["6.5"],
	"login/min_password_diff": ["6.5"],
	"login/min_password_digits": ["6.5"],
	"login/min_password_letters": ["6.5"],
	"login/min_password_lng": ["6.5"],
	"login/min_password_lowercase": ["6.5"],
	"login/min_password_specials": ["6.5"],
	"login/min_password_uppercase": ["6.5"],
	"login/password_change_for_SSO": ["6.5"],
	"login/password_change_waittime": ["6.5"],
	"login/password_compliance_to_current_policy": ["6.5"],
	"login/password_downwards_compatibility": ["6.5"],
	"login/password_expiration_time": ["6.5"],
	"login/password_history_size": ["6.5"],
	"login/password_logon_usergroup": ["6.5"],
	"login/password_max_idle_initial": ["6.5"],
	"login/password_max_idle_productive": ["6.5"],
	"rdisp/gui_auto_logout": ["6.5"],
	"rec/client": ["5.4"],
	"rsau/enable": ["6.5"],
}

# Baseline requirements an audit programme covers as a subject (this library's reading).
by_requirement := {
	"STDUSR-A": ["6.4"],
	"SSO-A": ["6.4"],
	"PWDPOL-A": ["6.5"],
	"AUDIT-A": ["6.5", "4.10"],
	"CRITAU-A": ["6.6", "4.7"],
	"AUTHASSIGN-A": ["6.6", "4.5"],
	"USRTYP-A": ["6.6", "4.6"],
	"USRCHAR-A": ["6.6", "4.6"],
	"USRCTR-A": ["6.6", "4.6"],
	"CHANGE-A": ["5.4"],
	"OBSCNT-A": ["5.4"],
}

# One pass over the registry, then a lookup per section (not a scan per section).
_by_section[sec] contains id if {
	some id, c in registry.checks
	some sec in by_parameter[c.parameter]
}

_by_section[sec] contains id if {
	some id, c in registry.checks
	some sec in by_requirement[c.requirement]
}

_canonical(sec) := sort(_by_section[sec])

_canonical(sec) := [] if not _by_section[sec]

references := [ref |
	some s in sections
	ref := {
		"ref": concat("", ["DSAG-S4-", s.ref]),
		"title": s.title,
		"canonical": _canonical(s.ref),
	}
]
