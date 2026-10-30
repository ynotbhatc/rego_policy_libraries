# Tests for sap_abap_baseline.main — SAP Security Baseline Template v2.6 (ABAP), host-collectable checks.
#
# Shape: an empty-input fail-closed set; one test per translator shape against a real SAP check (numeric,
# between, enum, case-insensitive, regex, wildcard parameter names, dotted version); the hand-written rules
# (gateway / message-server ACL files, kernel and CommonCryptoLib age, kernel patch level per release);
# profile gating; the results map; and the three projections' bookkeeping against the registry.

package sap_abap_baseline.main_test

import rego.v1

import data.sap_abap_baseline.main
import data.sap_abap_baseline.registry

_facts(params) := {"sap": {"abap": {"profile": "extended", "profile_parameters": params}}}

# `with` cannot sit inside a helper function (the wasm planner rejects it), so every test binds the report
# or the violation set itself and passes the value to a plain helper.
_ids(vs) := {id |
	some msg in vs
	i := indexof(msg, ": ")
	id := substring(msg, 0, i)
}

# ---------------------------------------------------------------------------------------------------------
# empty input: fail closed, report well-formed
# ---------------------------------------------------------------------------------------------------------
test_empty_input_report_wellformed if {
	r := main.compliance_report with input as {}
	is_object(r)
	r.compliant == false
	r.controls_evaluated > 0
	r.violation_count > 0
	r.profile == "extended"
}

# On empty input every evaluated check violates except two kinds SAP defines that way: checks marked
# not_found="positive" (the parameter may be absent) and the ACL-file content checks (.2), whose missing file is
# reported once, by their .1 sibling.
test_empty_input_compliant_set_is_exactly_the_absent_ok_checks if {
	r := main.compliance_report with input as {}
	compliant := {id | some id, s in r.results; s == "compliant"}
	compliant == {"DISCL-O_h", "PWDPOL-A_j.5a", "PWDPOL-A_l", "RFCGW-A_a secinfo.2", "RFCGW-A_a reginfo.2", "RFCGW-A_h prxinfo.2"}
	r.violation_count == r.controls_evaluated - count(compliant)
}

test_registry_bookkeeping if {
	r := main.compliance_report with input as {}
	r.registry_total == count(registry.checks)
	r.assessable_total + r.not_assessable_count == r.registry_total
	r.assessable_total >= 135
	r.not_assessable_count >= 200
	count(r.results) == r.registry_total
}

test_unknown_profile_is_a_violation_and_evaluates_as_extended if {
	inp := {"sap": {"abap": {"profile": "paranoid"}}}
	vs1 := main.violations with input as inp
	"SAP-INPUT" in _ids(vs1)
	r := main.compliance_report with input as inp
	r.profile == "extended"
}

# ---------------------------------------------------------------------------------------------------------
# translator shapes, each against a real check
# ---------------------------------------------------------------------------------------------------------
# PWDPOL-A_a.1: login/min_password_lng >= 12  (lpad numeric compare)
test_numeric_ge_passes if {
	vs := main.violations with input as _facts({"login/min_password_lng": "12"})
	not "PWDPOL-A_a.1" in _ids(vs)
}

test_numeric_ge_fails_below if {
	vs := main.violations with input as _facts({"login/min_password_lng": "8"})
	"PWDPOL-A_a.1" in _ids(vs)
}

test_numeric_ge_fails_when_not_numeric if {
	vs := main.violations with input as _facts({"login/min_password_lng": "twelve"})
	"PWDPOL-A_a.1" in _ids(vs)
}

test_numeric_ge_fails_when_missing if {
	vs := main.violations with input as _facts({})
	"PWDPOL-A_a.1" in _ids(vs)
}

test_numeric_value_sent_as_number_is_tolerated if {
	vs := main.violations with input as _facts({"login/min_password_lng": 14})
	not "PWDPOL-A_a.1" in _ids(vs)
}

test_missing_parameter_message_says_not_set if {
	some msg in main.violations with input as _facts({})
	startswith(msg, "PWDPOL-A_a.1: ")
	endswith(msg, "(not set in the collected facts)")
}

# PWDPOL-A_b.1: login/password_max_idle_initial between 1 and 14
test_between_passes_inside if {
	vs := main.violations with input as _facts({"login/password_max_idle_initial": "7"})
	not "PWDPOL-A_b.1" in _ids(vs)
}

test_between_fails_outside if {
	vs := main.violations with input as _facts({"login/password_max_idle_initial": "30"})
	"PWDPOL-A_b.1" in _ids(vs)
}

# PWDPOL-A_d: login/password_downwards_compatibility = 0  (string equality)
test_equality_passes if {
	vs := main.violations with input as _facts({"login/password_downwards_compatibility": "0"})
	not "PWDPOL-A_d" in _ids(vs)
}

test_equality_fails if {
	vs := main.violations with input as _facts({"login/password_downwards_compatibility": "5"})
	"PWDPOL-A_d" in _ids(vs)
}

# NETENC-A_e: system/secure_communication = ON  (UPPER(VALUE))
test_case_insensitive_passes if {
	vs := main.violations with input as _facts({"system/secure_communication": "on"})
	not "NETENC-A_e" in _ids(vs)
}

test_case_insensitive_fails if {
	vs := main.violations with input as _facts({"system/secure_communication": "OFF"})
	"NETENC-A_e" in _ids(vs)
}

# SSO-A_d: login/accept_sso2_ticket in ('1','2') or = '2' — SAP publishes two variants; either passes
test_enum_variant_passes if {
	vs := main.violations with input as _facts({"login/accept_sso2_ticket": "1"})
	not "SSO-A_d" in _ids(vs)
}

test_enum_variant_fails if {
	vs := main.violations with input as _facts({"login/accept_sso2_ticket": "0"})
	"SSO-A_d" in _ids(vs)
}

# MSGSRV-A_d.1: ms/acl_info path regex
test_regex_passes if {
	vs := main.violations with input as _facts({"ms/acl_info": "/usr/sap/S4H/SYS/global/ms_acl_info"})
	not "MSGSRV-A_d.1" in _ids(vs)
}

test_regex_fails if {
	vs := main.violations with input as _facts({"ms/acl_info": "/tmp/acl"})
	"MSGSRV-A_d.1" in _ids(vs)
}

# DISCL-O_c: every icm/HTTP/admin_<n> must carry CLIENTHOST= and ALLOWPUB=FALSE (wildcard parameter name)
test_wildcard_passes_when_every_match_ok if {
	vs := main.violations with input as _facts({
		"icm/HTTP/admin_0": "PREFIX=/sap/admin,DOCROOT=./admin,AUTHFILE=icmauth.txt,CLIENTHOST=10.0.0.1,ALLOWPUB=FALSE",
		"icm/HTTP/admin_1": "PREFIX=/sap/admin2,CLIENTHOST=10.0.0.2,ALLOWPUB=FALSE",
	})
	not "DISCL-O_c" in _ids(vs)
}

test_wildcard_fails_when_one_match_bad if {
	vs := main.violations with input as _facts({
		"icm/HTTP/admin_0": "PREFIX=/sap/admin,CLIENTHOST=10.0.0.1,ALLOWPUB=FALSE",
		"icm/HTTP/admin_1": "PREFIX=/sap/admin2,ALLOWPUB=TRUE",
	})
	"DISCL-O_c" in _ids(vs)
}

test_wildcard_fails_when_nothing_matches if {
	vs := main.violations with input as _facts({"icm/HTTP/other": "x"})
	"DISCL-O_c" in _ids(vs)
}

test_wildcard_underscore_is_literal if {
	# icm/HTTP/adminX0 must NOT satisfy the icm/HTTP/admin_% pattern (SQL `_` is literal in parameter names)
	vs2 := main.violations with input as _facts({"icm/HTTP/adminX0": "CLIENTHOST=1,ALLOWPUB=FALSE"})
	"DISCL-O_c" in _ids(vs2)
}

# CHANGE-A_g.1: TP_RELEASE >= 380.44.90 (dotted version compare)
test_version_ge_passes if {
	vs := main.violations with input as {"sap": {"abap": {"transport_parameters": {"TP_RELEASE": "380.44.95"}}}}
	not "CHANGE-A_g.1" in _ids(vs)
}

test_version_ge_passes_on_more_components if {
	vs := main.violations with input as {"sap": {"abap": {"transport_parameters": {"TP_RELEASE": "381.0.1"}}}}
	not "CHANGE-A_g.1" in _ids(vs)
}

test_version_ge_fails_below if {
	vs := main.violations with input as {"sap": {"abap": {"transport_parameters": {"TP_RELEASE": "380.44.89"}}}}
	"CHANGE-A_g.1" in _ids(vs)
}

test_version_ge_fails_on_garbage if {
	vs := main.violations with input as {"sap": {"abap": {"transport_parameters": {"TP_RELEASE": "latest"}}}}
	"CHANGE-A_g.1" in _ids(vs)
}

# CHANGE-A_f: TLOGOCHECK = 1 or TRUE/ON/YES (transport parameters are a separate fact key)
test_transport_parameter_passes if {
	vs := main.violations with input as {"sap": {"abap": {"transport_parameters": {"TLOGOCHECK": "true"}}}}
	not "CHANGE-A_f" in _ids(vs)
}

# ---------------------------------------------------------------------------------------------------------
# hand-written: gateway ACL files
# ---------------------------------------------------------------------------------------------------------
_gw(secinfo_lines) := {"sap": {"abap": {"gateway": {
	"secinfo": {"present": true, "lines": secinfo_lines},
	"reginfo": {"present": true, "lines": ["P TP=* HOST=app1.example.com ACCESS=app1.example.com CANCEL=internal"]},
	"prxyinfo": {"present": true, "lines": ["P SOURCE=internal DEST=internal"]},
}}}}

test_gateway_secinfo_specific_lines_pass if {
	vs := main.violations with input as _gw(["P TP=* USER=* HOST=app1.example.com USER-HOST=internal", "D TP=* USER=* HOST=* USER-HOST=*"])
	ids := _ids(vs)
	not "RFCGW-A_a secinfo.1" in ids
	not "RFCGW-A_a secinfo.2" in ids
	not "RFCGW-A_a reginfo.2" in ids
	not "RFCGW-A_h prxinfo.2" in ids
}

test_gateway_secinfo_fully_generic_permit_fails if {
	vs3 := main.violations with input as _gw(["P TP=* USER=* HOST=* USER-HOST=*"])
	"RFCGW-A_a secinfo.2" in _ids(vs3)
}

test_gateway_secinfo_permit_with_absent_selectors_is_generic if {
	vs4 := main.violations with input as _gw(["P TP=*"])
	"RFCGW-A_a secinfo.2" in _ids(vs4)
}

test_gateway_secinfo_deny_line_is_not_a_permit if {
	vs5 := main.violations with input as _gw(["D TP=* USER=* HOST=* USER-HOST=*"])
	not "RFCGW-A_a secinfo.2" in _ids(vs5)
}

test_gateway_file_missing if {
	inp := {"sap": {"abap": {"gateway": {"secinfo": {"present": false, "lines": []}}}}}
	vs := main.violations with input as inp
	ids := _ids(vs)
	"RFCGW-A_a secinfo.1" in ids
	"RFCGW-A_a reginfo.1" in ids
	"RFCGW-A_h prxinfo.1" in ids
	not "RFCGW-A_a secinfo.2" in ids
}

test_gateway_reginfo_generic_fails if {
	inp := {"sap": {"abap": {"gateway": {"reginfo": {"present": true, "lines": ["P TP=* HOST=* ACCESS=* CANCEL=*"]}}}}}
	vs6 := main.violations with input as inp
	"RFCGW-A_a reginfo.2" in _ids(vs6)
}

test_gateway_prxyinfo_generic_fails_only_in_extended if {
	inp := {"sap": {"abap": {"gateway": {"prxyinfo": {"present": true, "lines": ["P SOURCE=* DEST=*"]}}}}}
	vs7 := main.violations with input as inp
	"RFCGW-A_h prxinfo.2" in _ids(vs7)
	crit := object.union(inp, {"sap": {"abap": {"profile": "critical"}}})
	vs8 := main.violations with input as crit
	not "RFCGW-A_h prxinfo.2" in _ids(vs8)
}

# ---------------------------------------------------------------------------------------------------------
# hand-written: message server ACL
# ---------------------------------------------------------------------------------------------------------
test_message_server_acl_generic_host_fails if {
	inp := {"sap": {"abap": {"message_server": {"acl": {"present": true, "lines": ["HOST=*"]}}}}}
	vs := main.violations with input as inp
	ids := _ids(vs)
	"MSGSRV-A_e.1" in ids
	"MSGSRV-A_e.3" in ids
}

test_message_server_acl_suffix_pattern_passes if {
	inp := {"sap": {"abap": {"message_server": {"acl": {"present": true, "lines": ["HOST=*.example.com", "HOST=app1.example.com"]}}}}}
	vs := main.violations with input as inp
	ids := _ids(vs)
	not "MSGSRV-A_e.1" in ids
	not "MSGSRV-A_e.3" in ids
}

test_message_server_acl_missing_fails if {
	inp := {"sap": {"abap": {"message_server": {"acl": {"present": false, "lines": []}}}}}
	vs9 := main.violations with input as inp
	"MSGSRV-A_e.1" in _ids(vs9)
}

# ---------------------------------------------------------------------------------------------------------
# hand-written: currency and kernel patch level
# ---------------------------------------------------------------------------------------------------------
_kernel(k, collected) := {"sap": {"abap": {"collected_at": collected, "kernel": k}}}

test_kernel_date_fresh_passes if {
	vs10 := main.violations with input as _kernel({"KERN_COMP_TIME": "Jan 15 2026"}, "2026-10-29")
	not "SECUPD-A_a.3" in _ids(vs10)
}

test_kernel_date_single_digit_day_parses if {
	vs11 := main.violations with input as _kernel({"KERN_COMP_TIME": "Mar  5 2026 21:14:33"}, "2026-10-29")
	not "SECUPD-A_a.3" in _ids(vs11)
}

test_kernel_date_old_fails if {
	vs12 := main.violations with input as _kernel({"KERN_COMP_TIME": "Sep 1 2025"}, "2026-10-29")
	"SECUPD-A_a.3" in _ids(vs12)
}

test_kernel_date_unparseable_fails if {
	vs13 := main.violations with input as _kernel({"KERN_COMP_TIME": "unknown"}, "2026-10-29")
	"SECUPD-A_a.3" in _ids(vs13)
}

test_cryptolib_date_fresh_passes if {
	inp := {"sap": {"abap": {"collected_at": "2026-10-29T10:00:00Z", "cryptolib": {"CCL": "8.5.50", "CCL_DATE": "2026-02-01"}}}}
	vs14 := main.violations with input as inp
	not "SECUPD-A_a.4" in _ids(vs14)
}

test_cryptolib_date_old_fails if {
	inp := {"sap": {"abap": {"collected_at": "2026-10-29", "cryptolib": {"CCL": "8.5.50", "CCL_DATE": "2025-02-01"}}}}
	vs15 := main.violations with input as inp
	"SECUPD-A_a.4" in _ids(vs15)
}

test_kernel_patch_ok_for_release if {
	vs16 := main.violations with input as _kernel({"KERN_REL": "793_REL", "KERN_PATCHLEVEL": "401"}, "2026-10-29")
	not "CHANGE-A_g.4" in _ids(vs16)
}

test_kernel_patch_below_minimum_fails if {
	vs17 := main.violations with input as _kernel({"KERN_REL": "793_REL", "KERN_PATCHLEVEL": "400"}, "2026-10-29")
	"CHANGE-A_g.4" in _ids(vs17)
}

test_kernel_patch_unknown_release_fails if {
	vs18 := main.violations with input as _kernel({"KERN_REL": "749_REL", "KERN_PATCHLEVEL": "9999"}, "2026-10-29")
	"CHANGE-A_g.4" in _ids(vs18)
}

# CHANGE-A_g.3 (generated): kernel release in maintenance
test_kernel_release_in_maintenance_passes if {
	vs19 := main.violations with input as _kernel({"KERN_REL": "793_REL"}, "2026-10-29")
	not "CHANGE-A_g.3" in _ids(vs19)
}

# ---------------------------------------------------------------------------------------------------------
# profile gating
# ---------------------------------------------------------------------------------------------------------
test_critical_profile_evaluates_only_p1 if {
	r := main.compliance_report with input as {"sap": {"abap": {"profile": "critical"}}}
	r.profile == "critical"
	r.controls_evaluated == count({c.id | some _, c in registry.checks; c.assessable; c.level == "critical"})
	# a p2 check is out of profile, not a violation
	r.results["PWDPOL-A_e.1"] == "out_of_profile"
	r.results["PWDPOL-A_a.1"] == "violation"
}

test_standard_profile_includes_p1_and_p2 if {
	r := main.compliance_report with input as {"sap": {"abap": {"profile": "standard"}}}
	r.results["PWDPOL-A_e.1"] == "violation"
	r.results["CHANGE-A_g.4"] == "out_of_profile"
}

test_extended_profile_evaluates_every_assessable_check if {
	r := main.compliance_report with input as {}
	r.controls_evaluated == r.assessable_total
}

# ---------------------------------------------------------------------------------------------------------
# results map and projections
# ---------------------------------------------------------------------------------------------------------
test_results_cover_every_registry_row_exactly_once if {
	r := main.compliance_report with input as _facts({"login/min_password_lng": "12"})
	every id, _ in registry.checks {
		r.results[id] in {"compliant", "violation", "not_assessable", "out_of_profile"}
	}
	r.results["PWDPOL-A_a.1"] == "compliant"
	r.results["CRITAU-A_a.1"] == "not_assessable"
}

test_violation_details_carry_severity_for_every_violation if {
	r := main.compliance_report with input as _facts({"login/min_password_lng": "8"})
	count(r.violation_details) == r.violation_count - count([m | some m in r.violations; startswith(m, "SAP-INPUT")])
	some d in r.violation_details
	d.id == "PWDPOL-A_a.1"
	d.severity == "critical"
	d.level == "critical"
	d.requirement == "PWDPOL-A"
	startswith(d.message, "PWDPOL-A_a.1: ")
}

test_not_assessable_rows_carry_a_reason if {
	rows := main.not_assessable with input as {}
	every row in rows {
		is_string(row.reason)
		count(row.reason) > 0
	}
}

test_baseline_projection_covers_every_check_once if {
	p := main.projections.baseline with input as {}
	all := [id | some ref in p.references; some id in ref.canonical]
	count(all) == count(registry.checks)
	count({id | some id in all}) == count(registry.checks)
	p.summary.references == count(p.references)
	p.summary.compliant + p.summary.violation + p.summary.not_assessable == p.summary.references
}

test_baseline_projection_requirement_with_no_assessable_check_is_not_assessable if {
	p := main.projections.baseline with input as {}
	some ref in p.references
	ref.ref == "CRITAU-A"
	ref.status == "not_assessable"
	count(ref.not_assessable) == count(ref.canonical)
}

test_baseline_projection_status_follows_results if {
	inp := _facts({"login/min_password_lng": "12"})
	p := main.projections.baseline with input as inp
	some ref in p.references
	ref.ref == "PWDPOL-A"
	ref.status == "violation"
	"PWDPOL-A_a.1" in ref.compliant
}

test_dsag_projection_lists_unmapped_sections_as_not_assessable if {
	p := main.projections.dsag_s4hana with input as {}
	some cloud in p.references
	cloud.ref == "DSAG-S4-7.4"
	cloud.canonical == []
	cloud.status == "not_assessable"
	some params in p.references
	params.ref == "DSAG-S4-6.5"
	"PWDPOL-A_a.1" in params.canonical
	params.status == "violation"
	p.summary.references == 27
}

test_csf_projection_has_all_106_subcategories if {
	p := main.projections.nist_csf_2_0 with input as {}
	p.summary.references == 106
	some aa in p.references
	aa.ref == "PR.AA-01"
	"PWDPOL-A_a.1" in aa.canonical
	aa.status == "violation"
	some gv in p.references
	gv.ref == "GV.OC-01"
	gv.status == "not_assessable"
}

test_csf_mapping_names_only_known_subcategories if {
	refs := main.projections.nist_csf_2_0.references with input as {}
	known := {ref.ref | some ref in refs}
	every _, list in data.sap_abap_baseline.mappings.nist_csf_2_0.by_requirement {
		every sc in list {
			sc in known
		}
	}
}

test_csf_mapping_names_only_known_requirements if {
	reqs := {c.requirement | some _, c in registry.checks}
	every r, _ in data.sap_abap_baseline.mappings.nist_csf_2_0.by_requirement {
		r in reqs
	}
	every r, _ in data.sap_abap_baseline.mappings.dsag.by_requirement {
		r in reqs
	}
}

test_dsag_parameter_mapping_names_only_assessed_parameters if {
	params := {c.parameter | some _, c in registry.checks; c.parameter != null}
	every p, _ in data.sap_abap_baseline.mappings.dsag.by_parameter {
		p in params
	}
}
