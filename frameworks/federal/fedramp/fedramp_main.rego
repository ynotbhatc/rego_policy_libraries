# METADATA
# title: "FedRAMP Rev 5 — authorization, ConMon and selected baseline checks (not a full baseline assessment)"
# custom:
#   class: compliance
#   framework: fedramp
#   source: fedramp
#   domains: [us-federal, cloud]
#   coverage:
#     checks: 40
#     cited: 13
#     density: orchestrator
#     basis: role
#     tested: true
#     entrypoint: none
#     guard: n/a
#     as_of: v2.5.0
package fedramp

import rego.v1

import data.crosswalk.correlation as spine
import data.crosswalk.framework_overlay as overlay

# =============================================================================
# FedRAMP Rev 5 — authorization, continuous monitoring and selected baseline checks
#
# What this module is: a check of FedRAMP authorization status and a small set of FedRAMP Rev 5 baseline
# controls with their FedRAMP parameter values. It is NOT an assessment of the Low / Moderate / High
# baseline: it evaluates 10 to 12 controls (see applicable_checks), not the hundreds a baseline selects.
#
# FedRAMP Rev 5 baseline sizes (controls + enhancements selected), from the FedRAMP OSCAL baseline profiles
# (GSA/fedramp-automation dist/content/rev5/baselines/json; the GSA repository is no longer online, the
# OSCAL Compass mirror at commit 76d0473e is what converters/exports/oscal pins). They agree with this
# repo's converters/exports/oscal/dist/profiles/coverage_summary.json:
#   Low       156  (135 base + 21 enhancements)
#   Moderate  323  (181 base + 142 enhancements)
#   High      410  (191 base + 219 enhancements)
#   LI-SaaS   156  (same control selection as Low; not evaluated separately here)
# (125 / 325 / 421 were the Rev 4 sizes.)
#
# Parameter values used below are FedRAMP's Rev 5 set-parameters in those profiles:
#   CA-2 / CA-8 at least annually; RA-5 monthly OS/infrastructure, web application (incl. APIs) and
#   database scans, high / moderate / low-risk vulnerabilities mitigated within 30 / 90 / 180 days
#   (KEV due dates take precedence when supplied); SC-13 "FIPS-validated or
#   NSA-approved cryptography"; SA-9(5) (High only) U.S./U.S. Territories or U.S. jurisdiction.
# Baseline membership used for gating (same profiles): CA-2, CA-6, CA-7, CA-8, IR-8, PS-3, RA-2, RA-5,
# SC-13, SR-2 at every level; CP-7 Moderate and High; SA-9(5) Moderate and High, with a FedRAMP-fixed
# location only at High; PS-3(3) Moderate and High with agency-defined screening criteria (evaluated at
# Moderate/High only, and only when the agency sets the US-person criterion).
#
# Input shape:
#   input.impact_level            - "low", "moderate", or "high"
#   input.authorization           - ATO/P-ATO status, 3PAO assessment
#   input.cryptography            - fips_140_validated / nsa_approved, algorithms_in_use[] (string or
#                                   {"algorithm", "usage"})
#   input.continuous_monitoring   - ConMon program and RA-5 scanning facts; open-days per risk tier;
#                                   optional kev_findings[] (cve, due_date, remediated)
#   input.assessment_date         - YYYY-MM-DD, the "today" for KEV due dates (else evaluation time)
#   input.cloud_service           - penetration_test_annual, incident_response_plan_approved, redundant_processing
#   input.supply_chain            - risk_management_plan
#   input.personnel[]             - admin personnel (admin_access, background_check_completed, us_person)
#   input.personnel_requirements  - us_persons_required_for_admin (agency PS-3(3) criterion, optional)
#   input.data_residency          - storage_locations[] / processing_locations[], us_only_required (optional)
#
# Benchmark results (optional): the same input may carry STIG results in the two shapes
# data.crosswalk.correlation reads, and no other:
#   input.reports  : [ <STIG compliance_report with rule_results and facts_supplied>, ... ]
#   input.findings : [ {"stig_id": "RHEL-09-255010", "status": "Not_a_Finding" | "Open" | ...}, ... ]
# The crosswalk carries them to the controls of the FedRAMP Rev 5 baseline at the declared impact level (the
# High baseline until a level is declared): STIG rule -> CCI -> NIST SP 800-53 (crosswalk/stig_800_53, DISA),
# then 800-53 -> the FedRAMP baseline control with the same id (crosswalk/framework_maps fedramp_rev5_<level>,
# generated from the FedRAMP OSCAL baseline profiles), read from
# data.crosswalk.framework_overlay.control_evidence. The combination rule is the NIST SP 800-53 module's:
#   - gap (a mapped rule is Open): the baseline control fails, whatever this module's own check, declared
#     evidence or attestation says. The finding names the Open rules.
#   - satisfied, not_reviewed, not_applicable: recorded on the control's row under "benchmark" with the
#     contributing rule ids. Nothing else changes: benchmark results never turn a control into a pass.
#   - no mapped rule supplied: benchmark.status is "not_evaluated".
# The spine is at base-control granularity, so an enhancement row is always "not_evaluated". A verdict on an
# 800-53 control the baseline does not select is not a FedRAMP finding at this level; it is listed under
# benchmark_evidence.controls_not_in_baseline (gaps among them under gap_not_in_baseline). Fail closed: a
# report with facts_supplied == false counts every one of its rules as Open; a rule id the crosswalk does not
# know speaks to no control and is listed under benchmark_evidence.unmapped_rules; benchmark results that
# cannot be read, or that arrive when the crosswalk packages and their two data files are not loaded next to
# this module, are FAIL-CLOSED findings.
# With benchmark results the reports gain control_results (one row per baseline control and per check of this
# module: status pass / fail / not_evaluated, where not_evaluated means this module has no check for the
# control and no benchmark gap was found, never a pass), control_result_counts and benchmark_evidence. With
# neither key in the input both reports are what they were before, with none of the three. compliance_score
# and areas describe this module's own assessment areas only; a benchmark gap is not an area. Nothing here
# scores, weights or ranks; verdicts are carried through the maps.
# =============================================================================

# FedRAMP Rev 5 baseline sizes (see header). Reported beside, never as, the evaluated count.
baseline_sizes := {"low": 156, "moderate": 323, "high": 410, "li_saas": 156}

# ---------------------------------------------------------------------------
# Impact level normalisation (fail closed)
#   A missing, non-string or unrecognised impact_level is itself a finding and
#   the Moderate/High checks are applied rather than skipped.
# ---------------------------------------------------------------------------

default impact_level_norm := "unknown"

impact_level_norm := lower(trim_space(input.impact_level)) if {
	is_string(input.impact_level)
	lower(trim_space(input.impact_level)) in {"low", "moderate", "high"}
}

applies_moderate_high if impact_level_norm in {"moderate", "high", "unknown"}

applies_high if impact_level_norm in {"high", "unknown"}

default baseline_size := null

baseline_size := baseline_sizes[impact_level_norm]

_us_only_required if object.get(input, ["data_residency", "us_only_required"], false) == true

_us_persons_required if object.get(input, ["personnel_requirements", "us_persons_required_for_admin"], false) == true

_applies_sa_9_5 if applies_high

_applies_sa_9_5 if _us_only_required

# The checks this module evaluates at the declared impact level. One id per check; a failing check may
# carry several findings (one per person, location or algorithm), so failures are counted by id.
_checks_all_levels := {"RA-2", "CA-6", "CA-2", "CA-7", "RA-5", "SC-13", "CA-8", "IR-8", "SR-2", "PS-3"}

_checks_conditional contains "CP-7" if applies_moderate_high

_checks_conditional contains "SA-9(5)" if _applies_sa_9_5

_checks_conditional contains "PS-3(3)" if {
	applies_moderate_high
	_us_persons_required
}

applicable_checks := _checks_all_levels | _checks_conditional

_cm := object.get(input, "continuous_monitoring", {})

_auth := object.get(input, "authorization", {})

violation_impact_level contains msg if {
	impact_level_norm == "unknown"
	msg := "FedRAMP RA-2: evidence missing or invalid — input.impact_level (FIPS 199 security categorization) must be one of low, moderate, high. Moderate and High checks (CP-7, SA-9(5)) are applied until the impact level is declared."
}

# ---------------------------------------------------------------------------
# CA-6 Authorization — FedRAMP authorization status
# ---------------------------------------------------------------------------

violation_authorization contains msg if {
	not _auth.fedramp_authorized
	not _auth.in_process
	msg := "FedRAMP CA-6: Service is not FedRAMP authorized and not in process (input.authorization.fedramp_authorized / in_process). Federal agencies may only use FedRAMP authorized cloud services for federal data."
}

violation_authorization contains msg if {
	_auth.fedramp_authorized
	not _auth.authorization_type in {"ATO", "P-ATO"}
	msg := sprintf(
		"FedRAMP CA-6: Authorization type '%v' is not valid. Must be ATO (agency authorization) or P-ATO (provisional authorization).",
		[object.get(_auth, "authorization_type", "not collected")],
	)
}

violation_authorization contains msg if {
	_auth.fedramp_authorized
	is_number(_auth.ato_expiry_days)
	_auth.ato_expiry_days < 90
	msg := sprintf(
		"FedRAMP CA-6: ATO/P-ATO expires in %v days. Initiate renewal at least 90 days before expiration.",
		[_auth.ato_expiry_days],
	)
}

# ---------------------------------------------------------------------------
# SC-13 Cryptographic Protection — FedRAMP: FIPS-validated or NSA-approved
# ---------------------------------------------------------------------------

_crypto := object.get(input, "cryptography", {})

violation_crypto contains msg if {
	object.get(_crypto, "fips_140_validated", false) != true
	object.get(_crypto, "nsa_approved", false) != true
	msg := "FedRAMP SC-13: Cryptography is not evidenced as FIPS-validated or NSA-approved (input.cryptography.fips_140_validated / nsa_approved). FedRAMP's SC-13 parameter requires FIPS-validated or NSA-approved cryptography."
}

violation_crypto contains msg if {
	not is_array(object.get(_crypto, "algorithms_in_use", null))
	msg := "FedRAMP SC-13: evidence missing — input.cryptography.algorithms_in_use not collected"
}

# Algorithm status per NIST SP 800-131A Rev. 2 (March 2019) unless noted:
#   DES        - not approved (FIPS 46-3 withdrawn 2005)
#   3DES/TDEA  - two-key TDEA encryption disallowed; three-key TDEA encryption "Deprecated through 2023,
#                Disallowed after 2023" (§2, Table 1); decryption is legacy use only
#   SKIPJACK   - disallowed for applying cryptographic protection (§2)
#   RSA-1024   - RSA len(n) < 2048 disallowed for digital signature generation (§3, Table 2) and key
#                establishment (< 112 bits of security strength)
#   RC4, MD5   - never NIST-approved algorithms (no FIPS or SP approval)
#   SHA-1      - disallowed for digital signature generation except where NIST protocol guidance allows;
#                legacy use for signature verification; acceptable for non-signature uses (§9). It is
#                therefore judged by its stated usage, and a SHA-1 entry without a usage is missing evidence.
# Entries in algorithms_in_use are a string ("AES-256") or {"algorithm": "SHA1", "usage": "..."}.
_disallowed_algorithms := {"DES", "3DES", "2TDEA", "3TDEA", "TDEA", "SKIPJACK", "RC4", "MD5", "RSA-1024"}

_algo_name(a) := a if is_string(a)

_algo_name(a) := object.get(a, "algorithm", "") if is_object(a)

_algo_usage(a) := object.get(a, "usage", null) if is_object(a)

_algo_usage(a) := null if is_string(a)

_sha1_names := {"SHA1", "SHA-1"}

_sha1_allowed_usages := {"signature_verification", "hmac", "kdf", "rng", "non_signature"}

violation_crypto contains msg if {
	some algo in object.get(_crypto, "algorithms_in_use", [])
	upper(_algo_name(algo)) in _disallowed_algorithms
	msg := sprintf(
		"FedRAMP SC-13: Cryptographic algorithm '%v' is not approved or is disallowed for applying protection (NIST SP 800-131A Rev. 2). Use NIST-approved algorithms in FIPS-validated modules, or NSA-approved cryptography.",
		[_algo_name(algo)],
	)
}

violation_crypto contains msg if {
	some algo in object.get(_crypto, "algorithms_in_use", [])
	upper(_algo_name(algo)) in _sha1_names
	_algo_usage(algo) == "signature_generation"
	msg := "FedRAMP SC-13: SHA-1 used for digital signature generation, which NIST SP 800-131A Rev. 2 disallows outside protocol-specific allowances."
}

violation_crypto contains msg if {
	some algo in object.get(_crypto, "algorithms_in_use", [])
	upper(_algo_name(algo)) in _sha1_names
	not _algo_usage(algo) in (_sha1_allowed_usages | {"signature_generation"})
	msg := sprintf(
		"FedRAMP SC-13: evidence missing — usage of SHA-1 not stated (entry %v); SP 800-131A Rev. 2 allows SHA-1 only for signature verification (legacy) and non-signature uses. State usage as one of %v.",
		[algo, sort(_sha1_allowed_usages | {"signature_generation"})],
	)
}

# ---------------------------------------------------------------------------
# SA-9(5) Processing, Storage, and Service Location — FedRAMP High: U.S. jurisdiction.
# Below High the location is agency-defined; set data_residency.us_only_required when the agency requires it.
# ---------------------------------------------------------------------------

_residency := object.get(input, "data_residency", {})

violation_data_residency contains msg if {
	_applies_sa_9_5
	some field in ["storage_locations", "processing_locations"]
	not is_array(object.get(_residency, field, null))
	msg := sprintf("FedRAMP SA-9(5): evidence missing — input.data_residency.%s not collected", [field])
}

violation_data_residency contains msg if {
	_applies_sa_9_5
	some location in object.get(_residency, "storage_locations", [])
	not location.us_territory == true
	msg := sprintf(
		"FedRAMP SA-9(5): Federal data stored in non-US location '%v'. Storage must be in U.S./U.S. Territories or locations under U.S. jurisdiction.",
		[object.get(location, "region", "unknown")],
	)
}

violation_data_residency contains msg if {
	_applies_sa_9_5
	some location in object.get(_residency, "processing_locations", [])
	not location.us_territory == true
	msg := sprintf(
		"FedRAMP SA-9(5): Federal data processed in non-US location '%v'. Processing must be in U.S./U.S. Territories or locations under U.S. jurisdiction.",
		[object.get(location, "region", "unknown")],
	)
}

# ---------------------------------------------------------------------------
# PS-3 Personnel Screening (all levels); PS-3(3) US-person criterion only when the agency sets it
# ---------------------------------------------------------------------------

violation_personnel contains msg if {
	not is_array(object.get(input, "personnel", null))
	msg := "FedRAMP PS-3: evidence missing — input.personnel not collected"
}

violation_personnel contains msg if {
	some person in object.get(input, "personnel", [])
	person.admin_access == true
	not person.background_check_completed == true
	msg := sprintf(
		"FedRAMP PS-3: Personnel '%v' has administrative access without a completed background check. Individuals must be screened before access is authorized.",
		[object.get(person, "name", "unknown")],
	)
}

violation_personnel contains msg if {
	applies_moderate_high
	_us_persons_required
	some person in object.get(input, "personnel", [])
	person.admin_access == true
	not person.us_person == true
	not person.foreign_national_waiver == true
	msg := sprintf(
		"FedRAMP PS-3(3): Personnel '%v' has administrative access but is not a US person and has no waiver, and the agency requires US persons for administrative access (input.personnel_requirements.us_persons_required_for_admin).",
		[object.get(person, "name", "unknown")],
	)
}

# ---------------------------------------------------------------------------
# CA-7 Continuous Monitoring and RA-5 Vulnerability Monitoring and Scanning
# ---------------------------------------------------------------------------

violation_conmon contains msg if {
	not _cm.program_documented == true
	msg := "FedRAMP CA-7: No Continuous Monitoring (ConMon) program documented. FedRAMP requires a formal ConMon program."
}

violation_conmon contains msg if {
	not _cm.monthly_ato_report_submitted == true
	msg := "FedRAMP CA-7: Monthly ConMon report has not been submitted to the authorizing official. Monthly reporting is required."
}

violation_conmon contains msg if {
	some field in ["monthly_vulnerability_scans", "monthly_os_scan", "web_app_scan_enabled", "database_scan_enabled"]
	not _cm[field] == true
	msg := sprintf(
		"FedRAMP RA-5: input.continuous_monitoring.%s is not true. FedRAMP's RA-5 parameter requires monthly operating system/infrastructure, web application (including APIs) and database scans.",
		[field],
	)
}

violation_conmon contains msg if {
	some field in ["last_vulnerability_scan_days", "high_vulnerabilities_open_days", "critical_vulnerabilities_open_days", "moderate_vulnerabilities_open_days", "low_vulnerabilities_open_days"]
	not is_number(object.get(_cm, field, null))
	msg := sprintf("FedRAMP RA-5: evidence missing — input.continuous_monitoring.%s not collected", [field])
}

violation_conmon contains msg if {
	is_number(_cm.last_vulnerability_scan_days)
	_cm.last_vulnerability_scan_days > 30
	msg := sprintf(
		"FedRAMP RA-5: Last vulnerability scan was %v days ago. FedRAMP requires monthly scanning.",
		[_cm.last_vulnerability_scan_days],
	)
}

# FedRAMP's RA-5 parameter (ra-05_odp.03, identical at Low / Moderate / High): "high-risk vulnerabilities
# mitigated within thirty (30) days from date of discovery; moderate-risk ... ninety (90) days ...; low risk
# ... one hundred and eighty (180) days". There is no separate critical tier, so critical findings are held
# to the high-risk 30 days. The oldest open finding of each tier is compared with its limit.
_ra5_limits := {
	"critical_vulnerabilities_open_days": 30,
	"high_vulnerabilities_open_days": 30,
	"moderate_vulnerabilities_open_days": 90,
	"low_vulnerabilities_open_days": 180,
}

violation_conmon contains msg if {
	some field, limit in _ra5_limits
	is_number(_cm[field])
	_cm[field] > limit
	msg := sprintf(
		"FedRAMP RA-5: %v = %v days. FedRAMP's RA-5 parameter requires mitigation within %v days of discovery for this risk tier (critical held to the high-risk tier).",
		[field, _cm[field], limit],
	)
}

# CISA Known Exploited Vulnerabilities (KEV): FedRAMP's RA-5 guidance says a KEV-listed vulnerability is
# remediated by its KEV due date. Optional input continuous_monitoring.kev_findings = [{"cve", "due_date"
# (YYYY-MM-DD), "remediated"}]; "today" is input.assessment_date (YYYY-MM-DD) or the evaluation time.
# A KEV item past its due date is a finding whatever the 30-day parameter says. Without kev_findings the
# report says KEV due dates were not assessed (kev_assessed: false) — neither a pass nor a violation.
default kev_assessed := false

kev_assessed if is_array(object.get(_cm, "kev_findings", null))

_today_ns := time.parse_ns("2006-01-02", input.assessment_date) if is_string(input.assessment_date)

_today_ns := time.now_ns() if not is_string(input.assessment_date)

violation_conmon contains msg if {
	kev_assessed
	some k in _cm.kev_findings
	not is_string(object.get(k, "due_date", null))
	msg := sprintf("FedRAMP RA-5: evidence missing — due_date not collected for KEV finding %v", [object.get(k, "cve", "unknown")])
}

violation_conmon contains msg if {
	kev_assessed
	some k in _cm.kev_findings
	not k.remediated == true
	due := time.parse_ns("2006-01-02", k.due_date)
	_today_ns > due
	msg := sprintf(
		"FedRAMP RA-5: KEV-listed %v is unremediated past its CISA KEV due date %v. KEV due dates take precedence over the 30-day parameter.",
		[object.get(k, "cve", "unknown"), k.due_date],
	)
}

# ---------------------------------------------------------------------------
# CA-2 Control Assessments — 3PAO, at least annually
# ---------------------------------------------------------------------------

violation_3pao contains msg if {
	not _auth.assessed_by_3pao == true
	msg := "FedRAMP CA-2: System has not been assessed by a FedRAMP-recognized Third Party Assessment Organization (3PAO). 3PAO assessment is required for authorization."
}

violation_3pao contains msg if {
	_auth.assessed_by_3pao == true
	not is_number(object.get(_auth, "last_3pao_assessment_days", null))
	msg := "FedRAMP CA-2: evidence missing — input.authorization.last_3pao_assessment_days not collected"
}

violation_3pao contains msg if {
	_auth.assessed_by_3pao == true
	is_number(_auth.last_3pao_assessment_days)
	_auth.last_3pao_assessment_days > 365
	msg := sprintf(
		"FedRAMP CA-2: Last 3PAO assessment was %v days ago. FedRAMP's CA-2 parameter requires assessment at least annually.",
		[_auth.last_3pao_assessment_days],
	)
}

# ---------------------------------------------------------------------------
# CA-8 Penetration Testing and IR-8 Incident Response Plan (every level)
# ---------------------------------------------------------------------------

_svc := object.get(input, "cloud_service", {})

violation_testing_response contains msg if {
	not _svc.penetration_test_annual == true
	msg := "FedRAMP CA-8: Annual penetration testing is not evidenced (input.cloud_service.penetration_test_annual). CA-8 is in every FedRAMP Rev 5 baseline, at least annually."
}

violation_testing_response contains msg if {
	not _svc.incident_response_plan_approved == true
	msg := "FedRAMP IR-8: Incident response plan has not been reviewed and approved (input.cloud_service.incident_response_plan_approved)."
}

# ---------------------------------------------------------------------------
# CP-7 Alternate Processing Site (Moderate and High)
# ---------------------------------------------------------------------------

violation_contingency contains msg if {
	applies_moderate_high
	not _svc.redundant_processing == true
	msg := "FedRAMP CP-7: No alternate processing site is configured (input.cloud_service.redundant_processing). CP-7 is in the Moderate and High baselines."
}

# ---------------------------------------------------------------------------
# SR-2 Supply Chain Risk Management Plan (every level)
# ---------------------------------------------------------------------------

violation_scrm contains msg if {
	not object.get(input, ["supply_chain", "risk_management_plan"], false) == true
	msg := "FedRAMP SR-2: No supply chain risk management plan (input.supply_chain.risk_management_plan). SR-2 is in every FedRAMP Rev 5 baseline."
}

# ---------------------------------------------------------------------------
# Aggregate violations
# ---------------------------------------------------------------------------

assessment_areas := {
	"authorization": violation_authorization,
	"cryptography": violation_crypto,
	"data_residency": violation_data_residency,
	"personnel_security": violation_personnel,
	"continuous_monitoring": violation_conmon,
	"third_party_assessment": violation_3pao,
	"testing_and_response": violation_testing_response,
	"contingency": violation_contingency,
	"supply_chain": violation_scrm,
	"impact_level": violation_impact_level,
}

_module_violations := sort([v | some area in assessment_areas; some v in area])

all_violations := array.concat(_module_violations, _bench_violations)

# ---------------------------------------------------------------------------
# Benchmark results through the crosswalk (see the header)
# ---------------------------------------------------------------------------

default benchmark_supplied := false

benchmark_supplied if _ = input.reports

benchmark_supplied if _ = input.findings

# The baseline whose controls take the verdicts: the declared level, High until one is declared (the High
# baseline selects every Low and Moderate control).
default _bench_baseline := "high"

_bench_baseline := impact_level_norm if impact_level_norm != "unknown"

_bench_map_key := concat("", ["fedramp_rev5_", _bench_baseline])

# {<baseline control id>: {status, spine, not_evaluated}} for that baseline. The crosswalk packages and their
# data are separate files; when any is absent this is undefined, which must read as "could not be evaluated",
# never as "no gap".
_bench_map := overlay.control_evidence[_bench_map_key]

default _spine_loaded := false

_spine_loaded if {
	spine.spine_loaded == true
	is_number(spine.summary.rules_supplied)
	count(_bench_map) > 0
}

# Technical verdict per baseline control the supplied rules reach; empty unless benchmark results were supplied
# and the crosswalk is loaded.
_bench[id] := b if {
	benchmark_supplied
	_spine_loaded
	some id, ev in _bench_map
	count(ev.spine) > 0
	b := {
		"status": _bench_status(ev),
		"rules": sort({r | some e in ev.spine; some r in e.rules}),
		"open_rules": sort({r | some e in ev.spine; some r in e.open_rules}),
		"not_reviewed_rules": sort({r | some e in ev.spine; some r in e.not_reviewed_rules}),
	}
}

# gap and satisfied are the overlay's; not_reviewed and not_applicable are the spine's own verdicts, kept apart
# from "no rule supplied". None of them is a pass.
_bench_status(ev) := "gap" if {
	ev.status == "gap"
} else := "satisfied" if {
	ev.status == "satisfied"
} else := "not_reviewed" if {
	some e in ev.spine
	e.status == "not_reviewed"
} else := "not_applicable" if {
	count(ev.not_evaluated) == 0
	every e in ev.spine {
		e.status == "not_applicable"
	}
} else := "not_evaluated"

# Natural id order (AC-2 before AC-10, AC-2 before AC-2(1)).
_id_num(s) := 0 if {
	s == ""
} else := to_number(s)

_id_key(id) := [m[1], _id_num(m[2]), _id_num(m[3]), id] if {
	some m in regex.find_all_string_submatch_n(`^([A-Z]{2})-([0-9]+)(?:\(([0-9]+)\))?$`, id, 1)
} else := [id, 0, 0, id]

_natural(ids) := [k[3] | some k in sort([_id_key(id) | some id in ids])]

_baseline_ids := {id | _spine_loaded; some id, _ in _bench_map}

_bench_ids_with(st) := _natural({id | some id, b in _bench; b.status == st})

benchmark_gap_ids := _bench_ids_with("gap")

_bench_rule_list(rules) := concat(", ", rules) if {
	count(rules) <= 5
} else := sprintf("%s and %d more, listed on the control's row", [concat(", ", array.slice(rules, 0, 5)), count(rules) - 5])

_bench_gap_violations := [msg |
	some id in benchmark_gap_ids
	rules := _bench[id].open_rules
	msg := sprintf("FedRAMP %s: benchmark results show a gap: %d mapped STIG rule(s) Open (%s); the control fails regardless of its declared evidence or attestation", [id, count(rules), _bench_rule_list(rules)])
]

_bench_fail_closed contains "FAIL-CLOSED: benchmark results were supplied (input.reports / input.findings) but the crosswalk (crosswalk/correlation.rego, crosswalk/framework_overlay.rego, crosswalk/stig_800_53/data.json and the FedRAMP baseline map in crosswalk/framework_maps/data.json) is not loaded, so no technical verdict could be taken; this is not a passing result" if {
	benchmark_supplied
	not _spine_loaded
}

_bench_fail_closed contains "FAIL-CLOSED: benchmark results were supplied (input.reports / input.findings) but no rule row could be read from them; this is not a passing result" if {
	benchmark_supplied
	_spine_loaded
	spine.summary.rules_supplied == 0
}

_bench_fail_closed contains msg if {
	benchmark_supplied
	_spine_loaded
	n := spine.summary.rules_supplied
	is_number(n)
	n > 0
	count(spine.control_evidence) == 0
	msg := sprintf("FAIL-CLOSED: none of the %d benchmark rule id(s) supplied is in the crosswalk, so no technical verdict could be taken; this is not a passing result", [n])
}

_bench_fail_closed contains msg if {
	benchmark_supplied
	_spine_loaded
	n := spine.reports_without_facts
	is_number(n)
	n > 0
	msg := sprintf("FAIL-CLOSED: %d benchmark report(s) had no facts supplied (facts_supplied is false); every rule in them counts as Open", [n])
}

_bench_violations := array.concat(_bench_gap_violations, sort(_bench_fail_closed))

_bench_not_evaluated := {"status": "not_evaluated", "rules": [], "open_rules": [], "not_reviewed_rules": []}

_bench_row(id) := _bench[id] if {
	_bench[id]
} else := _bench_not_evaluated

# Spine verdicts on 800-53 controls the baseline does not select: shown, never a FedRAMP finding at this level.
_bench_outside := sort({id | some id, _ in spine.control_evidence; not id in _baseline_ids})

_bench_rule := "A benchmark gap fails the baseline control regardless of this module's own check, declared evidence or attestation. A satisfied benchmark verdict is recorded on the row and changes nothing else. Benchmark results never turn a control into a pass."

# The benchmark_evidence block; undefined when no benchmark results were supplied. The crosswalk's values are
# bound in the body, so anything it cannot give falls through to the short block and the report stays defined.
_bench_block := {
	"supplied": true,
	"spine_loaded": true,
	"source": "crosswalk.framework_overlay: STIG rule id -> CCI -> NIST SP 800-53 (DISA) -> FedRAMP Rev 5 baseline control with the same id (FedRAMP OSCAL baseline profile), base-control granularity",
	"map": _bench_map_key,
	"baseline": _bench_baseline,
	"combination_rule": _bench_rule,
	"rules_supplied": summary.rules_supplied,
	"rules_unmapped": summary.rules_unmapped,
	"unmapped_rules": unmapped,
	"reports_without_facts": without_facts,
	"baseline_controls": count(_baseline_ids),
	"baseline_controls_reached": count(_bench),
	"satisfied": _bench_ids_with("satisfied"),
	"gap": _bench_ids_with("gap"),
	"not_reviewed": _bench_ids_with("not_reviewed"),
	"not_applicable": _bench_ids_with("not_applicable"),
	"controls_not_in_baseline": _bench_outside,
	"gap_not_in_baseline": [id | some id in _bench_outside; spine.control_evidence[id].status == "gap"],
} if {
	benchmark_supplied
	_spine_loaded
	summary := spine.summary
	is_number(summary.rules_supplied)
	is_number(summary.rules_unmapped)
	unmapped := sort(spine.unmapped_rules)
	without_facts := spine.reports_without_facts
} else := {
	"supplied": true,
	"spine_loaded": false,
	"map": _bench_map_key,
	"baseline": _bench_baseline,
	"combination_rule": _bench_rule,
} if {
	benchmark_supplied
}

# Per-control rows, only with benchmark results: one per control of the baseline (when the crosswalk is loaded)
# and per check of this module, in natural id order.
#   pass           a check of this module with no finding
#   fail           a finding names the control: this module's own, or a benchmark gap
#   not_evaluated  this module has no check for the control and the benchmark found no gap; never a pass
# checked says whether this module has its own check for the id at the declared level.
_finding_ids(msg) := {m[1] | some m in regex.find_all_string_submatch_n(`^FedRAMP ([A-Z]{2}-[0-9]+(?:\([0-9]+\))?):`, msg, 1)}

_findings_by_id[id] contains v if {
	some v in all_violations
	some id in _finding_ids(v)
}

_findings_for(id) := sort(object.get(_findings_by_id, id, set()))

_row_status(id) := "fail" if {
	count(_findings_for(id)) > 0
} else := "pass" if {
	id in applicable_checks
} else := "not_evaluated"

_control_rows := [{
	"id": id,
	"status": _row_status(id),
	"checked": id in applicable_checks,
	"findings": _findings_for(id),
	"benchmark": _bench_row(id),
} |
	some id in _natural(_baseline_ids | applicable_checks)
]

# What the reports gain: nothing without benchmark results, so they are then what they have always been.
benchmark_addition := object.union({}, {}) if not benchmark_supplied

benchmark_addition := object.union({}, {
	"control_results": _control_rows,
	"control_result_counts": {s: count([r | some r in _control_rows; r.status == s]) | some s in ["pass", "fail", "not_evaluated"]},
	"benchmark_evidence": _bench_block,
}) if benchmark_supplied

default fedramp_compliant := false

fedramp_compliant if count(all_violations) == 0

# The check id each finding names: the "FedRAMP <ID>:" prefix every message carries.
failed_checks := {id |
	some v in all_violations
	some m in regex.find_all_string_submatch_n(`^FedRAMP ([A-Z]{2}-[0-9]+(?:\([0-9]+\))?):`, v, 1)
	id := m[1]
	id in applicable_checks
}

passing_areas := count([name | some name, area in assessment_areas; count(area) == 0])

compliance_score := round((passing_areas / count(assessment_areas)) * 100)

fedramp_compliance_report := object.union(_policy_report, benchmark_addition)

_policy_report := {
	"standard": "FedRAMP Rev 5",
	"impact_level": impact_level_norm,
	"compliant": fedramp_compliant,
	"compliance_score": compliance_score,
	"checks_evaluated": count(applicable_checks),
	"checks_failed": count(failed_checks),
	"baseline_size": baseline_size,
	"kev_assessed": kev_assessed,
	"total_violations": count(all_violations),
	"violations": all_violations,
	"areas": {name: {"compliant": count(area) == 0, "violations": area} | some name, area in assessment_areas},
}
