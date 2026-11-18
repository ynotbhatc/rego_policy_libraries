# METADATA
# title: "FedRAMP Rev 5 — authorization, ConMon and selected baseline checks (not a full baseline assessment)"
# custom:
#   class: compliance
#   framework: fedramp
#   source: fedramp
#   domains: [us-federal, cloud]
#   coverage:
#     checks: 38
#     cited: 22
#     density: orchestrator
#     basis: role
#     tested: true
#     entrypoint: none
#     guard: n/a
#     as_of: v2.4.2
package fedramp

import rego.v1

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
#   database scans, high-risk vulnerabilities mitigated within 30 days; SC-13 "FIPS-validated or
#   NSA-approved cryptography"; SA-9(5) (High only) U.S./U.S. Territories or U.S. jurisdiction.
# Baseline membership used for gating (same profiles): CA-2, CA-6, CA-7, CA-8, IR-8, PS-3, RA-2, RA-5,
# SC-13, SR-2 at every level; CP-7 Moderate and High; SA-9(5) Moderate and High, with a FedRAMP-fixed
# location only at High; PS-3(3) Moderate and High with agency-defined screening criteria.
#
# Input shape:
#   input.impact_level            - "low", "moderate", or "high"
#   input.authorization           - ATO/P-ATO status, 3PAO assessment
#   input.cryptography            - fips_140_validated / nsa_approved, algorithms_in_use[]
#   input.continuous_monitoring   - ConMon program and RA-5 scanning facts
#   input.cloud_service           - penetration_test_annual, incident_response_plan_approved, redundant_processing
#   input.supply_chain            - risk_management_plan
#   input.personnel[]             - admin personnel (admin_access, background_check_completed, us_person)
#   input.personnel_requirements  - us_persons_required_for_admin (agency PS-3(3) criterion, optional)
#   input.data_residency          - storage_locations[] / processing_locations[], us_only_required (optional)
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

_checks_conditional contains "PS-3(3)" if _us_persons_required

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

violation_crypto contains msg if {
	some algo in object.get(_crypto, "algorithms_in_use", [])
	algo in {"DES", "3DES", "RC4", "MD5", "SHA1", "RSA-1024"}
	msg := sprintf(
		"FedRAMP SC-13: Cryptographic algorithm '%v' is not approved for federal use. Use NIST-approved algorithms in FIPS-validated modules (or NSA-approved cryptography; CNSA 2.0 for national security systems).",
		[algo],
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
	some field in ["last_vulnerability_scan_days", "high_vulnerabilities_open_days", "critical_vulnerabilities_open_days"]
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

# FedRAMP's RA-5 parameter names high-risk (30 days), moderate-risk (90) and low-risk (180) tiers and no
# separate critical tier, so critical findings are held to the high-risk 30 days.
violation_conmon contains msg if {
	some field in ["high_vulnerabilities_open_days", "critical_vulnerabilities_open_days"]
	is_number(_cm[field])
	_cm[field] > 30
	msg := sprintf(
		"FedRAMP RA-5: %v = %v days. FedRAMP requires high-risk vulnerabilities (critical included) to be mitigated within 30 days of discovery.",
		[field, _cm[field]],
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

all_violations := sort([v | some area in assessment_areas; some v in area])

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

fedramp_compliance_report := {
	"standard": "FedRAMP Rev 5",
	"impact_level": impact_level_norm,
	"compliant": fedramp_compliant,
	"compliance_score": compliance_score,
	"checks_evaluated": count(applicable_checks),
	"checks_failed": count(failed_checks),
	"baseline_size": baseline_size,
	"total_violations": count(all_violations),
	"violations": all_violations,
	"areas": {name: {"compliant": count(area) == 0, "violations": area} | some name, area in assessment_areas},
}
