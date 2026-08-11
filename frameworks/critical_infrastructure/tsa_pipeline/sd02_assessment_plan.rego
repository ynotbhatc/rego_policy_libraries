package tsa_pipeline.sd02_assessment_plan

import rego.v1

# =============================================================================
# TSA Security Directive Pipeline-2021-02G
# Section III.G — Cybersecurity Assessment Plan
#
# Directive:  SD Pipeline-2021-02G
# Effective:  May 3, 2026 through May 2, 2027
#
# Requirements evaluated: III.G.1, III.G.2.a–e, III.G.3, III.G.4
#                         (10 subparagraphs)
#
# THE CLOCKS in this section:
#   III.G.2.b — cybersecurity architecture design review at least once every
#               TWO years
#   III.G.2.d — schedule must assess at least ONE-THIRD of the policies,
#               procedures, measures, and capabilities in the TSA-approved
#               Cybersecurity Implementation Plan each year, with 100 percent
#               assessed over any THREE-year period
#   III.G.3   — Cybersecurity Assessment Plan submitted annually, no later than
#               12 months from the date of TSA's approval of the previous Plan
#   III.G.4   — Assessment Plan report submitted no later than 12 months from
#               the date of TSA's approval of the most recent Assessment Plan
#
# --- INPUT CONTRACT ----------------------------------------------------------
# input.assessment_plan: {
#   "exists":                     boolean,
#   "assesses_critical_cyber_systems": boolean,
#   "implementation_plan_effectiveness_assessed": boolean,   # III.G.2.a
#   "architecture_design_review": {                          # III.G.2.b
#       "conducted":                    boolean,
#       "months_since_last_review":     number,   # must be <= 24
#       "network_traffic_verified":     boolean,
#       "system_log_review_conducted":  boolean
#   },
#   "other_assessment_capabilities": {                       # III.G.2.c
#       "penetration_testing":  boolean,
#       "red_or_purple_team":   boolean
#   },
#   "schedule": {                                            # III.G.2.d
#       "defined":                        boolean,
#       "annual_coverage_percent":        number,   # must be >= 33
#       "three_year_coverage_percent":    number    # must be 100
#   },
#   "annual_report": {                                       # III.G.2.e, III.G.4
#       "submitted":                    boolean,
#       "months_since_plan_approval":   number,   # must be <= 12
#       "methods_documented":           boolean,  # G.2.e.i
#       "results_documented":           boolean   # G.2.e.ii
#   },
#   "submission": {                                          # III.G.3
#       "submitted_to_tsa":             boolean,
#       "months_since_previous_approval": number   # must be <= 12
#   }
# }
#
# NO FACT SOURCE EXISTS YET — see sd01_cybersecurity_coordinator.rego.
#
# OPA endpoint: POST <opa_ot_url>/v1/data/tsa_pipeline/sd02_assessment_plan
# =============================================================================

# `input` is UNDEFINED (not {}) when OPA receives an empty request body. Routing
# every lookup through this defaulted alias makes an absent fact evaluate to the
# fail-closed default instead of silently skipping the violation rule entirely.
default facts := {}

facts := input

default compliant := false

compliant if {
	count(violations) == 0
}

cap_flag(path) := value if {
	value := object.get(facts, array.concat(["assessment_plan"], path), false)
}

cap_number(path, fallback) := value if {
	raw := object.get(facts, array.concat(["assessment_plan"], path), fallback)
	is_number(raw)
	value := raw
}

cap_number(path, fallback) := fallback if {
	raw := object.get(facts, array.concat(["assessment_plan"], path), fallback)
	not is_number(raw)
}

# ── III.G.1 — Plan exists ────────────────────────────────────────────────────

violations contains msg if {
	cap_flag(["exists"]) == false
	msg := "TSA SD Pipeline-2021-02G III.G.1: No Cybersecurity Assessment Plan developed for proactively assessing and auditing cybersecurity measures"
}

violations contains msg if {
	cap_flag(["assesses_critical_cyber_systems"]) == false
	msg := "TSA SD Pipeline-2021-02G III.G.1: The Cybersecurity Assessment Plan does not proactively assess Critical Cyber Systems to ascertain the effectiveness of cybersecurity measures and to identify and resolve device, network, and/or system vulnerabilities"
}

# ── III.G.2.a — Effectiveness of the Implementation Plan ─────────────────────

violations contains msg if {
	cap_flag(["implementation_plan_effectiveness_assessed"]) == false
	msg := "TSA SD Pipeline-2021-02G III.G.2.a: The Cybersecurity Assessment Plan does not assess the effectiveness of the Owner/Operator's TSA-approved Cybersecurity Implementation Plan"
}

# ── III.G.2.b — Architecture design review (every 2 years) ───────────────────

violations contains msg if {
	cap_flag(["architecture_design_review", "conducted"]) == false
	msg := "TSA SD Pipeline-2021-02G III.G.2.b: No cybersecurity architecture design review — one is required at least once every two years"
}

violations contains msg if {
	months := cap_number(["architecture_design_review", "months_since_last_review"], 0)
	months > 24
	msg := sprintf("TSA SD Pipeline-2021-02G III.G.2.b: The last cybersecurity architecture design review was %v months ago — a review is required at least once every two years (24 months)", [months])
}

violations contains msg if {
	cap_flag(["architecture_design_review", "network_traffic_verified"]) == false
	msg := "TSA SD Pipeline-2021-02G III.G.2.b: The cybersecurity architecture design review does not include verification and validation of network traffic"
}

violations contains msg if {
	cap_flag(["architecture_design_review", "system_log_review_conducted"]) == false
	msg := "TSA SD Pipeline-2021-02G III.G.2.b: The cybersecurity architecture design review does not include system log review and analysis to identify vulnerabilities related to network design, configuration, and inter-connectivity to internal and external systems"
}

# ── III.G.2.c — Other assessment capabilities ────────────────────────────────

violations contains msg if {
	cap_flag(["other_assessment_capabilities", "penetration_testing"]) == false
	msg := "TSA SD Pipeline-2021-02G III.G.2.c: The Cybersecurity Assessment Plan does not incorporate penetration testing of Information Technology systems"
}

violations contains msg if {
	cap_flag(["other_assessment_capabilities", "red_or_purple_team"]) == false
	msg := "TSA SD Pipeline-2021-02G III.G.2.c: The Cybersecurity Assessment Plan does not incorporate 'red' or 'purple' team (adversarial perspective) testing"
}

# ── III.G.2.d — Assessment schedule and coverage ─────────────────────────────

violations contains msg if {
	cap_flag(["schedule", "defined"]) == false
	msg := "TSA SD Pipeline-2021-02G III.G.2.d: No schedule for assessing and auditing the specific cybersecurity measures and actions required by III.G.2.a through III.G.2.c"
}

violations contains msg if {
	coverage := cap_number(["schedule", "annual_coverage_percent"], 0)
	coverage < 33
	msg := sprintf("TSA SD Pipeline-2021-02G III.G.2.d: The assessment schedule covers %v percent of the policies, procedures, measures, and capabilities in the TSA-approved Cybersecurity Implementation Plan each year — at least one-third must be assessed annually", [coverage])
}

violations contains msg if {
	coverage := cap_number(["schedule", "three_year_coverage_percent"], 0)
	coverage < 100
	msg := sprintf("TSA SD Pipeline-2021-02G III.G.2.d: The assessment schedule reaches %v percent coverage over a three-year period — 100 percent must be assessed over any three-year period", [coverage])
}

# ── III.G.2.e / III.G.4 — Annual report ──────────────────────────────────────

violations contains msg if {
	cap_flag(["annual_report", "submitted"]) == false
	msg := "TSA SD Pipeline-2021-02G III.G.2.e: The Cybersecurity Assessment Plan annual report of assessment results has not been submitted to TSA"
}

violations contains msg if {
	cap_flag(["annual_report", "methods_documented"]) == false
	msg := "TSA SD Pipeline-2021-02G III.G.2.e.i: The annual report does not indicate which assessment method(s) were used in the previous 12 months to determine whether the policies, procedures, and capabilities described in the Cybersecurity Implementation Plan are effective"
}

violations contains msg if {
	cap_flag(["annual_report", "results_documented"]) == false
	msg := "TSA SD Pipeline-2021-02G III.G.2.e.ii: The annual report does not include the results of the individual assessments conducted in the previous 12 months"
}

violations contains msg if {
	months := cap_number(["annual_report", "months_since_plan_approval"], 0)
	months > 12
	msg := sprintf("TSA SD Pipeline-2021-02G III.G.4: The Cybersecurity Assessment Plan report was submitted %v months from the date of TSA's approval of the most recent Assessment Plan — it must be submitted no later than 12 months", [months])
}

# ── III.G.3 — Annual plan submission ─────────────────────────────────────────

violations contains msg if {
	cap_flag(["submission", "submitted_to_tsa"]) == false
	msg := "TSA SD Pipeline-2021-02G III.G.3: The Cybersecurity Assessment Plan has not been submitted to TSA for approval — submission is required on an annual basis"
}

violations contains msg if {
	months := cap_number(["submission", "months_since_previous_approval"], 0)
	months > 12
	msg := sprintf("TSA SD Pipeline-2021-02G III.G.3: The Cybersecurity Assessment Plan was submitted %v months from the date of TSA's approval of the previous Plan — it must be submitted no later than 12 months", [months])
}

# ── Compliance report ────────────────────────────────────────────────────────

compliance_report := {
	"directive": "TSA SD Pipeline-2021-02G",
	"section": "III.G",
	"name": "Cybersecurity Assessment Plan",
	"architecture_review_interval_months": 24,
	"minimum_annual_coverage_percent": 33,
	"required_three_year_coverage_percent": 100,
	"plan_submission_interval_months": 12,
	"requirements_evaluated": 10,
	"compliant": compliant,
	"violations": violations,
	"violation_count": count(violations),
}
