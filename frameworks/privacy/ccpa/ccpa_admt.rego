# METADATA
# title: "CCPA — Automated Decisionmaking Technology (11 CCR Article 11, §§7200–7222)"
# custom:
#   class: compliance
#   framework: ccpa
#   source: us-state
#   domains: [privacy, us-state, ai]
#   coverage:
#     checks: 45
#     cited: 40
#     density: sized
#     basis: size
#     tested: false
#     entrypoint: compliance_report
#     as_of: v2.3.3
package ccpa.admt

import rego.v1

# ---------------------------------------------------------------------------
# CCPA Regulations, Article 11 — Automated Decisionmaking Technology
# (11 CCR §§7200, 7220, 7221, 7222). Approved 2025-09-22, effective
# 2026-01-01; a business using ADMT for significant decisions must comply
# by 2027-01-01 (§7200(b)). Reference: cppa.ca.gov/regulations/ccpa_updates.html
#
# Scope: a business that uses ADMT to make a "significant decision" about a
# consumer (financial/lending, housing, education, employment, healthcare —
# §7001). Three duties: a Pre-use Notice (§7220), a right to opt out unless
# an exception applies (§7221), and a right to access ADMT (§7222).
#
# Fail-closed: uses_admt_for_significant_decisions must be declared true or
# false; absent is a violation. When true, every required fact must be
# boolean true. Opt-out exceptions (§7221(b)) must be named and must carry
# their own conditions. Violations are reported before 2027-01-01 so a gap
# is visible while it can still be closed; compliance_date is in the report.
#
# Input contract — input.ccpa.admt.*
#   uses_admt_for_significant_decisions   bool (required)
#   pre_use_notice.*        §7220        opt_out.*   §7221    access.*   §7222
#   opt_out.exception       "" | "human_appeal" | "admission_or_hiring" | "work_allocation_or_compensation"
# ---------------------------------------------------------------------------

default compliant := false

compliant if {
	count(violations) == 0
}

default _in := {}

_in := input.ccpa.admt

compliance_date := "2027-01-01T00:00:00Z"

violations contains msg if {
	not _in.uses_admt_for_significant_decisions == true
	not _in.uses_admt_for_significant_decisions == false
	msg := "CCPA §7200(a): uses_admt_for_significant_decisions must be declared true or false — whether ADMT makes significant decisions about consumers cannot be assumed"
}

_uses if _in.uses_admt_for_significant_decisions == true

# ── §7220 — Pre-use Notice ────────────────────────────────────────────────

_notice_checks := {
	"provided": "CCPA §7220(a): no Pre-use Notice informing consumers of the ADMT use and of their rights to opt out of and access ADMT",
	"at_or_before_collection": "CCPA §7220(b)(2): Pre-use Notice not presented prominently at or before collection of the personal information the ADMT will process (or before repurposing already-collected data)",
	"in_primary_interaction_manner": "CCPA §7220(b)(3): Pre-use Notice not presented in the manner in which the business primarily interacts with the consumer",
	"specific_purpose_stated": "CCPA §7220(c)(1): Pre-use Notice does not give a plain-language, specific purpose for the ADMT (generic 'to make a significant decision' is not permitted)",
	"opt_out_right_and_method_described": "CCPA §7220(c)(2): Pre-use Notice does not describe the right to opt out of ADMT and how to submit the request (or, under an exception, the appeal route or the exception relied on)",
	"access_right_and_method_described": "CCPA §7220(c)(3): Pre-use Notice does not describe the right to access ADMT and how to submit the request",
	"non_retaliation_stated": "CCPA §7220(c)(4): Pre-use Notice does not state that the business is prohibited from retaliating for exercising CCPA rights",
	"how_it_works_explained": "CCPA §7220(c)(5): Pre-use Notice lacks the plain-language explanation of how the ADMT processes personal information (categories that affect the output), the type of output and how it is used (sole factor, other factors, human role), and the alternative process for consumers who opt out",
}

violations contains msg if {
	_uses
	some key, msg in _notice_checks
	not _in.pre_use_notice[key] == true
}

# ── §7221 — Opt-out of ADMT ───────────────────────────────────────────────

_exceptions := {"human_appeal", "admission_or_hiring", "work_allocation_or_compensation"}

_exception := object.get(_in, ["opt_out", "exception"], "")

_claims_exception if _exception != ""

violations contains msg if {
	_uses
	_claims_exception
	not _exception in _exceptions
	msg := sprintf("CCPA §7221(b): opt_out.exception '%v' is not one of the three recognized exceptions (human_appeal, admission_or_hiring, work_allocation_or_compensation)", [_exception])
}

# Human-appeal exception conditions (§7221(b)(1)).
_human_appeal_checks := {
	"reviewer_designated_with_authority_to_overturn": "CCPA §7221(b)(1)(A): human-appeal exception claimed but no designated human reviewer who understands the ADMT output, considers the consumer's information and has authority to change the decision",
	"appeal_method_clear_and_easy": "CCPA §7221(b)(1)(B): human-appeal exception claimed but the appeal method is not clearly described, easy, minimal-step, and compliant with §§7003, 7004, 7021 and Article 5 verification",
}

violations contains msg if {
	_uses
	_exception == "human_appeal"
	some key, msg in _human_appeal_checks
	not _in.opt_out.human_appeal[key] == true
}

# Admission/hiring and work-allocation exceptions (§7221(b)(2)-(3)): sole use plus no unlawful discrimination.
_assessment_exception_checks := {
	"used_solely_for_stated_purpose": "CCPA §7221(b)(2)-(3): exception claimed but the ADMT is not used solely for the assessment of ability to perform (admission/hiring) or solely for work allocation/compensation",
	"works_for_purpose_without_unlawful_discrimination": "CCPA §7221(b)(2)(B)/(3)(B): exception claimed without evidence that the ADMT works for its purpose and does not unlawfully discriminate on protected characteristics",
}

violations contains msg if {
	_uses
	_exception in {"admission_or_hiring", "work_allocation_or_compensation"}
	some key, msg in _assessment_exception_checks
	not _in.opt_out.exception_conditions[key] == true
}

# When no exception applies, the opt-out must be offered and run properly.
_opt_out_required if {
	_uses
	not _claims_exception
}

_opt_out_checks := {
	"offered": "CCPA §7221(a): consumers are not given the ability to opt out of ADMT for significant decisions and no §7221(b) exception is claimed",
	"two_or_more_methods": "CCPA §7221(c): fewer than two designated opt-out methods, or none reflects how the business primarily interacts with consumers",
	"online_form_via_named_link": "CCPA §7221(c)(1): online business does not offer an interactive opt-out form reachable from a link in the Pre-use Notice whose title says what is being opted out of (e.g. 'Opt-out of Automated Decisionmaking Technology')",
	"not_cookie_banner_only": "CCPA §7221(c)(4): a cookie banner or cookie controls is the only opt-out mechanism — not acceptable, the method must be specific to ADMT",
	"easy_minimal_steps_no_dark_patterns": "CCPA §7221(d): opt-out method is not easy to execute with minimal steps and §7004 compliance (no dark patterns)",
	"no_account_or_extra_information_required": "CCPA §7221(e): opt-out requires creating an account or information beyond what is needed to direct the opt-out",
	"no_verification_required": "CCPA §7221(f): opt-out is treated as a verifiable consumer request — verification must not be required",
	"fraud_denials_explained": "CCPA §7221(g): opt-out requests denied as fraudulent without a documented good-faith belief and an explanation to the requestor",
	"confirmation_provided": "CCPA §7221(h): no means for the consumer to confirm the opt-out was processed",
	"single_opt_out_of_all_offered": "CCPA §7221(i): granular choices offered without a single option to opt out of all ADMT uses",
	"authorized_agents_accepted": "CCPA §7221(j): opt-out requests from authorized agents with the consumer's signed permission are not accepted",
	"twelve_month_wait_before_reconsent": "CCPA §7221(k): business re-asks opted-out consumers for consent within 12 months of the opt-out",
	"no_retaliation": "CCPA §7221(l): consumers who opt out are retaliated against (Civ. Code §1798.125, Article 7)",
	"pre_processing_opt_out_honored": "CCPA §7221(m): processing with the ADMT is initiated despite an opt-out received before processing began",
	"ceases_within_15_business_days": "CCPA §7221(n)(1): after a post-initiation opt-out, processing with the ADMT does not cease within 15 business days",
	"service_providers_notified": "CCPA §7221(n)(2): service providers, contractors and other recipients are not notified of the opt-out and instructed to comply within the same timeframe",
}

violations contains msg if {
	_opt_out_required
	some key, msg in _opt_out_checks
	not _in.opt_out[key] == true
}

# ── §7222 — Access to ADMT ────────────────────────────────────────────────

_access_checks := {
	"specific_purpose_explained": "CCPA §7222(b)(1): access response does not state the specific purpose for which ADMT was used for the consumer",
	"logic_explained": "CCPA §7222(b)(2): access response does not explain the ADMT logic — how the consumer's personal information produced the output, the parameters and the specific output",
	"outcome_and_human_role_explained": "CCPA §7222(b)(3): access response does not explain the outcome — whether the output was the sole factor, the other factors, the human's role, and any planned future use of the output",
	"non_retaliation_and_rights_instructions": "CCPA §7222(b)(4): access response lacks the non-retaliation statement and direct instructions/links for exercising other CCPA rights",
	"easy_methods_no_dark_patterns": "CCPA §7222(d): methods to request access to ADMT are not easy to use or use dark patterns",
	"verification_per_article_5": "CCPA §7222(e): access requests are not verified per Article 5, or unverifiable requestors are not told so",
	"denials_explained": "CCPA §7222(f): denials of verified access requests are not explained, or partial denials withhold the disclosable remainder",
	"secure_transmission": "CCPA §7222(g): requested information is not transmitted with reasonable security measures",
	"service_provider_assistance": "CCPA §7222(i): service providers and contractors do not assist with access-to-ADMT requests",
}

violations contains msg if {
	_uses
	some key, msg in _access_checks
	not _in.access[key] == true
}

# Aggregate responses are only allowed when the ADMT was used on the consumer more than four times in 12 months (§7222(j)).
violations contains msg if {
	_uses
	_in.access.aggregate_responses_used == true
	not _in.access.aggregate_only_when_more_than_four_uses_in_12_months == true
	msg := "CCPA §7222(j): aggregate-level access responses are given without the ADMT having been used on the consumer more than four times in a 12-month period"
}

# ── Report ────────────────────────────────────────────────────────────────

compliance_report := {
	"standard": "CCPA Regulations — Article 11 Automated Decisionmaking Technology (11 CCR §§7200–7222, effective 2026-01-01)",
	"domain": "Automated Decisionmaking Technology",
	"uses_admt_for_significant_decisions": object.get(_in, "uses_admt_for_significant_decisions", "undeclared"),
	"opt_out_exception_claimed": _exception,
	"compliance_date": substring(compliance_date, 0, 10),
	"compliance_date_reached": time.now_ns() >= time.parse_rfc3339_ns(compliance_date),
	"compliant": compliant,
	"violation_count": count(violations),
	"violations": violations,
}
