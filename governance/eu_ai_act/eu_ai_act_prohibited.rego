package eu_ai_act.prohibited

import rego.v1

default compliant := false

compliant if {
	count(violations) == 0
}

# =============================================================================
# Article 5.1(a) — Subliminal manipulation beyond conscious awareness
# =============================================================================

violations contains msg if {
	input.eu_ai_act.prohibited.subliminal_manipulation.uses_subliminal_techniques == true
	msg := "Article 5.1(a): AI system employs subliminal techniques beyond a person's consciousness to materially distort behavior in a manner causing or likely to cause significant harm"
}

violations contains msg if {
	input.eu_ai_act.prohibited.subliminal_manipulation.exploits_psychological_weaknesses == true
	msg := "Article 5.1(a): AI system exploits psychological weaknesses or biases of persons in a manner causing or likely to cause significant harm"
}

violations contains msg if {
	input.eu_ai_act.prohibited.subliminal_manipulation.exploits_cognitive_biases == true
	msg := "Article 5.1(a): AI system exploits cognitive biases to manipulate behavior in ways that impair free and informed decision-making"
}

# =============================================================================
# Article 5.1(b) — Exploitation of vulnerabilities of specific groups
# =============================================================================

violations contains msg if {
	input.eu_ai_act.prohibited.vulnerability_exploitation.targets_age_vulnerability == true
	input.eu_ai_act.prohibited.vulnerability_exploitation.causes_significant_harm == true
	msg := "Article 5.1(b): AI system exploits vulnerabilities due to age of a specific group in a manner causing or likely to cause significant harm"
}

violations contains msg if {
	input.eu_ai_act.prohibited.vulnerability_exploitation.targets_disability_vulnerability == true
	input.eu_ai_act.prohibited.vulnerability_exploitation.causes_significant_harm == true
	msg := "Article 5.1(b): AI system exploits vulnerabilities due to disability of a specific group in a manner causing or likely to cause significant harm"
}

violations contains msg if {
	input.eu_ai_act.prohibited.vulnerability_exploitation.targets_social_economic_situation == true
	input.eu_ai_act.prohibited.vulnerability_exploitation.causes_significant_harm == true
	msg := "Article 5.1(b): AI system exploits vulnerabilities due to social or economic situation of a specific group causing or likely to cause significant harm"
}

violations contains msg if {
	input.eu_ai_act.prohibited.vulnerability_exploitation.distorts_behavior == true
	not input.eu_ai_act.prohibited.vulnerability_exploitation.harm_prevented_by_safeguards == true
	msg := "Article 5.1(b): AI system causes harmful distortion of behavior of persons belonging to vulnerable groups without adequate safeguards"
}

# =============================================================================
# Article 5.1(c) — Social scoring by public authorities
# =============================================================================

violations contains msg if {
	input.eu_ai_act.prohibited.social_scoring.deployed_by_public_authority == true
	input.eu_ai_act.prohibited.social_scoring.evaluates_persons_based_on_social_behavior == true
	msg := "Article 5.1(c): Public authority AI system evaluates or classifies persons based on social behavior or personal characteristics leading to detrimental or unfavorable treatment"
}

violations contains msg if {
	input.eu_ai_act.prohibited.social_scoring.deployed_by_public_authority == true
	input.eu_ai_act.prohibited.social_scoring.treatment_is_unjustified == true
	msg := "Article 5.1(c): AI system causes unjustified or disproportionate treatment of persons in social contexts unrelated to the context in which the data was generated"
}

violations contains msg if {
	input.eu_ai_act.prohibited.social_scoring.deployed_by_public_authority == true
	input.eu_ai_act.prohibited.social_scoring.treatment_is_disproportionate == true
	msg := "Article 5.1(c): AI system by public authority causes disproportionate detrimental treatment compared to the gravity of the social behavior assessed"
}

# =============================================================================
# Article 5.1(d) — Real-time remote biometric identification in public spaces
# =============================================================================

violations contains msg if {
	input.eu_ai_act.prohibited.realtime_biometric_id.deployed_in_public_spaces == true
	input.eu_ai_act.prohibited.realtime_biometric_id.deployed_by_law_enforcement == true
	not input.eu_ai_act.prohibited.realtime_biometric_id.exception_applies == true
	msg := "Article 5.1(d): Real-time remote biometric identification system deployed in publicly accessible spaces by law enforcement without applicable exception"
}

violations contains msg if {
	input.eu_ai_act.prohibited.realtime_biometric_id.deployed_in_public_spaces == true
	input.eu_ai_act.prohibited.realtime_biometric_id.deployed_by_law_enforcement == true
	input.eu_ai_act.prohibited.realtime_biometric_id.exception_applies == true
	not input.eu_ai_act.prohibited.realtime_biometric_id.prior_judicial_authorization == true
	not input.eu_ai_act.prohibited.realtime_biometric_id.prior_independent_body_authorization == true
	msg := "Article 5.1(d): Real-time remote biometric identification deployed under exception without required prior judicial or independent body authorization"
}

violations contains msg if {
	input.eu_ai_act.prohibited.realtime_biometric_id.deployed_in_public_spaces == true
	input.eu_ai_act.prohibited.realtime_biometric_id.deployed_by_law_enforcement == true
	input.eu_ai_act.prohibited.realtime_biometric_id.exception_applies == true
	not input.eu_ai_act.prohibited.realtime_biometric_id.limited_to_annex_ii_offenses == true
	msg := "Article 5.1(d): Real-time remote biometric identification under exception not limited to specific criminal offenses listed in Annex II"
}

violations contains msg if {
	input.eu_ai_act.prohibited.realtime_biometric_id.deployed_in_public_spaces == true
	input.eu_ai_act.prohibited.realtime_biometric_id.geographically_unlimited == true
	msg := "Article 5.1(d): Real-time remote biometric identification deployment is not geographically and temporally limited as required for authorized exceptions"
}

# =============================================================================
# Article 5.1(e) — Biometric categorization inferring sensitive attributes
# =============================================================================

violations contains msg if {
	input.eu_ai_act.prohibited.biometric_categorization.infers_race == true
	not input.eu_ai_act.prohibited.biometric_categorization.law_enforcement_strict_conditions == true
	msg := "Article 5.1(e): AI system categorizes individuals by race inferred from biometric data without meeting strict law enforcement conditions"
}

violations contains msg if {
	input.eu_ai_act.prohibited.biometric_categorization.infers_political_opinion == true
	not input.eu_ai_act.prohibited.biometric_categorization.law_enforcement_strict_conditions == true
	msg := "Article 5.1(e): AI system categorizes individuals by political opinion inferred from biometric data without meeting strict law enforcement conditions"
}

violations contains msg if {
	input.eu_ai_act.prohibited.biometric_categorization.infers_religion == true
	not input.eu_ai_act.prohibited.biometric_categorization.law_enforcement_strict_conditions == true
	msg := "Article 5.1(e): AI system categorizes individuals by religion or philosophical belief inferred from biometric data without meeting strict law enforcement conditions"
}

violations contains msg if {
	input.eu_ai_act.prohibited.biometric_categorization.infers_trade_union_membership == true
	not input.eu_ai_act.prohibited.biometric_categorization.law_enforcement_strict_conditions == true
	msg := "Article 5.1(e): AI system categorizes individuals by trade union membership inferred from biometric data without meeting strict law enforcement conditions"
}

violations contains msg if {
	input.eu_ai_act.prohibited.biometric_categorization.infers_sexual_orientation == true
	not input.eu_ai_act.prohibited.biometric_categorization.law_enforcement_strict_conditions == true
	msg := "Article 5.1(e): AI system categorizes individuals by sexual orientation or gender identity inferred from biometric data without meeting strict law enforcement conditions"
}

# =============================================================================
# Article 5.1(f) — Emotion recognition in workplace or educational institutions
# =============================================================================

violations contains msg if {
	input.eu_ai_act.prohibited.emotion_recognition.deployed_in_workplace == true
	not input.eu_ai_act.prohibited.emotion_recognition.medical_purpose == true
	not input.eu_ai_act.prohibited.emotion_recognition.safety_purpose == true
	msg := "Article 5.1(f): Emotion recognition system used in workplace context without documented medical or safety purpose exception"
}

violations contains msg if {
	input.eu_ai_act.prohibited.emotion_recognition.deployed_in_educational_institution == true
	not input.eu_ai_act.prohibited.emotion_recognition.medical_purpose == true
	not input.eu_ai_act.prohibited.emotion_recognition.safety_purpose == true
	msg := "Article 5.1(f): Emotion recognition system used in educational institution without documented medical or safety purpose exception"
}

violations contains msg if {
	input.eu_ai_act.prohibited.emotion_recognition.exception_claimed == true
	not input.eu_ai_act.prohibited.emotion_recognition.exception_documented == true
	msg := "Article 5.1(f): Emotion recognition exception (medical or safety) claimed but not formally documented as required"
}

# =============================================================================
# Article 5.1(g) — Untargeted scraping for facial recognition databases
# =============================================================================

violations contains msg if {
	input.eu_ai_act.prohibited.facial_recognition_scraping.database_created_by_scraping == true
	input.eu_ai_act.prohibited.facial_recognition_scraping.scraping_untargeted == true
	msg := "Article 5.1(g): Facial recognition database created or expanded through untargeted scraping of facial images from internet or CCTV footage"
}

violations contains msg if {
	input.eu_ai_act.prohibited.facial_recognition_scraping.database_created_by_scraping == true
	not input.eu_ai_act.prohibited.facial_recognition_scraping.scraping_targeted == true
	not input.eu_ai_act.prohibited.facial_recognition_scraping.legal_basis_documented == true
	msg := "Article 5.1(g): Facial recognition database creation via scraping lacks documented legal basis and targeted scope justification"
}

# =============================================================================
# Article 5.1(h) — Predictive policing based solely on profiling
# =============================================================================

violations contains msg if {
	input.eu_ai_act.prohibited.predictive_policing.assesses_individual_criminal_risk == true
	input.eu_ai_act.prohibited.predictive_policing.based_solely_on_profiling == true
	not input.eu_ai_act.prohibited.predictive_policing.objective_factual_basis_present == true
	msg := "Article 5.1(h): AI system assesses risk of criminal offense by individual persons based solely on profiling without objective factual basis relating to that person"
}

violations contains msg if {
	input.eu_ai_act.prohibited.predictive_policing.assesses_individual_criminal_risk == true
	input.eu_ai_act.prohibited.predictive_policing.uses_only_group_characteristics == true
	msg := "Article 5.1(h): Predictive policing system uses only group-level characteristics or statistical profiling without individual objective factual basis"
}

violations contains msg if {
	input.eu_ai_act.prohibited.predictive_policing.crime_prediction_without_human_review == true
	msg := "Article 5.1(h): Predictive policing system produces crime risk assessments for individuals without meaningful human review before any enforcement action"
}

# =============================================================================
# Compliance report
# =============================================================================

compliance_report := {
	"module": "prohibited_practices",
	"standard": "EU AI Act — Title II, Article 5",
	"applies_from": "February 2025",
	"compliant": compliant,
	"total_violations": count(violations),
	"violations": violations,
	"articles_assessed": [
		"5.1(a) — Subliminal manipulation",
		"5.1(b) — Exploitation of vulnerabilities",
		"5.1(c) — Social scoring by public authorities",
		"5.1(d) — Real-time remote biometric identification",
		"5.1(e) — Biometric categorization inferring sensitive attributes",
		"5.1(f) — Emotion recognition in workplace/education",
		"5.1(g) — Untargeted facial recognition scraping",
		"5.1(h) — Predictive policing on individual basis",
	],
}
