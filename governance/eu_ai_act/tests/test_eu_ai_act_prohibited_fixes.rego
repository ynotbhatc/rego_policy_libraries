package eu_ai_act.prohibited_test

import rego.v1

# Validation fixes 2026-10-17: an Article 5 practice that was not assessed is a violation.

assessed := {"eu_ai_act": {"prohibited": {
	"subliminal_manipulation": {"uses_subliminal_techniques": false},
	"vulnerability_exploitation": {"distorts_behavior": false},
	"social_scoring": {"deployed_by_public_authority": false},
	"realtime_biometric_id": {"deployed_in_public_spaces": false},
	"biometric_categorization": {"infers_race": false},
	"emotion_recognition": {"deployed_in_workplace": false},
	"facial_recognition_scraping": {"database_created_by_scraping": false},
	"predictive_policing": {"assesses_individual_criminal_risk": false},
	"intimate_imagery": {"can_generate_realistic_intimate_imagery": false},
	"csam": {"can_generate_csam": false},
}}}

test_prohibited_empty_input_not_compliant if {
	not data.eu_ai_act.prohibited.compliant with input as {}
	count(data.eu_ai_act.prohibited.violations) == 10 with input as {}
}

test_prohibited_all_assessed_all_false_is_compliant if {
	data.eu_ai_act.prohibited.compliant with input as assessed
}

test_prohibited_each_unassessed_section_is_violation if {
	every sec in ["subliminal_manipulation", "vulnerability_exploitation", "social_scoring", "realtime_biometric_id", "biometric_categorization", "emotion_recognition", "facial_recognition_scraping", "predictive_policing", "intimate_imagery", "csam"] {
		not data.eu_ai_act.prohibited.compliant with input as json.remove(assessed, [concat("", ["/eu_ai_act/prohibited/", sec])])
	}
}

test_prohibited_empty_section_object_is_unassessed if {
	i := json.patch(assessed, [{"op": "replace", "path": "/eu_ai_act/prohibited/social_scoring", "value": {}}])
	not data.eu_ai_act.prohibited.compliant with input as i
}

test_prohibited_real_violation_still_flagged if {
	i := json.patch(assessed, [{"op": "replace", "path": "/eu_ai_act/prohibited/subliminal_manipulation/uses_subliminal_techniques", "value": true}])
	not data.eu_ai_act.prohibited.compliant with input as i
	r := data.eu_ai_act.prohibited.compliance_report with input as i
	r.compliant == false
	r.total_violations == 1
}
