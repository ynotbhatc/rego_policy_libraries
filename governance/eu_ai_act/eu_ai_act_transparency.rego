package eu_ai_act.transparency

import rego.v1

default compliant := false

compliant if {
	count(violations) == 0
}

# =============================================================================
# Article 50.1 — Chatbots interacting with natural persons
# =============================================================================

violations contains msg if {
	input.eu_ai_act.transparency.chatbot.interacts_with_natural_persons == true
	not input.eu_ai_act.transparency.chatbot.users_informed_of_ai_nature == true
	not input.eu_ai_act.transparency.chatbot.obvious_ai_context == true
	msg := "Article 50.1: Chatbot or conversational AI system does not inform users they are interacting with an AI and not a human at the start of each interaction"
}

violations contains msg if {
	input.eu_ai_act.transparency.chatbot.interacts_with_natural_persons == true
	not input.eu_ai_act.transparency.chatbot.disclosure_at_interaction_start == true
	not input.eu_ai_act.transparency.chatbot.obvious_ai_context == true
	msg := "Article 50.1: AI interaction disclosure not provided at the start of the interaction; disclosure must occur before the user becomes engaged in the conversation"
}

violations contains msg if {
	input.eu_ai_act.transparency.chatbot.interacts_with_natural_persons == true
	input.eu_ai_act.transparency.chatbot.obvious_ai_context == true
	not input.eu_ai_act.transparency.chatbot.obvious_ai_context_documented == true
	msg := "Article 50.1: 'Obvious AI context' exception claimed for chatbot disclosure exemption but not formally documented with justification"
}

violations contains msg if {
	input.eu_ai_act.transparency.chatbot.impersonates_human == true
	msg := "Article 50.1: AI system actively impersonates a natural person in a way that could deceive users about the AI nature of the interaction"
}

# =============================================================================
# Article 50.2 — Emotion recognition and biometric categorization
# =============================================================================

violations contains msg if {
	input.eu_ai_act.transparency.emotion_recognition.system_deployed == true
	not input.eu_ai_act.transparency.emotion_recognition.persons_notified == true
	msg := "Article 50.2: Persons exposed to emotion recognition system not notified of the system's operation and the fact that they are subject to it"
}

violations contains msg if {
	input.eu_ai_act.transparency.emotion_recognition.processes_personal_data == true
	not input.eu_ai_act.transparency.emotion_recognition.gdpr_compliant == true
	msg := "Article 50.2: Emotion recognition system processes personal data without compliance with applicable data protection requirements including GDPR"
}

violations contains msg if {
	input.eu_ai_act.transparency.emotion_recognition.requires_consent == true
	not input.eu_ai_act.transparency.emotion_recognition.consent_obtained == true
	msg := "Article 50.2: GDPR consent not obtained from individuals before processing their biometric or emotional state data"
}

violations contains msg if {
	input.eu_ai_act.transparency.biometric_categorization.system_deployed == true
	not input.eu_ai_act.transparency.biometric_categorization.persons_notified == true
	msg := "Article 50.2: Persons subject to biometric categorization system not notified of the categorization and its basis"
}

# =============================================================================
# Article 50.3 — Deep fakes and AI-generated/manipulated content
# =============================================================================

violations contains msg if {
	input.eu_ai_act.transparency.deep_fake.generates_synthetic_image == true
	not input.eu_ai_act.transparency.deep_fake.labeled_as_ai_generated == true
	not input.eu_ai_act.transparency.deep_fake.legitimate_purpose_evident == true
	msg := "Article 50.3: AI-generated or AI-manipulated image not labeled as artificially generated or manipulated; machine-readable disclosure is required"
}

violations contains msg if {
	input.eu_ai_act.transparency.deep_fake.generates_synthetic_audio == true
	not input.eu_ai_act.transparency.deep_fake.labeled_as_ai_generated == true
	not input.eu_ai_act.transparency.deep_fake.legitimate_purpose_evident == true
	msg := "Article 50.3: AI-generated or AI-manipulated audio content not labeled as artificially generated or manipulated"
}

violations contains msg if {
	input.eu_ai_act.transparency.deep_fake.generates_synthetic_video == true
	not input.eu_ai_act.transparency.deep_fake.labeled_as_ai_generated == true
	not input.eu_ai_act.transparency.deep_fake.legitimate_purpose_evident == true
	msg := "Article 50.3: AI-generated or AI-manipulated video content not labeled as artificially generated or manipulated"
}

violations contains msg if {
	input.eu_ai_act.transparency.deep_fake.labeled_as_ai_generated == true
	not input.eu_ai_act.transparency.deep_fake.machine_readable_disclosure_embedded == true
	msg := "Article 50.3: AI-generated content disclosure not embedded as machine-readable metadata; technical labeling in content format is required in addition to human-visible labeling"
}

violations contains msg if {
	input.eu_ai_act.transparency.deep_fake.legitimate_purpose_evident == true
	not input.eu_ai_act.transparency.deep_fake.purpose_documented == true
	msg := "Article 50.3: Legitimate purpose exception (satire, art, clearly fictional) for deep fake disclosure claimed but not documented"
}

# =============================================================================
# Article 50.4 — AI-generated text on matters of public interest
# =============================================================================

violations contains msg if {
	input.eu_ai_act.transparency.public_interest_text.generates_text_on_public_interest == true
	not input.eu_ai_act.transparency.public_interest_text.labeled_as_ai_generated == true
	not input.eu_ai_act.transparency.public_interest_text.human_editorial_responsibility_taken == true
	msg := "Article 50.4: AI-generated text on matters of public interest not labeled as AI-generated; labeling is required unless human editorial responsibility has been assumed"
}

violations contains msg if {
	input.eu_ai_act.transparency.public_interest_text.human_editorial_responsibility_taken == true
	not input.eu_ai_act.transparency.public_interest_text.editorial_review_process_documented == true
	msg := "Article 50.4: Human editorial responsibility exception claimed for AI-generated public interest text but editorial review process is not documented"
}

violations contains msg if {
	input.eu_ai_act.transparency.public_interest_text.generates_text_on_public_interest == true
	not input.eu_ai_act.transparency.public_interest_text.disclosure_format_compliant == true
	msg := "Article 50.4: Format of AI-generated text disclosure does not meet requirements; disclosure must be clear, prominent, and distinguishable from the content"
}

# =============================================================================
# Article 50.5 — Deployment transparency and EU database registration
# =============================================================================

violations contains msg if {
	input.eu_ai_act.transparency.deployment.high_risk_system == true
	not input.eu_ai_act.transparency.deployment.registered_in_eu_database == true
	msg := "Article 50.5: High-risk AI system not registered in the EU database for AI systems as required before deployment"
}

violations contains msg if {
	input.eu_ai_act.transparency.deployment.deployer_of_emotion_recognition == true
	not input.eu_ai_act.transparency.deployment.affected_persons_informed == true
	msg := "Article 50.5: Deployer of emotion recognition system has not informed affected persons of the system's deployment and use"
}

violations contains msg if {
	input.eu_ai_act.transparency.deployment.deployer_of_emotion_recognition == true
	not input.eu_ai_act.transparency.deployment.information_provided_before_exposure == true
	msg := "Article 50.5: Information about emotion recognition system not provided to affected persons before their exposure to the system"
}

# =============================================================================
# Compliance report
# =============================================================================

compliance_report := {
	"module": "transparency_obligations",
	"standard": "EU AI Act — Title IV, Article 50",
	"applies_from": "August 2026",
	"compliant": compliant,
	"total_violations": count(violations),
	"violations": violations,
	"articles_assessed": [
		"Article 50.1 — Chatbots interacting with natural persons",
		"Article 50.2 — Emotion recognition and biometric categorization",
		"Article 50.3 — Deep fakes and AI-generated/manipulated content",
		"Article 50.4 — AI-generated text on matters of public interest",
		"Article 50.5 — Deployment transparency and EU database registration",
	],
}
