# NIST SSDF for Generative AI (SP 800-218A) mapped onto the supply-chain
# substrate. AI-generated artifacts run the SAME substrate controls as any other
# software; the GenAI profile adds one supply-chain-specific control — that AI
# contributions are attested (marked, reviewable, traceable) — and relies on the
# coverage triage (data.supply_chain.coverage) to force focused human review
# when AI-generated output touches the spine (auth / crypto / config / audit).
package supply_chain.ssdf_genai

import rego.v1

import data.supply_chain.substrate

# AI contributions must be attested. If there are no AI contributions, the
# control is vacuously satisfied.
default ai_attested := false

ai_attested if {
	input.ai.has_ai_contributions == true
	input.ai.ai_contributions_attested == true
}

ai_attested if input.ai.has_ai_contributions == false

reuses_substrate := ["provenance", "signing", "source_control", "dependencies"]

report := {
	"framework": "NIST SSDF for GenAI (SP 800-218A)",
	"ai_contributions_attested": ai_attested,
	"reuses_substrate": reuses_substrate,
	"note": "AI-generated artifacts run the same substrate controls; the coverage triage forces focused review when AI output touches the spine.",
}
