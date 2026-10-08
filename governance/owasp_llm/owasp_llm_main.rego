# OWASP Top 10 for LLM Applications — 2026 edition (OWASP GenAI
# Security Project, released 2026-08-04; supersedes the 2025 edition —
# 8 entries moved, LLM07:2025 "System Prompt Leakage" became
# LLM08:2026 "Hidden Context Exposure").
#
# Three checkable controls per risk. Each risk carries MITRE ATLAS
# mitigation crosswalk ids (atlas-data v2026.09, AML.M0000-M0034) in
# the atlas_crosswalk table — metadata for threat-informed coverage
# reporting, deliberately NOT separate checks (ATLAS revs monthly and
# its mitigations overlap these and the MCP-governance module).
#
# Query: POST /v1/data/owasp_llm/main/compliance_report
#
# Fail-closed: every control fact must be affirmatively true.
# Input contract — input.owasp_llm.<llmNN>.<control> (all bool), e.g.
#   input.owasp_llm.llm01.privilege_separation_enforced

# METADATA
# title: "OWASP Top 10 for LLM Applications — 2026 edition (OWASP GenAI"
# custom:
#   class: governance
#   framework: owasp_llm
#   source: owasp
#   domains: [ai]
package owasp_llm.main

import rego.v1

default compliant := false

compliant if {
	count(violations) == 0
}

# ── LLM01:2026 — Prompt Injection ──
violations contains msg if {
	not input.owasp_llm.llm01.privilege_separation_enforced == true
	msg := "OWASP LLM01:2026 (Prompt Injection): authorization is checked on every request including tool/resource access, independent of model output — not in place"
}

violations contains msg if {
	not input.owasp_llm.llm01.untrusted_input_filtered == true
	msg := "OWASP LLM01:2026 (Prompt Injection): model behavior is constrained with system-level instructions plus input/output filtering on untrusted content — not in place"
}

violations contains msg if {
	not input.owasp_llm.llm01.high_impact_actions_gated == true
	msg := "OWASP LLM01:2026 (Prompt Injection): human approval is required for high-impact actions reachable from model-processed untrusted input — not in place"
}

# ── LLM02:2026 — Sensitive Information Disclosure ──
violations contains msg if {
	not input.owasp_llm.llm02.data_sanitized_before_use == true
	msg := "OWASP LLM02:2026 (Sensitive Information Disclosure): data sanitization/masking is applied before training and before context insertion — not in place"
}

violations contains msg if {
	not input.owasp_llm.llm02.retrieval_access_controlled == true
	msg := "OWASP LLM02:2026 (Sensitive Information Disclosure): per-user access control is enforced in retrieval — identity and entitlement verified before documents enter context — not in place"
}

violations contains msg if {
	not input.owasp_llm.llm02.outputs_scanned_for_sensitive_data == true
	msg := "OWASP LLM02:2026 (Sensitive Information Disclosure): no secrets live in prompts/hidden context, and outputs are scanned for sensitive-data leakage — not in place"
}

# ── LLM03:2026 — Excessive Agency ──
violations contains msg if {
	not input.owasp_llm.llm03.tools_minimized == true
	msg := "OWASP LLM03:2026 (Excessive Agency): only tools required for the task are exposed, with narrowest-scope functions — not in place"
}

violations contains msg if {
	not input.owasp_llm.llm03.downstream_permissions_least_privilege == true
	msg := "OWASP LLM03:2026 (Excessive Agency): downstream permissions are scoped to least privilege per agent identity — no shared super-credentials — not in place"
}

violations contains msg if {
	not input.owasp_llm.llm03.consequential_actions_require_human == true
	msg := "OWASP LLM03:2026 (Excessive Agency): a human-in-the-loop approval gate covers consequential actions (write/delete/payment/send) — not in place"
}

# ── LLM04:2026 — Supply Chain ──
violations contains msg if {
	not input.owasp_llm.llm04.model_artifacts_verified == true
	msg := "OWASP LLM04:2026 (Supply Chain): integrity/signatures of models, datasets and adapters are verified before use and versions are pinned — not in place"
}

violations contains msg if {
	not input.owasp_llm.llm04.aibom_maintained == true
	msg := "OWASP LLM04:2026 (Supply Chain): an AI Bill of Materials covering models, datasets and libraries is maintained — not in place"
}

violations contains msg if {
	not input.owasp_llm.llm04.vetted_sources_only == true
	msg := "OWASP LLM04:2026 (Supply Chain): models and dependencies come only from vetted registries, with serving dependencies vulnerability-scanned — not in place"
}

# ── LLM05:2026 — Data and Model Poisoning ──
violations contains msg if {
	not input.owasp_llm.llm05.training_data_provenance_tracked == true
	msg := "OWASP LLM05:2026 (Data and Model Poisoning): training/fine-tuning data provenance is tracked, validated and sanitized before ingestion — not in place"
}

violations contains msg if {
	not input.owasp_llm.llm05.behavior_shaping_stores_write_restricted == true
	msg := "OWASP LLM05:2026 (Data and Model Poisoning): write access to stores that shape model behavior (training sets, vector DBs, memory) is restricted — not in place"
}

violations contains msg if {
	not input.owasp_llm.llm05.pre_release_behavioral_testing == true
	msg := "OWASP LLM05:2026 (Data and Model Poisoning): models are red-team evaluated / canary-tested for anomalous behavior before release — not in place"
}

# ── LLM06:2026 — Unbounded Consumption ──
violations contains msg if {
	not input.owasp_llm.llm06.rate_limits_enforced == true
	msg := "OWASP LLM06:2026 (Unbounded Consumption): rate limits and quotas are enforced per user/key with input-size and context-length caps — not in place"
}

violations contains msg if {
	not input.owasp_llm.llm06.workflow_resource_metering == true
	msg := "OWASP LLM06:2026 (Unbounded Consumption): cumulative resource use is metered across whole workflows (cascaded model/tool calls) with hard stops — not in place"
}

violations contains msg if {
	not input.owasp_llm.llm06.spend_circuit_breakers == true
	msg := "OWASP LLM06:2026 (Unbounded Consumption): budget alerts and circuit breakers cover inference spend, with timeouts on long generations — not in place"
}

# ── LLM07:2026 — Misinformation ──
violations contains msg if {
	not input.owasp_llm.llm07.high_stakes_outputs_grounded == true
	msg := "OWASP LLM07:2026 (Misinformation): high-stakes outputs are grounded via retrieval with source attribution — not in place"
}

violations contains msg if {
	not input.owasp_llm.llm07.independent_verification_path == true
	msg := "OWASP LLM07:2026 (Misinformation): model output is never validated by the same model; human review covers critical domains — not in place"
}

violations contains msg if {
	not input.owasp_llm.llm07.limitations_communicated == true
	msg := "OWASP LLM07:2026 (Misinformation): model limitations are communicated to users and hallucination rates are monitored in evals — not in place"
}

# ── LLM08:2026 — Hidden Context Exposure ──
violations contains msg if {
	not input.owasp_llm.llm08.no_secrets_in_model_visible_context == true
	msg := "OWASP LLM08:2026 (Hidden Context Exposure): no secrets, credentials or role definitions live in system prompts, tool schemas or other model-visible context — not in place"
}

violations contains msg if {
	not input.owasp_llm.llm08.guardrails_outside_model == true
	msg := "OWASP LLM08:2026 (Hidden Context Exposure): security controls are enforced outside the model — not dependent on hidden instructions staying hidden — not in place"
}

violations contains msg if {
	not input.owasp_llm.llm08.sensitive_config_separated == true
	msg := "OWASP LLM08:2026 (Hidden Context Exposure): sensitive configuration is separated from model context — all model-visible context is treated as extractable — not in place"
}

# ── LLM09:2026 — Vector and Embedding Weaknesses ──
violations contains msg if {
	not input.owasp_llm.llm09.retrieval_authorization_enforced == true
	msg := "OWASP LLM09:2026 (Vector and Embedding Weaknesses): authorization is enforced at retrieval time (per-document ACLs in the vector store) — not in place"
}

violations contains msg if {
	not input.owasp_llm.llm09.vector_stores_tenant_isolated == true
	msg := "OWASP LLM09:2026 (Vector and Embedding Weaknesses): vector databases are partitioned/tenant-isolated with document provenance validated — not in place"
}

violations contains msg if {
	not input.owasp_llm.llm09.embedding_leakage_monitored == true
	msg := "OWASP LLM09:2026 (Vector and Embedding Weaknesses): embedding inversion and cross-tenant leakage are monitored; knowledge-base mutations audited — not in place"
}

# ── LLM10:2026 — Improper Output Handling ──
violations contains msg if {
	not input.owasp_llm.llm10.output_treated_as_untrusted == true
	msg := "OWASP LLM10:2026 (Improper Output Handling): model output is treated as untrusted input with context-appropriate encoding per destination (HTML, SQL, shell) — not in place"
}

violations contains msg if {
	not input.owasp_llm.llm10.deterministic_output_validation == true
	msg := "OWASP LLM10:2026 (Improper Output Handling): deterministic (non-LLM) validation sits between model output and downstream executors — not in place"
}

violations contains msg if {
	not input.owasp_llm.llm10.generated_code_sandboxed == true
	msg := "OWASP LLM10:2026 (Improper Output Handling): model-generated code or queries are parameterized/sandboxed before execution — not in place"
}

# MITRE ATLAS mitigation crosswalk (atlas-data v2026.09) — metadata only.
atlas_crosswalk := {
	"LLM01:2026": {"title": "Prompt Injection", "mitigations": ["AML.M0020", "AML.M0030", "AML.M0029"]},
	"LLM02:2026": {"title": "Sensitive Information Disclosure", "mitigations": ["AML.M0005", "AML.M0019", "AML.M0012"]},
	"LLM03:2026": {"title": "Excessive Agency", "mitigations": ["AML.M0028", "AML.M0026", "AML.M0029"]},
	"LLM04:2026": {"title": "Supply Chain", "mitigations": ["AML.M0014", "AML.M0023", "AML.M0016"]},
	"LLM05:2026": {"title": "Data and Model Poisoning", "mitigations": ["AML.M0025", "AML.M0007", "AML.M0008"]},
	"LLM06:2026": {"title": "Unbounded Consumption", "mitigations": ["AML.M0004"]},
	"LLM07:2026": {"title": "Misinformation", "mitigations": ["AML.M0021"]},
	"LLM08:2026": {"title": "Hidden Context Exposure", "mitigations": ["AML.M0020", "AML.M0033"]},
	"LLM09:2026": {"title": "Vector and Embedding Weaknesses", "mitigations": ["AML.M0019", "AML.M0031"]},
	"LLM10:2026": {"title": "Improper Output Handling", "mitigations": ["AML.M0033"]},
}

compliance_report := {
	"framework": "OWASP Top 10 for LLM Applications",
	"edition": "2026 (released 2026-08-04)",
	"controls_evaluated": 30,
	"atlas_crosswalk": atlas_crosswalk,
	"violations": violations,
	"violation_count": count(violations),
	"compliant": compliant,
}
