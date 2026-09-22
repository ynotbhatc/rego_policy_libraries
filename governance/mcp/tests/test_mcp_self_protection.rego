# Red-team tests: the governance plane protecting itself from the governed
# agents. Every case here is an escalation path that existed (or a regression
# guard proving legitimate work still flows).
package ai_governance.mcp_test

import rego.v1

import data.ai_governance.mcp

# Mock registry: one ordinary AAC template, one governance-plane template,
# and one agent-authored-style name (the create side of create-then-launch
# is closed separately; a REGISTERED name still launches — registration is
# the human review boundary).
_templates := {"seeded": {
	"26": "AAC - NERC CIP Compliance Report",
	"27": "AAC - Load OPA Policies",
	"999": "AAC_Agent_Minted_Automation",
}}

# --- Direct path: governance-plane templates are denied even though they sit
# --- in the legacy ID allowlist (27/28/36/37/40) or carry an AAC name.

test_policy_loader_launch_denied_by_id if {
	r := mcp.response with input as {"tool": "api_job_templates_launch_create", "arguments": {"id": 27}, "agent": "aac-operator"}
	r.allow == false
	r.risk_level == "blocked"
}

test_policy_loader_launch_denied_by_registered_name if {
	r := mcp.response with input as {"tool": "run_job", "arguments": {"template_id": "27"}, "agent": "aac-operator"}
		with data.aac.templates as _templates
	r.allow == false
	r.risk_level == "blocked"
}

test_registry_seed_template_denied if {
	r := mcp.response with input as {"tool": "run_job", "arguments": {"template_id": 37}, "agent": "aac-operator"}
	r.allow == false
}

test_mcp_token_rotation_denied if {
	r := mcp.response with input as {"tool": "run_job", "arguments": {"template_id": 40}, "agent": "aac-operator"}
	r.allow == false
}

test_data_driven_governance_plane_id_denied if {
	r := mcp.response with input as {"tool": "run_job", "arguments": {"template_id": 300}, "agent": "aac-operator"}
		with data.aac.governance_plane_template_ids as ["300"]
	r.allow == false
	r.risk_level == "blocked"
}

# --- Indirect path: the create side of create-then-launch is closed.

test_template_create_denied if {
	r := mcp.response with input as {"tool": "api_job_templates_create", "arguments": {}, "agent": "aac-operator"}
	r.allow == false
	r.risk_level == "blocked"
}

test_workflow_node_create_denied if {
	r := mcp.response with input as {"tool": "api_workflow_job_template_nodes_create", "arguments": {}, "agent": "aac-operator"}
	r.allow == false
}

# --- Regression guards: legitimate agent work still flows.

test_ordinary_allowlisted_launch_still_allowed if {
	r := mcp.response with input as {"tool": "api_job_templates_launch_create", "arguments": {"id": 26}, "agent": "aac-operator"}
	r.allow == true
	r.risk_level == "low"
}

test_registered_aac_name_launch_still_allowed if {
	r := mcp.response with input as {"tool": "run_job", "arguments": {"template_id": "999"}, "agent": "aac-operator"}
		with data.aac.templates as _templates
	r.allow == true
}

test_workflow_launch_of_registered_template_allowed if {
	r := mcp.response with input as {"tool": "api_workflow_job_templates_launch_create", "arguments": {"id": "26"}, "agent": "aac-operator"}
		with data.aac.templates as {"seeded": {"26": "AAC - Nightly Audit"}}
	r.allow == true
}

test_read_only_still_allowed if {
	r := mcp.response with input as {"tool": "api_jobs_list", "arguments": {}, "agent": "aac-operator"}
	r.allow == true
	r.risk_level == "read_only"
}

# --- Agent identity: load-bearing once the registry is published.

test_unregistered_agent_denied_when_registry_present if {
	r := mcp.response with input as {"tool": "api_jobs_list", "arguments": {}, "agent": "rogue-agent"}
		with data.aac.agents as ["aac-operator", "aac-reporter"]
	r.allow == false
	contains(r.reason, "not in the registered agent set")
}

test_registered_agent_allowed_when_registry_present if {
	r := mcp.response with input as {"tool": "api_jobs_list", "arguments": {}, "agent": "aac-operator"}
		with data.aac.agents as ["aac-operator", "aac-reporter"]
	r.allow == true
}

test_identity_not_enforced_when_registry_absent if {
	r := mcp.response with input as {"tool": "api_jobs_list", "arguments": {}, "agent": "anything"}
	r.allow == true
}

# Identity denial never opens a stronger denial: governance-plane launch by an
# unregistered agent is still reported as the plane violation, not identity.
test_plane_denial_wins_over_identity_denial if {
	r := mcp.response with input as {"tool": "run_job", "arguments": {"template_id": 27}, "agent": "rogue-agent"}
		with data.aac.agents as ["aac-operator"]
	r.allow == false
	r.risk_level == "blocked"
}
