package ai_governance.mcp

import rego.v1

# =============================================================================
# MCP Governance Policy
# Controls what Claude Code (AI agent) can do via the AAP MCP server.
#
# Input shape:
#   input.tool       - MCP tool name (e.g. "run_job", "delete_host")
#   input.arguments  - Tool arguments (e.g. {"template_id": 33})
#   input.agent      - Caller identity (e.g. "claude-code")
#
# Decision shape:
#   allow            - bool
#   decision         - "ALLOW" | "DENY"
#   risk_level       - "read_only" | "low" | "medium" | "high" | "blocked"
#   reason           - human-readable explanation
# =============================================================================

# ---------------------------------------------------------------------------
# Tool categories
# ---------------------------------------------------------------------------

read_only_tools := {
	"list_inventories", "get_inventory", "list_hosts", "get_host",
	"list_job_templates", "get_job_template", "list_jobs", "job_status",
	"job_logs", "list_projects", "get_project", "list_groups",
	"list_credentials", "get_credential", "list_users", "get_user",
	"list_organizations", "api_ping_list", "api_me_list",
	"api_dashboard_list", "api_jobs_read", "api_jobs_list",
	"api_jobs_stdout_read", "api_jobs_job_events_list",
	"api_job_templates_read", "api_job_templates_list",
	"api_job_templates_launch_read",
	"api_inventories_read", "api_inventories_list",
	"api_hosts_read", "api_hosts_list",
	"api_projects_read", "api_projects_list",
	"api_projects_update_read",
	"api_credentials_read", "api_credentials_list",
	"api_organizations_read", "api_organizations_list",
	"api_users_read", "api_users_list",
	"api_workflow_job_templates_read", "api_workflow_job_templates_list",
	"api_workflow_job_templates_launch_read",
	"api_workflow_jobs_read", "api_workflow_jobs_list",
	"api_workflow_jobs_workflow_nodes_list",
	"api_workflow_job_nodes_read", "api_workflow_job_nodes_list",
	"api_workflow_job_template_nodes_read", "api_workflow_job_template_nodes_list",
	"api_execution_environments_read", "api_execution_environments_list",
	"api_schedules_read", "api_schedules_list",
	"api_unified_job_templates_list", "api_unified_jobs_list",
	"api_job_templates_survey_spec_list",
}

# ---------------------------------------------------------------------------
# Option 1 — Name-based registry (survives ID reassignment across reinstalls)
# Seed playbooks push {str(id): name} to OPA after template creation:
#   PUT http://<opa-compliance>:8182/v1/data/aac/templates/<group>
# Any registered template whose name starts with "AAC_" is automatically approved.
# ---------------------------------------------------------------------------

# Flatten all registered template groups into a single id → name lookup
_registered_name(tid) := name if {
	some _group, templates in data.aac.templates
	some id_str, name in templates
	tid == to_number(id_str)
}

_has_registered_name(tid) if _registered_name(tid)

# ---------------------------------------------------------------------------
# Option 2 — ID allowlist (legacy fallback for templates not yet synced to OPA)
# ---------------------------------------------------------------------------

# Job templates explicitly approved for AI launch
approved_template_ids := {
	10, 11, 12, 13, # CIS assessments (RHEL 9/8, Ubuntu, Windows)
	15, 16, 17, # Fact collection
	23, 24, # PostgreSQL init, trending report
	25, 26, # OPA policy report, NERC-CIP report
	27, 28, # Load OPA policies, deploy OPA containers
	29, # AMI full compliance audit
	30, 31, # Deploy smart meter containers, Grafana dashboard
	32, 33, 34, 35, # Sentinel: TF validate, Ansible validate, runtime block, audit sweep
	36, 37, # Sentinel: AI controls, seed templates
	38, 39, # Sentinel preflight, demo stability setup
	40, # AAC - Rotate MCP Token
	41, 42, 43, # AMI: NIST, device, head-end
	45, 46, 47, 48, # Build compliance EE, Sentinel TF bad/good, Ansible good
	53, 57, # DS: seed workflow, assessment
	101, # NERC/AMI - Generate Audit PDF
	106, # DS - Generate Audit PDF
	107, 108, 109, 110, # Network devices: VyOS/OPNsense deploy, CIS VyOS/pfSense
	111, 112, 113, 114, # Seed workflows: CIS/Nightly/NERC-AMI, PostgreSQL init
	115, # IEC 62443 Assessment
	116, # CIP-010 Baseline Capture/Check
	117, # CIP-008 Incident Response Evidence
	102, 103, 104, 105, # Sentinel: runtime block, audit sweep, AI governance, preflight
	121, # AAC - Seed Golden Image Workflow
	122, 123, 124, # Golden Image: Check, Rollback, Notify Help Desk
	125, # AAC - Golden Image Enforcement (workflow)
	126, # AAC - Demo: Introduce Drift
	160, 165, # Golden Image: Reset Demo, Manage RHPDS Demo Host
	166, 167, # CAF 4.0: Fact Collection, Assessment and Store
}

# ---------------------------------------------------------------------------
# Self-protection: the governance plane is a crown jewel.
#
# A governed agent must not be able to modify, reload, or dilute its own gate.
# Two escalation paths existed before this section:
#   1. Direct — the legacy ID allowlist approved the templates that reload OPA
#      policy (27), recreate the OPA containers (28), seed/mutate the template
#      registry OPA decides from (36, 37), and rotate the MCP token (40).
#   2. Indirect — scaffold ops let the agent CREATE a template; any registered
#      name starting "AAC" was then auto-approved for launch (create-then-launch).
# Both are closed here: governance-plane templates classify as "blocked" and
# override every allow path; template/workflow creation is no longer agent work.
# Governance-plane changes are human work, through PR review and the console.
# ---------------------------------------------------------------------------

# Legacy IDs of governance-plane templates (same caveat as the allowlist: IDs
# drift across reinstalls — the name fragments below are the durable match).
governance_plane_template_ids := {27, 28, 36, 37, 40}

_governance_plane_name_fragments := {"load opa", "deploy opa", "seed template", "rotate mcp"}

_is_governance_plane(tid) if tid in governance_plane_template_ids

_is_governance_plane(tid) if {
	name := _registered_name(tid)
	some frag in _governance_plane_name_fragments
	contains(lower(name), frag)
}

# Data-driven additions without a policy change (same push path as the registry)
_is_governance_plane(tid) if {
	some id in data.aac.governance_plane_template_ids
	tid == to_number(id)
}

_launch_tools := {"run_job", "api_job_templates_launch_create", "api_workflow_job_templates_launch_create"}

# Scaffold/creation ops — formerly "medium: allowed with logging". Creating a
# template or workflow node is authoring automation, and combined with the
# AAC-name auto-approval it was a self-elevation chain. Agents run reviewed
# automation; they do not author it.
governance_scaffold_tools := {
	"api_job_templates_create",
	"api_job_templates_credentials_create",
	"api_job_templates_survey_spec_create",
	"api_workflow_job_templates_create",
	"api_workflow_job_template_nodes_create",
	"api_workflow_job_template_nodes_success_nodes_create",
	"api_workflow_job_template_nodes_failure_nodes_create",
	"api_workflow_job_template_nodes_always_nodes_create",
}

# ---------------------------------------------------------------------------
# Agent identity — load-bearing when the registry is published.
# Push the registry the same way as the template registry:
#   PUT /v1/data/aac/agents   e.g. ["aac-operator-agent", "aac-reporting-agent"]
# Registry present  → only listed identities may act (fail-closed per identity).
# Registry absent   → identity not yet enforced (transition state, so existing
#                     deployments keep working until the ops push lands).
# ---------------------------------------------------------------------------

default agent_authorized := false

agent_authorized if {
	some a in data.aac.agents
	a == input.agent
}

agent_authorized if not data.aac.agents

# Tools that are always blocked regardless of context
blocked_tools := {
	# Destructive operations
	"api_hosts_delete", "api_inventories_delete",
	"api_job_templates_delete", "api_projects_delete",
	"api_credentials_delete", "api_users_delete",
	"api_organizations_delete", "api_teams_delete",
	"api_jobs_delete",
	# Credential management
	"api_credentials_create", "api_credentials_update",
	"api_credentials_partial_update",
	# User/org admin
	"api_users_create", "api_users_update",
	"api_organizations_create", "api_organizations_update",
	# System settings
	"api_settings_update", "api_settings_partial_update",
	"api_settings_delete", "api_config_create", "api_config_delete",
	# Job cancellation (read-only AI shouldn't stop running jobs)
	"api_jobs_cancel_create",
}

# ---------------------------------------------------------------------------
# Risk classification
# ---------------------------------------------------------------------------

default risk_level := "high"

risk_level := "read_only" if input.tool in read_only_tools

risk_level := "blocked" if input.tool in blocked_tools

# Match "AAC" rather than "AAC_": the estate uses BOTH conventions and the
# underscore-only form missed two thirds of them. On the reference controller,
# 98 templates are named "AAC - <thing>" and 50 "AAC_<thing>" — the space-dash
# form includes the whole NERC-CIP demo set (Collate, Capture Baseline, Check
# Drift), so launching them fell through to the default-deny and the agent could
# not do ordinary work.
# Governance-plane self-protection overrides every launch-allow path below
risk_level := "blocked" if {
	input.tool in _launch_tools
	_is_governance_plane(_template_id)
}

# Scaffold/creation ops: blocked (see governance_scaffold_tools rationale)
risk_level := "blocked" if input.tool in governance_scaffold_tools

risk_level := "low" if {
	input.tool in _launch_tools
	name := _registered_name(_template_id)
	startswith(name, "AAC")
	not _is_governance_plane(_template_id)
}

risk_level := "low" if {
	input.tool in _launch_tools
	template_id := _template_id
	template_id in approved_template_ids
	not _is_governance_plane(template_id)
}

risk_level := "medium" if {
	input.tool in {"sync_project", "api_projects_update_create"}
}

# ---------------------------------------------------------------------------
# Allow/deny decision
# ---------------------------------------------------------------------------

default allow := false

allow if {
	risk_level == "read_only"
	agent_authorized
}

allow if {
	risk_level == "low"
	agent_authorized
}

allow if {
	risk_level == "medium"
	agent_authorized
}

# Blocked and high/unknown risk → deny; unregistered agent → deny at any risk

# ---------------------------------------------------------------------------
# Decision output
# ---------------------------------------------------------------------------

decision := "ALLOW" if allow
decision := "DENY" if not allow

# `response` is an object literal: if any field is undefined the WHOLE object is
# undefined and OPA returns {} to the MCP server. A default guarantees `reason`
# always resolves, so a missed rule degrades to a vague message instead of
# silently voiding the decision. This bit us when risk_level was broadened to
# "AAC" but this rule still required "AAC_".
default reason := "No specific rule matched — see risk_level for the decision basis"

reason := "Read-only operation — allowed" if {
	allow
	risk_level == "read_only"
}

reason := msg if {
	allow
	risk_level == "low"
	tid := _template_id
	name := _registered_name(tid)
	startswith(name, "AAC")
	msg := sprintf("Job launch approved — '%v' (id: %v) is a registered AAC template", [name, tid])
}

reason := msg if {
	allow
	risk_level == "low"
	tid := _template_id
	not _has_registered_name(tid)
	msg := sprintf("Job launch approved — template %v is in the legacy ID allowlist", [tid])
}

reason := "Project sync — allowed with logging" if {
	allow
	risk_level == "medium"
	input.tool in {"sync_project", "api_projects_update_create"}
}

reason := msg if {
	not allow
	risk_level == "blocked"
	input.tool in blocked_tools
	msg := sprintf("Tool '%v' is blocked — destructive or privileged operations are not permitted for AI agents", [input.tool])
}

reason := msg if {
	not allow
	risk_level == "blocked"
	input.tool in governance_scaffold_tools
	msg := sprintf("Tool '%v' is blocked — agents run reviewed automation, they do not author it (create-then-launch self-elevation is closed)", [input.tool])
}

reason := msg if {
	not allow
	risk_level == "blocked"
	input.tool in _launch_tools
	tid := _template_id
	_is_governance_plane(tid)
	msg := sprintf("Template %v mutates the governance plane (policy load / OPA deploy / registry seed / token rotation) — agents cannot modify their own gate; this change is human work", [tid])
}

reason := msg if {
	not allow
	not agent_authorized
	risk_level in {"read_only", "low", "medium"}
	msg := sprintf("Agent identity '%v' is not in the registered agent set (data/aac/agents) — denied", [object.get(input, ["agent"], "")])
}

reason := msg if {
	not allow
	agent_authorized
	risk_level == "low"
	tid := _template_id
	not tid in approved_template_ids
	msg := sprintf("Job launch denied — template %v is not in the compliance assessment allowlist", [tid])
}

reason := msg if {
	not allow
	risk_level == "high"
	msg := sprintf("Tool '%v' has no explicit approval rule — defaulting to DENY (unknown risk)", [object.get(input, ["tool"], "unknown")])
}

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

# Coerce to number — MCP passes path params as strings (e.g. "26"), but
# approved_template_ids contains integers; to_number handles both cases.
_template_id := v if v := to_number(input.arguments.template_id)
_template_id := v if v := to_number(input.arguments.id)

# ---------------------------------------------------------------------------
# Full response object (queried by MCP server)
# ---------------------------------------------------------------------------

response := {
	"allow": allow,
	"decision": decision,
	"risk_level": risk_level,
	"reason": reason,
	"tool": object.get(input, ["tool"], ""),
	"agent": object.get(input, ["agent"], ""),
}
