package cicd.pipeline

# CI/CD Pipeline Security Governance
#
# Validates CI/CD pipeline configurations for security best practices.
# Supports: GitHub Actions, GitLab CI, Jenkins, generic pipeline metadata.
#
# Key controls:
#   - Action/step version pinning to full commit SHA
#   - No plaintext secrets in environment variables
#   - Workflow permissions minimized (no write-all)
#   - OIDC credential federation (no long-lived cloud tokens)
#   - Required approvals for production deployments
#   - No curl|bash or wget|sh patterns
#   - Container images pinned to digest in prod
#   - Self-hosted runner governance
#
# OPA endpoint: POST http://localhost:8181/v1/data/cicd/pipeline
# Input: parsed pipeline configuration (GitHub Actions workflow JSON or equivalent)

import rego.v1

default compliant := false

compliant if { count(violations) == 0 }

# =============================================================================
# GITHUB ACTIONS — ACTION VERSION PINNING
# =============================================================================

# Actions must be pinned to a full 40-character commit SHA, not a branch or
# mutable tag. A compromised action tag can inject malicious code.

violations contains sprintf("Pinning: Action '%s' in job '%s' uses mutable ref '%s' — pin to full SHA (e.g. uses: %s@<sha>)", [step.uses, job_name, ref, split(step.uses, "@")[0]]) if {
	some job_name, job in input.jobs
	some step in job.steps
	step.uses
	ref := split(step.uses, "@")[1]
	not is_full_sha(ref)
	not is_sha_prefix_comment(step)
}

is_full_sha(ref) if {
	count(ref) == 40
	regex.match(`^[0-9a-f]{40}$`, ref)
}

is_sha_prefix_comment(step) if {
	step["# sha"] != ""
}

# =============================================================================
# GITHUB ACTIONS — WORKFLOW PERMISSIONS
# =============================================================================

violations contains "Permissions: Workflow uses 'permissions: write-all' — minimize to least privilege" if {
	input.permissions == "write-all"
}

violations contains "Permissions: Workflow grants 'contents: write' at workflow level — restrict to job level" if {
	input.permissions.contents == "write"
}

violations contains "Permissions: Workflow grants 'packages: write' without attestation workflow justification" if {
	input.permissions.packages == "write"
	not input._metadata.is_attestation_workflow
}

violations contains sprintf("Permissions: Job '%s' does not define explicit permissions (inherits workflow-level — should be explicit)", [job_name]) if {
	input.permissions
	some job_name, job in input.jobs
	not job.permissions
	not input._metadata.permissions_set_at_workflow_level_intentionally
}

# =============================================================================
# SECRETS AND CREDENTIAL HYGIENE
# =============================================================================

# Detect patterns that look like hardcoded secrets or tokens
secret_patterns := [
	`[A-Za-z0-9+/]{40,}={0,2}`,
	`ghp_[A-Za-z0-9]{36}`,
	`ghs_[A-Za-z0-9]{36}`,
	`AKIA[0-9A-Z]{16}`,
	`-----BEGIN (RSA|EC|OPENSSH) PRIVATE KEY-----`,
	`[0-9a-f]{32}:[0-9a-f]{32}`,
]

violations contains sprintf("Secrets: Potential hardcoded secret found in job '%s' step '%s' env var '%s'", [job_name, step_name, env_key]) if {
	some job_name, job in input.jobs
	some step in job.steps
	step_name := object.get(step, "name", "unnamed")
	some env_key, env_val in object.get(step, "env", {})
	not startswith(env_val, "${{")
	some pattern in secret_patterns
	regex.match(pattern, env_val)
}

violations contains sprintf("Secrets: Job '%s' passes secret '%s' as a positional argument — use env var instead", [job_name, secret_ref]) if {
	some job_name, job in input.jobs
	some step in job.steps
	step["run"]
	secret_ref := regex.find_all_string_submatch_n(`\$\{\{\s*secrets\.[A-Za-z0-9_]+\s*\}\}`, step["run"], -1)[_][0]
	contains(step["run"], secret_ref)
	not is_safe_secret_usage(step["run"], secret_ref)
}

is_safe_secret_usage(run_script, _secret_ref) if {
	contains(run_script, "env.")
}

# =============================================================================
# SHELL INJECTION AND DANGEROUS PATTERNS
# =============================================================================

violations contains sprintf("Injection: Job '%s' step '%s' uses curl|bash/wget|sh pattern — download and verify before executing", [job_name, step_name]) if {
	some job_name, job in input.jobs
	some step in job.steps
	step_name := object.get(step, "name", "unnamed")
	step["run"]
	dangerous_pipe_pattern(step["run"])
}

dangerous_pipe_pattern(script) if { regex.match(`curl\s+.*\|\s*(ba)?sh`, script) }
dangerous_pipe_pattern(script) if { regex.match(`wget\s+.*\|\s*(ba)?sh`, script) }
dangerous_pipe_pattern(script) if { regex.match(`curl\s+.*\|\s*python`, script) }
dangerous_pipe_pattern(script) if { regex.match(`curl\s+.*\|\s*ruby`, script) }

violations contains sprintf("Injection: Job '%s' step '%s' interpolates GitHub context expression into shell run — use env var to avoid script injection", [job_name, step_name]) if {
	some job_name, job in input.jobs
	some step in job.steps
	step_name := object.get(step, "name", "unnamed")
	step["run"]
	regex.match(`\$\{\{\s*(github\.(event|head_ref|base_ref)|inputs\.)`, step["run"])
}

# =============================================================================
# CLOUD CREDENTIAL FEDERATION (OIDC)
# =============================================================================

violations contains sprintf("Credentials: Job '%s' uses long-lived AWS access key — migrate to OIDC federation (aws-actions/configure-aws-credentials with role-to-assume)", [job_name]) if {
	some job_name, job in input.jobs
	some step in job.steps
	step.uses
	startswith(step.uses, "aws-actions/configure-aws-credentials")
	step["with"]["aws-access-key-id"]
}

violations contains sprintf("Credentials: Job '%s' uses long-lived GCP service account key JSON — migrate to Workload Identity Federation", [job_name]) if {
	some job_name, job in input.jobs
	some step in job.steps
	step.uses
	startswith(step.uses, "google-github-actions/auth")
	step["with"]["credentials_json"]
}

violations contains sprintf("Credentials: Job '%s' uses long-lived Azure service principal secret — migrate to federated identity credentials", [job_name]) if {
	some job_name, job in input.jobs
	some step in job.steps
	step.uses
	startswith(step.uses, "azure/login")
	step["with"]["client-secret"]
}

# =============================================================================
# PRODUCTION DEPLOYMENT GATES
# =============================================================================

violations contains sprintf("Deployment: Job '%s' deploys to production environment without required reviewer approval (environment.reviewers must be configured)", [job_name]) if {
	some job_name, job in input.jobs
	is_production_deployment(job)
	not job.environment
}

violations contains sprintf("Deployment: Job '%s' targets production environment but no required reviewers configured", [job_name]) if {
	some job_name, job in input.jobs
	is_production_deployment(job)
	job.environment
	not job.environment.url
	not has_required_reviewers(job_name)
}

is_production_deployment(job) if {
	env_name := lower(object.get(job, ["environment", "name"], object.get(job, "environment", "")))
	env_name in {"production", "prod", "prd"}
}

is_production_deployment(job) if {
	some step in job.steps
	step["with"]["environment"]
	lower(step["with"]["environment"]) in {"production", "prod"}
}

has_required_reviewers(job_name) if {
	some env in input._metadata.environments
	env.name == job_name
	count(env.reviewers) > 0
}

# =============================================================================
# SELF-HOSTED RUNNER GOVERNANCE
# =============================================================================

violations contains sprintf("Runners: Job '%s' uses self-hosted runner without runner group restriction — specify runs-on with a named group", [job_name]) if {
	some job_name, job in input.jobs
	some label in job["runs-on"]
	label == "self-hosted"
	count(job["runs-on"]) == 1
}

violations contains sprintf("Runners: Job '%s' uses self-hosted runner for PR from fork — potential privilege escalation (restrict to github-hosted or require approval)", [job_name]) if {
	some job_name, job in input.jobs
	some label in job["runs-on"]
	label == "self-hosted"
	input._metadata.trigger == "pull_request"
	input._metadata.is_fork_pr
}

# =============================================================================
# CONTAINER IMAGE PINNING
# =============================================================================

violations contains sprintf("Images: Job '%s' container '%s' uses 'latest' tag — pin to digest for reproducibility", [job_name, container_name]) if {
	some job_name, job in input.jobs
	container_name := object.get(job, ["container", "image"], "")
	container_name != ""
	endswith(container_name, ":latest")
}

violations contains sprintf("Images: Job '%s' service '%s' uses 'latest' tag — pin to digest", [job_name, svc_name]) if {
	some job_name, job in input.jobs
	some svc_name, svc in object.get(job, "services", {})
	endswith(svc.image, ":latest")
}

violations contains sprintf("Images: Job '%s' container image '%s' is from unapproved registry", [job_name, image]) if {
	input._metadata.environment == "production"
	some job_name, job in input.jobs
	image := object.get(job, ["container", "image"], "")
	image != ""
	not approved_registry(image)
}

approved_registry(image) if { startswith(image, "ghcr.io/") }
approved_registry(image) if { startswith(image, "quay.io/") }
approved_registry(image) if { startswith(image, "registry.access.redhat.com/") }
approved_registry(image) if { startswith(image, "registry.redhat.io/") }
approved_registry(image) if { regex.match(`^[0-9]+\.dkr\.ecr\.[a-z0-9-]+\.amazonaws\.com/`, image) }

# =============================================================================
# DEPENDENCY REVIEW (PIPELINE-LEVEL)
# =============================================================================

violations contains "Dependencies: No dependency-review or SBOM generation step found in CI workflow" if {
	input._metadata.has_dependency_changes
	not has_dependency_review_step
}

has_dependency_review_step if {
	some _job_name, job in input.jobs
	some step in job.steps
	step.uses
	startswith(step.uses, "actions/dependency-review-action")
}

has_dependency_review_step if {
	some _job_name, job in input.jobs
	some step in job.steps
	step.uses
	startswith(step.uses, "anchore/sbom-action")
}

has_dependency_review_step if {
	some _job_name, job in input.jobs
	some step in job.steps
	step.uses
	startswith(step.uses, "CycloneDX/gh-cyclonedx-action")
}

# =============================================================================
# COMPLIANCE REPORT
# =============================================================================

violations_by_category := {
	"pinning":      [v | some v in violations; contains(v, "Pinning:")],
	"permissions":  [v | some v in violations; contains(v, "Permissions:")],
	"secrets":      [v | some v in violations; contains(v, "Secrets:")],
	"injection":    [v | some v in violations; contains(v, "Injection:")],
	"credentials":  [v | some v in violations; contains(v, "Credentials:")],
	"deployment":   [v | some v in violations; contains(v, "Deployment:")],
	"runners":      [v | some v in violations; contains(v, "Runners:")],
	"images":       [v | some v in violations; contains(v, "Images:")],
	"dependencies": [v | some v in violations; contains(v, "Dependencies:")],
}

compliance_report := {
	"framework":           "CI/CD Pipeline Security Governance",
	"standard":            "cicd.pipeline",
	"compliant":           compliant,
	"violation_count":     count(violations),
	"violations":          [v | some v in violations],
	"violations_by_category": violations_by_category,
	"pipeline_type":       object.get(input, ["_metadata", "pipeline_type"], "github_actions"),
}
