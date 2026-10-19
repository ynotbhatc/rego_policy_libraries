package cicd.pipeline_test

import rego.v1

# Regression tests for validation 2026-10-17 fixes.

sha := "0123456789abcdef0123456789abcdef01234567"

good := {"jobs": {"build": {
	"runs-on": "ubuntu-latest",
	"steps": [{"uses": concat("@", ["actions/checkout", sha])}],
}}}

with_job(name, job) := object.union(good, {"jobs": {name: job}})

has_prefix(i, p) if {
	vs := data.cicd.pipeline.violations with input as i
	some v in vs
	startswith(v, p)
}

test_cicd_clean_pipeline_is_compliant if {
	data.cicd.pipeline.compliant with input as good
}

test_cicd_empty_input_is_not_compliant if {
	not data.cicd.pipeline.compliant with input as {}
	has_prefix({}, "Evidence:")
}

test_cicd_empty_jobs_is_not_compliant if {
	not data.cicd.pipeline.compliant with input as {"jobs": {}}
}

test_cicd_sha_annotation_does_not_pin_mutable_tag if {
	i := with_job("build", {"runs-on": "ubuntu-latest", "steps": [{"uses": "actions/checkout@v4", "# sha": "v4.1.1"}]})
	has_prefix(i, "Pinning:")
	not data.cicd.pipeline.compliant with input as i
}

test_cicd_prod_reviewers_found_via_environment_name if {
	i := object.union(with_job("deploy", {"runs-on": "ubuntu-latest", "environment": {"name": "production"}, "steps": []}), {"_metadata": {"environments": [{"name": "production", "reviewers": ["alice"]}]}})
	not has_prefix(i, "Deployment:")
}

test_cicd_prod_reviewers_found_for_string_environment if {
	i := object.union(with_job("deploy", {"runs-on": "ubuntu-latest", "environment": "production", "steps": []}), {"_metadata": {"environments": [{"name": "production", "reviewers": ["alice"]}]}})
	not has_prefix(i, "Deployment:")
}

test_cicd_prod_without_reviewers_still_flagged if {
	i := object.union(with_job("deploy", {"runs-on": "ubuntu-latest", "environment": {"name": "production"}, "steps": []}), {"_metadata": {"environments": [{"name": "production", "reviewers": []}]}})
	has_prefix(i, "Deployment:")
}

test_cicd_self_hosted_string_runs_on_flagged if {
	i := with_job("b2", {"runs-on": "self-hosted", "steps": []})
	has_prefix(i, "Runners:")
}

test_cicd_self_hosted_single_label_list_flagged if {
	i := with_job("b2", {"runs-on": ["self-hosted"], "steps": []})
	has_prefix(i, "Runners:")
}

test_cicd_self_hosted_multi_label_flagged if {
	i := with_job("b2", {"runs-on": ["self-hosted", "linux"], "steps": []})
	has_prefix(i, "Runners:")
}

test_cicd_self_hosted_with_group_not_flagged if {
	i := with_job("b2", {"runs-on": {"group": "prod-runners", "labels": ["self-hosted"]}, "steps": []})
	not has_prefix(i, "Runners:")
}

test_cicd_github_hosted_list_not_flagged if {
	i := with_job("b2", {"runs-on": ["ubuntu-latest"], "steps": []})
	not has_prefix(i, "Runners:")
}

test_cicd_dotenv_substring_does_not_suppress_secret_check if {
	i := with_job("b2", {"runs-on": "ubuntu-latest", "steps": [{"run": "curl -H \"Authorization: ${{ secrets.TOKEN }}\" https://x && cat .env.example"}]})
	has_prefix(i, "Secrets:")
}

test_cicd_untagged_container_image_flagged if {
	i := with_job("b2", {"runs-on": "ubuntu-latest", "container": {"image": "ghcr.io/org/app"}, "steps": []})
	has_prefix(i, "Images:")
}

test_cicd_registry_port_untagged_image_flagged if {
	i := with_job("b2", {"runs-on": "ubuntu-latest", "container": {"image": "localhost:5000/app"}, "steps": []})
	has_prefix(i, "Images:")
}

test_cicd_tagged_and_digest_images_not_flagged if {
	i := with_job("b2", {"runs-on": "ubuntu-latest", "container": {"image": "ghcr.io/org/app:1.2.3"}, "services": {"db": {"image": "quay.io/x/pg@sha256:abc"}}, "steps": []})
	not has_prefix(i, "Images:")
}

test_cicd_untagged_service_image_flagged if {
	i := with_job("b2", {"runs-on": "ubuntu-latest", "services": {"db": {"image": "quay.io/x/pg"}}, "steps": []})
	has_prefix(i, "Images:")
}

test_cicd_report_has_evidence_category if {
	r := data.cicd.pipeline.compliance_report with input as {}
	count(object.get(r.violations_by_category, "evidence", [])) == 1
}

# Theme F (decisions 2026-10-19): an env expression exempts only the secret it wraps.
test_cicd_unrelated_env_expression_does_not_exempt_secret if {
	i := with_job("b2", {"runs-on": "ubuntu-latest", "steps": [{"env": {"REGION": "us-east-1"}, "run": "echo ${{ env.REGION }} && curl -H \"A: ${{ secrets.TOKEN }}\" https://x"}]})
	has_prefix(i, "Secrets:")
}

test_cicd_env_wrapping_same_secret_exempts if {
	i := with_job("b2", {"runs-on": "ubuntu-latest", "steps": [{"env": {"TOKEN": "${{ secrets.TOKEN }}"}, "run": "curl -H \"A: ${{ env.TOKEN }}\" https://x && echo ${{ secrets.TOKEN }}"}]})
	not has_prefix(i, "Secrets:")
}

test_cicd_env_wrapping_other_secret_does_not_exempt if {
	i := with_job("b2", {"runs-on": "ubuntu-latest", "steps": [{"env": {"A": "${{ secrets.OTHER }}"}, "run": "echo ${{ env.A }} ${{ secrets.TOKEN }}"}]})
	has_prefix(i, "Secrets:")
}
