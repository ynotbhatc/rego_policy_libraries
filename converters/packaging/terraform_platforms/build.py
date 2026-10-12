#!/usr/bin/env python3
"""Rego → Terraform Cloud / Enterprise OPA policy set (also Spacelift and env0).

Terraform Cloud evaluates OPA policies with the plan under `input.plan` and the run
under `input.run`, selected by a `policies.hcl` manifest naming the query per policy.
This writes out/policy-set/ with the library's Terraform gate, an adapter that maps
`input.plan` to the policy's expected input, and the manifest.
"""
from __future__ import annotations
import pathlib, shutil, sys

ROOT = pathlib.Path(__file__).resolve().parents[3]
OUT = pathlib.Path(__file__).resolve().parent / "out" / "policy-set"

ADAPTER = '''package terraform_cloud

import rego.v1

# Terraform Cloud supplies the plan JSON at input.plan; the library gate reads a plan JSON at the root.
# Fail-closed: no plan in the input is itself a violation, and `allowed` defaults to false,
# so a missing or malformed payload never evaluates to "allowed".
default allowed := false

violations := v if {
	is_object(input.plan)
	v := data.enforcement.terraform.plan.violation with input as input.plan
}

violations := {"Terraform Cloud input has no plan object (input.plan) — refusing to evaluate"} if {
	not is_object(object.get(input, "plan", null))
}

allowed if {
	count(violations) == 0
}

main := {"allowed": allowed, "violations": sort(violations)}
'''

MANIFEST = '''policy "aac-terraform-plan-gate" {
  query             = "data.terraform_cloud.allowed"
  enforcement_level = "mandatory"
  description       = "AAC Rego Policy Libraries — enforcement/terraform/terraform_plan_validation.rego via converters/packaging/terraform_platforms"
}
'''


def main():
    if OUT.exists():
        shutil.rmtree(OUT)
    OUT.mkdir(parents=True)
    shutil.copy(ROOT / "enforcement/terraform/terraform_plan_validation.rego", OUT / "terraform_plan_validation.rego")
    (OUT / "adapter.rego").write_text(ADAPTER)
    (OUT / "policies.hcl").write_text(MANIFEST)
    print("policy-set: terraform_plan_validation.rego, adapter.rego, policies.hcl")
    return 0


if __name__ == "__main__":
    sys.exit(main())
