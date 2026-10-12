# Rego → Terraform Cloud / Enterprise, Spacelift, env0 policy set

**Status:** shipping (generator, round-trip test)
**Kind:** packaging — an adapter maps the platform's `input.plan` to the library gate's root input, plus the
`policies.hcl` manifest Terraform Cloud reads
**Covers:** `enforcement/terraform/terraform_plan_validation.rego` (17 checks)

```
python3 converters/packaging/terraform_platforms/build.py   # -> out/policy-set/{adapter.rego, terraform_plan_validation.rego, policies.hcl}
```

Point a Terraform Cloud OPA policy set at `out/policy-set/` (or commit it to the VCS repo the policy set tracks).
Spacelift and env0 take the same two Rego files with their own manifest conventions. `test/roundtrip.sh` evaluates the
adapter on `{"plan": P}` and the gate on `P` and compares violations.
