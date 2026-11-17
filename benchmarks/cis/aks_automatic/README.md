# CIS Azure Kubernetes Service Automatic (AKS Automatic) Benchmark v1.0.0

**Version:** v1.0 · generated 2026-11-17 by `tools/cis_generators/gen_aks.py cis_aks_automatic` from the CIS workbook

Every one of the 33 recommendations (12 Automated, 21 Manual). 14 are decided from collected facts, 2 of them Manual in
the workbook because their audit is a configuration comparison. The other 19 need a person's judgement (RBAC reviews,
registry and identity policy, monitoring) and are reported as not attested until `input.attest.<key>` is true. A check
whose facts were not collected reports `<id>: evidence missing — <field> not collected`. It never passes. Messages are our
own wording; no CIS text is reproduced.

Query: `POST /v1/data/cis_aks_automatic/main/compliance_report`

## Profile

`input.cis_profile.level` is `1` or `2` (Level 2 includes Level 1; default `2`). Level 1 holds 25 recommendations, Level 2
adds 8. Recommendations outside the selection raise nothing and are not counted in `total_controls`.

## Facts

Cluster facts are the `az aks show` object under `input.aks.cluster` plus `input.aks.subscription_tenant_id`. Cluster
queries reuse the Kubernetes module's paths (`service_accounts.default`, `secrets.env_var_usage_count`,
`cluster.namespace_resources.default`, `collection_status.<query>`) and add `pod_security.*`,
`service_accounts.unneeded_token_mounts`. There are no node checks: AKS Automatic manages the nodes. The module header lists every path.

## Regenerate

```
/usr/bin/python3 tools/cis_generators/dump_workbook.py <workbook.xlsx> wb.json
/usr/bin/python3 tools/cis_generators/gen_aks.py automatic wb.json benchmarks/cis/aks_automatic
opa fmt -w benchmarks/cis/aks_automatic
```
