# CIS Azure Kubernetes Service (AKS) Benchmark v2.1.0

**Version:** v1.0 · generated 2026-11-17 by `tools/cis_generators/gen_aks.py cis_aks` from the CIS workbook

Every one of the 50 recommendations (25 Automated, 25 Manual). 30 are decided from collected facts, 5 of them Manual in
the workbook because their audit is a configuration comparison. The other 20 need a person's judgement (RBAC reviews,
registry and identity policy, monitoring) and are reported as not attested until `input.attest.<key>` is true. A check
whose facts were not collected reports `<id>: evidence missing — <field> not collected`. It never passes. Messages are our
own wording; no CIS text is reproduced.

Query: `POST /v1/data/cis_aks/main/compliance_report`

## Profile

`input.cis_profile.level` is `1` or `2` (Level 2 includes Level 1; default `2`). Level 1 holds 38 recommendations, Level 2
adds 12. Recommendations outside the selection raise nothing and are not counted in `total_controls`.

## Facts

Cluster facts are the `az aks show` object under `input.aks.cluster` plus `input.aks.subscription_tenant_id`. Cluster
queries reuse the Kubernetes module's paths (`service_accounts.default`, `secrets.env_var_usage_count`,
`cluster.namespace_resources.default`, `collection_status.<query>`) and add `pod_security.*`,
`service_accounts.unneeded_token_mounts`. Node facts (kubelet flags and configuration, `files.kubelet_kubeconfig`, `files.azure_json`) follow the Kubernetes module's contract, collected per node. The module header lists every path.

## Regenerate

```
/usr/bin/python3 tools/cis_generators/dump_workbook.py <workbook.xlsx> wb.json
/usr/bin/python3 tools/cis_generators/gen_aks.py aks wb.json benchmarks/cis/aks
opa fmt -w benchmarks/cis/aks
```
