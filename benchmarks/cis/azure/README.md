# CIS Microsoft Azure Foundations Benchmark v7.0.0

**Version:** v1.0 · generated 2026-11-14 by `tools/cis_generators/gen_azure.py` from the CIS workbook

All 128 recommendations (73 Level 1, 55 Level 2): the 100 that CIS marks Automated are decided from collected
resource inventories, and the 28 Manual ones are reported as requiring operator attestation
(`input.attest.<key>`, listed in `attestations`). Replaces the v3.0.0 module that stood here.

Query: `POST /v1/data/cis_azure/main/compliance_report`

## Files

| File | Package | Role |
|---|---|---|
| `cis_azure_foundations.rego` | `cis_azure` | engine: recommendation table, input contract, every check |
| `cis_azure_main.rego` | `cis_azure.main` | framework-key report (fail-closed on an input without facts) |
| `l2_validation.rego` | `cis_azure.l2` | Level 2 subset, messages prefixed `CIS L2` |
| `tests/` | | generated: pass / fail / evidence-missing per recommendation, edge cases, report contract |

## Sections

| Section | Recommendations | Attested |
|---|---|---|
| 5 Identity Services | 20 | 11 |
| 6 Logging and Monitoring | 31 | 9 |
| 7 Networking Services | 22 | 2 |
| 8 Security Services | 48 | 6 |
| 9 Storage Services | 7 | 0 |

## Input

One subscription per evaluation. Each service is a list of the resources the collector read from the Azure CLI,
Resource Graph or Microsoft Graph (field names as those tools print them; ARM's nested `properties` object is read
too). The full contract is in the header of `cis_azure_foundations.rego`.

- An empty list means no resources of that kind and passes; an absent list raises
  `<id>: evidence missing — input.<list> not collected`.
- A resource without the property a check reads is a finding for that resource.
- Network rules treat `*`, `Internet`, `Any`, `0.0.0.0/0` and `::/0` as open sources, and read port ranges and
  the `*Ranges` / `*Prefixes` lists.
- `input.cis_profile.level`: `1` evaluates Level 1 only; anything else (the default) evaluates Level 1 and Level 2.
  `total_controls` is the size of the selected profile.

Regenerate: `/usr/bin/python3 tools/cis_generators/gen_azure.py <workbook.xlsx> benchmarks/cis/azure`
