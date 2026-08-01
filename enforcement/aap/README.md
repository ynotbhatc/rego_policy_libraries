# AAP job policy — Policy as Code decision set

Rego policies that gate **Ansible Automation Platform job execution**, written against AAP's
published Policy as Code contract so they drop straight into the platform's own enforcement feature.

Every rule returns exactly what AAP expects:

```json
{ "allowed": false, "violations": ["reason 1", "reason 2"] }
```

Package: `aac.aap.policy` — one rule per decision, so each can be associated independently with an
organization, an inventory, or a job template.

## Why this exists

Red Hat ships the *enforcement mechanism* and a handful of example policies. It ships **no policy
library**. This is the library — the same relationship AAC has to compliance frameworks, applied to
automation governance.

## The decision set

| Query path | Blocks on |
|---|---|
| `/v1/data/aac/aap/policy/maintenance_window` | Time of day, day of week, dated change freezes |
| `/v1/data/aac/aap/policy/maintenance_mode` | A named freeze on specific inventories or platform-wide |
| `/v1/data/aac/aap/policy/owner_scope` | Which users/teams may target which inventories; inventory-to-org coherence |
| `/v1/data/aac/aap/policy/superuser_restriction` | Superuser launches (use an attributable service account) |
| `/v1/data/aac/aap/policy/credential_scope` | Global credentials; credential/inventory environment mismatch |
| `/v1/data/aac/aap/policy/required_labels` | Required, forbidden, one-of, and `key:value`-format labels |
| `/v1/data/aac/aap/policy/extra_vars_control` | Disallowed keys, secret-shaped keys, malformed values |
| `/v1/data/aac/aap/policy/team_extra_vars` | Which teams may set which variables |
| `/v1/data/aac/aap/policy/naming_standard` | Job-template naming convention, length, forbidden terms |
| `/v1/data/aac/aap/policy/source_control` | Approved repo and branch; SSH URLs; detached-HEAD execution |
| `/v1/data/aac/aap/policy/deny_all` | Everything — the incident switch |

## Coverage against Red Hat's published examples

All twelve are covered:

| Red Hat example | Covered by |
|---|---|
| `maintenance_window` | `maintenance_window` |
| `restrict_inv_use_to_org` | `owner_scope` |
| `superuser_allowed_false` | `superuser_restriction` |
| `global_credential_allowed_false` | `credential_scope` |
| `mismatch_prefix_allowed_false` | `credential_scope` |
| `extra_vars_allowlist` | `extra_vars_control` |
| `extra_vars_validation` | `extra_vars_control` |
| `team_based_extra_vars_restriction` | `team_extra_vars` |
| `jt_naming_validation` | `naming_standard` |
| `github_repo_validation` | `source_control` |
| `project_scm_branch` | `source_control` |
| `allowed_false` | `deny_all` |

`maintenance_mode` and `required_labels` have no Red Hat equivalent.

## Configuration

Policies ship with safe defaults and are tuned entirely through data — no policy edits. Load
`data/aap_policy_config.example.json` (or your own) alongside the policies:

```bash
opa run --server \
  enforcement/aap/ \
  enforcement/aap/data/aap_policy_config.example.json
```

Every block under `data.aac.aap.config.*` is optional; anything absent falls back to the defaults
declared in the policy.

### Defaults are permissive by design

An unconfigured deployment allows automation. Bindings, allowlists, and freezes only take effect
once you supply them — so loading these policies cannot accidentally halt a platform. The two
exceptions are deliberate and safe: superuser launches are denied by default, and secret-shaped
`extra_vars` keys (`password`, `token`, `api_key`, …) are rejected by default.

## Evaluation time

Time-based rules prefer `input.created` — the job's own timestamp — so a decision is reproducible
when replayed during an audit. They fall back to wall-clock time only when `created` is absent.

## Break glass

`maintenance_window`, `maintenance_mode`, and `deny_all` each honour a bypass label
(`break-glass`, `incident-response`). Bypassing is not silent: the label is part of the job record,
so the override is itself evidence.

## Testing

```bash
opa test enforcement/aap/ -v
```

47 tests cover allow and deny paths for every decision, plus a contract test asserting all eleven
return `{allowed: bool, violations: []}`.

## Input contract

Consumes AAP's job-context input: `id`, `name`, `created`, `created_by` (`username`,
`is_superuser`, `teams`), `credentials[]`, `execution_environment`, `extra_vars`, `inventory`,
`job_template`, `labels[]`, `project`, and the rest of the documented payload. Fields absent from a
given deployment degrade gracefully — a rule that cannot see its subject does not fire.

`extra_vars` is accepted as either an object or a JSON string.
