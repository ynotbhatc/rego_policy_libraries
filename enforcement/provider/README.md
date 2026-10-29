# Provider change gate — `provider_change.main`

The OPA decision behind the `aac.tfprovider` `resource` module. Ansible drives a Terraform
provider directly over its plugin protocol; before anything is applied, the module sends the
provider's planned change here and applies it only when this package answers `allow: true`.

There is no Terraform CLI and no plan JSON in this path. The input is the module's own
planned-diff document, defined in aac-tfprovider `docs/CONTRACTS.md` §4.

| | |
|---|---|
| **File** | `enforcement/provider/provider_change.rego` |
| **Package** | `provider_change.main` |
| **Query** | `POST /v1/data/provider_change/main` with `{"input": <document>}` → `result.decision` |
| **OPA container** | opa-compliance (`class: enforcement`) |
| **AAC routing** | `opa_framework_map` key `provider_change: compliance`, loader key `provider_change` (compliance repository) |
| **Policy version** | `policy_version` in the decision, `1.0.0` |

## Input: the planned-diff document

One document per planned change to one resource. The `resource` module builds it from the
provider's `PlanResourceChange` answer; a policy author never writes one by hand except as a
test fixture. The fields this package reads are marked.

```json
{
  "kind": "provider_change",                        // read: must be exactly this
  "version": 1,                                     // read: must be 1
  "environment": "lab",
  "address": "aws_s3_bucket.evidence",              // read: named in every reason
  "resource_type": "aws_s3_bucket",                 // read: selects the rules that apply
  "provider": {"source": "registry.terraform.io/hashicorp/aws", "version": "6.70.0", "protocol": 6},
  "action": "update",                               // read: create | update | replace | delete | no-op
  "requires_replace": ["bucket"],
  "prior_state": {...},                             // read: tags of the resource as it exists (PC-004); null on create
  "planned_state": {...},                           // read: what the provider will apply; null on delete
  "config": {...},                                  // read: stands in for planned values that are still unknown
  "changes": [{"path": "acl", "before": "private", "after": "public-read", "unknown": false}],
  "unknown_paths": ["arn"],
  "sensitive_paths": ["secret"],
  "tainted": false,
  "options": {"force_replace": false, "prevent_destroy": false, "ignore_changes": [], "create_before_destroy": false},
  "context": {"job_id": "1234", "operator": "tim", "playbook": "provider_apply.yml", "task": "evidence bucket"}
}
```

The rules look at the **effective** resource: `planned_state` where the provider already knows
the value, `config` where the planned value is unknown until apply (`null`). `prior_state` is
read only to find out what the resource is today (protected tags).

**Sensitive values.** The module replaces every value at `sensitive_paths` with the string
`"__SENSITIVE__"` in `prior_state`, `planned_state`, `config` and `changes`. This package never
compares a masked value with an expectation and never writes one into a reason: a masked tag
counts as *present* (the value exists, it is only not visible here), a masked `protected` tag on
a replace or delete is a deny (it cannot prove the resource is unprotected), and a masked CIDR
or ACL cannot match a public one. Tests assert that no reason, for any fixture, contains the
marker.

**Unknown values.** `unknown_paths` lists the dotted paths (`acl`, `ingress.0.cidr_blocks`)
whose planned value the provider cannot know until apply. A rule whose governing attribute is
listed there denies with `cannot evaluate: <attribute> unknown at plan time`. A `null` or absent
attribute that is *not* listed is the provider default and is judged as such (no `acl` is
private, no `ingress` is no ingress).

## Output: the decision

```json
{
  "allow": false,
  "reasons": ["PC-001: aws_s3_bucket aws_s3_bucket.evidence grants public access through its ACL (acl=public-read)"],
  "policy_version": "1.0.0",
  "evaluated_rules": 3
}
```

| Field | Meaning |
|---|---|
| `allow` | `default false`; true only when the `deny` set is empty |
| `reasons` | every reason the `deny` rules contributed, sorted, each prefixed with its rule id |
| `policy_version` | the version of this policy that decided |
| `evaluated_rules` | how many catalog rules were in scope for this document's `resource_type` and `action` (PC-000 always is) |

`compliance_report` (`compliant`, `violations`, `violation_count`, `decision`, ...) is exposed as
well, so the library's `compliance_report` convention and the compliance repository's
framework-map validator read this package like any other. `decision` is the contract.

## Fail closed

- `allow` defaults to false. An undefined rule, an evaluation error or an OPA that does not hold
  this package cannot produce `true`; the `resource` module treats an undefined decision, a
  non-200, a timeout or an absent `allow` as a deny with reason `policy evaluation failed: <why>`.
- A document that is not a `provider_change` version 1 with a valid `action` and a non-empty
  `resource_type` is denied by PC-000 with one reason per missing or wrong field. Empty input
  gives four reasons and `allow: false`.
- A flag whose safe value is `true` (the four S3 public-access-block protections) is denied when
  it is absent or unknown, not only when it is `false`.
- A rule whose governing attribute is unknown at plan time (its path is in `unknown_paths`) is
  denied with `PC-00n: <type> <address> cannot evaluate: <attribute> unknown at plan time`. The
  `governing_attributes` table in the package names them per rule and resource type: `acl` and
  `access_control_policy` for PC-001; `ingress`, the rule CIDR fields, `direction` / `access` /
  source prefixes, and the GCP `direction` / `disabled` / `allow` / source fields for PC-003.
  A `null` or absent attribute that is not listed as unknown is the provider default and is
  judged normally.
- A rule that cannot see what it needs never turns a deny into an allow. A masked tag can
  satisfy a presence check (PC-005) but cannot satisfy a value check; a masked `protected` tag
  on a replace or delete is denied with `protected tag is masked; cannot prove the resource is
  unprotected` (PC-004).

## Rules

Each rule is its own `deny contains reason if` statement with a rule-scoped `# METADATA` block
naming it and the resource types it applies to. The `rule_catalog` object in the package is the
single list of rule ids, titles, resource types and actions, and is what `evaluated_rules` counts.

| Id | Resource types | Actions | Denies when |
|---|---|---|---|
| PC-000 | any | any | `kind` is not `provider_change`; `version` is not 1; `action` is not one of create, update, replace, delete, no-op; `resource_type` is missing or empty |
| PC-001 | `aws_s3_bucket`, `aws_s3_bucket_acl` | create, update, replace | `acl` is `public-read`, `public-read-write` or `authenticated-read`; or an `access_control_policy` grant names the AllUsers or AuthenticatedUsers group; or `acl` / `access_control_policy` is unknown at plan time |
| PC-002 | `aws_s3_bucket_public_access_block` | create, update, replace | any of `block_public_acls`, `block_public_policy`, `ignore_public_acls`, `restrict_public_buckets` is false, absent or unknown (one reason per flag) |
| PC-003 | `aws_security_group` (inline `ingress`), `aws_security_group_rule` (`type: ingress`), `aws_vpc_security_group_ingress_rule` (`cidr_ipv4` / `cidr_ipv6`), `azurerm_network_security_rule` (`direction: Inbound`, `access: Allow`, source `*`, `Internet`, `0.0.0.0/0` or `::/0` in `source_address_prefix` or `source_address_prefixes`), `google_compute_firewall` (not EGRESS, not disabled, `allow` is non-empty, and `source_ranges` holds a world CIDR or none of `source_ranges`, `source_tags`, `source_service_accounts` is set, which GCP treats as `0.0.0.0/0`) | create, update, replace | ingress is open to `0.0.0.0/0` or `::/0`; or the governing attribute (`ingress`, the CIDR fields, direction / access / sources) is unknown at plan time |
| PC-004 | any | replace, delete | `prior_state.tags`, `tags_all` or `labels` carries `protected` = `"true"` (case-insensitive key and value, boolean `true` accepted), or carries a masked (`"__SENSITIVE__"`) `protected` value |
| PC-005 | the `taggable_resource_types` set (AWS `tags` / `tags_all`, Azure `tags`, GCP `labels`) | create, update, replace | `owner` or `environment` is absent or empty across `tags`, `tags_all` and `labels` of the effective resource (keys matched case-insensitively; one reason per missing tag) |
| PC-006 | `aws_iam_user_login_profile`, `aws_iam_user` | create | an `aws_iam_user_login_profile` is created, or an `aws_iam_user` is created with a non-empty `login_profile` in its config |

`taggable_resource_types` is data, not logic: extend the set in the package, or override it per
site with `with data.provider_change.main.taggable_resource_types as [...]`; the override may be
a set or an array (a JSON/YAML document is an array), both are normalised. The rule is defined in
the package, so a data document loaded *at that path* conflicts with it; override through `with`
(tests, `opa eval`) or edit the set. `required_tags`, `world_cidrs`, `public_acls`,
`azure_internet_sources` and `governing_attributes` are the same kind of table.

## How AAC routes to it

1. The compliance repository maps the key: `provider_change: compliance` in `opa_framework_map`
   (`ansible/vars/site_config.yml`), with a `provider_change` entry in the OPA loader and the
   framework catalog so the package is loaded into opa-compliance.
2. A playbook sets `framework: provider_change` and includes `ansible/tasks/resolve_opa_url.yml`,
   which sets `opa_server_url` to the compliance OPA service. No playbook holds a literal OPA URL.
3. The `resource` task passes `policy: {mode: enforce, url: "{{ opa_server_url }}"}`. The module
   POSTs the §4 document to `<url>/v1/data/provider_change/main` and reads `result.decision`.
   `mode: audit` records the decision and continues; `mode: off` skips the gate.
4. The decision is stored on the change-log row with the outcome (`applied`, `denied`, ...), so
   the evidence of *why* a change was allowed or stopped lives next to the change.

## Fixtures and tests

`tests/fixtures/<name>/input.json` holds one complete §4 document per case, at least one allow
and one deny per rule. The directory name ends in `_allow` or `_deny`: the decision the gate
must return. Each fixture can be sent to OPA as-is:

```bash
opa eval -d enforcement/provider -i enforcement/provider/tests/fixtures/s3_public_acl_deny/input.json \
  -f pretty 'data.provider_change.main.decision'
```

The tests load the fixtures as OPA data, so run them from the repository root or from the
`enforcement` or `enforcement/provider` tree (the fixture loader knows those three mount points):

```bash
opa check --strict enforcement
opa test enforcement/provider -v
opa test . --ignore .github --ignore converters --timeout 30s    # what CI runs
opa fmt --diff enforcement/provider
make wasm                                                       # CI builds enforcement/ to wasm, tests included
```

The fixture decisions are a partial object rule (`decisions[name]`), not a function: `opa build
-t wasm` cannot plan a function whose body carries `with input as`, and `make wasm` compiles the
test files along with the package.

`test_every_fixture_decides_as_named` evaluates every fixture against its suffix, so a new
fixture is tested the moment it exists; the per-rule tests pin the exact reason text.

## Adding a rule

1. Add a `rule_catalog` row: id, title, `resource_types` (a set or `"*"`), `actions`.
2. Write the `deny contains reason if` rule with its `# METADATA` block; guard it with
   `"PC-00n" in applicable_rules`; start the reason with the id; name `_type` and `_address`;
   read attributes through `_attr` / `_effective` (planned, then config) and never echo a value
   you have not checked with `_visible`. If the rule's decision rests on an attribute the
   provider may not know at plan time, add it to `governing_attributes` so an unknown value
   fails closed.
3. Add an allow and a deny fixture and a test that pins the reason.
4. Bump `policy_version` when a decision can change for an input that already exists.
