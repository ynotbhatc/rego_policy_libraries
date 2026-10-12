# Rego → IaC scanners (Conftest, Trivy, KICS, Regula, Snyk IaC)

**Status:** Conftest shipping; Trivy, KICS, Regula, Snyk IaC planned (each needs an adapter, below)
**Kind:** packaging
**Covers:** `enforcement/*` (Terraform plans, Dockerfiles, CI pipelines, Ansible playbooks, Kubernetes manifests,
SLSA provenance) — the gate-shaped policies

## Conftest (shipping)

Conftest runs Rego as-is and recognises `deny`, `violation` and `warn` rules in any package. `build.py` lays the
enforcement policies out under `out/conftest/policy/` and writes `NAMESPACES.md`, the `--namespace` to use per policy:

```
make -C converters/packaging/iac_scanners        # or: python3 build.py
conftest test --policy converters/packaging/iac_scanners/out/conftest/policy \
              --namespace enforcement.terraform.plan  tfplan.json
```

`test/roundtrip.sh` compiles the layout and, where `conftest` is installed, runs it against the Terraform fixture and
compares with `opa eval`.

## Trivy, KICS, Regula, Snyk IaC (planned)

All four execute Rego but each wants its own shape, so each is an adapter generator, not a copy:

- **Trivy** checks must declare `# METADATA` with `custom.id`, `custom.avd_id`, `custom.severity`, `custom.input.selector`
  and return `deny contains res if { … res := result.new(msg, cause) }`. A generator wraps each of our `violation`
  messages in `result.new` and emits the metadata from ours.
- **KICS** queries live one per directory with `metadata.json` and a `CxPolicy[result]` rule returning
  `documentId`, `searchKey`, `issueType`, `keyExpectedValue`, `keyActualValue`.
- **Regula** evaluates `deny[msg]` per resource with `input` as a single resource plus `resource_type`; our plan-level
  policies need splitting per resource.
- **Snyk IaC** custom rules use `deny[msg]` with `msg` as an object (`publicId`, `title`, `severity`, `msg`, `resolve`).

Each follows the same recipe: generator → `out/<scanner>/` → round-trip against `opa eval` on the shared fixtures.
