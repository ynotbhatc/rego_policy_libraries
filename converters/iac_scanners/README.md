# Rego → Conftest / Trivy / KICS / Regula / Snyk module layout

**Status:** planned
**Kind:** packaging
**Covers:** enforcement/*, cis cloud (~200)
**How:** directory and metadata conventions, avd ids for Trivy, conftest pull layout

Not built yet. When it is: the generator lives here, output goes to `out/` (git-ignored) and to the release,
and `test/` holds the round-trip fixture required by [`../CONTRACT.md`](../CONTRACT.md).
