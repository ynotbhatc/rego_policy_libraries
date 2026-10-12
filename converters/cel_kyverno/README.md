# Rego → CEL (ValidatingAdmissionPolicy) and Kyverno

**Status:** planned
**Kind:** generator (hand-written)
**Covers:** ~60
**How:** CEL per Kubernetes policy; mechanical transpile is not safe

Not built yet. When it is: the generator lives here, output goes to `out/` (git-ignored) and to the release,
and `test/` holds the round-trip fixture required by [`../CONTRACT.md`](../CONTRACT.md).
