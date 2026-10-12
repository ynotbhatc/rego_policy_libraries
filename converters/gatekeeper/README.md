# Rego → Gatekeeper ConstraintTemplates

**Status:** planned
**Kind:** packaging
**Covers:** pss, nsa_cisa, enforcement/kubernetes (~60)
**How:** wrap each Kubernetes-input policy in a ConstraintTemplate with a Constraint example

Not built yet. When it is: the generator lives here, output goes to `out/` (git-ignored) and to the release,
and `test/` holds the round-trip fixture required by [`../CONTRACT.md`](../CONTRACT.md).
