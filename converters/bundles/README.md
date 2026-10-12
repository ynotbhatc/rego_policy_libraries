# Rego → Signed OPA bundles per class

**Status:** planned
**Kind:** packaging
**Covers:** all
**How:** extend `scripts/gen_bundle_manifest.py`: build, sign, publish to the GitHub release and an OCI registry

Not built yet. When it is: the generator lives here, output goes to `out/` (git-ignored) and to the release,
and `test/` holds the round-trip fixture required by [`../CONTRACT.md`](../CONTRACT.md).
