# Rego → OPA bundles (signed, per class, on GHCR and on the release)

**Status:** shipping (unsigned, since 2026-10) — `.github/workflows/publish-ghcr.yml` builds one bundle with explicit
roots (`scripts/gen_bundle_manifest.py`) on every push to `main` and every `v*` tag and pushes it to
`ghcr.io/ynotbhatc/rego_policy_libraries:<tag>` with `oras`. `opa run -s ghcr.io/ynotbhatc/rego_policy_libraries:v2.2.0`
style consumption works today for OPA, Enterprise OPA and Styra DAS.
**Kind:** packaging
**Covers:** all

## What remains for `shipping (signed)`

1. A signing keypair held as a repository secret (`BUNDLE_SIGNING_KEY`), `opa build --signing-key` in the workflow,
   and the public key published in this directory so consumers verify with `opa run --verification-key`.
2. Per-class bundles (`opa-security`, `opa-compliance`, `opa-ot`) beside the all-in-one, matching the three
   containers AAC deploys.
3. The same tarballs attached to the GitHub release as assets, which is what `converters.yml` does for the wasm
   output and will do here once signing exists.
