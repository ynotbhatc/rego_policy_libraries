# Rego → WASM modules + language SDK examples

**Status:** planned
**Kind:** packaging
**Covers:** all 7,867
**How:** `opa build -t wasm` per entrypoint; publish per class with Go, JavaScript, Python, Java, .NET and Rust snippets

Not built yet. When it is: the generator lives here, output goes to `out/` (git-ignored) and to the release,
and `test/` holds the round-trip fixture required by [`../CONTRACT.md`](../CONTRACT.md).
