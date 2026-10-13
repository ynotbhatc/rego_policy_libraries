# Rego → WASM modules

**Status:** shipping (build + round-trip test; release upload via `.github/workflows/converters.yml`)
**Kind:** packaging — the policies are compiled, not translated
**Covers:** every `<framework>.main` orchestrator plus `kubernetes.admission` — all 13,775 control-level checks
**How:** `build.py` discovers the entrypoints from the tree and runs `opa build -t wasm` once per OPA class
(`opa-security`, `opa-compliance`, `opa-ot`) and once for everything, writing `out/<class>.tar.gz` and
`out/manifest.json` (entrypoints, sha256, size).

```
make wasm                       # builds into converters/packaging/wasm/out/
make check-converters           # round-trip test (needs an opa with the wasm engine)
```

Each tarball is a standard OPA bundle containing `policy.wasm`, `data.json` and `.manifest`. Load it with any
OPA WASM SDK, no server required. The entrypoint for a framework is `<framework>/main/compliance_report`
(e.g. `mas_trm/main/compliance_report`); the full list is in `manifest.json`.

## Using it from each language

- **JavaScript / TypeScript** — `@open-policy-agent/opa-wasm`: `loadPolicy(wasm)`, `policy.setData(data)`,
  `policy.evaluate(input, "mas_trm/main/compliance_report")`. See `sdk/javascript.md`.
- **Go** — `github.com/open-policy-agent/opa/sdk` or the `rego` package with `rego.Target("wasm")` and the bundle path.
- **Python** — `opa-wasm` (`OPAPolicy("policy.wasm")`, `.set_data(...)`, `.evaluate(input)`).
- **Java** — `io.github.sangkeon:opa-wasm`; **.NET** — `OpaDotNet.Wasm`; **Rust** — `opa-wasm` crate.

Every SDK takes the same three things: the `policy.wasm`, the bundle's `data.json`, and an input document in the
shape the framework's header documents. The output is the same `compliance_report` object OPA returns.

## Round-trip test

`test/roundtrip.sh` evaluates each fixture in `test/fixtures/` with the Rego target and with the WASM target
and compares the violation sets. It skips, loudly, on an OPA binary without the wasm engine (the Homebrew macOS
build and the `_static` Linux build); CI uses `opa_linux_amd64`, which has it.

## What it does not do

Signing (see `../bundles/`) and per-language packages on npm / PyPI (a later step: the wasm inside a package
with the SDK glue, so `npm install @aac/rego-policies` is one line).
