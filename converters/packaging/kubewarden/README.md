# Rego → Kubewarden policies

**Status:** shipping (generator, round-trip test); registry publish and Artifact Hub listing need `kwctl push` from CI
**Kind:** packaging — OPA wasm with a `policy/main` entrypoint that answers an AdmissionReview
**Covers:** `k8s-pss-baseline`, `k8s-pss-restricted` (Pod Security Standards) and `k8s-aac-admission`

```
python3 converters/packaging/kubewarden/build.py     # -> out/<policy>/{policy.wasm, metadata.yml, adapter.rego}
kwctl annotate -m out/k8s-pss-restricted/metadata.yml -o annotated.wasm out/k8s-pss-restricted/policy.wasm
kwctl push annotated.wasm ghcr.io/ynotbhatc/kubewarden/k8s-pss-restricted:v2.3.3
```

`test/roundtrip.sh` evaluates adapter + policy with plain OPA on AdmissionReview fixtures and checks that the
response denies exactly when the original policy reports violations, with the same messages. `kwctl run` is the
in-engine equivalent.
