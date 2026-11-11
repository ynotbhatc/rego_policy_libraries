# Other Rego policy work on GitHub

<!-- Moved out of README.md on 2026-11-11 so the front page stays short. Content unchanged except headings. -->

Pointers to other great policy-as-code work in the community — **full credit to the owners and authors** of each project below. These are references, not vendored copies: we link to them so you can find them; the policies stay in their home repositories under their own maintainers and licenses.

### Policy libraries

| Repository | Owner / Author | What it covers |
|---|---|---|
| [redhat-cop/rego-policies](https://github.com/redhat-cop/rego-policies) | Red Hat Community of Practice | Kubernetes/OpenShift + general config-compliance policies for OPA, Gatekeeper, and Conftest |
| [kubewarden/rego-policies-library](https://github.com/kubewarden/rego-policies-library) | Kubewarden project (SUSE) | Kubernetes security & compliance admission policies (Gatekeeper/Kubewarden-compatible, compiled to Wasm) |
| [conforma/policy](https://github.com/conforma/policy) | Conforma / Konflux-CI (Enterprise Contract) | Software supply-chain verification — image attestations, build provenance, pipeline-definition validation |
| [raedrizk/ansible-policy-as-code](https://github.com/raedrizk/ansible-policy-as-code) | Raed Rizk ([@raedrizk](https://github.com/raedrizk)) | AAP governance / pipeline enforcement — job-template naming, EE security, fork limits, time-based access, SCM branch enforcement, superuser restrictions |

### Style, linting & tooling

| Repository | Owner / Author | What it is |
|---|---|---|
| [open-policy-agent/rego-style-guide](https://github.com/open-policy-agent/rego-style-guide) | Open Policy Agent maintainers | Official Rego style guide / authoring best practices (complements the Regal linter) |
| [open-policy-agent/rego-python](https://github.com/open-policy-agent/rego-python) | Open Policy Agent | Python library for working with Rego ASTs |
| [itaysk/regogo](https://github.com/itaysk/regogo) | Itay Shakury ([@itaysk](https://github.com/itaysk)) | Go library wrapping the Rego engine for general-purpose JSON querying (jq-style) |

> Credit to each project's maintainers and authors. Adding a repository? Link to it (don't copy the policies), name the owner/author, and give a one-line description.
