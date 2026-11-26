# Rego Policy Libraries — Makefile
# Requires: opa (CI tests 1.10.0 and 1.22.4), curl

OPA ?= opa

.PHONY: test lint metadata check count mutation wasm wasm-classes coverage check-no-data check-no-library-tests check-bad-input check-generated check-coverage check-per-file-load schemas oscal crosswalk xccdf check-converters check-cis-verbatim check-standards standards-releases load-security load-compliance load-ot help

help:
	@echo "Targets:"
	@echo "  make test          Run the full opa test suite (same as CI)"
	@echo "  make lint          Check syntax of all .rego files"
	@echo "  make metadata      Verify every package carries a conforming METADATA block"
	@echo "  make check         lint + test + metadata"
	@echo "  make check-standards  Verify standards.yaml covers every framework key and matches the module text, the registry and docs/FRAMEWORKS.md (offline)"
	@echo "  make standards-releases  Check upstream sources for releases newer than standards.yaml (network)"
	@echo "  make mutation MODULE=<dir> [ARGS=...]  Mutation-test one module directory (slow; not run in CI)"
	@echo "  make check-bad-input  Empty / null / string-typed input, string and null facts, and mutated fixtures never pass (known failures listed, accepted cases carry a reason)"
	@echo "  make check-no-library-tests  No policy file defines a test_* rule (opa test would run it)"
	@echo "  make schemas       Regenerate the input schemas (schemas/input/<key>/schema.json); check-generated fails when stale"
	@echo "  make check-per-file-load  Upload every policy file one at a time into a throwaway OPA server, as the product does"
	@echo "  make load-security    Load benchmarks into opa-security (:8181)"
	@echo "  make load-compliance  Load frameworks into opa-compliance (:8182)"
	@echo "  make load-ot          Load OT policies into opa-ot (:8183)"
	@echo "  make load-all         Load all three containers"

lint:
	@echo "=== Checking syntax of all .rego files ==="
	@RC=0; \
	for f in $$(find . -name "*.rego" -not -path "./.git/*" | sort); do \
	  if $(OPA) check "$$f" 2>&1; then \
	    echo "  OK: $$f"; \
	  else \
	    echo "  FAIL: $$f"; \
	    RC=1; \
	  fi; \
	done; \
	exit $$RC

# Same suite CI runs. The previous recipe only globbed *_test.rego, which
# skipped the test_*.rego files this repo actually uses.
test:
	@echo "=== Running OPA tests (same suite as .github/workflows/opa-test.yml) ==="
	$(OPA) test . --ignore .github --ignore converters --timeout 30s

# Mutation testing of one module directory (#306): flips comparisons and booleans, drops a `not` or a body
# line, and reports which changes the module's own tests did not notice. Slow, so not part of CI.
#   make mutation MODULE=frameworks/financial/pci_dss/access_control
#   make mutation MODULE=benchmarks/cis/rhel_9 ARGS="--file ssh_validation.rego --json /tmp/m.json"
mutation:
	@test -n "$(MODULE)" || { echo 'usage: make mutation MODULE=<module dir> [ARGS="--file <glob> --ops eq,bool --json out.json"]'; exit 2; }
	@python3 scripts/mutation_test.py $(MODULE) $(ARGS)

count:
	@echo "=== Control-level check count (scripts/count_controls.py) — also restamps docs/metrics.json ==="
	@python3 scripts/count_controls.py --write-json

wasm:
	@python3 converters/packaging/wasm/build.py

# per-class bundles only (pull-request CI; the combined bundle is built at release)
wasm-classes:
	@python3 converters/packaging/wasm/build.py --no-all

oscal:
	@python3 converters/exports/oscal/build.py
	@python3 converters/exports/oscal/build_profiles.py
	@python3 converters/exports/oscal/build_baseline_coverage.py
	@python3 converters/exports/oscal/build_component.py

crosswalk:
	@python3 converters/exports/crosswalk_csv/build.py

xccdf:
	@python3 converters/exports/xccdf_ids/build.py

check-converters:
	@bash converters/packaging/wasm/test/roundtrip.sh
	@bash converters/packaging/gatekeeper/test/roundtrip.sh
	@bash converters/packaging/kubewarden/test/roundtrip.sh
	@bash converters/packaging/iac_scanners/test/roundtrip.sh
	@bash converters/packaging/terraform_platforms/test/roundtrip.sh
	@bash converters/exports/oscal/test/roundtrip.sh
	@bash converters/exports/sarif/test/roundtrip.sh
	@bash converters/exports/_lib/test/roundtrip.sh
	@bash converters/exports/ocsf/test/roundtrip.sh
	@bash converters/exports/crosswalk_csv/test/roundtrip.sh
	@bash converters/exports/xccdf_ids/test/roundtrip.sh
	@git diff --exit-code -- converters/packaging/gatekeeper/dist >/dev/null || { echo 'gatekeeper dist/ is stale: run build.py and commit'; exit 1; }
	@python3 converters/exports/oscal/build.py >/dev/null && python3 converters/exports/oscal/build_profiles.py >/dev/null && python3 converters/exports/oscal/build_baseline_coverage.py >/dev/null && python3 converters/exports/oscal/build_component.py >/dev/null && git diff --exit-code -- converters/exports/oscal/dist >/dev/null || { echo 'oscal dist/ is stale: run make oscal and commit'; exit 1; }
	@python3 converters/exports/crosswalk_csv/build.py >/dev/null && git diff --exit-code -- converters/exports/crosswalk_csv/dist >/dev/null || { echo 'crosswalk_csv dist/ is stale: run make crosswalk and commit'; exit 1; }
	@python3 converters/exports/xccdf_ids/build.py >/dev/null && git diff --exit-code -- converters/exports/xccdf_ids/dist >/dev/null || { echo 'xccdf_ids dist/ is stale: run make xccdf and commit'; exit 1; }

coverage:
	@echo "=== Stamping custom.coverage into every module's METADATA + docs/COVERAGE_SCAN.md ==="
	@OPA=$(OPA) python3 scripts/coverage_stamp.py --report docs/COVERAGE_SCAN.md

# no data never passes: the generated test must list every compliance_report entrypoint
check-no-data:
	@python3 scripts/check_no_data_fails.py --check-test

# no policy (non-test) file defines a rule named test_*: `opa test` executes it and the library publishes it.
# Run by check-coverage, so by `make check` and by CI.
check-no-library-tests:
	@python3 scripts/check_no_library_test_rules.py

# bad input never passes (#301): empty / missing / null / string-typed input, every input path the module's
# sources read set to "false" / "true" / "no" / null (no fixture needed), and mutated all-pass fixtures, for every
# entrypoint; fails only on a failure not in scripts/bad_input_known_failures.txt (to fix) and not accepted with
# a reason in scripts/bad_input_accepted.txt (reviewed and right; an entry that no longer fails is an error).
# CONTRIBUTING.md, "Bad input never passes". The unit tests of the check scripts (scripts/tests/) run first.
check-bad-input:
	@OPA=$(OPA) python3 -m unittest discover -s scripts/tests -q
	@OPA=$(OPA) python3 scripts/check_bad_input_fails.py --check

check-coverage:
	@$(MAKE) --no-print-directory check-no-library-tests
	@OPA=$(OPA) python3 scripts/coverage_stamp.py --check
	@python3 scripts/check_numeric_guards.py --check
	@OPA=$(OPA) python3 scripts/check_undefined_negation.py --check
	@python3 scripts/coverage_report.py --check
	@$(MAKE) --no-print-directory check-generated
	@$(MAKE) --no-print-directory check-bad-input

# generated files that CI must see current: the no-data test lists every entrypoint; the NIST 800-53 index
# matches the module and the OSCAL baseline profiles; the PCI DSS evidence_spec blocks match their rule bodies;
# the Linux STIG collector contract matches the rule tables; standards.yaml matches the module versions;
# the input schemas (schemas/input/) match their sources and pass their self-tests; the site catalog's sections
# hold every policy file once and add up to the README policy count; the crosswalk framework maps match the
# FedRAMP profiles, the GovRAMP maps and index match scripts/govramp_baselines.json, and, for the NIST-published maps,
# their recorded map hash and pinned sources (no network)
check-generated: check-no-data check-standards
	@OPA=$(OPA) python3 scripts/gen_nist_800_53_index.py --check
	@echo "NIST 800-53 index current; the evaluated-id count stated in the module header and docs matches"
	@python3 scripts/gen_pci_dss_evidence_spec.py --check
	@python3 tools/stig_generators/gen_collector_contract.py --check
	@OPA=$(OPA) python3 scripts/gen_input_schemas.py --check
	@python3 scripts/gen_pages_catalog.py --check
	@python3 scripts/gen_fedramp_framework_maps.py --check
	@OPA=$(OPA) python3 scripts/gen_govramp_framework_maps.py --check
	@python3 scripts/gen_nist_framework_maps.py --check

# one JSON Schema per framework key for the facts its module reads, generated from the rule tables, the collector
# manifests and the sources (docs/INPUT_SCHEMAS.md); validate a document with scripts/validate_input.py
schemas:
	@OPA=$(OPA) python3 scripts/gen_input_schemas.py

# standards.yaml must list every custom.framework key and each version must match literal module text (no network)
check-standards:
	@python3 scripts/check_standard_releases.py --offline --quiet

# network: upstream releases newer than what standards.yaml records (monthly job); exit 1 = something to review
standards-releases:
	@python3 scripts/check_standard_releases.py --json standards-report.json

# The product loads this library with one PUT /v1/policies per file into an empty
# server; a module that only compiles next to its siblings is rejected there even
# though `opa check <dir>` and `opa test` pass. OPA_IMAGE=docker.io/openpolicyagent/opa:latest
# runs the server from a container with podman instead of the local binary.
check-per-file-load:
	@echo "=== Per-file load into a throwaway OPA server (scripts/check_per_file_load.py) ==="
	@python3 scripts/check_per_file_load.py --quiet $(if $(OPA_IMAGE),--podman-image $(OPA_IMAGE),--opa $(OPA))

metadata:
	@echo "=== Checking policy METADATA annotations ==="
	@python3 scripts/check_metadata.py

check-cis-verbatim:
	@python3 scripts/check_cis_verbatim.py benchmarks/cis

check: lint test metadata check-no-data check-coverage check-per-file-load check-cis-verbatim

OPA_SECURITY_URL  ?= http://localhost:8181
OPA_COMPLIANCE_URL ?= http://localhost:8182
OPA_OT_URL        ?= http://localhost:8183

load-security:
	@echo "=== Loading benchmarks into opa-security ($(OPA_SECURITY_URL)) ==="
	@find benchmarks -name "*.rego" | while read f; do \
	  id=$$(echo $$f | tr '/' '_' | sed 's/\.rego$$//'); \
	  curl -s -X PUT --data-binary @"$$f" \
	    "$(OPA_SECURITY_URL)/v1/policies/$$id" | python3 -c "import sys,json; r=json.load(sys.stdin); print('  OK' if not r.get('code') else '  ERR: '+str(r))"; \
	done
	@echo "Loaded. Policy count:"
	@curl -s $(OPA_SECURITY_URL)/v1/policies | python3 -c "import sys,json; r=json.load(sys.stdin); print('  ',len(r.get('result',[])), 'policies')"

load-compliance:
	@echo "=== Loading frameworks into opa-compliance ($(OPA_COMPLIANCE_URL)) ==="
	@for dir in frameworks/management frameworks/financial frameworks/federal \
	             frameworks/privacy frameworks/sovereignty enforcement governance; do \
	  find $$dir -name "*.rego" 2>/dev/null | while read f; do \
	    id=$$(echo $$f | tr '/' '_' | sed 's/\.rego$$//'); \
	    curl -s -X PUT --data-binary @"$$f" \
	      "$(OPA_COMPLIANCE_URL)/v1/policies/$$id" | python3 -c "import sys,json; r=json.load(sys.stdin); print('  OK' if not r.get('code') else '  ERR: '+str(r))"; \
	  done; \
	done
	@echo "Loaded. Policy count:"
	@curl -s $(OPA_COMPLIANCE_URL)/v1/policies | python3 -c "import sys,json; r=json.load(sys.stdin); print('  ',len(r.get('result',[])), 'policies')"

load-ot:
	@echo "=== Loading OT policies into opa-ot ($(OPA_OT_URL)) ==="
	@for dir in frameworks/critical_infrastructure governance threat_detection; do \
	  find $$dir -name "*.rego" 2>/dev/null | while read f; do \
	    id=$$(echo $$f | tr '/' '_' | sed 's/\.rego$$//'); \
	    curl -s -X PUT --data-binary @"$$f" \
	      "$(OPA_OT_URL)/v1/policies/$$id" | python3 -c "import sys,json; r=json.load(sys.stdin); print('  OK' if not r.get('code') else '  ERR: '+str(r))"; \
	  done; \
	done
	@echo "Loaded. Policy count:"
	@curl -s $(OPA_OT_URL)/v1/policies | python3 -c "import sys,json; r=json.load(sys.stdin); print('  ',len(r.get('result',[])), 'policies')"

load-all: load-security load-compliance load-ot
	@echo "=== All containers loaded ==="
