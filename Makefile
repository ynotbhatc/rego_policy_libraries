# Rego Policy Libraries — Makefile
# Requires: opa (v0.60+), curl

OPA ?= opa

.PHONY: test lint metadata check count wasm coverage check-coverage oscal crosswalk xccdf check-converters load-security load-compliance load-ot help

help:
	@echo "Targets:"
	@echo "  make test          Run all opa tests (policy + test files)"
	@echo "  make lint          Check syntax of all .rego files"
	@echo "  make metadata      Verify every package carries a conforming METADATA block"
	@echo "  make check         lint + test + metadata"
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

test:
	@echo "=== Running OPA tests ==="
	@RC=0; \
	for f in $$(find . -name "*_test.rego" -not -path "./.git/*"); do \
	  dir=$$(dirname $$f); \
	  $(OPA) test $$dir -v 2>&1 || RC=1; \
	done; \
	exit $$RC

count:
	@echo "=== Control-level check count (scripts/count_controls.py) — also restamps docs/metrics.json ==="
	@python3 scripts/count_controls.py --write-json

wasm:
	@python3 converters/packaging/wasm/build.py

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
	@bash converters/exports/ocsf/test/roundtrip.sh
	@bash converters/exports/crosswalk_csv/test/roundtrip.sh
	@bash converters/exports/xccdf_ids/test/roundtrip.sh
	@git diff --exit-code -- converters/packaging/gatekeeper/dist >/dev/null || { echo 'gatekeeper dist/ is stale: run build.py and commit'; exit 1; }
	@python3 converters/exports/oscal/build.py >/dev/null && python3 converters/exports/oscal/build_profiles.py >/dev/null && python3 converters/exports/oscal/build_baseline_coverage.py >/dev/null && python3 converters/exports/oscal/build_component.py >/dev/null && git diff --exit-code -- converters/exports/oscal/dist >/dev/null || { echo 'oscal dist/ is stale: run make oscal and commit'; exit 1; }
	@python3 converters/exports/crosswalk_csv/build.py >/dev/null && git diff --exit-code -- converters/exports/crosswalk_csv/dist >/dev/null || { echo 'crosswalk_csv dist/ is stale: run make crosswalk and commit'; exit 1; }
	@python3 converters/exports/xccdf_ids/build.py >/dev/null && git diff --exit-code -- converters/exports/xccdf_ids/dist >/dev/null || { echo 'xccdf_ids dist/ is stale: run make xccdf and commit'; exit 1; }

coverage:
	@echo "=== Stamping custom.coverage into every module's METADATA + docs/COVERAGE_SCAN.md ==="
	@python3 scripts/coverage_stamp.py --report docs/COVERAGE_SCAN.md

check-coverage:
	@python3 scripts/coverage_stamp.py --check

metadata:
	@echo "=== Checking policy METADATA annotations ==="
	@python3 scripts/check_metadata.py

check: lint test metadata check-coverage

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
