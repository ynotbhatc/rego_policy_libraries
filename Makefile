# Rego Policy Libraries — Makefile
# Requires: opa (v0.60+), curl

OPA ?= opa

.PHONY: test lint check load-security load-compliance load-ot help

help:
	@echo "Targets:"
	@echo "  make test          Run all opa tests (policy + test files)"
	@echo "  make lint          Check syntax of all .rego files"
	@echo "  make check         lint + test"
	@echo "  make load-security    Load benchmarks into opa-security (:8181)"
	@echo "  make load-compliance  Load frameworks into opa-compliance (:8182)"
	@echo "  make load-ot          Load OT policies into opa-ot (:8183)"
	@echo "  make load-all         Load all three containers"

lint:
	@echo "=== Checking syntax of all .rego files ==="
	@find . -name "*.rego" -not -path "./.git/*" | sort | while read f; do \
	  $(OPA) check "$$f" 2>&1 && echo "  OK: $$f" || echo "  FAIL: $$f"; \
	done
	@echo "Done."

test:
	@echo "=== Running OPA tests ==="
	@find . -name "*_test.rego" -not -path "./.git/*" | while read f; do \
	  dir=$$(dirname $$f); \
	  $(OPA) test $$dir -v 2>&1; \
	done

check: lint test

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
