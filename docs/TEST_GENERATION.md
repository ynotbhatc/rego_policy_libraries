# Test generation — what each untested module was proven to do

`scripts/gen_tests.py` wrote a smoke test for every module without one and kept only the expectations each module meets. Suite: **4701 tests pass**.

| expectation | asserted by | not met by |
|---|---|---|
| module evaluates on empty input | 0 | 0 |
| report is an object on empty input | 0 | 0 |
| report is not compliant on empty input (fail-closed) | 0 | 0 |
| violations non-empty on empty input | 0 | 0 |

## Modules that report compliant on empty input

Classified by the fail-closed guard the coverage scan measures (`custom.coverage.guard`):

### guarded by their orchestrator (by design for sectioned benchmarks: the orchestrator is fail-closed and references them) (0)


### **unguarded — fail-open; the work queue for the library's fail-closed rule** (0)


### report defined and compliant on empty input while the module itself emits violations — the report's `compliant` is computed from a subset of the checks; a defect in the report literal (0)


### no report or violations rule (0)


## Modules whose report is undefined on empty input

The report rule itself does not evaluate without facts (Rego v1 undefined, the `{}` collapse the library's contract forbids): a consumer gets nothing, not a non-compliant report. Each is a defect against the fail-closed contract.


## Modules whose violations are empty on empty input

Often by design (the module iterates a list that is absent); classified the same way.

### guard = orchestrator (0)


### guard = none (0)


### guard = self (0)


### guard = n/a (0)



## Modules with a runtime error on empty input (defects; no test written)

