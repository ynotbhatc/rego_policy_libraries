# Test generation — what each untested module was proven to do

`scripts/gen_tests.py` writes a smoke test for every module that has none and keeps only the expectations each module meets. This page is the report of the run that wrote them. It is not the size of the suite: run `opa test .` for the current total (CHANGELOG states the figure at each release; it was 4,701 when the tables below were first generated and is above 36,000 now).

**How to read it.**

- A smoke test is a floor, not a behavioural test. It shows that the module loads, that its report is an object, that the report is not compliant on empty input and that violations are non-empty. It cannot catch a wrong threshold or a withdrawn control id. At the 2026-11-17 audit, about 160 policy files were covered only by generated smoke tests (486 generated smoke files in the tree).
- A module that fails an expectation does not fail the build: the generator removes that expectation, leaves a `# NOT MET (dropped by gen_tests.py)` marker in the test file, and lists the module below. Search the test files for `NOT MET` to see every module whose smoke test has been weakened (the counts in the tables below describe the last run that wrote tests; the tables show zeros when a run had nothing to write, and the generator now leaves this page alone in that case).
- The fail-closed expectation asserts `compliant == false`. A report with no `compliant` field no longer passes it.


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

