## What this changes

<!-- One or two sentences. If it is tests for an existing policy, say which file. -->

## Type

- [ ] Tests for an existing policy
- [ ] New policy / framework
- [ ] Fix to an existing policy
- [ ] Documentation

## Checklist

- [ ] `opa test <changed dirs> -v` passes
- [ ] `import rego.v1` at the top of every new file
- [ ] `default <rule> := false` on every rule that can be undefined
- [ ] Every field of a returned object is defaulted — verified with `opa eval` on
      **empty input**, which returns a populated object rather than `{}`
- [ ] `array.concat()` calls take exactly two arrays
- [ ] Violation messages name the control ID and say what is actually wrong
- [ ] No lab IPs, hostnames, credentials or customer names in policies, tests or
      sample input — use `192.0.2.x` (RFC 5737) or `<host>`

## Source

<!-- For a new or changed control: which standard, which version, which control ID.
     Policies cite their source; a reviewer should be able to check it. -->

<!-- Taking a file from COVERAGE.md? Say which, so two people don't duplicate work. -->
