package governance.geisa.lee_missing_fields_test

import rego.v1

# `not is_string(_container.runtime)` is undefined when runtime is missing, so "must be set" never fired for it.
test_lee_container_without_runtime_must_be_set if {
	v := data.governance.geisa.lee.violations with input as {"container": {"isolated": true}}
	"LEE: container.runtime must be set" in v
}

test_lee_container_with_runtime_is_not_asked_to_set_it if {
	v := data.governance.geisa.lee.violations with input as {"container": {"isolated": true, "runtime": "podman"}}
	not "LEE: container.runtime must be set" in v
}
