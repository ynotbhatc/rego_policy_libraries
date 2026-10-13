package kubernetes.admission_test

import rego.v1

import data.kubernetes.admission as adm

# The allowlist is anchored on the registry host: a look-alike host that merely
# starts with an approved name must not be admitted.
test_approved_registry_admits_exact_host if {
	adm.from_approved_registry("quay.io/org/app:1.0") with input as {}
}

test_approved_registry_rejects_lookalike_host if {
	not adm.from_approved_registry("quay.io.evil.example/app:1.0") with input as {}
	not adm.from_approved_registry("quay.ioevil/app:1.0") with input as {}
}

test_approved_registry_accepts_trailing_slash_in_policy if {
	adm.from_approved_registry("registry.example/app:1.0") with input as {"policy": {"approved_registries": ["registry.example/"]}}
	not adm.from_approved_registry("registry.example.evil/app:1.0") with input as {"policy": {"approved_registries": ["registry.example/"]}}
}

test_cluster_local_image_without_registry_still_admitted if {
	adm.from_approved_registry("app:1.0") with input as {}
}
