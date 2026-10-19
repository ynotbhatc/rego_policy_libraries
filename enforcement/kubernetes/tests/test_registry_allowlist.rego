package kubernetes.admission_test

import rego.v1

# The allowlist is anchored on the registry host: a look-alike host that merely
# starts with an approved name must not be admitted.
test_approved_registry_admits_exact_host if {
	not registry_violation_p("quay.io/org/app:1.0", {})
}

test_approved_registry_rejects_lookalike_host if {
	registry_violation_p("quay.io.evil.example/app:1.0", {})
	registry_violation_p("quay.ioevil/app:1.0", {})
}

test_approved_registry_accepts_trailing_slash_in_policy if {
	not registry_violation_p("registry.example/app:1.0", {"approved_registries": ["registry.example/"]})
	registry_violation_p("registry.example.evil/app:1.0", {"approved_registries": ["registry.example/"]})
}

# Owner-approved change (decisions 2026-10-19): a bare image name resolves to
# docker.io, so it is no longer admitted by default. The test name is kept for
# test-discovery stability; it now pins "admitted only when docker.io is approved".
# (Driven through the violations rule: the pre-commit hook type-checks this file alone.)
test_cluster_local_image_without_registry_still_admitted if {
	not registry_violation("app:1.0", ["docker.io"])
}

registry_violation(image, approved) if registry_violation_p(image, {"approved_registries": approved})

registry_violation_p(image, policy) if {
	i := {"request": {"operation": "CREATE", "namespace": "dev", "kind": {"kind": "Pod"}, "object": {"metadata": {"name": "p"}, "spec": {"containers": [{"name": "c", "image": image}]}}}, "policy": policy}
	some v in data.kubernetes.admission.violations with input as i
	startswith(v, "Registry:")
}

test_bare_image_denied_by_default if {
	registry_violation("nginx:1.25", ["quay.io"])
	registry_violation("myorg/app:1.0", ["quay.io"])
}

test_bare_image_admitted_when_docker_io_approved if {
	not registry_violation("nginx:1.25", ["quay.io", "docker.io/"])
	not registry_violation("myorg/app:1.0", ["docker.io"])
}

test_registry_host_with_port_is_not_bare if {
	registry_violation("reg.example:5000/app:1.0", ["docker.io"])
	not registry_violation("reg.example:5000/app:1.0", ["reg.example:5000"])
}