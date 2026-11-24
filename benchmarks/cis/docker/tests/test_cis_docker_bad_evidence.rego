# Bad evidence never passes (CIS Docker Benchmark v1.9.0): every boolean and number in the all-pass fixture is
# sent as a string, as null and not at all, and the report must not come back compliant. The tables below are
# the only exceptions, each with its reason; a new leaf in the fixture is covered without editing this file.

package cis_docker.bad_evidence_test

import rego.v1

_green := data.cis_docker_test.green

_report := data.cis_docker.main.compliance_report

# leaves the module does not read (path pattern: reason): no value of theirs can change the result. They are
# in the fixture because it mirrors `docker info`, `docker inspect` and daemon.json.
_unread := {
	"docker/containers/[0-9]+/State/Pid": "no recommendation reads the process id",
	"docker/daemon/icc": "2.2 reads the default bridge's com.docker.network.bridge.enable_icc option, the effective setting",
	"docker/daemon/live-restore": "2.16 reads docker.info.LiveRestoreEnabled, the effective setting",
	"docker/daemon/default-ulimits/nofile/(Soft|Hard)": "2.9 asks that default ulimits are set; the values are the operator's",
	"docker/info/(Containers|ContainersRunning|Images)": "counts no recommendation reads (6.2 reads ContainersStopped)",
	"docker/info/Swarm/(Managers|Nodes)": "7.1 is an attested review of the manager count",
}

# leaves read only to take something OUT of scope, and only as the boolean false: any other value (a string,
# a number, null, absent) keeps the object in scope, which is the stricter reading, so the fixture still
# passes on its merits. Path pattern: reason.
_scope_switch := {
	"docker/containers/[0-9]+/State/Running": "only Running == false drops a stopped container from the section 5 checks",
	"docker/containers/[0-9]+/Mounts/[0-9]+/RW": "5.6 exempts a mount of a sensitive host directory only when RW == false",
	"docker/info/Swarm/ControlAvailable": "only ControlAvailable == false marks a worker and drops the manager-only 7.1, 7.4 to 7.8",
}

# leaves that may be left out (the documented default applies); null and a value of the wrong type are findings
_optional := {
	"cis_profile/level": "absent selects Level 2, the stricter profile",
	"docker/daemon/iptables": "2.4: a daemon.json without the key leaves iptables management on, the Docker default",
}

_key(p) := concat("/", [sprintf("%v", [x]) | some x in p])

_listed(key, patterns) if {
	some pattern, _ in patterns
	regex.match(sprintf("^%s$", [pattern]), key)
}

_judged(p) if {
	not _listed(_key(p), _unread)
	not _listed(_key(p), _scope_switch)
}

_booleans := [p | walk(_green, [p, v]); is_boolean(v); _judged(p)]

_numbers := [p | walk(_green, [p, v]); is_number(v); _judged(p)]

_passes(inp) if _report.compliant == true with input as inp

test_fixture_passes_and_has_leaves if {
	_passes(_green)
	count(_booleans) > 10
	count(_numbers) > 0
}

test_empty_and_null_input_fail if {
	not _passes({})
	not _passes(null)
}

test_boolean_of_the_wrong_type_never_passes if {
	every p in _booleans {
		v := object.get(_green, p, null)
		every bad in [sprintf("%v", [v]), sprintf("%v", [v == false]), "no", "yes", 0, 1, null] {
			not _passes(json.patch(_green, [{"op": "replace", "path": p, "value": bad}]))
		}
	}
}

test_boolean_removed_never_passes if {
	every p in [q | some q in _booleans; not _listed(_key(q), _optional)] {
		not _passes(json.patch(_green, [{"op": "remove", "path": p}]))
	}
}

test_number_of_the_wrong_type_never_passes if {
	every p in _numbers {
		every bad in [sprintf("%v", [object.get(_green, p, 0)]), "x", null] {
			not _passes(json.patch(_green, [{"op": "replace", "path": p, "value": bad}]))
		}
	}
}

test_number_removed_never_passes if {
	every p in [q | some q in _numbers; not _listed(_key(q), _optional)] {
		not _passes(json.patch(_green, [{"op": "remove", "path": p}]))
	}
}

# The exception lists stay honest: a listed pattern must match a leaf of the fixture.
test_exception_lists_name_real_leaves if {
	keys := {_key(p) | walk(_green, [p, v]); not is_object(v); not is_array(v)}
	every pattern, _ in object.union(object.union(_unread, _scope_switch), _optional) {
		some k in keys
		regex.match(sprintf("^%s$", [pattern]), k)
	}
}

# The scope switches take the stricter reading: a value that is not the boolean false keeps the object in scope.
test_scope_switch_of_another_type_keeps_the_object_in_scope if {
	every bad in ["false", "no", 0, null] {
		# a read-write mount of /etc that claims RW: "false" is still a sensitive mount (5.6)
		mount := json.patch(_green, [{"op": "add", "path": "/docker/containers/0/Mounts/0", "value": {"Source": "/etc", "Destination": "/host-etc", "RW": bad}}])
		some v in _report.violations with input as mount
		startswith(v, "5.6:")

		# a worker flag that is not the boolean false leaves the manager-only recommendations in scope
		worker := json.patch(_green, [{"op": "replace", "path": "/docker/info/Swarm/ControlAvailable", "value": bad}])
		_total(worker) == _total(_green)
	}
	_total(json.patch(_green, [{"op": "replace", "path": "/docker/info/Swarm/ControlAvailable", "value": false}])) < _total(_green)
}

_total(inp) := n if {
	r := _report with input as inp
	n := r.total_controls
}

# 2.5: every registry index must state Secure: true. An index entry without the flag used to default to secure.
test_registry_index_without_secure_fails_2_5 if {
	path := "/docker/info/RegistryConfig/IndexConfigs/docker.io/Secure"
	every patch in [{"op": "remove", "path": path}, {"op": "replace", "path": path, "value": null}, {"op": "replace", "path": path, "value": "true"}] {
		inp := json.patch(_green, [patch])
		not _passes(inp)
		some v in _report.violations with input as inp
		startswith(v, "2.5:")
	}
}
