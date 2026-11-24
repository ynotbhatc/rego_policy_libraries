# Bad evidence never reads as a clean host: a fact that is null or not a list, an item that is not an
# object, and a field of the wrong type are each reported, and the host is not compliant.

package security.crypto_miner_detection_bad_evidence_test

import rego.v1

import data.crypto_miner_detection.main
import data.security.crypto_miner_detection as detect

clean_host := {
	"running_processes": [{"name": "sshd", "cmdline": "/usr/sbin/sshd -D", "pid": 812, "cpu_percent": 0.3, "running_time_minutes": 4000}],
	"installed_packages": [{"name": "openssh-server"}],
	"network_connections": [{"remote_host": "repo.example.com", "remote_port": 443, "state": "ESTABLISHED"}],
	"systemd_services": [{"name": "sshd.service", "exec_start": "/usr/sbin/sshd -D"}],
	"cron_jobs": [{"command": "/usr/bin/dnf -y makecache"}],
	"suspicious_files": [],
}

_clean(inp) if {
	detect.compliant with input as inp
	main.compliance_report.compliant == true with input as inp
}

_not_clean(inp) if {
	not detect.compliant with input as inp
	main.compliance_report.compliant == false with input as inp
}

_invalid(inp) if {
	some msg in detect.violations with input as inp
	startswith(msg, "EVIDENCE INVALID - ")
}

test_clean_host_is_clean if _clean(clean_host)

test_empty_input_is_not_clean if _not_clean({})

test_fact_of_the_wrong_type_is_not_clean if {
	every fact, _ in detect.fact_fields {
		every bad in [null, "true", "1", 1, true, {"a": 1}] {
			inp := object.union(clean_host, {fact: bad})
			_not_clean(inp)
			_invalid(inp)
		}
	}
}

test_all_facts_null_or_strings_is_not_clean if {
	every bad in [null, "true", "1"] {
		_not_clean({fact: bad | some fact, _ in detect.fact_fields})
	}
}

test_item_that_is_not_an_object_is_not_clean if {
	every fact, _ in detect.fact_fields {
		every bad in ["xmrig", null, 1] {
			inp := object.union(clean_host, {fact: [bad]})
			_not_clean(inp)
			_invalid(inp)
		}
	}
}

test_field_of_the_wrong_type_is_not_clean if {
	every fact, fields in detect.fact_fields {
		every field, _ in fields {
			every bad in [true, ["x"], {"a": 1}] {
				inp := object.union(clean_host, {fact: [{field: bad}]})
				_not_clean(inp)
				_invalid(inp)
			}
		}
	}
}

# A mining-pool port sent as a string is not a number and cannot be matched: it is reported, not skipped.
test_string_port_is_reported if {
	inp := json.patch(clean_host, [{"op": "replace", "path": "/network_connections/0/remote_port", "value": "3333"}])
	_not_clean(inp)
	"EVIDENCE INVALID - network_connections[0].remote_port must be a number, got string" in detect.violations with input as inp
}

# Every one of the six lists must be sent: a detection whose list was not collected did not run.
test_missing_fact_list_is_not_clean if {
	every fact, _ in detect.fact_fields {
		inp := object.remove(clean_host, [fact])
		_not_clean(inp)
		sprintf("EVIDENCE MISSING - %s not collected (a list; empty when there are none); the host was NOT evaluated on it", [fact]) in detect.violations with input as inp
	}
}

test_all_six_lists_empty_is_clean if _clean({fact: [] | some fact, _ in detect.fact_fields})
