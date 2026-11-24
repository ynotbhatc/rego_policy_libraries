# Kubernetes Pod Security Standards (PSS)
# Source: kubernetes.io/docs/concepts/security/pod-security-standards/
# (official, versionless page; field lists current as of 2026-09).
#
# Unlike the attestation-shaped frameworks, this module evaluates an
# ACTUAL POD MANIFEST: input.pod is a Kubernetes Pod object (or the
# pod template of a workload). It implements the two restrictive
# profiles:
#
#   Baseline   — 12 controls: hostProcess, host namespaces, privileged,
#                capabilities (allow-list), hostPath, hostPort,
#                host probes/lifecycle hosts, AppArmor, SELinux,
#                /proc mount, seccomp (no Unconfined), sysctls (safe set)
#   Restricted — everything in Baseline plus 6 controls: volume types,
#                allowPrivilegeEscalation=false, runAsNonRoot,
#                runAsUser != 0, explicit seccomp profile,
#                drop ALL capabilities (+ only NET_BIND_SERVICE back)
#
# Target profile: input.pss_profile ("baseline" | "restricted");
# defaults to "restricted" — the strictest reading is the fail-closed
# default, callers must opt DOWN explicitly. `compliant` is judged
# against the target profile; both profiles' violations are always
# reported in full either way.
#
# Fail-closed: no pod manifest supplied → explicit violation, never a
# silent pass.
#
# OPA query path: /v1/data/k8s_pss/main/compliance_report

# METADATA
# title: "Kubernetes Pod Security Standards (PSS)"
# custom:
#   class: security
#   framework: pss_kubernetes
#   source: kubernetes
#   domains: [kubernetes, container]
#   coverage:
#     checks: 34
#     cited: 0
#     expected: 18
#     found: 34
#     scope: module
#     density: over
#     basis: declared-total
#     tested: true
#     entrypoint: compliance_report
#     guard: self
#     as_of: v2.5.0
package k8s_pss.main

import rego.v1

# ── Manifest presence gate ───────────────────────────────────────────────────

default pod_present := false

pod_present if {
	is_object(input.pod.spec)
}

# Containers across all three classes. Ephemeral containers carry no
# probes/lifecycle but share the securityContext surface.
all_containers := array.concat(
	array.concat(_container_list("containers"), _container_list("initContainers")),
	_container_list("ephemeralContainers"),
)

probe_containers := array.concat(_container_list("containers"), _container_list("initContainers"))

# A container list as the manifest states it. Missing, null or anything that is not a list reads as empty
# here (array.concat on a string is an error, and every container rule then went silent); the fail-closed
# rule below reports a manifest whose containers cannot be read.
_container_list(field) := list if {
	list := object.get(input.pod.spec, field, null)
	is_array(list)
} else := []

default containers_readable := false

containers_readable if {
	main := object.get(input.pod.spec, "containers", null)
	is_array(main)
	count(main) > 0
	every field in ["containers", "initContainers", "ephemeralContainers"] {
		_list_of_objects(object.get(input.pod.spec, field, null))
	}
}

_list_of_objects(list) if is_null(list)

_list_of_objects(list) if {
	is_array(list)
	every c in list {
		is_object(c)
	}
}

# The pod securityContext when it is an object; anything else reads as empty and is reported below
# (object.get on a string is an error, which silenced every rule that reads the security context).
default pod_sc := {}

pod_sc := sc if {
	sc := input.pod.spec.securityContext
	is_object(sc)
}

_unreadable_security_contexts contains "pod" if {
	sc := input.pod.spec.securityContext
	not is_null(sc)
	not is_object(sc)
}

_unreadable_security_contexts contains sprintf("container %q", [object.get(c, "name", "?")]) if {
	some c in all_containers
	is_object(c)
	sc := c.securityContext
	not is_null(sc)
	not is_object(sc)
}

# A switch that must stay off is off only as the boolean false or when unset. Any other value turns the
# finding on: true, and also the strings "true" and "false" and numbers, which Kubernetes would reject.
_on(value) if {
	not is_null(value)
	value != false
}

# runAsUser set to 0, or to something that is not a number (a string "0" is not a non-root UID)
_root_uid(value) if value == 0

_root_uid(value) if {
	not is_null(value)
	not is_number(value)
}

# ═════════════════════════════════ BASELINE ═════════════════════════════════

baseline_violations contains msg if {
	not pod_present
	msg := "PSS baseline (fail-closed): no pod manifest supplied at input.pod — nothing was evaluated"
}

# A pod has at least one container (the API server rejects one without), and each container is an object.
# A manifest whose containers cannot be read has nothing the per-container controls could judge, so it is
# reported instead of passing them by default. This is input handling, not a control of either profile.
baseline_violations contains msg if {
	pod_present
	not containers_readable
	msg := "PSS baseline (fail-closed): input.pod.spec.containers is not a non-empty list of container objects (or initContainers / ephemeralContainers is not a list of objects) — the containers were not evaluated"
}

baseline_violations contains msg if {
	some where in _unreadable_security_contexts
	msg := sprintf("PSS baseline (fail-closed): %s securityContext is not an object — its settings were not evaluated", [where])
}

# ── hostProcess (Windows) ────────────────────────────────────────────────────

baseline_violations contains msg if {
	_on(object.get(pod_sc, ["windowsOptions", "hostProcess"], null))
	msg := "PSS baseline (host-process): pod securityContext sets windowsOptions.hostProcess=true"
}

baseline_violations contains msg if {
	some c in all_containers
	_on(object.get(c, ["securityContext", "windowsOptions", "hostProcess"], null))
	msg := sprintf("PSS baseline (host-process): container %q sets windowsOptions.hostProcess=true", [object.get(c, "name", "?")])
}

# ── Host namespaces ──────────────────────────────────────────────────────────

baseline_violations contains msg if {
	_on(object.get(input.pod.spec, "hostNetwork", null))
	msg := "PSS baseline (host-namespaces): spec.hostNetwork=true shares the host network namespace"
}

baseline_violations contains msg if {
	_on(object.get(input.pod.spec, "hostPID", null))
	msg := "PSS baseline (host-namespaces): spec.hostPID=true shares the host PID namespace"
}

baseline_violations contains msg if {
	_on(object.get(input.pod.spec, "hostIPC", null))
	msg := "PSS baseline (host-namespaces): spec.hostIPC=true shares the host IPC namespace"
}

# ── Privileged containers ────────────────────────────────────────────────────

baseline_violations contains msg if {
	some c in all_containers
	_on(object.get(c, ["securityContext", "privileged"], null))
	msg := sprintf("PSS baseline (privileged): container %q runs privileged", [object.get(c, "name", "?")])
}

# ── Capabilities (baseline allow-list) ───────────────────────────────────────

BASELINE_ALLOWED_CAPS := {
	"AUDIT_WRITE", "CHOWN", "DAC_OVERRIDE", "FOWNER", "FSETID", "KILL",
	"MKNOD", "NET_BIND_SERVICE", "SETFCAP", "SETGID", "SETPCAP",
	"SETUID", "SYS_CHROOT",
}

baseline_violations contains msg if {
	some c in all_containers
	some cap in object.get(c, ["securityContext", "capabilities", "add"], [])
	not cap in BASELINE_ALLOWED_CAPS
	msg := sprintf("PSS baseline (capabilities): container %q adds capability %q beyond the baseline allow-list", [object.get(c, "name", "?"), cap])
}

# ── HostPath volumes ─────────────────────────────────────────────────────────

baseline_violations contains msg if {
	some v in object.get(input.pod.spec, "volumes", [])
	object.get(v, "hostPath", null) != null
	msg := sprintf("PSS baseline (hostpath): volume %q mounts a hostPath", [object.get(v, "name", "?")])
}

# ── Host ports ───────────────────────────────────────────────────────────────

baseline_violations contains msg if {
	some c in all_containers
	some p in object.get(c, "ports", [])
	object.get(p, "hostPort", 0) != 0
	msg := sprintf("PSS baseline (host-ports): container %q binds hostPort %v", [object.get(c, "name", "?"), p.hostPort])
}

# ── Host probes / lifecycle hook hosts ───────────────────────────────────────

PROBE_KINDS := {"livenessProbe", "readinessProbe", "startupProbe"}

baseline_violations contains msg if {
	some c in probe_containers
	some kind in PROBE_KINDS
	h := object.get(c, [kind, "httpGet", "host"], "")
	h != ""
	msg := sprintf("PSS baseline (host-probes): container %q %s targets host %q", [object.get(c, "name", "?"), kind, h])
}

baseline_violations contains msg if {
	some c in probe_containers
	some kind in PROBE_KINDS
	h := object.get(c, [kind, "tcpSocket", "host"], "")
	h != ""
	msg := sprintf("PSS baseline (host-probes): container %q %s tcpSocket targets host %q", [object.get(c, "name", "?"), kind, h])
}

HOOK_KINDS := {"postStart", "preStop"}

baseline_violations contains msg if {
	some c in probe_containers
	some hook in HOOK_KINDS
	h := object.get(c, ["lifecycle", hook, "httpGet", "host"], "")
	h != ""
	msg := sprintf("PSS baseline (host-probes): container %q lifecycle %s targets host %q", [object.get(c, "name", "?"), hook, h])
}

baseline_violations contains msg if {
	some c in probe_containers
	some hook in HOOK_KINDS
	h := object.get(c, ["lifecycle", hook, "tcpSocket", "host"], "")
	h != ""
	msg := sprintf("PSS baseline (host-probes): container %q lifecycle %s tcpSocket targets host %q", [object.get(c, "name", "?"), hook, h])
}

# ── AppArmor ─────────────────────────────────────────────────────────────────

APPARMOR_ALLOWED := {"RuntimeDefault", "Localhost"}

baseline_violations contains msg if {
	t := object.get(pod_sc, ["appArmorProfile", "type"], "RuntimeDefault")
	not t in APPARMOR_ALLOWED
	msg := sprintf("PSS baseline (apparmor): pod appArmorProfile.type %q is not RuntimeDefault or Localhost", [t])
}

baseline_violations contains msg if {
	some c in all_containers
	t := object.get(c, ["securityContext", "appArmorProfile", "type"], "RuntimeDefault")
	not t in APPARMOR_ALLOWED
	msg := sprintf("PSS baseline (apparmor): container %q appArmorProfile.type %q is not RuntimeDefault or Localhost", [object.get(c, "name", "?"), t])
}

# The annotation form, which the Baseline AppArmor control lists beside the field form:
# metadata.annotations["container.apparmor.security.beta.kubernetes.io/*"], allowed values undefined / nil,
# runtime/default and localhost/*. The standard does not require a pod to carry metadata or annotations,
# so their absence (or null) is the allowed "undefined".
baseline_violations contains msg if {
	some key, value in _annotations
	startswith(key, "container.apparmor.security.beta.kubernetes.io/")
	not _apparmor_annotation_allowed(value)
	msg := sprintf("PSS baseline (apparmor): annotation %s is %v, not runtime/default or localhost/*", [key, value])
}

# metadata, or its annotations, set to something that is not an object: the annotation form cannot be read,
# so the AppArmor control cannot be cleared.
baseline_violations contains msg if {
	pod_present
	not _annotations_readable
	msg := "PSS baseline (apparmor): input.pod.metadata or its annotations is not an object — the AppArmor annotations cannot be evaluated"
}

default _annotations := {}

_annotations := a if {
	a := input.pod.metadata.annotations
	is_object(a)
}

_annotations_readable if {
	meta := object.get(input.pod, "metadata", null)
	_object_or_null(meta)
	_object_or_null(object.get(_as_object(meta), "annotations", null))
}

_object_or_null(x) if is_null(x)

_object_or_null(x) if is_object(x)

_as_object(x) := x if {
	is_object(x)
} else := {}

_apparmor_annotation_allowed(value) if is_null(value)

_apparmor_annotation_allowed(value) if value == "runtime/default"

_apparmor_annotation_allowed(value) if {
	is_string(value)
	startswith(value, "localhost/")
}

# ── SELinux ──────────────────────────────────────────────────────────────────

SELINUX_ALLOWED_TYPES := {"", "container_t", "container_init_t", "container_kvm_t", "container_engine_t"}

baseline_violations contains msg if {
	t := object.get(pod_sc, ["seLinuxOptions", "type"], "")
	not t in SELINUX_ALLOWED_TYPES
	msg := sprintf("PSS baseline (selinux): pod seLinuxOptions.type %q is outside the allowed set", [t])
}

baseline_violations contains msg if {
	some c in all_containers
	t := object.get(c, ["securityContext", "seLinuxOptions", "type"], "")
	not t in SELINUX_ALLOWED_TYPES
	msg := sprintf("PSS baseline (selinux): container %q seLinuxOptions.type %q is outside the allowed set", [object.get(c, "name", "?"), t])
}

baseline_violations contains msg if {
	some field in {"user", "role"}
	object.get(pod_sc, ["seLinuxOptions", field], "") != ""
	msg := sprintf("PSS baseline (selinux): pod seLinuxOptions.%s must be unset", [field])
}

baseline_violations contains msg if {
	some c in all_containers
	some field in {"user", "role"}
	object.get(c, ["securityContext", "seLinuxOptions", field], "") != ""
	msg := sprintf("PSS baseline (selinux): container %q seLinuxOptions.%s must be unset", [object.get(c, "name", "?"), field])
}

# ── /proc mount type ─────────────────────────────────────────────────────────

baseline_violations contains msg if {
	some c in all_containers
	pm := object.get(c, ["securityContext", "procMount"], "Default")
	pm != "Default"
	msg := sprintf("PSS baseline (proc-mount): container %q sets procMount=%q (only Default is allowed)", [object.get(c, "name", "?"), pm])
}

# ── Seccomp (baseline: must not be Unconfined) ───────────────────────────────

baseline_violations contains msg if {
	object.get(pod_sc, ["seccompProfile", "type"], "") == "Unconfined"
	msg := "PSS baseline (seccomp): pod seccompProfile.type=Unconfined is not allowed"
}

baseline_violations contains msg if {
	some c in all_containers
	object.get(c, ["securityContext", "seccompProfile", "type"], "") == "Unconfined"
	msg := sprintf("PSS baseline (seccomp): container %q sets seccompProfile.type=Unconfined", [object.get(c, "name", "?")])
}

# ── Sysctls (safe set) ───────────────────────────────────────────────────────

SAFE_SYSCTLS := {
	"kernel.shm_rmid_forced",
	"net.ipv4.ip_local_port_range",
	"net.ipv4.ip_unprivileged_port_start",
	"net.ipv4.tcp_syncookies",
	"net.ipv4.ping_group_range",
	"net.ipv4.ip_local_reserved_ports",
	"net.ipv4.tcp_keepalive_time",
	"net.ipv4.tcp_fin_timeout",
	"net.ipv4.tcp_keepalive_intvl",
	"net.ipv4.tcp_keepalive_probes",
	"net.ipv4.tcp_rmem",
	"net.ipv4.tcp_wmem",
}

baseline_violations contains msg if {
	some s in object.get(pod_sc, "sysctls", [])
	not s.name in SAFE_SYSCTLS
	msg := sprintf("PSS baseline (sysctls): sysctl %q is outside the safe set", [s.name])
}

# ════════════════════════════════ RESTRICTED ════════════════════════════════
# Restricted = Baseline + the checks below. restricted_violations holds
# only the additional findings; the report unions them with baseline.

RESTRICTED_VOLUME_TYPES := {
	"configMap", "csi", "downwardAPI", "emptyDir", "ephemeral",
	"persistentVolumeClaim", "projected", "secret",
}

restricted_violations contains msg if {
	some v in object.get(input.pod.spec, "volumes", [])
	some k, _ in object.remove(v, ["name"])
	not k in RESTRICTED_VOLUME_TYPES
	msg := sprintf("PSS restricted (volume-types): volume %q uses disallowed type %q", [object.get(v, "name", "?"), k])
}

restricted_violations contains msg if {
	some c in all_containers
	not object.get(c, ["securityContext", "allowPrivilegeEscalation"], true) == false
	msg := sprintf("PSS restricted (privilege-escalation): container %q must explicitly set allowPrivilegeEscalation=false", [object.get(c, "name", "?")])
}

# runAsNonRoot: true at pod level, or explicitly true per container;
# an explicit container-level false always violates.
pod_run_as_nonroot if {
	object.get(pod_sc, "runAsNonRoot", false) == true
}

container_nonroot_ok(c) if {
	_on(object.get(c, ["securityContext", "runAsNonRoot"], null))
}

container_nonroot_ok(c) if {
	object.get(c, ["securityContext", "runAsNonRoot"], "unset") == "unset"
	pod_run_as_nonroot
}

restricted_violations contains msg if {
	some c in all_containers
	not container_nonroot_ok(c)
	msg := sprintf("PSS restricted (run-as-nonroot): container %q does not run as non-root (set runAsNonRoot=true at pod or container level)", [object.get(c, "name", "?")])
}

restricted_violations contains msg if {
	_root_uid(object.get(pod_sc, "runAsUser", null))
	msg := "PSS restricted (run-as-user): pod securityContext.runAsUser=0 (root) is not allowed"
}

restricted_violations contains msg if {
	some c in all_containers
	_root_uid(object.get(c, ["securityContext", "runAsUser"], null))
	msg := sprintf("PSS restricted (run-as-user): container %q sets runAsUser=0 (root)", [object.get(c, "name", "?")])
}

# Seccomp: profile must be explicitly RuntimeDefault or Localhost at pod
# level or on every container.
SECCOMP_ALLOWED := {"RuntimeDefault", "Localhost"}

pod_seccomp_set if {
	object.get(pod_sc, ["seccompProfile", "type"], "") in SECCOMP_ALLOWED
}

container_seccomp_ok(c) if {
	object.get(c, ["securityContext", "seccompProfile", "type"], "") in SECCOMP_ALLOWED
}

container_seccomp_ok(c) if {
	object.get(c, ["securityContext", "seccompProfile", "type"], "unset") == "unset"
	pod_seccomp_set
}

restricted_violations contains msg if {
	some c in all_containers
	not container_seccomp_ok(c)
	msg := sprintf("PSS restricted (seccomp): container %q has no explicit RuntimeDefault/Localhost seccomp profile", [object.get(c, "name", "?")])
}

restricted_violations contains msg if {
	some c in all_containers
	not "ALL" in object.get(c, ["securityContext", "capabilities", "drop"], [])
	msg := sprintf("PSS restricted (capabilities): container %q must drop ALL capabilities", [object.get(c, "name", "?")])
}

restricted_violations contains msg if {
	some c in all_containers
	some cap in object.get(c, ["securityContext", "capabilities", "add"], [])
	cap != "NET_BIND_SERVICE"
	msg := sprintf("PSS restricted (capabilities): container %q adds capability %q (only NET_BIND_SERVICE may be added back)", [object.get(c, "name", "?"), cap])
}

# ── Profile selection and report ─────────────────────────────────────────────

default target_profile := "restricted"

target_profile := input.pss_profile if {
	input.pss_profile in {"baseline", "restricted"}
}

all_restricted := baseline_violations | restricted_violations

default baseline_compliant := false

baseline_compliant if {
	pod_present
	count(baseline_violations) == 0
}

default restricted_compliant := false

restricted_compliant if {
	pod_present
	count(all_restricted) == 0
}

default compliant := false

compliant if {
	target_profile == "baseline"
	baseline_compliant
}

compliant if {
	target_profile == "restricted"
	restricted_compliant
}

effective_violations := baseline_violations if target_profile == "baseline"

effective_violations := all_restricted if target_profile == "restricted"

default pod_name := "unknown"

pod_name := object.get(input.pod, ["metadata", "name"], "unknown")

compliance_report := {
	"framework": "Kubernetes Pod Security Standards",
	"version": "kubernetes.io Pod Security Standards (baseline + restricted; field lists as of 2026-09)",
	"pod_name": pod_name,
	"target_profile": target_profile,
	"compliant": compliant,
	"baseline_compliant": baseline_compliant,
	"restricted_compliant": restricted_compliant,
	"total_controls": 18,
	"violations": effective_violations,
	"violation_count": count(effective_violations),
	"failed_controls": min([18, count(effective_violations)]),
	"baseline_violation_count": count(baseline_violations),
	"restricted_additional_violation_count": count(restricted_violations),
	"scope_note": "Evaluates one Pod manifest (input.pod) or workload pod template. 12 baseline controls + 6 restricted controls; a control may emit multiple findings (one per offending container/volume/field). Default target profile is restricted — pass pss_profile: baseline to opt down explicitly.",
}
