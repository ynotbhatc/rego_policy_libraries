"""CIS Docker Benchmark v1.9.0 -> benchmarks/cis/docker/ (cis_docker, cis_docker.main, tests, README).

    python3 tools/cis_generators/dump_workbook.py <workbook.xlsx> docker.json
    python3 tools/cis_generators/gen_docker.py docker.json benchmarks/cis/docker
    opa fmt -w benchmarks/cis/docker

Same pattern as gen_apache.py (cis_genlib.py emitter): ids, levels, profiles and Automated/Manual status come from
the workbook; the logic table below is hand-authored from each recommendation's audit procedure. Every entry carries a
keyword that must occur in the workbook title of its id, so logic cannot attach to a renumbered recommendation. The run
aborts on any count, id, status, profile or keyword mismatch. Titles are our own wording, written here.
"""
import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from cis_genlib import emit_control, emit_tests, table, norm_title, u  # noqa: E402
from neutralize import neutralize_title  # noqa: E402

OUT = sys.argv[2]
BENCH = "CIS Docker Benchmark v1.9.0"
VERSION = "v1.9.0"
D = "input.docker"
EXPECT = {"total": 117, "Automated": 23, "Manual": 94,
          "Level 1 - Docker - Linux": 78, "Level 2 - Docker - Linux": 30, "Level 1 - Docker Swarm": 9}


def load(path):
    """dump_workbook.py JSON -> {id: {title, assessment, level, profiles}} (this workbook has no Combined Profiles sheet)."""
    out = {}
    for e in json.load(open(path)):
        sheets = [s for s in e["sheets"] if s not in ("Combined Profiles", "License", "Overview")]
        if len(sheets) != 1 or sheets[0] not in EXPECT:
            raise SystemExit(f"{e['id']}: unexpected profile sheets {e['sheets']}")
        out[e["id"]] = {"title": norm_title(e["title"]), "assessment": e["status"],
                        "level": int(re.match(r"Level (\d)", sheets[0]).group(1)), "profiles": sheets}
    return out


WB = load(sys.argv[1])


def rep(path, value):
    return [{"op": "add", "path": path, "value": value}]


def rm(path):
    return [{"op": "remove", "path": path}]


def fact(cid, kw, title, ev, label, ok, fail, miss, ok2=None, pre=""):
    return {"id": cid, "kw": kw, "title": title, "kind": "fact", "ev": ev, "label": label,
            "ok": [ok] + ([ok2] if ok2 else []), "fail": fail, "miss": miss, "pre": pre}


def att(cid, kw, title, key):
    return {"id": cid, "kw": kw, "title": title, "kind": "attest", "attest": key, "attest_root": D, "pre": ""}


def attested(key):
    return [f"{D}.attest.{key} == true"]


# ── audit rules (input.auditd.active_rules, the Linux modules' fact) ─────────────────────────────────────────────
AUDIT_PATHS = {}


def audit(cid, kw, what, key, default):
    AUDIT_PATHS[cid] = default
    return fact(cid, kw, f"an audit rule must cover {what}", ["_audit_collected"], "auditd.active_rules",
                [f'_audit_ok("{key}", "{default}")'], None, rm("/auditd/active_rules"))


# ── daemon settings (input.docker.daemon: effective daemon.json keys merged with dockerd flags) ────────────────
def daemon(cid, kw, title, ok, fail, ok2=None):
    return fact(cid, kw, title, ["_daemon_collected"], "docker.daemon", ok, fail, rm("/docker/daemon"), ok2)


def info(cid, kw, title, field, typ, ok, fail, ok2=None):
    return fact(cid, kw, title, [f"is_{typ}({D}.info.{field})"], f"docker.info.{field}", ok, fail,
                rm("/docker/info/" + field.split(".")[0]), ok2)


# ── files (input.docker.files.<key>: {exists, path, owner, group, mode}) ───────────────────────────────────────────
def owner(cid, kw, what, key, grp="root"):
    return fact(cid, kw, f"{what} must be owned by root:{grp}", [f'_file_known("{key}")'], f"docker.files.{key}",
                [f'_owned("{key}", "root", "{grp}")'], rep(f"/docker/files/{key}/owner", "app"), rm(f"/docker/files/{key}"))


def mode(cid, kw, what, key, most, bad):
    return fact(cid, kw, f"{what} must have mode {most} or stricter", [f'_file_known("{key}")'], f"docker.files.{key}",
                [f'_mode_ok("{key}", "{most}")'], rep(f"/docker/files/{key}/mode", bad), rm(f"/docker/files/{key}"))


# ── per-container / per-image checks: every collected item must satisfy the predicate ────────────────────────────
def per(cid, kw, title, lst, oks, fail, scope="_containers", ok2=None, extra_ev=None, extra_label=""):
    uu = u(cid)
    var, namer = ("c", "_cname") if lst == "containers" else ("i", "_iname")
    if lst == "images":
        scope = "_images"
    pre = []
    for body in oks:
        pre += [f"_ok_{uu}({var}) if {{"] + ["\t" + ln for ln in body] + ["}", ""]
    pre += [f"_bad_{uu} contains {namer}({var}) if {{", f"\tsome {var} in {scope}", f"\tnot _ok_{uu}({var})", "}", "",
            f'_offenders["{cid}"] := sort([n | some n in _bad_{uu}]) if {{', f'\t_applies("{cid}")',
            f"\tcount(_bad_{uu}) > 0", "}", ""]
    return fact(cid, kw, title, [f"_{lst}_collected"] + (extra_ev or []), f"docker.{lst}" + extra_label,
                [f"count(_bad_{uu}) == 0"], fail, rm(f"/docker/{lst}"), ok2, "\n".join(pre))


def con(n, path, value):
    return rep(f"/docker/containers/{n}/{path}", value)


def img(path, value):
    return rep(f"/docker/images/0/{path}", value)


def host_ns(cid, kw, what, field):
    return per(cid, kw, f"containers must not share the host's {what} namespace", "containers",
               [[f"is_string(c.HostConfig.{field})", f'c.HostConfig.{field} != "host"']], con(0, f"HostConfig/{field}", "host"))


C = [
    # 1 Host configuration
    fact("1.1.1", "separate partition", "the Docker data root must be its own mount point",
         [f"is_boolean({D}.host.data_root_is_mountpoint)"], "docker.host.data_root_is_mountpoint",
         [f"{D}.host.data_root_is_mountpoint == true"], rep("/docker/host/data_root_is_mountpoint", False),
         rm("/docker/host/data_root_is_mountpoint")),
    fact("1.1.2", "trusted users", "every member of the docker group must be on the approved list",
         [f"is_array({D}.docker_group.members)", f"is_array({D}.docker_group.approved_members)"],
         "docker.docker_group.{members,approved_members}",
         [f"every m in {D}.docker_group.members {{ m in {D}.docker_group.approved_members }}"],
         rep("/docker/docker_group/members/-", "intern"), rm("/docker/docker_group/approved_members")),
    audit("1.1.3", "docker daemon", "the dockerd binary", "dockerd_binary", "/usr/bin/dockerd"),
    audit("1.1.4", "/run/containerd", "the containerd runtime directory", "run_containerd", "/run/containerd"),
    fact("1.1.5", "/var/lib/docker", "an audit rule must cover the Docker data root",
         ["_audit_collected", f"is_string({D}.info.DockerRootDir)"], "auditd.active_rules / docker.info.DockerRootDir",
         [f"_audited({D}.info.DockerRootDir)"], None, rm("/auditd/active_rules")),
    audit("1.1.6", "/etc/docker", "the Docker configuration directory", "etc_docker", "/etc/docker"),
    audit("1.1.7", "docker.service", "the docker.service unit file", "docker_service", "/usr/lib/systemd/system/docker.service"),
    audit("1.1.8", "containerd.sock", "the containerd socket", "containerd_sock", "/run/containerd/containerd.sock"),
    audit("1.1.9", "docker.sock", "the Docker socket", "docker_sock", "/var/run/docker.sock"),
    audit("1.1.10", "/etc/default/docker", "the /etc/default/docker file", "etc_default_docker", "/etc/default/docker"),
    audit("1.1.11", "daemon.json", "the daemon.json file", "daemon_json", "/etc/docker/daemon.json"),
    audit("1.1.12", "config.toml", "the containerd config.toml file", "containerd_config", "/etc/containerd/config.toml"),
    audit("1.1.13", "/etc/sysconfig/docker", "the /etc/sysconfig/docker file", "etc_sysconfig_docker", "/etc/sysconfig/docker"),
    audit("1.1.14", "/usr/bin/containerd", "the containerd binary", "containerd_binary", "/usr/bin/containerd"),
    audit("1.1.15", "/usr/bin/containerd-shim", "the containerd-shim binary", "containerd_shim_binary", "/usr/bin/containerd-shim"),
    audit("1.1.16", "containerd-shim-runc-v1", "the containerd-shim-runc-v1 binary", "containerd_shim_runc_v1_binary",
          "/usr/bin/containerd-shim-runc-v1"),
    audit("1.1.17", "containerd-shim-runc-v2", "the containerd-shim-runc-v2 binary", "containerd_shim_runc_v2_binary",
          "/usr/bin/containerd-shim-runc-v2"),
    audit("1.1.18", "/usr/bin/runc", "the runc binary", "runc_binary", "/usr/bin/runc"),
    att("1.2.1", "hardened", "the container host must be hardened to its own OS baseline", "host_hardened"),
    att("1.2.2", "version of docker", "the Docker engine version must be free of known critical and high vulnerabilities",
        "docker_version_reviewed"),
    # 2 Daemon configuration
    fact("2.1", "non-root user", "the Docker daemon must run rootless unless a rootful daemon is attested as required",
         [f"is_string({D}.daemon_process.user)"], "docker.daemon_process.user",
         [f'not {D}.daemon_process.user in {{"", "root", "0"}}'], rep("/docker/daemon_process/user", "root"),
         rm("/docker/daemon_process"), ok2=attested("rootful_daemon_required")),
    fact("2.2", "default bridge", "inter-container traffic on the default bridge network must be off",
         ["_networks_collected"], "docker.networks",
         ["every n in _default_bridges { _opt(n, \"com.docker.network.bridge.enable_icc\") == \"false\" }"],
         rep("/docker/networks/0/Options/com.docker.network.bridge.enable_icc", "true"), rm("/docker/networks")),
    daemon("2.3", "logging level", "the daemon log level must be info",
           ['lower(_d("log-level", "info")) == "info"'], rep("/docker/daemon/log-level", "debug")),
    daemon("2.4", "iptables", "the daemon must keep managing iptables rules",
           ['_d("iptables", true) == true'], rep("/docker/daemon/iptables", False)),
    fact("2.5", "insecure registries", "insecure registries must not be configured beyond loopback",
         ["_daemon_collected", f"is_object({D}.info.RegistryConfig)"], "docker.daemon / docker.info.RegistryConfig",
         ['count(_as_list(_d("insecure-registries", []))) == 0',
          f'every r in _as_list(object.get({D}.info.RegistryConfig, "InsecureRegistryCIDRs", [])) {{ r in _loopback_cidrs }}',
          f'every _, x in object.get({D}.info.RegistryConfig, "IndexConfigs", {{}}) {{ object.get(x, "Secure", null) == true }}'],
         rep("/docker/info/RegistryConfig/InsecureRegistryCIDRs/-", "10.0.0.0/8"), rm("/docker/info/RegistryConfig")),
    info("2.6", "aufs", "the storage driver must not be aufs", "Driver", "string",
         [f'lower({D}.info.Driver) != "aufs"'], rep("/docker/info/Driver", "aufs")),
    info("2.7", "devicemapper", "the storage driver must not be devicemapper", "Driver", "string",
         [f'lower({D}.info.Driver) != "devicemapper"'], rep("/docker/info/Driver", "devicemapper")),
    daemon("2.8", "tls authentication", "a daemon listening on TCP must verify client certificates (tlsverify, CA, cert, key)",
           ["not _daemon_tcp"], rep("/docker/daemon/hosts", ["unix:///var/run/docker.sock", "tcp://0.0.0.0:2376"]),
           ok2=['_d("tlsverify", false) == true', '_nonempty(_d("tlscacert", ""))', '_nonempty(_d("tlscert", ""))',
                '_nonempty(_d("tlskey", ""))']),
    daemon("2.9", "default ulimit", "default ulimits must be set on the daemon or the defaults attested as suitable",
           ['count(_d("default-ulimits", {})) > 0'], rm("/docker/daemon/default-ulimits"),
           ok2=attested("default_ulimits_reviewed")),
    daemon("2.15", "new privileges", "the daemon must set no-new-privileges for containers",
           ['_d("no-new-privileges", false) == true'], rep("/docker/daemon/no-new-privileges", False)),
    info("2.16", "live restore", "live restore must be on", "LiveRestoreEnabled", "boolean",
         [f"{D}.info.LiveRestoreEnabled == true"], rep("/docker/info/LiveRestoreEnabled", False)),
    daemon("2.17", "userland proxy", "the userland proxy must be off",
           ['_d("userland-proxy", true) == false'], rm("/docker/daemon/userland-proxy")),
    fact("2.19", "experimental", "the engine must not run with experimental features",
         [f"is_boolean({D}.version.Server.Experimental)"], "docker.version.Server.Experimental",
         [f"{D}.version.Server.Experimental == false"], rep("/docker/version/Server/Experimental", True),
         rm("/docker/version")),
    info("2.10", "user namespace", "user namespace remapping must be on", "SecurityOptions", "array",
         ['_secopt("userns")'], rep("/docker/info/SecurityOptions", ["name=seccomp,profile=builtin", "name=selinux"])),
    daemon("2.11", "cgroup", "the daemon must keep the default cgroup parent unless another is attested as reviewed",
           ['_d("cgroup-parent", "") == ""'], rep("/docker/daemon/cgroup-parent", "/custom"),
           ok2=attested("cgroup_parent_reviewed")),
    daemon("2.12", "base device size", "the devicemapper base device size must not be overridden",
           ['every o in _as_list(_d("storage-opts", [])) { not startswith(lower(trim_space(o)), "dm.basesize") }'],
           rep("/docker/daemon/storage-opts", ["dm.basesize=50G"])),
    daemon("2.13", "authorization", "an authorization plugin must be configured for client commands",
           ['count(_as_list(_d("authorization-plugins", []))) > 0'], rep("/docker/daemon/authorization-plugins", [])),
    info("2.14", "remote logging", "the daemon must use a remote logging driver or central log shipping must be attested",
         "LoggingDriver", "string", [f"lower({D}.info.LoggingDriver) in _remote_log_drivers"],
         rep("/docker/info/LoggingDriver", "json-file"), ok2=attested("central_logging_configured")),
    fact("2.18", "seccomp profile", "seccomp must be on with a custom daemon profile or the built-in profile attested as sufficient",
         ["_daemon_collected", f"is_array({D}.info.SecurityOptions)"], "docker.daemon / docker.info.SecurityOptions",
         ['_secopt("seccomp")', "not _seccomp_unconfined", '_nonempty(_d("seccomp-profile", ""))'],
         rep("/docker/info/SecurityOptions", ["name=seccomp,profile=unconfined", "name=userns", "name=selinux"]),
         rm("/docker/info/SecurityOptions"),
         ok2=['_secopt("seccomp")', "not _seccomp_unconfined", f"{D}.attest.default_seccomp_profile_sufficient == true"]),
    # 3 Daemon configuration files
    owner("3.1", "docker.service", "the docker.service unit file", "docker_service"),
    mode("3.2", "docker.service", "the docker.service unit file", "docker_service", "644", "664"),
    owner("3.3", "docker.socket", "the docker.socket unit file", "docker_socket_unit"),
    mode("3.4", "docker.socket", "the docker.socket unit file", "docker_socket_unit", "644", "646"),
    owner("3.5", "/etc/docker", "the /etc/docker directory", "etc_docker"),
    mode("3.6", "/etc/docker", "the /etc/docker directory", "etc_docker", "755", "775"),
    fact("3.7", "registry certificate", "registry certificate files must be owned by root:root",
         [f"is_array({D}.files.registry_certs)"], "docker.files.registry_certs",
         [f'every f in {D}.files.registry_certs {{ f.owner == "root"; f.group == "root" }}'],
         rep("/docker/files/registry_certs/0/group", "docker"), rm("/docker/files/registry_certs")),
    fact("3.8", "registry certificate", "registry certificate files must have mode 444 or stricter",
         [f"is_array({D}.files.registry_certs)"], "docker.files.registry_certs",
         [f'every f in {D}.files.registry_certs {{ mode_within(f.mode, "444") }}'],
         rep("/docker/files/registry_certs/0/mode", "644"), rm("/docker/files/registry_certs")),
    owner("3.9", "ca certificate", "the daemon TLS CA certificate", "tls_ca_cert"),
    mode("3.10", "ca certificate", "the daemon TLS CA certificate", "tls_ca_cert", "444", "644"),
    owner("3.11", "server certificate file", "the daemon TLS server certificate", "tls_server_cert"),
    mode("3.12", "server certificate file", "the daemon TLS server certificate", "tls_server_cert", "444", "464"),
    owner("3.13", "certificate key", "the daemon TLS server key", "tls_server_key"),
    mode("3.14", "certificate key", "the daemon TLS server key", "tls_server_key", "400", "440"),
    owner("3.15", "docker socket", "the Docker socket", "docker_sock", "docker"),
    mode("3.16", "docker socket", "the Docker socket", "docker_sock", "660", "666"),
    owner("3.17", "daemon.json", "the daemon.json file", "daemon_json"),
    mode("3.18", "daemon.json", "the daemon.json file", "daemon_json", "644", "666"),
    owner("3.19", "/etc/default/docker", "the /etc/default/docker file", "etc_default_docker"),
    mode("3.20", "/etc/default/docker", "the /etc/default/docker file", "etc_default_docker", "644", "664"),
    mode("3.21", "/etc/sysconfig/docker", "the /etc/sysconfig/docker file", "etc_sysconfig_docker", "644", "674"),
    owner("3.22", "/etc/sysconfig/docker", "the /etc/sysconfig/docker file", "etc_sysconfig_docker"),
    owner("3.23", "containerd socket", "the containerd socket", "containerd_sock"),
    mode("3.24", "containerd socket", "the containerd socket", "containerd_sock", "660", "662"),
    # 4 Images and build files
    per("4.1", "user for the container", "the main process of a running container must not run as uid 0", "containers",
        [["is_number(c.runtime.pid1_euid)", "c.runtime.pid1_euid != 0"]], con(0, "runtime/pid1_euid", 0), scope="_running"),
    att("4.2", "trusted base images", "base images must come from sources the organisation trusts", "trusted_base_images"),
    att("4.3", "unnecessary packages", "images must carry only the packages the workload needs", "minimal_packages_reviewed"),
    att("4.4", "scanned and rebuilt", "images must be vulnerability-scanned and rebuilt with security patches",
        "images_scanned_and_rebuilt"),
    per("4.5", "healthcheck", "every image must define a health check", "images",
        [["is_array(i.Config.Healthcheck.Test)", "count(i.Config.Healthcheck.Test) > 0",
          'upper(i.Config.Healthcheck.Test[0]) != "NONE"']], [{"op": "remove", "path": "/docker/images/0/Config/Healthcheck"}]),
    per("4.6", "update instructions", "an image build step must not refresh the package index without installing in the same step",
        "images", [["is_array(i.history)", "every h in i.history { not _update_alone(h) }"]],
        img("history/-", "/bin/sh -c apt-get update")),
    per("4.8", "copy is used", "image build steps must not use ADD (the base root filesystem layer aside)", "images",
        [["is_array(i.history)", "every h in i.history { not _add_step(h) }"]],
        img("history/-", "/bin/sh -c #(nop) ADD https://example.com/app.tar.gz /opt/")),
    att("4.9", "secrets", "image build steps must not embed secrets", "no_secrets_in_images"),
    att("4.11", "signed artifacts", "signatures of signed artifacts must be verified before use", "signed_artifacts_validated"),
    per("4.7", "setuid and setgid", "images must hold no setuid or setgid files unless the list is attested as reviewed",
        "images", [["is_array(i.setuid_files)", "count(i.setuid_files) == 0"],
                   ["is_array(i.setuid_files)", f"{D}.attest.setuid_files_reviewed == true"]],
        img("setuid_files", ["/usr/bin/passwd"])),
    att("4.10", "verified packages", "packages installed into images must be authenticity-checked", "verified_packages_only"),
    # 5 Container runtime
    fact("5.1", "swarm mode", "swarm mode must be inactive unless it is attested as required",
         [f"is_string({D}.info.Swarm.LocalNodeState)"], "docker.info.Swarm.LocalNodeState",
         ['_swarm_state == "inactive"'], rm("/docker/attest/swarm_mode_required"), rm("/docker/info/Swarm/LocalNodeState"),
         ok2=attested("swarm_mode_required")),
    per("5.2", "apparmor", "every container must run under an AppArmor profile", "containers",
        [["is_string(c.AppArmorProfile)", 'not lower(c.AppArmorProfile) in {"", "unconfined"}']],
        con(0, "AppArmorProfile", "unconfined")),
    per("5.4", "kernel capabilities", "containers must drop NET_RAW and add only capabilities on the allowed list", "containers",
        [["is_object(c.HostConfig)", "dropped := _caps(c.HostConfig, \"CapDrop\")", "added := _caps(c.HostConfig, \"CapAdd\")",
          'count(dropped & {"NET_RAW", "ALL"}) > 0', "every a in added { a in _allowed_caps }"]],
        con(0, "HostConfig/CapAdd", ["SYS_ADMIN"])),
    per("5.5", "privileged containers", "containers must not run privileged", "containers",
        [["c.HostConfig.Privileged == false"]], con(0, "HostConfig/Privileged", True)),
    per("5.6", "sensitive host", "containers must not mount sensitive host system directories read-write", "containers",
        [["is_array(c.Mounts)", "every m in c.Mounts { not _sensitive_mount(m) }"]],
        con(0, "Mounts/-", {"Type": "bind", "Source": "/etc", "Destination": "/host/etc", "RW": True, "Propagation": "rprivate"})),
    per("5.7", "sshd", "running containers must not run an SSH server", "containers",
        [["is_array(c.runtime.processes)", "every p in c.runtime.processes { not _is_sshd(p) }"]],
        con(0, "runtime/processes/-", "/usr/sbin/sshd -D"), scope="_running"),
    per("5.8", "privileged ports", "containers must not publish host ports below 1024 outside the allowed list", "containers",
        [["bs := _bindings(c)", "every b in bs { _host_port_ok(b) }"]],
        con(0, "NetworkSettings/Ports/8080~1tcp", [{"HostIp": "10.0.0.5", "HostPort": "80"}]), scope="_running"),
    att("5.9", "only needed ports", "containers must publish only the ports the workload needs", "only_needed_ports_open"),
    host_ns("5.10", "network namespace", "network", "NetworkMode"),
    per("5.11", "memory usage", "every container must have a memory limit", "containers",
        [["is_number(c.HostConfig.Memory)", "c.HostConfig.Memory > 0"]], con(0, "HostConfig/Memory", 0)),
    per("5.12", "cpu priority", "every container must have CPU shares set away from the default", "containers",
        [["is_number(c.HostConfig.CpuShares)", "not c.HostConfig.CpuShares in {0, 1024}"]], con(0, "HostConfig/CpuShares", 1024)),
    per("5.13", "read only", "the root filesystem of every container must be read-only", "containers",
        [["c.HostConfig.ReadonlyRootfs == true"]], con(0, "HostConfig/ReadonlyRootfs", False)),
    per("5.14", "specific host interface", "published container ports must bind a specific host address, not the wildcard",
        "containers", [["bs := _bindings(c)", "every b in bs { _host_ip_specific(b) }"]],
        con(0, "NetworkSettings/Ports/8080~1tcp", [{"HostIp": "0.0.0.0", "HostPort": "8080"}]), scope="_running"),
    per("5.15", "restart policy", "a container restart policy must be off or on-failure with at most 5 retries", "containers",
        [['c.HostConfig.RestartPolicy.Name in {"", "no"}'],
         ['c.HostConfig.RestartPolicy.Name == "on-failure"', "is_number(c.HostConfig.RestartPolicy.MaximumRetryCount)",
          "c.HostConfig.RestartPolicy.MaximumRetryCount > 0", "c.HostConfig.RestartPolicy.MaximumRetryCount <= 5"]],
        con(0, "HostConfig/RestartPolicy", {"Name": "on-failure", "MaximumRetryCount": 0})),
    host_ns("5.16", "process namespace", "process", "PidMode"),
    host_ns("5.17", "ipc namespace", "IPC", "IpcMode"),
    per("5.18", "host devices", "containers must not be given host devices outside the allowed list", "containers",
        [["is_object(c.HostConfig)", 'every d in _as_list(object.get(c.HostConfig, "Devices", [])) { d.PathOnHost in _allowed_devices }']],
        con(0, "HostConfig/Devices", [{"PathOnHost": "/dev/sda", "PathInContainer": "/dev/sda", "CgroupPermissions": "rwm"}])),
    per("5.19", "default ulimit", "containers must not override ulimits unless the overrides are attested as reviewed",
        "containers", [["is_object(c.HostConfig)", 'count(_as_list(object.get(c.HostConfig, "Ulimits", []))) == 0'],
                       ["is_object(c.HostConfig)", f"{D}.attest.container_ulimit_overrides_reviewed == true"]],
        con(0, "HostConfig/Ulimits", [{"Name": "nofile", "Soft": 1024, "Hard": 2048}])),
    per("5.20", "mount propagation", "container mounts must not use shared propagation", "containers",
        [["is_array(c.Mounts)", 'every m in c.Mounts { not lower(object.get(m, "Propagation", "")) in {"shared", "rshared"} }']],
        con(0, "Mounts/0/Propagation", "shared")),
    host_ns("5.21", "uts namespace", "UTS", "UTSMode"),
    per("5.22", "seccomp profile", "containers must not run with seccomp unconfined", "containers",
        [["is_object(c.HostConfig)", 'every o in _secopts(c) { not _opt_is(o, "seccomp", "unconfined") }']],
        con(0, "HostConfig/SecurityOpt/-", "seccomp=unconfined")),
    per("5.25", "cgroup usage", "containers must run under the default cgroup parent", "containers",
        [['c.HostConfig.CgroupParent == ""']], con(0, "HostConfig/CgroupParent", "/custom")),
    per("5.26", "additional privileges", "every container must run with no-new-privileges (its own option or the daemon default)",
        "containers", [["is_object(c.HostConfig)", "_nnp_on(c)"],
                       ["is_object(c.HostConfig)", "not _nnp_off(c)", '_d("no-new-privileges", false) == true']],
        [{"op": "add", "path": "/docker/containers/0/HostConfig/SecurityOpt", "value": ["no-new-privileges=false", "label=type:container_t"]}]),
    per("5.27", "health", "every running container must report a health status", "containers",
        [['lower(c.State.Health.Status) in {"healthy", "unhealthy", "starting"}']],
        [{"op": "remove", "path": "/docker/containers/0/State/Health"}], scope="_running"),
    att("5.28", "latest version", "images must be pulled fresh before use, not taken from a stale local cache",
        "images_pulled_fresh_before_use"),
    per("5.29", "pids cgroup", "every running container must have a PIDs limit", "containers",
        [["is_number(c.HostConfig.PidsLimit)", "c.HostConfig.PidsLimit > 0"]], con(0, "HostConfig/PidsLimit", -1), scope="_running"),
    host_ns("5.31", "user namespaces", "user", "UsernsMode"),
    per("5.32", "docker socket", "containers must not mount the Docker socket", "containers",
        [["is_array(c.Mounts)", "every m in c.Mounts { not _is_docker_sock(m) }"]],
        con(0, "Mounts/-", {"Type": "bind", "Source": "/var/run/docker.sock", "Destination": "/var/run/docker.sock", "RW": True})),
    per("5.3", "selinux", "every container must run with SELinux labels", "containers",
        [["is_object(c.HostConfig)", "_nonempty(c.ProcessLabel)", "_nonempty(c.MountLabel)",
          'every o in _secopts(c) { not _opt_is(o, "label", "disable") }']], con(0, "ProcessLabel", "")),
    fact("5.23", "privileged option", "the audit trail must hold no docker exec run with the privileged option",
         [f"is_array({D}.exec_audit.privileged_events)"], "docker.exec_audit.privileged_events",
         [f"count({D}.exec_audit.privileged_events) == 0"],
         rep("/docker/exec_audit/privileged_events/-", "docker exec --privileged web sh"), rm("/docker/exec_audit/privileged_events")),
    fact("5.24", "user=root", "the audit trail must hold no docker exec run as root",
         [f"is_array({D}.exec_audit.root_user_events)"], "docker.exec_audit.root_user_events",
         [f"count({D}.exec_audit.root_user_events) == 0"],
         rep("/docker/exec_audit/root_user_events/-", "docker exec --user=root web sh"), rm("/docker/exec_audit/root_user_events")),
    per("5.30", "docker0", "containers must not attach to a network on the docker0 bridge", "containers",
        [["is_object(c.NetworkSettings.Networks)", "every n, _ in c.NetworkSettings.Networks { not n in _docker0_networks }"]],
        con(0, "NetworkSettings/Networks/bridge", {"IPAddress": "172.17.0.2"}),
        extra_ev=["_networks_collected"], extra_label=" / docker.networks"),
    # 6 Security operations
    fact("6.1", "image sprawl", "the host must hold no unused images unless they are attested as reviewed",
         ["_images_collected", "_containers_collected"], "docker.images / docker.containers",
         ["count(_unused_images) == 0"], rep("/docker/images/-", {"Id": "sha256:0ld", "RepoTags": ["old:1"]}), rm("/docker/images"),
         ok2=attested("unused_images_reviewed")),
    info("6.2", "container sprawl", "the host must hold no stopped containers unless they are attested as reviewed",
         "ContainersStopped", "number", [f"{D}.info.ContainersStopped == 0"], rep("/docker/info/ContainersStopped", 12),
         ok2=attested("stopped_containers_reviewed")),
    # 7 Swarm
    att("7.1", "manager nodes", "the number of swarm managers must be the minimum the cluster needs", "swarm_manager_count_reviewed"),
    fact("7.2", "specific host interface", "swarm ports 2377 and 7946 must listen on a specific address, not the wildcard",
         [f"is_array({D}.swarm.listeners)", f"count({D}.swarm.listeners) > 0"], "docker.swarm.listeners",
         [f"every l in {D}.swarm.listeners {{ _addr_specific(l.address) }}"],
         rep("/docker/swarm/listeners/0/address", "0.0.0.0"), rm("/docker/swarm/listeners")),
    fact("7.3", "overlay networks", "every overlay network must be encrypted", ["_networks_collected"], "docker.networks",
         ["every n in _overlays { _has_opt(n, \"encrypted\") }"],
         [{"op": "remove", "path": "/docker/networks/1/Options/encrypted"}], rm("/docker/networks")),
    att("7.4", "secret management", "swarm services must take their secrets from Docker secrets", "swarm_secrets_used"),
    fact("7.5", "auto-lock", "swarm manager auto-lock must be on",
         [f"is_boolean({D}.info.Swarm.Cluster.Spec.EncryptionConfig.AutoLockManagers)"],
         "docker.info.Swarm.Cluster.Spec.EncryptionConfig.AutoLockManagers",
         [f"{D}.info.Swarm.Cluster.Spec.EncryptionConfig.AutoLockManagers == true"],
         rep("/docker/info/Swarm/Cluster/Spec/EncryptionConfig/AutoLockManagers", False),
         rm("/docker/info/Swarm/Cluster/Spec/EncryptionConfig")),
    att("7.6", "auto-lock key", "the swarm unlock key must be rotated on the organisation's schedule", "autolock_key_rotated"),
    fact("7.7", "node certificates", "the swarm node certificate lifetime must be within the allowed maximum (90 days unless set)",
         [f"is_number({D}.info.Swarm.Cluster.Spec.CAConfig.NodeCertExpiry)"],
         "docker.info.Swarm.Cluster.Spec.CAConfig.NodeCertExpiry",
         [f"{D}.info.Swarm.Cluster.Spec.CAConfig.NodeCertExpiry > 0",
          f"{D}.info.Swarm.Cluster.Spec.CAConfig.NodeCertExpiry <= _max_node_cert_ns"],
         rep("/docker/info/Swarm/Cluster/Spec/CAConfig/NodeCertExpiry", 31536000000000000),
         rm("/docker/info/Swarm/Cluster/Spec/CAConfig")),
    att("7.8", "ca certificates", "the swarm root CA certificate must be rotated on the organisation's schedule",
        "swarm_ca_rotated"),
    fact("7.9", "management plane", "the swarm data path address must differ from the management address",
         [f"is_string({D}.info.Swarm.NodeAddr)", f"is_string({D}.swarm.data_path_addr)"],
         "docker.info.Swarm.NodeAddr / docker.swarm.data_path_addr",
         [f"_nonempty({D}.info.Swarm.NodeAddr)", f"_nonempty({D}.swarm.data_path_addr)",
          f"{D}.info.Swarm.NodeAddr != {D}.swarm.data_path_addr"],
         rep("/docker/swarm/data_path_addr", "10.0.0.5"), rm("/docker/swarm/data_path_addr")),
]

MANAGER_ONLY = {"7.1", "7.4", "7.5", "7.6", "7.7", "7.8"}
MAC = {"5.2": "apparmor", "5.3": "selinux"}


def idkey(i):
    return [int(p) for p in i.split(".")]


C.sort(key=lambda c: idkey(c["id"]))

# ── workbook checks: abort on any count, id, status, profile or keyword mismatch ─────────────────────────────────
ids = [c["id"] for c in C]
if len(ids) != len(set(ids)):
    raise SystemExit("duplicate id in the logic table")
if set(ids) != set(WB):
    raise SystemExit(f"id mismatch with the workbook: {sorted(set(ids) ^ set(WB), key=idkey)}")
got = {"total": len(WB)}
for w in WB.values():
    got[w["assessment"]] = got.get(w["assessment"], 0) + 1
    got[w["profiles"][0]] = got.get(w["profiles"][0], 0) + 1
if got != EXPECT:
    raise SystemExit(f"workbook counts {got} differ from {EXPECT}")
for c in C:
    w = WB[c["id"]]
    if c["kw"] not in w["title"].lower():
        raise SystemExit(f"{c['id']}: logic keyword {c['kw']!r} not in the workbook title")
    if w["assessment"] == "Automated" and c["kind"] != "fact":
        raise SystemExit(f"{c['id']}: Automated in the workbook but attested here")
    if neutralize_title(c["title"]) != c["title"] or re.search(r"\bEnsure\b", c["title"]):
        raise SystemExit(f"{c['id']}: title {c['title']!r} is not in house wording")
    if (w["profiles"][0] == "Level 1 - Docker Swarm") != c["id"].startswith("7."):
        raise SystemExit(f"{c['id']}: swarm profile and section 7 no longer coincide")

# the emitter reads titles from the record map: hand it ours, never the workbook's
WBX = {c["id"]: dict(WB[c["id"]], title=c["title"]) for c in C}

SECTIONS = ["host_configuration", "daemon_configuration", "daemon_files", "images", "container_runtime",
            "security_operations", "swarm"]
SECTION_TITLES = {
    "host_configuration": "1 Host configuration (partition, docker group, audit rules, host baseline)",
    "daemon_configuration": "2 Docker daemon configuration", "daemon_files": "3 Docker daemon configuration files",
    "images": "4 Container images and build files", "container_runtime": "5 Container runtime",
    "security_operations": "6 Docker security operations",
    "swarm": "7 Docker Swarm (applies when swarm mode is active)",
}


def section(cid):
    return SECTIONS[int(cid.split(".")[0]) - 1]


def cont(name, **over):
    c = {
        "Id": f"{name}0001", "Name": f"/{name}", "Image": "sha256:app1",
        "State": {"Running": True, "Pid": 4242, "Health": {"Status": "healthy"}},
        "AppArmorProfile": "docker-default", "ProcessLabel": "system_u:system_r:container_t:s0:c1,c2",
        "MountLabel": "system_u:object_r:container_file_t:s0:c1,c2",
        "HostConfig": {"Privileged": False, "CapAdd": None, "CapDrop": ["ALL"], "NetworkMode": "app_net", "Memory": 536870912,
                       "CpuShares": 512, "ReadonlyRootfs": True, "RestartPolicy": {"Name": "on-failure", "MaximumRetryCount": 5},
                       "PidMode": "", "IpcMode": "private", "UTSMode": "", "UsernsMode": "", "Devices": [], "Ulimits": None,
                       "SecurityOpt": ["no-new-privileges", "label=type:container_t"], "CgroupParent": "", "PidsLimit": 100},
        "Mounts": [{"Type": "volume", "Source": "/var/lib/docker/volumes/data/_data", "Destination": "/data", "RW": True,
                    "Propagation": ""}],
        "NetworkSettings": {"Ports": {"8080/tcp": [{"HostIp": "10.0.0.5", "HostPort": "8080"}], "9090/tcp": None},
                            "Networks": {"app_net": {"IPAddress": "10.10.0.2"}}},
        "runtime": {"pid1_euid": 1000, "processes": ["/usr/bin/app --serve", "/usr/bin/app --worker"]},
    }
    c.update(over)
    return c


def f(path, owner="root", group="root", mode="644"):
    return {"exists": True, "path": path, "owner": owner, "group": group, "mode": mode}


FILES = {
    "docker_service": f("/usr/lib/systemd/system/docker.service"),
    "docker_socket_unit": f("/usr/lib/systemd/system/docker.socket"),
    "etc_docker": f("/etc/docker", mode="755"),
    "registry_certs": [{"path": "/etc/docker/certs.d/registry.example.com/ca.crt", "owner": "root", "group": "root", "mode": "444"}],
    "tls_ca_cert": f("/etc/docker/tls/ca.pem", mode="444"), "tls_server_cert": f("/etc/docker/tls/server-cert.pem", mode="444"),
    "tls_server_key": f("/etc/docker/tls/server-key.pem", mode="400"),
    "docker_sock": f("/var/run/docker.sock", group="docker", mode="660"),
    "containerd_sock": f("/run/containerd/containerd.sock", mode="660"),
    "daemon_json": f("/etc/docker/daemon.json"), "etc_default_docker": f("/etc/default/docker"),
    "etc_sysconfig_docker": f("/etc/sysconfig/docker", mode="640"),
}
DATA_ROOT = "/var/lib/docker"
AUDIT_PATHS["1.1.5"] = DATA_ROOT
RULE = {cid: (f"-a always,exit -F arch=b64 -F path={p} -F perm=x -F key=docker" if p.startswith("/usr/bin/")
              else f"-w {p} -p rwxa -k docker") for cid, p in AUDIT_PATHS.items()}
RULES = [RULE[cid] for cid in sorted(RULE, key=idkey)]
for c in C:
    if c["id"] in RULE:
        c["fail"] = [{"op": "replace", "path": "/auditd/active_rules", "value": [r for r in RULES if r != RULE[c["id"]]]}]

GREEN = {
    "cis_profile": {"level": 2},
    "auditd": {"active_rules": RULES},
    "docker": {
        "platform": {},
        "host": {"data_root_is_mountpoint": True},
        "docker_group": {"members": ["deploy"], "approved_members": ["deploy", "ops"]},
        "daemon_process": {"user": "dockeruser"},  # 2.1 reads the user; no recommendation reads a rootless flag
        "daemon": {"icc": False, "log-level": "info", "iptables": True, "hosts": ["unix:///var/run/docker.sock"],
                   "default-ulimits": {"nofile": {"Name": "nofile", "Soft": 1024, "Hard": 4096}}, "no-new-privileges": True,
                   "live-restore": True, "userland-proxy": False, "userns-remap": "default",
                   "authorization-plugins": ["opa-docker-authz"], "log-driver": "syslog", "seccomp-profile": "/etc/docker/seccomp.json"},
        "info": {"Driver": "overlay2", "DockerRootDir": DATA_ROOT, "LiveRestoreEnabled": True, "LoggingDriver": "syslog",
                 "SecurityOptions": ["name=seccomp,profile=/etc/docker/seccomp.json", "name=selinux", "name=userns"],
                 "RegistryConfig": {"InsecureRegistryCIDRs": ["127.0.0.0/8", "::1/128"],
                                    "IndexConfigs": {"docker.io": {"Name": "docker.io", "Secure": True}}},
                 "Containers": 2, "ContainersRunning": 2, "ContainersStopped": 0, "Images": 1,
                 "Swarm": {"LocalNodeState": "active", "ControlAvailable": True, "Managers": 3, "Nodes": 5, "NodeAddr": "10.0.0.5",
                           "Cluster": {"Spec": {"EncryptionConfig": {"AutoLockManagers": True},
                                                "CAConfig": {"NodeCertExpiry": 7776000000000000}}}}},
        "version": {"Server": {"Version": "27.3.1", "Experimental": False}},
        "networks": [
            {"Name": "bridge", "Driver": "bridge", "Scope": "local",
             "Options": {"com.docker.network.bridge.enable_icc": "false", "com.docker.network.bridge.name": "docker0"}},
            {"Name": "app_net", "Driver": "overlay", "Scope": "swarm", "Options": {"encrypted": ""}},
        ],
        "files": FILES,
        "containers": [cont("web"), cont("worker")],
        "images": [{"Id": "sha256:app1", "RepoTags": ["registry.example.com/app:1.4.2"],
                    "Config": {"User": "app", "Healthcheck": {"Test": ["CMD", "/usr/bin/app", "--health"]}},
                    "history": ["/bin/sh -c #(nop) ADD file:0a1b2c3d4e5f in / ",
                                "/bin/sh -c apt-get update && apt-get install -y --no-install-recommends ca-certificates",
                                "/bin/sh -c #(nop) COPY file:77aa in /usr/bin/app ", "/bin/sh -c #(nop)  USER app"],
                    "setuid_files": []}],
        "exec_audit": {"privileged_events": [], "root_user_events": []},
        "swarm": {"listeners": [{"address": "10.0.0.5"}, {"address": "10.0.0.5"}],  # 7.2 reads each listener's address only
                  "data_path_addr": "10.0.1.5"},
        "attest": {"swarm_mode_required": True},
    },
}
attest_ids = [c["id"] for c in C if c["kind"] == "attest"]
for c in C:
    if c["kind"] == "attest":
        GREEN["docker"]["attest"][c["attest"]] = True
fact_manual = [c["id"] for c in C if c["kind"] == "fact" and WB[c["id"]]["assessment"] == "Manual"]
N = {k: sum(1 for i in ids if WB[i]["profiles"][0] == k) for k in EXPECT if k.startswith("Level")}
L1, L2, SW = N["Level 1 - Docker - Linux"], N["Level 2 - Docker - Linux"], N["Level 1 - Docker Swarm"]
AUTO = EXPECT["Automated"]


def meta(title, density, entry):
    return f'''# METADATA
# title: "{title}"
# custom:
#   class: security
#   framework: cis_docker
#   source: cis
#   domains: [container]
#   coverage:
#     checks: 0
#     cited: 0
#     density: {density}
#     basis: {"role" if density == "orchestrator" else "size"}
#     tested: true
#     entrypoint: {entry}
#     guard: self
#     as_of: v2.4.2
'''


HEADER = meta(BENCH, "sized", "compliance_report") + f'''package cis_docker

# {BENCH}. Generated by tools/cis_generators/gen_docker.py from the CIS workbook: do not edit by hand, regenerate.
# The framework entrypoint is data.cis_docker.main.compliance_report (cis_docker_main.rego).
#
# {len(ids)} recommendations, every one in the benchmark; ids, profiles and assessment status are read from the workbook
# ({L1} Level 1 and {L2} Level 2 for Docker on a Linux host, {SW} Level 1 for Docker Swarm; {AUTO} Automated, {len(ids) - AUTO} Manual).
# - {len(ids) - len(attest_ids)} are decided from collected facts and fail closed: a fact that was not collected is an
#   "evidence missing" violation, never a pass. {len(fact_manual)} of them are Manual in the workbook but their audit
#   procedure reads a collectable value, so they are checked like the Automated ones.
# - {len(attest_ids)} need a human judgement and use an attestation boolean under input.docker.attest
#   (not attested => violation): {", ".join(attest_ids)}.
# - Where the benchmark says "unless needed", the fact decides first and a named attestation is the documented
#   exception: 2.1 rootful_daemon_required, 2.9 default_ulimits_reviewed, 2.11 cgroup_parent_reviewed,
#   2.14 central_logging_configured, 2.18 default_seccomp_profile_sufficient, 4.7 setuid_files_reviewed,
#   5.1 swarm_mode_required, 5.19 container_ulimit_overrides_reviewed, 6.1 unused_images_reviewed,
#   6.2 stopped_containers_reviewed.
#
# Profile (input.cis_profile):
#   level  : the number 1 or 2 (Level 2 includes Level 1). Absent => 2 (level_defaulted: true) with a PROFILE NOT
#            SELECTED finding, and the result is never compliant. Any other value
#            (the strings "1" and "2" included) is invalid evidence: the report is scoped at Level 2 and every
#            Level 2 recommendation in scope reports it.
#   swarm  : true forces the Swarm profile in, false leaves it out; absent => decided by the collected fact:
#            the {SW} Swarm recommendations apply unless input.docker.info.Swarm.LocalNodeState is "inactive".
#            A state that was not collected counts as possibly active, so they apply and report evidence missing.
#            On a worker (Swarm.ControlAvailable == false) the manager-only ones ({", ".join(sorted(MANAGER_ONLY, key=idkey))}) do not apply.
#            compliance_report.swarm_profile states the state, the selection, the decision and its reason.
#   5.2 (AppArmor) and 5.3 (SELinux) follow input.docker.platform.mac ("apparmor", "selinux" or "none");
#   absent or unknown => both apply.
#
# Per-container and per-image checks iterate the collected list. An empty list passes; an absent list is evidence
# missing; an item that lacks the inspected field fails. compliance_report.offenders names the failing items.
#
# Input contract:
#   auditd.active_rules[]           : `auditctl -l` lines (the fact the CIS Linux modules read)
#   docker.info                     : `docker info --format '{{{{json .}}}}'`
#   docker.version                  : `docker version --format '{{{{json .}}}}'`
#   docker.daemon                   : effective daemon settings, daemon.json key names, dockerd flags merged in
#                                     ({{}} when nothing is set; booleans as booleans)
#   docker.daemon_process.user      : the account running dockerd
#   docker.networks[]               : `docker network inspect` of every network
#   docker.containers[]             : `docker inspect` of every container (`docker ps --all`), plus per running container
#                                     runtime.pid1_euid (effective uid of PID 1) and runtime.processes[] (`docker top` commands)
#   docker.images[]                 : `docker image inspect` of every image, plus history[] (`docker history --no-trunc`
#                                     CreatedBy lines) and setuid_files[] (setuid/setgid paths in the image)
#   docker.files.<key>              : {{exists, path, owner, group, mode}} for docker_service, docker_socket_unit, etc_docker,
#                                     tls_ca_cert, tls_server_cert, tls_server_key, docker_sock, containerd_sock, daemon_json,
#                                     etc_default_docker, etc_sysconfig_docker; exists == false means the file is not on
#                                     this host and its checks do not apply. mode is the octal string from `stat -c %a`.
#                                     Optional keys for the audit-rule targets (dockerd_binary, run_containerd,
#                                     containerd_config, containerd_binary, containerd_shim_binary,
#                                     containerd_shim_runc_v1_binary, containerd_shim_runc_v2_binary, runc_binary):
#                                     path overrides the default location, exists == false skips the rule.
#   docker.files.registry_certs[]   : {{path, owner, group, mode}} per file under /etc/docker/certs.d
#   docker.host.data_root_is_mountpoint : `mountpoint` on the Docker data root
#   docker.docker_group.{{members,approved_members}}[] : `getent group docker` and the operator's approved list
#   docker.exec_audit.{{privileged_events,root_user_events}}[] : `ausearch -k docker` hits for docker exec
#   docker.swarm.listeners[].address        : the address of each listener on 2377 and 7946 (7.2 reads the address only);
#                                            docker.swarm.data_path_addr
#   docker.policy.{{allowed_added_capabilities,allowed_sensitive_mounts,allowed_privileged_ports,allowed_host_devices}}[],
#   docker.policy.max_node_cert_expiry_days : optional operator allowances (default: none, 90 days)
#   docker.attest.*                 : attestation booleans

import rego.v1

default compliant := false

compliant if {{
	# fail-closed: no facts, no compliance
	input.docker
	count(violations) == 0
	count(profile_violations) == 0
}}

violations := sort([m | some m in _all_violations])

'''

HELPERS = open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "docker_helpers.rego.tmpl")).read()

parts = [HEADER]
for s in SECTIONS:
    parts.append(f"# {SECTION_TITLES[s]}\n{s}_violations := sort([m | some m in _v_{s}])\n\n_all_violations contains m if some m in _v_{s}\n")
parts.append(HELPERS)
for c in C:
    if c["pre"]:
        parts.append(c["pre"])
    parts.append(emit_control(c, WBX, f"_v_{section(c['id'])}", applies=True))


def extra(c, w):
    e = {"section": int(c["id"].split(".")[0]), "swarm": c["id"].startswith("7."), "manager_only": c["id"] in MANAGER_ONLY}
    if c["id"] in MAC:
        e["mac"] = MAC[c["id"]]
    return e


parts.append("# Every recommendation in the benchmark: our title, level, assessment status, CIS profile, section.\n"
             "recommendations := " + table(C, WBX, extra) + "\n")
sec_results = ",\n".join(f'\t"{s}": _section_result({i + 1})' for i, s in enumerate(SECTIONS))
parts.append(f'''
_applicable_ids := {{id | some id, _ in recommendations; _applies(id)}}

_failed_ids := {{id | some v in violations; id := split(v, ":")[0]}}

_level_ids(l) := {{id | some id, r in recommendations; r.level == l; not r.swarm; _applies(id)}}

_swarm_ids := {{id | some id, r in recommendations; r.swarm; _applies(id)}}

_section_result(n) := {{"total": count(sids), "failed": count(sids & _failed_ids)}} if {{
	sids := {{id | some id, r in recommendations; r.section == n; _applies(id)}}
}}

section_results := {{
{sec_results},
}}

offenders := _offenders

findings := [{{
	"title": "Docker host, daemon and container hardening",
	"description": "{BENCH} assessment of host audit rules, daemon settings, daemon file ownership and modes, images, running containers, operations and swarm",
	"severity": "HIGH",
	"details": sprintf("Found %d violations across %d recommendations", [count(violations), count(_failed_ids)]),
	"violations": violations,
	"remediation": "Apply the {BENCH} recommendation named in each violation; collect the missing facts where a violation reports evidence missing",
}}]

compliance_report := {{
	"benchmark": "{BENCH}",
	"version": "{VERSION}",
	"total_controls": count(_applicable_ids),
	"benchmark_total_controls": count(recommendations),
	"standard_total": {len(ids)},
	"standard_total_source": "{BENCH}, recommendations counted from the CIS workbook",
	"profile": {{"level": _level, "level_defaulted": _level_defaulted, "mac_frameworks": sort([m | some m in _mac])}},
	"swarm_profile": swarm_profile,
	"failed_controls": count(_failed_ids),
	"passed_controls": count(_applicable_ids) - count(_failed_ids),
	"level_1": {{"total": count(_level_ids(1)), "failed": count(_level_ids(1) & _failed_ids)}},
	"level_2": {{"total": count(_level_ids(2)), "failed": count(_level_ids(2) & _failed_ids)}},
	"swarm": {{"total": count(_swarm_ids), "failed": count(_swarm_ids & _failed_ids)}},
	"section_results": section_results,
	"offenders": offenders,
	"compliant": compliant,
	"violation_count": count(violations) + count(profile_violations),
	"violations": array.concat(violations, profile_violations),
}}
''')
OWNED = ["cis_docker_benchmark.rego", "cis_docker_main.rego", "tests/test_cis_docker_controls.rego", "README.md"]
os.makedirs(f"{OUT}/tests", exist_ok=True)
open(f"{OUT}/cis_docker_benchmark.rego", "w").write("\n".join(parts))

MAIN = meta(f"{BENCH} - compliance_report entrypoint", "orchestrator", "compliance_report") + f'''package cis_docker.main

# OPA query path: /v1/data/cis_docker/main/compliance_report (the framework key cis_docker).
# Generated by tools/cis_generators/gen_docker.py. Thin bridge over data.cis_docker, which already fails closed per
# recommendation; with no facts at all the report also says so explicitly.

import data.cis_docker as bench
import rego.v1

default _facts_supplied := false

_facts_supplied if count(object.keys(input)) > 0

_total := bench.compliance_report.total_controls

_failed := bench.compliance_report.failed_controls

default _pct := 0

_pct := round(((_total - _failed) * 100000) / _total) / 1000 if {{
	_total > 0
	not _pct_withheld
}}

# 100 means compliant. Every recommendation passed but the report is not compliant (PROFILE NOT SELECTED: the
# profile level is absent or invalid): passed + failed == total stays true, and the percentage is null with a
# stated reason instead of 100 beside compliant == false.
_pct := null if {{
	_total > 0
	_pct_withheld
}}

_pct_withheld if {{
	_total > 0
	_failed == 0
	not bench.compliant
}}

# the reason is a field of the report only when the percentage is withheld, so a normal report keeps its shape
default _pct_reason_fields := {{}}

_pct_reason_fields := {{"compliance_percentage_reason": "no profile level selected (input.cis_profile.level absent or invalid): every recommendation was evaluated and none failed, but the report is not compliant until a level is selected"}} if _pct_withheld

_no_facts_msg := sprintf(
	"FAIL-CLOSED: no facts supplied for %s — the assessment could not be evaluated. This is NOT a passing result; check that fact collection ran and produced input.",
	["cis_docker"],
)

_report_violations := array.concat(bench.compliance_report.violations, [_no_facts_msg]) if not _facts_supplied

_report_violations := bench.compliance_report.violations if _facts_supplied

compliance_report := object.union(object.union(bench.compliance_report, _pct_reason_fields), {{
	"framework": "cis_docker",
	"facts_supplied": _facts_supplied,
	"controls_basis": "recommendations of the benchmark that apply to the selected profile",
	"compliance_percentage": _pct,
	"violations": _report_violations,
	"violation_count": count(_report_violations),
}})

compliant := bench.compliant

violations := bench.violations
'''
open(f"{OUT}/cis_docker_main.rego", "w").write(MAIN)

PER_CONTAINER = [c["id"] for c in C if c["pre"] and "_cname" in c["pre"]]
PER_IMAGE = [c["id"] for c in C if c["pre"] and "_iname" in c["pre"]]
TOTAL = len(ids)
tests = f'''package cis_docker_test

import rego.v1

import data.cis_docker as b
import data.cis_docker.main as m

# Generated by tools/cis_generators/gen_docker.py for {BENCH}: every recommendation has a pass test (green input)
# and a fail test; fact-based checks also have an evidence-missing test; attestations fail when false or absent.

green := {json.dumps(GREEN, indent=chr(9), ensure_ascii=False)}

_has_id(vs, id) if {{
	some v in vs
	startswith(v, concat("", [id, ":"]))
}}

_patched(ops) := json.patch(green, ops)

test_green_input_is_compliant if {{
	vs := b.violations with input as green
	count(vs) == 0
	b.compliant with input as green
	r := m.compliance_report with input as green
	r.compliant == true
	r.total_controls == {TOTAL}
	r.failed_controls == 0
	r.compliance_percentage == 100
	count(r.offenders) == 0
}}

test_recommendation_count_matches_workbook if {{
	count(b.recommendations) == {TOTAL}
	count([id | some id, r in b.recommendations; r.level == 1; not r.swarm]) == {L1}
	count([id | some id, r in b.recommendations; r.level == 2]) == {L2}
	count([id | some id, r in b.recommendations; r.swarm]) == {SW}
	count([id | some id, r in b.recommendations; r.assessment == "Automated"]) == {AUTO}
	count([id | some id, r in b.recommendations; r.check == "attestation"]) == {len(attest_ids)}
}}

# the framework-key contract on empty input: an object, not compliant, every control failed
test_report_contract_on_empty_input if {{
	r := m.compliance_report with input as {{}}
	is_object(r)
	r.framework == "cis_docker"
	r.compliant == false
	r.total_controls == {TOTAL}
	r.failed_controls == {TOTAL}
	r.passed_controls == 0
	r.compliance_percentage == 0
	is_array(r.violations)
	r.violation_count == count(r.violations)
	r.swarm_profile.state == "unknown"
	r.swarm_profile.applicable == true
	r.profile.level_defaulted == true
	some v in r.violations
	startswith(v, "FAIL-CLOSED: no facts supplied")
}}

test_every_recommendation_fails_on_empty_input if {{
	vs := b.violations with input as {{}}
	every id, _ in b.recommendations {{ _has_id(vs, id) }}
}}

test_level_1_profile_leaves_level_2_out if {{
	r := b.compliance_report with input as {{"cis_profile": {{"level": 1}}}}
	r.total_controls == {L1 + SW}
	r.failed_controls == {L1 + SW}
	r.profile.level == 1
	r.profile.level_defaulted == false
	r.level_2.total == 0
	not _has_id(r.violations, "5.3")
	_has_id(r.violations, "5.5")
}}

# the level is the number 1 or 2: a string (the strings "1" and "2" included), null or another number never
# selects a profile; the report is scoped at Level 2 and every Level 2 recommendation in scope says so
test_level_of_another_type_is_invalid_evidence if {{
	every bad in ["1", "2", "one", null, 3, true] {{
		r := b.compliance_report with input as object.union(green, {{"cis_profile": {{"level": bad}}}})
		r.profile.level == 2
		r.profile.level_defaulted == true
		r.compliant == false
		r.level_2.total > 0
		r.level_2.failed == r.level_2.total
		r.failed_controls == r.level_2.total
		r.passed_controls + r.failed_controls == r.total_controls
		every id in {{i | some i, rec in b.recommendations; rec.level == 2; not rec.swarm; not rec.mac}} {{
			_has(r.violations, sprintf("%s: evidence invalid — cis_profile.level must be the number 1 or 2, got %s, so this Level 2 recommendation could not be scoped", [id, json.marshal(bad)]))
		}}
	}}
	every bad in ["1", null, []] {{
		r := b.compliance_report with input as object.union(green, {{"cis_profile": bad}})
		r.compliant == false
		r.level_2.failed == r.level_2.total
	}}
}}

# an absent level is not a selection: the whole benchmark is evaluated at Level 2, the report says so in one
# PROFILE NOT SELECTED finding, and it is never compliant, however green the facts are
test_level_absent_is_not_selected_and_never_compliant if {{
	every inp in [json.remove(green, ["/cis_profile/level"])] {{
		r := b.compliance_report with input as inp
		r.profile.level == 2
		r.profile.level_defaulted == true
		r.compliant == false
		r.failed_controls == 0
		data.cis_docker.main.compliance_report.compliance_percentage < 100 with input as inp
		count([v | some v in r.violations; startswith(v, "PROFILE NOT SELECTED: ")]) == 1
		not main_compliant(inp)
	}}
	every inp in [object.union(green, {{"cis_profile": {{"level": 1}}}}), green] {{
		r := b.compliance_report with input as inp
		r.compliant == true
		count([v | some v in r.violations; startswith(v, "PROFILE NOT SELECTED")]) == 0
	}}
	# an unusable level is reported the same way, next to the per-recommendation findings
	r := b.compliance_report with input as object.union(green, {{"cis_profile": {{"level": "2"}}}})
	count([v | some v in r.violations; startswith(v, "PROFILE NOT SELECTED: evidence invalid")]) == 1
}}

main_compliant(inp) if data.cis_docker.main.compliance_report.compliant with input as inp
main_compliant(inp) if data.cis_docker.main.compliance_report.compliance_percentage == 100 with input as inp

_has(vs, msg) if msg in vs

# swarm applicability is decided by the collected state and stated in the report
test_swarm_inactive_excludes_swarm_profile_explicitly if {{
	inp := _patched([
		{{"op": "replace", "path": "/docker/info/Swarm", "value": {{"LocalNodeState": "inactive"}}}},
		{{"op": "remove", "path": "/docker/swarm"}},
		{{"op": "remove", "path": "/docker/attest/swarm_mode_required"}},
	])
	r := b.compliance_report with input as inp
	r.total_controls == {TOTAL - SW}
	r.failed_controls == 0
	r.swarm.total == 0
	r.swarm_profile == {{
		"state": "inactive", "selection": "auto", "applicable": false, "role": "unknown",
		"reason": "swarm mode is inactive on this engine: Swarm recommendations do not apply",
	}}
}}

test_swarm_state_not_collected_applies_and_reports_missing if {{
	inp := _patched([{{"op": "remove", "path": "/docker/info/Swarm"}}])
	r := b.compliance_report with input as inp
	r.total_controls == {TOTAL}
	r.swarm_profile.state == "unknown"
	r.swarm_profile.applicable == true
	"7.5: evidence missing — docker.info.Swarm.Cluster.Spec.EncryptionConfig.AutoLockManagers not collected" in r.violations
	"5.1: evidence missing — docker.info.Swarm.LocalNodeState not collected" in r.violations
}}

test_swarm_locked_or_pending_still_applies if {{
	every s in ["locked", "pending", "error", "Active"] {{
		r := b.compliance_report with input as _patched([{{"op": "replace", "path": "/docker/info/Swarm/LocalNodeState", "value": s}}])
		r.swarm_profile.applicable == true
		r.swarm.total == {SW}
	}}
}}

test_swarm_profile_forced_by_cis_profile if {{
	off := b.compliance_report with input as _patched([{{"op": "add", "path": "/cis_profile/swarm", "value": false}}])
	off.swarm_profile.applicable == false
	off.swarm_profile.selection == "forced_out"
	off.total_controls == {TOTAL - SW}
	on := b.compliance_report with input as {{"cis_profile": {{"swarm": true}}, "docker": {{"info": {{"Swarm": {{"LocalNodeState": "inactive"}}}}}}}}
	on.swarm_profile.applicable == true
	on.swarm.total == {SW}
	on.swarm.failed == {SW}
}}

test_swarm_worker_skips_manager_only if {{
	inp := _patched([
		{{"op": "replace", "path": "/docker/info/Swarm/ControlAvailable", "value": false}},
		{{"op": "remove", "path": "/docker/info/Swarm/Cluster"}},
	])
	r := b.compliance_report with input as inp
	r.swarm_profile.role == "worker"
	r.swarm.total == {SW - len(MANAGER_ONLY)}
	r.failed_controls == 0
}}

test_mac_selects_apparmor_or_selinux if {{
	se := _patched([{{"op": "add", "path": "/docker/platform/mac", "value": "SELinux"}}, {{"op": "replace", "path": "/docker/containers/0/AppArmorProfile", "value": ""}}])
	rs := b.compliance_report with input as se
	rs.failed_controls == 0
	rs.total_controls == {TOTAL - 1}
	rs.profile.mac_frameworks == ["selinux"]
	aa := _patched([{{"op": "add", "path": "/docker/platform/mac", "value": "apparmor"}}, {{"op": "replace", "path": "/docker/containers/0/ProcessLabel", "value": ""}}])
	ra := b.compliance_report with input as aa
	ra.failed_controls == 0
	none := b.compliance_report with input as _patched([{{"op": "add", "path": "/docker/platform/mac", "value": "none"}}])
	none.total_controls == {TOTAL - 2}
	unknown := b.violations with input as _patched([{{"op": "add", "path": "/docker/platform/mac", "value": "tomoyo"}}, {{"op": "replace", "path": "/docker/containers/0/ProcessLabel", "value": ""}}])
	_has_id(unknown, "5.3")
}}

# an EMPTY collected list passes the per-item checks; an ABSENT list is evidence missing
test_empty_container_list_passes_per_container_checks if {{
	vs := b.violations with input as _patched([{{"op": "replace", "path": "/docker/containers", "value": []}}])
	every id in {json.dumps(PER_CONTAINER)} {{ not _has_id(vs, id) }}
}}

test_absent_container_list_is_evidence_missing if {{
	vs := b.violations with input as _patched([{{"op": "remove", "path": "/docker/containers"}}])
	every id in {json.dumps([i for i in PER_CONTAINER if i != "5.30"])} {{
		concat("", [id, ": evidence missing — docker.containers not collected"]) in vs
	}}
	"5.30: evidence missing — docker.containers / docker.networks not collected" in vs
}}

test_empty_image_list_passes_and_absent_is_missing if {{
	vs := b.violations with input as _patched([{{"op": "replace", "path": "/docker/images", "value": []}}])
	every id in {json.dumps(PER_IMAGE)} {{ not _has_id(vs, id) }}
	ms := b.violations with input as _patched([{{"op": "remove", "path": "/docker/images"}}])
	every id in {json.dumps(PER_IMAGE)} {{ concat("", [id, ": evidence missing — docker.images not collected"]) in ms }}
}}

# a container that lacks the inspected field fails; it is never skipped
test_container_without_fields_fails_closed if {{
	inp := _patched([{{"op": "add", "path": "/docker/containers/-", "value": {{"Name": "/bare"}}}}])
	r := b.compliance_report with input as inp
	every id in {json.dumps(PER_CONTAINER)} {{ "bare" in r.offenders[id] }}
}}

test_offenders_name_the_failing_container if {{
	r := b.compliance_report with input as _patched([{{"op": "replace", "path": "/docker/containers/1/HostConfig/Privileged", "value": true}}])
	count(r.offenders) == 1
	r.offenders["5.5"] == ["worker"]
	r.failed_controls == 1
}}

test_stopped_container_skips_runtime_only_checks if {{
	stopped := {{"Name": "/old", "Image": "sha256:app1", "State": {{"Running": false}}}}
	r := b.compliance_report with input as _patched([{{"op": "add", "path": "/docker/containers/-", "value": stopped}}])
	every id in ["4.1", "5.7", "5.8", "5.14", "5.27", "5.29"] {{ not r.offenders[id] }}
	"old" in r.offenders["5.5"]
}}

# file modes are octal bit masks
test_mode_within_is_a_bit_mask if {{
	b.mode_within("644", "644")
	b.mode_within("0600", "644")
	b.mode_within("0o440", "644")
	b.mode_within("400", "660")
	not b.mode_within("700", "644")
	not b.mode_within("645", "644")
	not b.mode_within("1644", "644")
	not b.mode_within("4755", "755")
	not b.mode_within("rw-r--r--", "644")
	not b.mode_within("", "644")
	not b.mode_within("800", "755")
	b.mode_within(640, "644")
}}

test_file_absent_on_host_is_not_applicable_but_unknown_is_missing if {{
	gone := b.violations with input as _patched([{{"op": "replace", "path": "/docker/files/etc_default_docker", "value": {{"exists": false}}}}])
	not _has_id(gone, "3.19")
	not _has_id(gone, "3.20")
	not _has_id(gone, "1.1.10")
	unk := b.violations with input as _patched([{{"op": "replace", "path": "/docker/files/etc_default_docker", "value": {{"owner": "root", "group": "root", "mode": "644"}}}}])
	"3.19: evidence missing — docker.files.etc_default_docker not collected" in unk
}}

test_file_mode_missing_or_unparsable_fails if {{
	vs := b.violations with input as _patched([{{"op": "remove", "path": "/docker/files/docker_sock/mode"}}])
	_has_id(vs, "3.16")
	vs2 := b.violations with input as _patched([{{"op": "replace", "path": "/docker/files/tls_server_key/mode", "value": "0600"}}])
	_has_id(vs2, "3.14")
}}

# audit rules match the path as a whole token, and commented-out lines are not rules
test_audit_rule_token_match if {{
	b._audited("/usr/bin/containerd") with input as {{"auditd": {{"active_rules": ["-w /usr/bin/containerd -p x -k docker"]}}}}
	b._audited("/etc/docker") with input as {{"auditd": {{"active_rules": ["-a always,exit -F dir=/etc/docker/ -F perm=wa"]}}}}
	not b._audited("/usr/bin/containerd") with input as {{"auditd": {{"active_rules": ["-w /usr/bin/containerd-shim -p x -k docker"]}}}}
	not b._audited("/etc/docker") with input as {{"auditd": {{"active_rules": ["-w /etc/docker/daemon.json -k docker"]}}}}
	not b._audited("/etc/docker") with input as {{"auditd": {{"active_rules": ["# -w /etc/docker -k docker"]}}}}
	not b._audited("/etc/docker") with input as {{"auditd": {{"active_rules": []}}}}
}}

test_audit_rule_follows_collected_path if {{
	moved := _patched([{{"op": "replace", "path": "/docker/files/docker_service/path", "value": "/etc/systemd/system/docker.service"}}])
	vs := b.violations with input as moved
	_has_id(vs, "1.1.7")
	root := _patched([{{"op": "replace", "path": "/docker/info/DockerRootDir", "value": "/mnt/docker-data"}}])
	_has_id(b.violations, "1.1.5") with input as root
}}

test_2_8_tcp_listener_needs_full_tls if {{
	tcp := [{{"op": "replace", "path": "/docker/daemon/hosts", "value": ["tcp://10.0.0.5:2376"]}}]
	_has_id(b.violations, "2.8") with input as _patched(tcp)
	tls := array.concat(tcp, [
		{{"op": "add", "path": "/docker/daemon/tlsverify", "value": true}}, {{"op": "add", "path": "/docker/daemon/tlscacert", "value": "/etc/docker/tls/ca.pem"}},
		{{"op": "add", "path": "/docker/daemon/tlscert", "value": "/etc/docker/tls/server-cert.pem"}},
	])
	_has_id(b.violations, "2.8") with input as _patched(tls)
	full := array.concat(tls, [{{"op": "add", "path": "/docker/daemon/tlskey", "value": "/etc/docker/tls/server-key.pem"}}])
	not _has_id(b.violations, "2.8") with input as _patched(full)
}}

test_2_5_loopback_only if {{
	_has_id(b.violations, "2.5") with input as _patched([{{"op": "add", "path": "/docker/daemon/insecure-registries", "value": ["registry.lab:5000"]}}])
	_has_id(b.violations, "2.5") with input as _patched([{{"op": "replace", "path": "/docker/info/RegistryConfig/InsecureRegistryCIDRs", "value": ["0.0.0.0/0"]}}])
	_has_id(b.violations, "2.5") with input as _patched([{{"op": "replace", "path": "/docker/info/RegistryConfig/IndexConfigs/docker.io/Secure", "value": false}}])
}}

test_attested_exceptions if {{
	root := [{{"op": "replace", "path": "/docker/daemon_process/user", "value": "root"}}]
	_has_id(b.violations, "2.1") with input as _patched(root)
	not _has_id(b.violations, "2.1") with input as _patched(array.concat(root, [{{"op": "add", "path": "/docker/attest/rootful_daemon_required", "value": true}}]))
	ul := [{{"op": "replace", "path": "/docker/containers/0/HostConfig/Ulimits", "value": [{{"Name": "nofile", "Soft": 1, "Hard": 2}}]}}]
	_has_id(b.violations, "5.19") with input as _patched(ul)
	not _has_id(b.violations, "5.19") with input as _patched(array.concat(ul, [{{"op": "add", "path": "/docker/attest/container_ulimit_overrides_reviewed", "value": true}}]))
	jf := [{{"op": "replace", "path": "/docker/info/LoggingDriver", "value": "journald"}}]
	not _has_id(b.violations, "2.14") with input as _patched(array.concat(jf, [{{"op": "add", "path": "/docker/attest/central_logging_configured", "value": true}}]))
	builtin := [{{"op": "remove", "path": "/docker/daemon/seccomp-profile"}}, {{"op": "add", "path": "/docker/attest/default_seccomp_profile_sufficient", "value": true}}]
	not _has_id(b.violations, "2.18") with input as _patched(builtin)
	unconf := array.concat(builtin, [{{"op": "replace", "path": "/docker/info/SecurityOptions", "value": ["name=seccomp,profile=unconfined", "name=userns"]}}])
	_has_id(b.violations, "2.18") with input as _patched(unconf)
}}

test_5_4_capabilities if {{
	keep := [{{"op": "replace", "path": "/docker/containers/0/HostConfig/CapDrop", "value": []}}]
	_has_id(b.violations, "5.4") with input as _patched(keep)
	raw := [{{"op": "replace", "path": "/docker/containers/0/HostConfig/CapDrop", "value": ["CAP_NET_RAW"]}}]
	not _has_id(b.violations, "5.4") with input as _patched(raw)
	add := [{{"op": "replace", "path": "/docker/containers/0/HostConfig/CapAdd", "value": ["CAP_NET_BIND_SERVICE"]}}]
	_has_id(b.violations, "5.4") with input as _patched(add)
	not _has_id(b.violations, "5.4") with input as _patched(array.concat(add, [{{"op": "add", "path": "/docker/policy", "value": {{"allowed_added_capabilities": ["NET_BIND_SERVICE"]}}}}]))
}}

test_5_6_sensitive_mounts if {{
	b._sensitive_mount({{"Source": "/", "RW": true}})
	b._sensitive_mount({{"Source": "/etc"}})
	not b._sensitive_mount({{"Source": "/etc/localtime", "RW": false}})
	b._sensitive_mount({{"Source": "/etc/", "RW": true}})
	b._sensitive_mount({{"Source": "/usr/share/zoneinfo", "RW": true}})
	not b._sensitive_mount({{"Source": "/etcd-data"}})
	not b._sensitive_mount({{"Source": "/srv/app"}})
	not b._sensitive_mount({{"Source": "/etc/localtime"}}) with input as {{"docker": {{"policy": {{"allowed_sensitive_mounts": ["/etc/localtime"]}}}}}}
}}

test_5_8_and_5_14_port_bindings if {{
	b._host_port_ok({{"HostPort": "1024"}})
	not b._host_port_ok({{"HostPort": "443"}})
	not b._host_port_ok({{"HostPort": ""}})
	not b._host_port_ok({{}})
	b._host_port_ok({{"HostPort": "443"}}) with input as {{"docker": {{"policy": {{"allowed_privileged_ports": [443]}}}}}}
	b._host_ip_specific({{"HostIp": "127.0.0.1"}})
	not b._host_ip_specific({{"HostIp": ""}})
	not b._host_ip_specific({{"HostIp": "::"}})
	not b._host_ip_specific({{}})
	vs := b.violations with input as _patched([{{"op": "remove", "path": "/docker/containers/0/NetworkSettings/Ports"}}])
	_has_id(vs, "5.8")
	_has_id(vs, "5.14")
}}

test_5_15_restart_policy if {{
	every p in [{{"Name": "always", "MaximumRetryCount": 0}}, {{"Name": "unless-stopped", "MaximumRetryCount": 0}}, {{"Name": "on-failure", "MaximumRetryCount": 6}}, {{"Name": "on-failure", "MaximumRetryCount": 0}}, {{"Name": "on-failure"}}] {{
		_has_id(b.violations, "5.15") with input as _patched([{{"op": "replace", "path": "/docker/containers/0/HostConfig/RestartPolicy", "value": p}}])
	}}
	every p in [{{"Name": "no", "MaximumRetryCount": 0}}, {{"Name": "", "MaximumRetryCount": 0}}, {{"Name": "on-failure", "MaximumRetryCount": 3}}] {{
		not _has_id(b.violations, "5.15") with input as _patched([{{"op": "replace", "path": "/docker/containers/0/HostConfig/RestartPolicy", "value": p}}])
	}}
}}

test_5_26_daemon_default_or_container_option if {{
	none := [{{"op": "replace", "path": "/docker/containers/0/HostConfig/SecurityOpt", "value": null}}]
	not _has_id(b.violations, "5.26") with input as _patched(none)
	_has_id(b.violations, "5.26") with input as _patched(array.concat(none, [{{"op": "replace", "path": "/docker/daemon/no-new-privileges", "value": false}}]))
}}

test_limits_of_zero_or_minus_one_are_not_limits if {{
	every v in [0, -1, null] {{
		_has_id(b.violations, "5.29") with input as _patched([{{"op": "replace", "path": "/docker/containers/0/HostConfig/PidsLimit", "value": v}}])
	}}
	_has_id(b.violations, "5.11") with input as _patched([{{"op": "remove", "path": "/docker/containers/0/HostConfig/Memory"}}])
	_has_id(b.violations, "5.12") with input as _patched([{{"op": "replace", "path": "/docker/containers/0/HostConfig/CpuShares", "value": 0}}])
	_has_id(b.violations, "7.7") with input as _patched([{{"op": "replace", "path": "/docker/info/Swarm/Cluster/Spec/CAConfig/NodeCertExpiry", "value": 0}}])
}}

test_image_history_rules if {{
	b._update_alone("/bin/sh -c apt-get update")
	b._update_alone("RUN /bin/sh -c apk update # buildkit")
	b._update_alone("/bin/sh -c apt-get -q update")
	not b._update_alone("/bin/sh -c apt-get update && apt-get install -y curl")
	not b._update_alone("RUN /bin/sh -c apk update && apk add curl")
	not b._update_alone("/bin/sh -c update-ca-certificates")
	b._add_step("ADD app.tar.gz /opt/ # buildkit")
	b._add_step("/bin/sh -c #(nop) ADD dir:9f8e in /opt/app ")
	not b._add_step("/bin/sh -c #(nop) ADD file:0a1b2c3d in / ")
	not b._add_step("/bin/sh -c echo ADDED > /tmp/x")
	not b._add_step("COPY app /opt/ # buildkit")
	not b._add_step("ADD alpine-minirootfs-3.20.0-x86_64.tar.gz / # buildkit")
	b._add_step("ADD rootfs.tar.gz /opt/ # buildkit")
}}

test_5_7_sshd_process_match if {{
	b._is_sshd("sshd: /usr/sbin/sshd -D [listener]")
	b._is_sshd("/usr/sbin/sshd")
	not b._is_sshd("/usr/bin/sshd-monitor-app")
	not b._is_sshd("/usr/bin/app --name=nosshd")
}}

test_5_30_default_bridge if {{
	vs := b.violations with input as _patched([{{"op": "add", "path": "/docker/containers/1/NetworkSettings/Networks/bridge", "value": {{}}}}])
	_has_id(vs, "5.30")
	r := b.compliance_report with input as _patched([{{"op": "add", "path": "/docker/containers/1/NetworkSettings/Networks/bridge", "value": {{}}}}])
	r.offenders["5.30"] == ["worker"]
}}

test_7_2_wildcard_listener_forms if {{
	every a in ["*", "0.0.0.0", "::", "[::]", ""] {{
		_has_id(b.violations, "7.2") with input as _patched([{{"op": "replace", "path": "/docker/swarm/listeners/1/address", "value": a}}])
	}}
	_has_id(b.violations, "7.2") with input as _patched([{{"op": "replace", "path": "/docker/swarm/listeners", "value": []}}])
}}

test_violation_count_never_inflates_total if {{
	r := m.compliance_report with input as {{"docker": {{}}}}
	r.failed_controls == r.total_controls
	r.facts_supplied == true
	every v in r.violations {{ not startswith(v, "FAIL-CLOSED") }}
}}

{emit_tests("cis_docker", C, WBX, GREEN, "/docker/attest")}'''
open(f"{OUT}/tests/test_cis_docker_controls.rego", "w").write(tests)

sec_rows = "\n".join(
    f"| {SECTION_TITLES[s].split(' (')[0]} | {sum(1 for i in ids if section(i) == s)} | "
    f"{sum(1 for c in C if section(c['id']) == s and c['kind'] == 'attest')} |" for s in SECTIONS)
README = f'''# {BENCH}

**Version:** v1.0 · generated by `tools/cis_generators/gen_docker.py` from the CIS workbook · co-authored with Claude (Anthropic)

All {TOTAL} recommendations of the benchmark ({AUTO} Automated, {TOTAL - AUTO} Manual in the workbook): {TOTAL - len(attest_ids)}
are decided from collected facts and {len(attest_ids)} that need a human judgement are attestation booleans. Nothing is
passed silently: a fact that was not collected is an `evidence missing` violation, an attestation that is absent is a
violation. Titles are our own wording; the benchmark text is not reproduced.

Query: `POST /v1/data/cis_docker/main/compliance_report` (framework key `cis_docker`).

## Files

| File | Holds |
|---|---|
| `cis_docker_benchmark.rego` | package `cis_docker`: every recommendation, the `recommendations` table, `compliance_report` |
| `cis_docker_main.rego` | package `cis_docker.main`: the framework entrypoint |
| `tests/test_cis_docker_controls.rego` | a pass and a fail per recommendation, an evidence-missing case per fact check, profile and helper tests |

Do not edit these by hand. Regenerate:

```
python3 tools/cis_generators/dump_workbook.py <workbook.xlsx> docker.json
python3 tools/cis_generators/gen_docker.py docker.json benchmarks/cis/docker
opa fmt -w benchmarks/cis/docker
```

## Sections

| Section | Recommendations | Attested |
|---|---|---|
{sec_rows}

## Profile

`input.cis_profile` selects the recommendations in scope; `total_controls` is the number in scope.

| Field | Values | When absent |
|---|---|---|
| `level` | `1`, `2` (Level 2 includes Level 1) | evaluated at `2`, the stricter selection, with a `PROFILE NOT SELECTED` finding (`level_defaulted: true`); never compliant |
| `swarm` | `true` forces the Swarm profile in, `false` leaves it out | decided by the collected swarm state (below) |

| Selection | `total_controls` |
|---|---|
| Level 1, swarm inactive | {L1} |
| Level 1, swarm active | {L1 + SW} |
| Level 2, swarm inactive | {L1 + L2} |
| Level 2, swarm active (and empty input) | {TOTAL} |

The {SW} Swarm recommendations apply unless `docker.info.Swarm.LocalNodeState` is `inactive`. A state that was not
collected counts as possibly active: they apply and report evidence missing. On a worker
(`Swarm.ControlAvailable == false`) the manager-only ones ({", ".join(sorted(MANAGER_ONLY, key=idkey))}) do not apply.
`compliance_report.swarm_profile` always states the state, the selection, the decision and the reason.

5.2 (AppArmor) and 5.3 (SELinux) follow `docker.platform.mac` (`apparmor`, `selinux`, `none`); absent means both apply.

## Facts

| Input | Source |
|---|---|
| `auditd.active_rules[]` | `auditctl -l` lines, the fact the CIS Linux modules read |
| `docker.info`, `docker.version` | `docker info --format '{{{{json .}}}}'`, `docker version --format '{{{{json .}}}}'` |
| `docker.daemon` | effective daemon settings under their `daemon.json` key names, `dockerd` flags merged in; `{{}}` when nothing is set |
| `docker.daemon_process.user` | the account running `dockerd` |
| `docker.networks[]` | `docker network inspect` of every network |
| `docker.containers[]` | `docker inspect` of every container (`docker ps --all`), plus `runtime.pid1_euid` and `runtime.processes[]` (`docker top`) for running ones |
| `docker.images[]` | `docker image inspect` of every image, plus `history[]` (`docker history --no-trunc`) and `setuid_files[]` |
| `docker.files.<key>` | `{{exists, path, owner, group, mode}}`; `mode` is the octal string from `stat -c %a`; `exists: false` means the file is not on this host |
| `docker.files.registry_certs[]` | `{{path, owner, group, mode}}` per file under `/etc/docker/certs.d` |
| `docker.host.data_root_is_mountpoint` | `mountpoint` on the Docker data root |
| `docker.docker_group.members[]`, `.approved_members[]` | `getent group docker` and the operator's approved list |
| `docker.exec_audit.privileged_events[]`, `.root_user_events[]` | `ausearch -k docker` hits for `docker exec` |
| `docker.swarm.listeners[]`, `docker.swarm.data_path_addr` | the address of each listener on 2377 / 7946 (`{{address}}`), the data path address |
| `docker.policy.*` | optional allowances: `allowed_added_capabilities`, `allowed_sensitive_mounts`, `allowed_privileged_ports`, `allowed_host_devices`, `max_node_cert_expiry_days` |
| `docker.attest.*` | attestation booleans |

Container and image checks iterate the collected list: an empty list passes, an absent list is evidence missing, and
an item without the inspected field fails. `compliance_report.offenders` names the failing containers and images.
File modes are compared as octal bit masks (`mode_within`), never as strings.

## Attestations

Judgement only ({len(attest_ids)}): {", ".join(f"{c['id']} `{c['attest']}`" for c in C if c["kind"] == "attest")}.

Exceptions the benchmark allows "when needed", used only when the fact alone does not pass: 2.1 `rootful_daemon_required`,
2.9 `default_ulimits_reviewed`, 2.11 `cgroup_parent_reviewed`, 2.14 `central_logging_configured`,
2.18 `default_seccomp_profile_sufficient`, 4.7 `setuid_files_reviewed`, 5.1 `swarm_mode_required`,
5.19 `container_ulimit_overrides_reviewed`, 6.1 `unused_images_reviewed`, 6.2 `stopped_containers_reviewed`.
'''
open(f"{OUT}/README.md", "w").write(README)
print("ok", TOTAL, "L1", L1, "L2", L2, "swarm", SW, "automated", AUTO, "attest", len(attest_ids), "fact-manual", len(fact_manual))
