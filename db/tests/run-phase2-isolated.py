#!/usr/bin/env python3
"""REVIEW ONLY. No action without a later, explicit execution approval.

No package installation, shell, environment inheritance or TCP/UDP. Every run
uses a new cluster. This is a trusted-source laboratory, not a hostile-SQL VM.
"""
import argparse
import ctypes
import errno
import glob
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import signal
import socket
import subprocess
import uuid

REPO = Path(__file__).resolve().parents[2]


def isolate_network():
    # Drop inherited non-stdio descriptors, including pre-opened network sockets.
    for item in Path("/proc/self/fd").iterdir():
        fd = int(item.name)
        if fd > 2:
            try:
                os.close(fd)
            except OSError:
                pass
    libraries = glob.glob("/nix/store/*-libseccomp-*/lib/libseccomp.so.2")
    if not libraries:
        raise RuntimeError("libseccomp unavailable; no fallback to unfiltered execution")
    lib = ctypes.CDLL(sorted(libraries)[-1], use_errno=True)
    lib.seccomp_init.argtypes = [ctypes.c_uint32]
    lib.seccomp_init.restype = ctypes.c_void_p
    lib.seccomp_syscall_resolve_name.argtypes = [ctypes.c_char_p]
    lib.seccomp_syscall_resolve_name.restype = ctypes.c_int
    lib.seccomp_rule_add.argtypes = [ctypes.c_void_p, ctypes.c_uint32, ctypes.c_int, ctypes.c_uint]
    lib.seccomp_load.argtypes = [ctypes.c_void_p]
    lib.seccomp_release.argtypes = [ctypes.c_void_p]

    class Compare(ctypes.Structure):
        _fields_ = [("arg", ctypes.c_uint), ("op", ctypes.c_int),
                    ("datum_a", ctypes.c_uint64), ("datum_b", ctypes.c_uint64)]

    ctx = lib.seccomp_init(0x7FFF0000)  # default ALLOW
    if not ctx:
        raise RuntimeError("seccomp_init failed")
    try:
        for name in [b"socket", b"socketpair"]:
            number = lib.seccomp_syscall_resolve_name(name)
            # SCMP_CMP_NE=1: only AF_UNIX sockets may be created.
            if number < 0 or lib.seccomp_rule_add(
                ctx, 0x50000 | errno.EPERM, number, 1, Compare(0, 1, socket.AF_UNIX, 0)
            ) != 0:
                raise RuntimeError("Required socket-family filter unavailable")
        for name in [b"socketcall", b"io_uring_setup"]:
            number = lib.seccomp_syscall_resolve_name(name)
            if number >= 0 and lib.seccomp_rule_add(ctx, 0x50000 | errno.EPERM, number, 0) != 0:
                raise RuntimeError("Cannot block alternate network syscall")
        if lib.seccomp_load(ctx) != 0:
            raise RuntimeError("Cannot load inherited seccomp filter")
    finally:
        lib.seccomp_release(ctx)
    for family in [socket.AF_INET, socket.AF_INET6]:
        try:
            probe = socket.socket(family, socket.SOCK_STREAM)
        except PermissionError:
            continue
        probe.close()
        raise RuntimeError("Network isolation self-check failed")


def processes_for(data):
    matches = []
    for entry in Path("/proc").iterdir():
        if not entry.name.isdigit():
            continue
        try:
            args = (entry / "cmdline").read_bytes().split(b"\0")
            if os.fsencode(data) in args:
                matches.append(int(entry.name))
        except (FileNotFoundError, PermissionError, ProcessLookupError):
            continue
    return matches


def safe_message(value):
    value = re.sub(r"(?i)postgres(?:ql)?://\S+", "[connection redacted]", str(value))
    value = re.sub(r"\b[0-9a-fA-F]{64}\b", "[proof redacted]", value)
    return re.sub(r"eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+", "[JWT redacted]", value)[:1000]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--suite", choices=["prerequisites", "inventory", "security"], required=True)
    parser.add_argument("--approved-local-execution", action="store_true")
    parser.add_argument("--report", required=True)
    args = parser.parse_args()
    if not args.approved_local_execution:
        parser.error("Preparation only. Separate human approval is required before execution.")
    def interrupt(signum, frame):
        raise KeyboardInterrupt(f"Interrupted by signal {signum}; cleanup required")
    signal.signal(signal.SIGTERM, interrupt)
    signal.signal(signal.SIGHUP, interrupt)
    report_path = (REPO / args.report).resolve()
    if report_path.parent != REPO / "db/test-reports" or report_path.suffix != ".json" or report_path.exists():
        parser.error("Report must be a NEW JSON file directly inside db/test-reports")
    node = shutil.which("node")
    candidates = glob.glob("/nix/store/*-postgresql-17.*/bin/pg_ctl")
    if not node or not candidates:
        parser.error("Existing Node/PostgreSQL 17 binaries required; installation is not authorized here")
    pg = Path(sorted(candidates)[-1]).parent
    isolate_network()  # fails closed BEFORE creating a cluster
    os.umask(0o077)
    suite = "prereq" if args.suite == "prerequisites" else "phase2"
    root = Path("/tmp") / f"stockwise-{suite}-{uuid.uuid4().hex}"
    root.mkdir(mode=0o700)
    marker = {"root": str(root), "suite": suite, "uid": os.getuid(), "launcher": os.getpid()}
    (root / "approved-lab.json").write_text(json.dumps(marker))
    (root / "socket").mkdir(mode=0o700)
    (root / "home").mkdir(mode=0o700)
    # Construct a new environment; NEVER inspect/copy DATABASE_URL or secrets.
    env = {"PATH": f"{pg}:{Path(node).parent}:/usr/bin:/bin",
           "HOME": str(root / "home"), "TMPDIR": str(root), "LC_ALL": "C", "TZ": "UTC",
           "STOCKWISE_PHASE2_EXECUTION": "explicitly-approved"}
    data = root / "data"
    attempted_start = False
    record = {"suite": args.suite, "status": "FAIL", "results": [], "cleanup": "NOT_ATTEMPTED",
              "scope": "disposable-local-only; synthetic fixtures; no hosted authentication",
              "migration_sha256": hashlib.sha256((REPO / "db/migrations/0001_inventory.sql").read_bytes()).hexdigest()}
    review_sources = [
        *sorted((REPO / "db/security-review/phase2").glob("*.sql")),
        *sorted((REPO / "db/tests/phase2").glob("*.cjs")),
        REPO / "db/tests/inventory.local.cjs", REPO / "db/tests/runtime-security.local.cjs",
        Path(__file__).resolve(),
    ]
    record["review_source_sha256"] = {
        str(p.relative_to(REPO)): hashlib.sha256(p.read_bytes()).hexdigest() for p in review_sources
    }

    def run(command, timeout=40, check=True):
        return subprocess.run([str(x) for x in command], cwd=REPO, env=env,
                              stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                              stderr=subprocess.STDOUT, close_fds=True,
                              text=True, timeout=timeout, check=check)

    def assert_root():
        if root.resolve() != root or root.is_symlink() or root.stat().st_uid != os.getuid():
            raise RuntimeError("Cleanup identity mismatch; stop without deleting")
        if json.loads((root / "approved-lab.json").read_text()) != marker:
            raise RuntimeError("Cleanup marker mismatch; stop without deleting")

    try:
        version = run([pg / "postgres", "--version"]).stdout.strip()
        if not re.search(r"\b17\.\d+\b", version):
            raise RuntimeError("PostgreSQL 17 required")
        record["postgres_version"] = version
        record["node_version"] = run([node, "--version"]).stdout.strip()
        run([pg / "initdb", "-D", data, "-U", "runner", "--auth-local=trust",
             "--auth-host=reject", "--no-locale", "-E", "UTF8"])
        with (data / "postgresql.conf").open("a") as conf:
            conf.write(f"""
listen_addresses = ''
port = 6543
unix_socket_directories = '{root}/socket'
unix_socket_permissions = 0700
shared_buffers = '16MB'
max_connections = 20
log_statement = 'none'
log_min_error_statement = 'panic'
log_parameter_max_length_on_error = 0
""")
        attempted_start = True
        run([pg / "pg_ctl", "-D", data, "-l", root / "server.log", "-w", "-t", "15", "start"])
        script = {"prerequisites": "db/tests/prerequisites.local.cjs",
                  "inventory": "db/tests/inventory.local.cjs",
                  "security": "db/tests/runtime-security.local.cjs"}[args.suite]
        result = run([node, script, root], timeout=180, check=False)
        record["exit_code"] = result.returncode
        results_file = root / "results.json"
        if not results_file.exists():
            raise RuntimeError("Harness produced no structured report")
        rows = json.loads(results_file.read_text())["results"]
        record["results"] = [{"name": x.get("name", x.get("test", "unnamed")),
                              "status": x["status"], "code": x.get("code"),
                              "message": safe_message(x.get("message", ""))} for x in rows]
        record["status"] = "PASS" if result.returncode == 0 and rows and all(x["status"] == "PASS" for x in rows) else "FAIL"
        record["remaining_cases"] = "UNTESTED after first failure" if result.returncode else "See PHASE-2A coverage map for delegated and hosted checks"
    except Exception as exc:
        # Do not retain subprocess stdout, SQL context, parameters, tokens or proofs.
        record["error"] = safe_message(type(exc).__name__ + ": " + str(exc))
    finally:
        try:
            assert_root()
            if attempted_start:
                state = run([pg / "pg_ctl", "-D", data, "status"], check=False)
                if state.returncode == 0:
                    lines = (data / "postmaster.pid").read_text().splitlines()
                    pid = int(lines[0])
                    if lines[1] != str(data) or pid not in processes_for(data):
                        raise RuntimeError("Postmaster identity mismatch; do not signal/delete")
                    run([pg / "pg_ctl", "-D", data, "-w", "-t", "15", "-m", "fast", "stop"])
                elif state.returncode != 3:
                    raise RuntimeError("Postmaster state unknown; do not delete")
                if run([pg / "pg_ctl", "-D", data, "status"], check=False).returncode != 3 or processes_for(data):
                    raise RuntimeError("Shutdown not confirmed; do not delete")
            if processes_for(data) or not shutil.rmtree.avoids_symlink_attacks:
                raise RuntimeError("Safe deletion unavailable; do not delete")
            shutil.rmtree(root)
            record["cleanup"] = "STOPPED_AND_REMOVED"
        except Exception as exc:
            record["cleanup"] = "BLOCKED"
            record["status"] = "FAIL"
            record["cleanup_error"] = safe_message(str(exc))
            record["manual_inspection_directory"] = str(root)
        # Exclusive creation: never replace retained historical reports.
        with report_path.open("x") as output:
            json.dump(record, output, indent=2)
        print(json.dumps({"status": record["status"], "cleanup": record["cleanup"],
                          "report": str(report_path.relative_to(REPO))}))
    return 0 if record["status"] == "PASS" and record["cleanup"] == "STOPPED_AND_REMOVED" else 1


if __name__ == "__main__":
    raise SystemExit(main())
