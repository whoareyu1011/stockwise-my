"""Run synthetic Node tests with inherited kernel-level network denial.

No installation, SQL, secret lookup or environment-file loading. Fail closed
if Linux seccomp cannot load. This is network isolation, not a filesystem sandbox.
"""
import ctypes
import errno
import glob
import os
from pathlib import Path
import resource
import shutil
import sys


def main():
    candidates = ["/lib/x86_64-linux-gnu/libseccomp.so.2",
                  "/usr/lib/x86_64-linux-gnu/libseccomp.so.2"]
    candidates += sorted(glob.glob("/nix/store/*-libseccomp-*-lib/lib/libseccomp.so.2"))
    library = next((p for p in candidates if Path(p).is_file()), None)
    node = shutil.which("node")
    if not library or not node:
        sys.exit("Offline test prerequisite unavailable; no tests started.")
    lib = ctypes.CDLL(library, use_errno=True)
    lib.seccomp_init.argtypes = [ctypes.c_uint32]
    lib.seccomp_init.restype = ctypes.c_void_p
    lib.seccomp_syscall_resolve_name.argtypes = [ctypes.c_char_p]
    lib.seccomp_syscall_resolve_name.restype = ctypes.c_int
    lib.seccomp_rule_add.argtypes = [ctypes.c_void_p, ctypes.c_uint32, ctypes.c_int, ctypes.c_uint]
    lib.seccomp_load.argtypes = [ctypes.c_void_p]
    lib.seccomp_release.argtypes = [ctypes.c_void_p]
    context = lib.seccomp_init(0x7FFF0000)  # SCMP_ACT_ALLOW
    if not context:
        sys.exit("Network isolation failed; no tests started.")
    try:
        for name in ("socket", "connect", "bind", "listen", "accept", "accept4",
                     "sendto", "sendmsg", "sendmmsg", "socketcall", "io_uring_setup"):
            syscall = lib.seccomp_syscall_resolve_name(name.encode("ascii"))
            if syscall >= 0 and lib.seccomp_rule_add(
                    context, 0x00050000 | errno.EPERM, syscall, 0) != 0:
                sys.exit("Network isolation failed; no tests started.")
        if lib.seccomp_load(context) != 0:
            sys.exit("Network isolation unavailable; no tests started.")
    finally:
        lib.seccomp_release(context)
    print("Kernel seccomp network block active; synthetic tests only.", flush=True)
    os.closerange(3, resource.getrlimit(resource.RLIMIT_NOFILE)[0])
    # Do not copy workspace secrets into the test process or its descendants.
    os.execve(node, [node, "--test", "--test-concurrency=1",
                    "tests/security/security.test.cjs",
                    "tests/security/components.test.cjs"],
              {"PATH": str(Path(node).parent), "TZ": "UTC"})


if __name__ == "__main__":
    main()
