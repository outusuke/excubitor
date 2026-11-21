#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""excubitor-helper: privileged data source for the Excubitor GUI.

It counts UDP and TCP bytes per process, lists sockets (netlink sock_diag) inside sandbox network namespaces,
and tells the GUI which process owns sockets of other users.

Run as root:   sudo python3 excubitor-helper.py              (foreground)
               sudo python3 excubitor-helper.py --install    (systemd service, starts now + at boot)
               sudo python3 excubitor-helper.py --uninstall  (stop and remove the service)
Needs:         bpftrace  (sudo dnf install bpftrace  /  sudo apt install bpftrace)

It attaches kernel probes to the UDP send/receive paths (IPv4 + IPv6), sums the
payload bytes per PID, and writes cumulative counters once per second to
/run/excubitor/udp.json (world-readable, written atomically). The GUI diffs them
to get rates and treats a file older than a few seconds as "helper is gone".
The GUI itself never needs privileges.

Optional privacy on multi-user machines: if a group named "excubitor" exists, the file
becomes 0640 root:excubitor and only its members (and root) can read it:
    sudo groupadd excubitor && sudo usermod -aG excubitor $USER   (then log in again)

Notes: bytes are UDP payload only (no IP/UDP headers), and MSG_PEEK reads are
counted each time. `pid` is the process (tgid), so threads are folded together.
Counters of an exited process are dropped (the last <1 s of its traffic is lost).
"""
import fcntl
import grp
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import threading
import time
import ctypes

sys.dont_write_bytecode = True  # as root: no root-owned .pyc in the user's folder
import netdiag

OUT_DIR = "/run/excubitor"
OUT = OUT_DIR + "/udp.json"
LOCK = OUT_DIR + "/lock"
GROUP = "excubitor"
SCHEMA = 1

TX_FUNCS = ("udp_sendmsg", "udpv6_sendmsg")
RX_FUNCS = ("udp_recvmsg", "udpv6_recvmsg")
TCP_TX_FUNCS = ("tcp_sendmsg",)  # sendfile/splice paths are not counted
TCP_RX_FUNCS = ("tcp_recvmsg",)

INSTALL_DIR = "/usr/local/lib/excubitor"
INSTALLED = INSTALL_DIR + "/excubitor-helper.py"
DIAG_INSTALLED = INSTALL_DIR + "/netdiag.py"
UNIT_NAME = "excubitor-helper.service"
UNIT_PATH = "/etc/systemd/system/" + UNIT_NAME

UNIT = """[Unit]
Description=Excubitor helper (per-process UDP byte counters via bpftrace)
Documentation=file://{script}

[Service]
Type=simple
ExecStart={python} {script}
Restart=on-failure
RestartSec=3
ProtectHome=yes
NoNewPrivileges=yes
ProtectSystem=full
ProtectControlGroups=yes
ProtectKernelModules=yes
LockPersonality=yes
RestrictRealtime=yes

[Install]
WantedBy=multi-user.target
"""

LINE = re.compile(r"^@(rx|tx|trx|ttx)\[(\d+)\]:\s+(\d+)\s*$")  # trx/ttx = TCP


def _empty():
    return {"rx": {}, "tx": {}, "trx": {}, "ttx": {}}

# ---- sockets: the host namespace (with owning PIDs, which an unprivileged GUI can't
# see for other users' processes) plus every other network namespace (sandboxes such as
# bwrap/Flatpak with their own netns). Everything comes from netlink sock_diag; one
# netlink socket per namespace is created once (setns) and kept, so there is no
# per-scan subprocess and /proc/*/fd is only walked when an unknown socket appears.
NS_INTERVAL = 2.0
NS_TRIES = 3  # pids to try per namespace, in case the first one just exited


def other_namespaces():
    """{netns id: [a few pids in it]}, host namespace excluded."""
    own = os.readlink("/proc/self/ns/net")
    found = {}
    for entry in os.listdir("/proc"):
        if not entry.isdigit():
            continue
        try:
            ns = os.readlink("/proc/%s/ns/net" % entry)
        except OSError:
            continue
        if ns != own:
            pids = found.setdefault(int(re.search(r"\d+", ns).group()), [])
            if len(pids) < NS_TRIES:
                pids.append(int(entry))
    return found


class Scanner:
    def __init__(self):
        self.host = netdiag.open_diag()
        self.ns = {}  # netns id -> Diag bound to that namespace
        self.inodes = netdiag.InodeMap()

    def scan(self):
        host = self.host.sockets()
        found = other_namespaces()
        for nsid in set(self.ns) - set(found):  # namespace gone: release it
            self.ns.pop(nsid).close()
        others = {}
        for nsid, pids in found.items():
            diag = self.ns.get(nsid)
            for pid in pids if diag is None else ():
                try:
                    diag = self.ns[nsid] = netdiag.open_diag(pid)
                    break
                except OSError:
                    continue
            if diag is None:
                continue
            try:
                others[nsid] = diag.sockets()
            except OSError:
                self.ns.pop(nsid).close()
        owner = self.inodes.pids({s["ino"] for s in host}
                                 | {s["ino"] for l in others.values() for s in l})
        return {"t": time.time(),
                "host": [[s["proto"], s["local"], s["peer"], owner[s["ino"]]]
                         for s in host if s["ino"] in owner],
                "socks": [dict(s, ns=nsid, pid=owner.get(s["ino"], 0))
                          for nsid, l in others.items() for s in l]}


def ns_scanner(state, stop):
    """Thread: refresh state['ns'] every NS_INTERVAL seconds (main loop publishes it)."""
    try:
        scanner = Scanner()
    except OSError as e:
        print("socket scanning disabled:", e, file=sys.stderr)
        return
    while not stop.is_set():
        try:
            state["ns"] = scanner.scan()
        except Exception as e:  # never let the scanner kill the helper
            print("socket scan failed:", e, file=sys.stderr)
        stop.wait(NS_INTERVAL)


def kprobes(pattern):
    """Names of the kprobe-able functions matching `pattern` on this kernel."""
    out = subprocess.run(["bpftrace", "-l", "kprobe:" + pattern],
                         capture_output=True, text=True).stdout
    return {l.split(":", 1)[1].strip() for l in out.splitlines() if ":" in l}


def available(funcs, have):
    """Only the functions this kernel actually exposes (e.g. no IPv6 = no udpv6_*)."""
    return [f for f in funcs if f in have]


def build_prog(tx, rx, ttx=(), trx=()):
    def probes(funcs):
        return ", ".join("kretprobe:" + f for f in funcs)

    def count(funcs, name):
        return (probes(funcs) + "\n/(int32)retval > 0/ { @%s[pid] = sum(retval & 0xffffffff); }\n\n"
                % name)

    maps = [("tx", tx), ("rx", rx), ("ttx", ttx), ("trx", trx)]
    maps = [(n, f) for n, f in maps if f]  # TCP maps only when their probes exist
    prog = "".join(count(f, n) for n, f in maps)
    # drop counters when the process (not just a thread) exits: no PID reuse, no map overflow
    prog += ("tracepoint:sched:sched_process_exit /pid == tid/ { "
             + " ".join("delete(@%s[pid]);" % n for n, _ in maps) + " }\n\n")
    prog += "interval:s:1 { " + " ".join("print(@%s);" % n for n, _ in maps) + ' printf("=\\n"); }\n'
    return prog


def _gid():
    try:
        return grp.getgrnam(GROUP).gr_gid
    except KeyError:
        return 0  # no such group: keep the file world-readable


def publish(cur, ns=None, gid=0):
    tmp = OUT + ".tmp"
    data = {"v": SCHEMA, "t": time.time(), "rx": cur["rx"], "tx": cur["tx"],
            "trx": cur["trx"], "ttx": cur["ttx"]}  # additive keys: older GUIs ignore them
    if ns is not None:
        data["ns"] = ns
    with open(tmp, "w") as f:
        json.dump(data, f)
    if gid:  # opt-in privacy: only root and members of group "excubitor" can read it
        os.chown(tmp, 0, gid)
        os.chmod(tmp, 0o640)
    else:  # original behavior: world-readable, so the GUI works with no setup
        os.chmod(tmp, 0o644)
    os.replace(tmp, OUT)  # atomic: the GUI never sees a half-written file


def single_instance():
    """Exclusive lock so a hand-run helper and the service can't fight over udp.json.
    The fd is not inheritable (Python default), so bpftrace doesn't keep the lock."""
    fd = os.open(LOCK, os.O_CREAT | os.O_RDWR, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        sys.exit("another excubitor-helper is already running")
    return fd


def _pdeathsig():
    """Runs in the child before exec: SIGTERM bpftrace if the helper dies (even by SIGKILL)."""
    ctypes.CDLL(None, use_errno=True).prctl(1, signal.SIGTERM)  # PR_SET_PDEATHSIG


def _systemctl(*args, check=True):
    r = subprocess.run(["systemctl", *args], capture_output=True, text=True)
    if check and r.returncode != 0:
        sys.exit("systemctl %s failed: %s" % (" ".join(args), (r.stderr or r.stdout).strip()))
    return r


def install():
    """Copy ourselves to a root-owned path and run that copy as a systemd service.

    The service must not point at the GUI's directory: that is user-writable, so
    anyone who can edit that file could get code running as root.
    """
    if not shutil.which("systemctl"):
        sys.exit("systemctl not found: this system does not use systemd. "
                 "Run the helper in the foreground instead.")
    if not shutil.which("bpftrace"):
        sys.exit("bpftrace not found. Install it first (dnf/apt install bpftrace).")
    here = os.path.dirname(os.path.abspath(__file__))
    diag_src = os.path.join(here, "netdiag.py")
    if not os.path.isfile(diag_src):
        sys.exit("netdiag.py not found next to %s" % os.path.abspath(__file__))
    os.makedirs(INSTALL_DIR, mode=0o755, exist_ok=True)
    os.chmod(INSTALL_DIR, 0o755)
    for src, dst in ((os.path.abspath(__file__), INSTALLED), (diag_src, DIAG_INSTALLED)):
        tmp = dst + ".tmp"
        shutil.copyfile(src, tmp)
        os.chmod(tmp, 0o755)
        os.replace(tmp, dst)
    with open(UNIT_PATH, "w") as f:
        f.write(UNIT.format(python=sys.executable or "/usr/bin/python3", script=INSTALLED))
    os.chmod(UNIT_PATH, 0o644)
    _systemctl("daemon-reload")
    _systemctl("enable", UNIT_NAME)
    _stop_strays()  # a hand-run helper would hold the lock and block the service
    _systemctl("restart", UNIT_NAME)  # also picks up a newer copy when re-installing
    print("Installed and started %s" % UNIT_NAME)


def _stray_helpers():
    """PIDs of helpers started by hand (`python3 excubitor-helper.py`), not by systemd.

    Matches only `python* .../excubitor-helper.py ...`, so an editor having the file open
    is never touched. The caller's own PID is excluded.
    """
    pids = []
    for entry in os.listdir("/proc"):
        if not entry.isdigit() or int(entry) == os.getpid():
            continue
        try:
            with open("/proc/%s/cmdline" % entry, "rb") as f:
                argv = f.read().decode(errors="replace").split("\0")
        except OSError:
            continue
        # Any python running excubitor-helper.py counts, including a leftover `--install`
        # from an older version that ran in the foreground. Only our own PID is skipped.
        if (len(argv) >= 2 and os.path.basename(argv[0]).startswith("python")
                and os.path.basename(argv[1]) == "excubitor-helper.py"):
            pids.append(int(entry))
    return pids


def _stop_strays():
    pids = _stray_helpers()
    for pid in pids:
        try:
            os.kill(pid, signal.SIGTERM)  # the helper's handler also stops bpftrace
        except OSError:
            pass
    deadline = time.time() + 5
    while time.time() < deadline and any(os.path.exists("/proc/%d" % p) for p in pids):
        time.sleep(0.1)
    for pid in pids:
        if os.path.exists("/proc/%d" % pid):
            try:
                os.kill(pid, signal.SIGKILL)
            except OSError:
                pass
    if pids:
        print("Stopped %d helper process(es) that were not running as a service" % len(pids))


def uninstall():
    """Stop and remove the service. Missing pieces are fine (idempotent)."""
    if shutil.which("systemctl"):
        _systemctl("disable", "--now", UNIT_NAME, check=False)
    _stop_strays()
    for path in (UNIT_PATH, INSTALLED, DIAG_INSTALLED):
        try:
            os.remove(path)
        except OSError:
            pass
    shutil.rmtree(INSTALL_DIR, ignore_errors=True)  # includes __pycache__
    if shutil.which("systemctl"):
        _systemctl("daemon-reload", check=False)
    for path in (OUT, LOCK):
        try:
            os.remove(path)
        except OSError:
            pass
    print("Removed %s" % UNIT_NAME)


def main():
    args = sys.argv[1:]
    if args and args[0] not in ("--run", "--install", "--uninstall"):
        sys.exit("usage: excubitor-helper.py [--run | --install | --uninstall]")
    if os.geteuid() != 0:
        sys.exit("excubitor-helper must run as root: sudo python3 excubitor-helper.py %s" % " ".join(args))
    if args and args[0] == "--install":
        return install()
    if args and args[0] == "--uninstall":
        return uninstall()
    if not shutil.which("bpftrace"):
        sys.exit("bpftrace not found. Install it first (dnf/apt install bpftrace).")

    have = kprobes("udp*msg")
    tx, rx = available(TX_FUNCS, have), available(RX_FUNCS, have)
    if not tx or not rx:
        sys.exit("No UDP send/receive kernel probes found (bpftrace -l 'kprobe:udp*msg'). "
                 "Kernel lockdown (Secure Boot) or a missing BTF/debugfs can cause this.")
    have = kprobes("tcp_*msg")
    ttx, trx = available(TCP_TX_FUNCS, have), available(TCP_RX_FUNCS, have)
    if not (ttx and trx):
        ttx = trx = []
        print("TCP send/receive probes not found: counting UDP only.", file=sys.stderr)

    os.makedirs(OUT_DIR, exist_ok=True)
    os.chmod(OUT_DIR, 0o755)
    lock = single_instance()  # keep this reference alive for the whole run  # noqa: F841
    gid = _gid()

    # stderr is inherited, so bpftrace errors land in the terminal / journal.
    proc = subprocess.Popen(["bpftrace", "-B", "line", "-e", build_prog(tx, rx, ttx, trx)],
                            stdout=subprocess.PIPE, text=True, bufsize=1,
                            preexec_fn=_pdeathsig,  # safe: no threads started yet
                            env={**os.environ, "BPFTRACE_MAX_MAP_KEYS": "16384"})
    stopping = False
    stop_ev = threading.Event()
    ns_state = {"ns": None}
    threading.Thread(target=ns_scanner, args=(ns_state, stop_ev), daemon=True).start()

    def stop(*_):
        nonlocal stopping
        stopping = True
        stop_ev.set()
        proc.terminate()

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)

    published = False
    cur = _empty()
    try:
        for line in proc.stdout:
            m = LINE.match(line)
            if m:
                cur[m.group(1)][m.group(2)] = int(m.group(3))
            elif line.strip() == "=":  # end of one 1-second sample
                publish(cur, ns_state["ns"], gid)
                published = True
                cur = _empty()
    finally:
        stop_ev.set()
        proc.terminate()
        try:
            proc.wait(5)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()
        try:
            os.remove(OUT)  # no file = the GUI knows the helper is gone
        except OSError:
            pass
    rc = proc.wait()
    if stopping:
        sys.exit(0)  # asked to stop: not a failure
    if not published:
        print("bpftrace exited before producing any data (see its error above).",
              file=sys.stderr)
    sys.exit(rc or 1)


if __name__ == "__main__":
    main()
