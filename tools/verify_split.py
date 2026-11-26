#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Prove that the built excubitor.py is a pure move of an earlier version.

    git show <commit>:excubitor.py > /tmp/excubitor.old.py
    python3 tools/verify_split.py /tmp/excubitor.old.py [excubitor.py]

Legs (exit status 1 if any fails):
  1. build.py --check: the committed excubitor.py is what src/ builds.
  2. AST: the same top-level statements, node for node, positions ignored (order may differ).
  3. Lines: every non-blank original line is still present; the only new lines are comments.
  4. Behaviour: both files are loaded by path and driven with identical inputs (pure
     helpers, UdpHelper fixtures, install/uninstall into a scratch HOME, and the real
     GTK window with FakeBackend). The old file is run twice first as a control, so a
     difference between old and new can only come from the move. Needs PyGObject with
     GTK 4 + libadwaita; uses xvfb-run when there is no display. Skipped if unavailable.
  5. Smoke: `--help` is identical and `--fake` stays up for a few seconds without a traceback.
"""
import argparse
import ast
import collections
import hashlib
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SIBLINGS = ("netdiag.py", "netresolve.py", "excapture.py", "excubitor-helper.py", "LICENSE")
SCRATCH = Path("/tmp/excubitor-verify-%d" % os.getuid())  # fixed, so paths seen by old and new are identical

failures, skipped = [], []


def leg(name, ok, detail=""):
    print("%-5s %s%s" % ("PASS" if ok else "FAIL", name, ("\n      " + detail.replace("\n", "\n      ")) if detail else ""))
    if not ok:
        failures.append(name)


def label(node):
    n = getattr(node, "name", None)
    if n:
        return "%s %s" % (type(node).__name__, n)
    return ast.unparse(node).split("\n")[0][:48]


# ------------------------------------------------------------------ legs 1 to 3
def leg_build():
    r = subprocess.run([sys.executable, str(ROOT / "build.py"), "--check"], capture_output=True, text=True)
    leg("build --check: excubitor.py is what src/ builds", r.returncode == 0, (r.stdout + r.stderr).strip())


def leg_ast(old_text, new_text):
    old, new = ast.parse(old_text).body, ast.parse(new_text).body
    ko, kn = [ast.dump(n) for n in old], [ast.dump(n) for n in new]
    co, cn = collections.Counter(ko), collections.Counter(kn)
    missing = [label(n) for n, k in zip(old, ko) if co[k] > cn[k]]
    added = [label(n) for n, k in zip(new, kn) if cn[k] > co[k]]
    leg("AST: %d top-level statements in old, %d in new, identical as a multiset" % (len(old), len(new)),
        co == cn, "missing from new: %s\nnot in old: %s" % (missing, added) if co != cn else "")
    # Which original neighbours were separated? An exact-string patch that spans two
    # top-level blocks would be affected only there.
    pos = {k: i for i, k in enumerate(kn)}
    split = [(label(a), label(b)) for (a, ka), (b, kb) in zip(zip(old, ko), zip(old[1:], ko[1:]))
             if pos.get(kb) != (pos.get(ka, -9) + 1)]
    print("      original neighbours that are no longer adjacent: %d of %d" % (len(split), len(old) - 1))
    for a, b in split:
        print("        %s | %s" % (a, b))


def leg_lines(old_text, new_text):
    def bag(t):
        return collections.Counter(l.rstrip() for l in t.split("\n") if l.strip())
    old, new = bag(old_text), bag(new_text)
    gone, extra = old - new, new - old
    leg("Lines: no original line missing (%d distinct non-blank lines checked)" % len(old), not gone,
        "\n".join("%dx %r" % (n, l) for l, n in gone.items()))
    code = [l for l in extra if not l.lstrip().startswith("#")]
    leg("Lines: the %d new line(s) are all comments" % sum(extra.values()), not code,
        "non-comment additions: %r" % code if code else "")
    for l in extra:
        print("        + %s" % l)


# ------------------------------------------------------------------ behaviour child
def child(path):
    """Load `path` by path, drive it with fixed inputs, print the observations as JSON."""
    import importlib.util
    import random
    import tempfile
    import time
    from unittest import mock

    stage = os.path.dirname(os.path.abspath(path))
    sys.path.insert(0, stage)  # like a test that loads the file by path next to its siblings
    spec = importlib.util.spec_from_file_location("excubitor_under_test", path)
    m = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = m
    spec.loader.exec_module(m)
    out = {}

    out["surface"] = {n: type(v).__name__ for n, v in vars(m).items() if not n.startswith("__")}

    # --- pure helpers
    out["rate"] = [m.rate(v) for v in (-1, 0, 0.5, 1, 1023, 1024, 1e6, 3e9)]
    out["addr_key"] = [m.addr_key(s) for s in ("1.2.3.4:80", "[::1]:53", "—", "", "bogus", "10.0.0.1:443")]
    rows = [m.Row(kind="process", name="firefox", pid=12, nconn=3, nproc=4, down=1500.0, up=-1.0),
            m.Row(kind="process", name="sshd", pid=0, nconn=1),
            m.Row(kind="conn", name="TCP", pid=5, local="1.2.3.4:5", remote="9.9.9.9:443", state="ESTABLISHED", down=10.0, up=0.0),
            m.Row(kind="conn", name="UDP", pid=5, local="[::1]:5", remote="[2606:4700::1]:443", grouped=True)]
    rows[2].host = "example.net"
    out["columns"] = [[title, [fmt(r) for r in rows], [repr(key(r)) for r in rows]]
                      for title, fmt, key, *_ in m.COLUMNS]
    snap = {10: ("smbd[10.0.0.181]", {("TCP", "a", "b"): ("TCP", "a", "b", "ESTABLISHED", 1.0, 2.0)}),
            11: ("smbd", {("UDP", "c", "d"): ("UDP", "c", "d", "", -1.0, -1.0)}),
            12: ("firefox", {}), 0: ("Other users' processes", {})}
    grouped, meta = m.MainWindow._group(snap)
    out["group"] = [sorted(map(repr, grouped.items())), sorted(map(repr, meta.items()))]

    # --- saved settings (XDG_CONFIG_HOME is a scratch dir set by the parent)
    sf = m.STATE_FILE
    out["state"] = [m.load_state()]
    m.save_state({"a": 1})
    m.save_state({"b": 2})
    out["state"].append(m.load_state())
    Path(sf).write_text("{not json")
    out["state"].append(m.load_state())
    Path(sf).unlink()
    out["state_file_tail"] = sf.split("/")[-2:]

    # --- what the GUI will run through pkexec
    class St:
        def __init__(self, uid, mode):
            self.st_uid, self.st_mode = uid, mode
    good = St(0, 0o100755)
    cases = {"ok": [good] * 3, "file not root": [St(1000, 0o100755), good, good],
             "netdiag not root": [good, St(1000, 0o100755), good], "dir not root": [good, good, St(1000, 0o40755)],
             "file group-writable": [St(0, 0o100775), good, good], "file world-writable": [St(0, 0o100757), good, good],
             "dir world-writable": [good, good, St(0, 0o40777)], "missing": OSError("nope")}
    out["trusted_helper"] = {}
    for name, eff in cases.items():
        with mock.patch.object(m.os, "stat", side_effect=eff):
            out["trusted_helper"][name] = m.trusted_helper()
    out["helper_consts"] = [m.HELPER_FILE, m.HELPER_MAX_AGE, m.INSTALLED_HELPER, m.UDP_TOTAL, m.TCP_CLOSED,
                            m.CLOSED_MIN_BPS, m.CLOSED_MIN_SHARE]

    # --- UdpHelper on fixture files, with a fixed clock
    tmp = Path(tempfile.mkdtemp())
    f = tmp / "udp.json"
    h = m.UdpHelper(str(f))
    ns = {"t": 1001.0, "host": [["TCP", "a", "b", 77]],
          "socks": [{"ns": 123456, "proto": "TCP", "local": "l", "peer": "p", "state": "ESTABLISHED", "ino": 9,
                     "rx": 10, "tx": 20, "pid": 5},
                    {"ns": 123456, "proto": "UDP", "local": "l2", "peer": "—", "state": "", "ino": 0, "pid": 5},
                    {"broken": True}]}
    steps = [("missing", None, 1000.5),
             ("first", {"t": 1000.0, "rx": {"10": 100}, "tx": {"10": 50}, "trx": {"10": 1000}, "ttx": {"10": 0}}, 1000.5),
             ("second", {"t": 1001.0, "rx": {"10": 300, "11": 5}, "tx": {"10": 150}, "trx": {"10": 3000}, "ttx": {"10": 500}, "ns": ns}, 1001.2),
             ("backwards", {"t": 1002.0, "rx": {"10": 10}, "tx": {"10": 10}, "trx": {}, "ttx": {}, "ns": dict(ns, t=1002.0)}, 1002.1),
             ("same sample", {"t": 1002.0, "rx": {"10": 10}, "tx": {"10": 10}, "trx": {}, "ttx": {}}, 1002.2),
             ("ns scan stalled", {"t": 1003.0, "rx": {"10": 20}, "tx": {"10": 20}, "trx": {}, "ttx": {}, "ns": dict(ns, t=980.0)}, 1003.1),
             ("stale", {"t": 900.0, "rx": {}, "tx": {}}, 1002.3),
             ("garbage", "[1, 2]", 1002.4)]
    out["udp"] = []
    for name, data, now in steps:
        if data is None:
            f.unlink(missing_ok=True)
        else:
            f.write_text(data if isinstance(data, str) else json.dumps(data))
        with mock.patch.object(m.time, "time", return_value=now):
            r = h.rates()
            rows_ = h.ns_rows()
            hp = h.host_pid("TCP", "a", "b"), h.host_pid("TCP", "x", "y")
        out["udp"].append([name, repr(r), repr(rows_), repr(hp), repr(h.tcp_rates)])

    # --- FakeBackend (seeded)
    random.seed(7)
    fb = m.FakeBackend()
    out["fake"] = [repr(sorted(fb.snapshot().items())) for _ in range(6)]

    # --- PsutilBackend on the live machine: shape only
    try:
        b = m.PsutilBackend()
        s = b.snapshot()
        out["psutil_shape"] = [type(s).__name__, all(isinstance(k, int) for k in s),
                               all(len(v) == 2 and isinstance(v[1], dict) for v in s.values()), b.helper_ok]
    except Exception as e:  # recorded, so old and new must fail the same way
        out["psutil_shape"] = ["error", type(e).__name__]

    # --- install / uninstall into a scratch HOME (the parent set HOME and XDG_DATA_HOME)
    home = Path(os.environ["HOME"])

    def tree():
        return sorted((str(p.relative_to(home)),
                       hashlib.sha256(p.read_bytes()).hexdigest()[:12] if p.is_file() and p.name != "excubitor.py" else "-",
                       oct(p.stat().st_mode & 0o777) if p.is_file() else "dir")
                      for p in home.rglob("*")
                      if "excubitor" in str(p.relative_to(home)) or p.suffix == ".desktop")
    out["install"] = {"before": m.is_installed("io.test.App")}
    m.install_app("io.test.App")
    out["install"].update(after=m.is_installed("io.test.App"), tree=tree(),
                          launcher=(home / ".local/bin/excubitor").read_text())
    m.uninstall_app("io.test.App")
    out["install"].update(removed=not m.is_installed("io.test.App"), tree_after=tree())
    m.save_state({"a": 1})
    m.save_state({"hide_idle": False, "group_apps": False, "resolve_names": False})

    # --- the real window, FakeBackend, no worker threads (so the run is deterministic)
    from gi.repository import GLib
    m.MainWindow._tick = lambda self: True
    random.seed(12345)
    app = m.App(True)
    app.register(None)
    app.activate()
    win = app.props.active_window
    ctx = GLib.MainContext.default()

    def pump(n=20):
        for _ in range(n):
            while ctx.iteration(False):
                pass
            time.sleep(0.005)

    def act(name, param=None):
        a = win.lookup_action(name)
        assert a is not None, "no action " + name
        a.activate(param)  # runs the real handler (toggles a stateful boolean)

    def rec(tag):
        pump()
        out.setdefault("window", []).append({
            "tag": tag, "procs": len(win.procs), "root": win.root.get_n_items(), "view": win.sort_model.get_n_items(),
            "conns": sum(len(r.cmap) for r in win.procs.values()), "subtitle": win.title.get_subtitle(),
            "flags": [win.group, win.hide_idle, win.paused, win.interval_ms, win.query],
            "rows": sorted([r.name, r.pid, r.nconn, r.nproc, round(r.down, 1), round(r.up, 1), r.grouped]
                           for r in win.procs.values()),
            "banner": [win.banner_rev.get_reveal_child(), win.banner_label.get_label(), win.act_udp.get_enabled()],
            "stack": win.stack.get_visible_child_name()})

    pump()
    rec("start")
    for i in range(12):
        win.apply(win.backend.snapshot())
        if i % 4 == 3:
            rec("tick %d" % i)
    act("group")
    rec("group on")
    for _ in range(3):
        win.apply(win.backend.snapshot())
    rec("group on, 3 ticks")
    act("idle")
    rec("hide idle")
    win.query = "fire"
    win.filter.changed(m.Gtk.FilterChange.DIFFERENT)
    rec("search fire")
    win.query = "zzzz-no-match"
    win.filter.changed(m.Gtk.FilterChange.DIFFERENT)
    rec("search nothing")
    win.query = ""
    act("idle")
    act("group")
    rec("group off")
    # rows only PsutilBackend makes (per-process UDP total, closed-TCP gap), fed in by hand
    synth = {4242: ("synthetic", {
        ("TCP", "1.1.1.1:1", "2.2.2.2:2"): ("TCP", "1.1.1.1:1", "2.2.2.2:2", "ESTABLISHED", 100.0, 50.0),
        ("UDP", m.UDP_TOTAL, "—"): ("UDP", m.UDP_TOTAL, "—", "", 10.0, 5.0),
        ("TCP", m.TCP_CLOSED, "—"): ("TCP", m.TCP_CLOSED, "—", "", 7.0, 3.0)}),
        0: ("Other users' processes", {("UDP", "x:1", "—"): ("UDP", "x:1", "—", "", -1.0, -1.0)})}
    win.apply(synth)
    rec("synthetic rows")
    act("group")
    win.apply(synth)
    rec("synthetic rows, grouped")
    act("group")
    act("pause")
    rec("paused")
    act("interval", GLib.Variant("s", "5"))
    out["window_state"] = [win.interval_ms, win.paused, win.group, win.hide_idle, m.load_state()]
    print(json.dumps(out, sort_keys=True, default=repr))
    sys.stdout.flush()
    os._exit(0)


# ------------------------------------------------------------------ legs 4 and 5
def stage(label_, src):
    d = SCRATCH / label_
    shutil.rmtree(d, ignore_errors=True)
    d.mkdir(parents=True)
    shutil.copy2(src, d / "excubitor.py")
    for s in SIBLINGS:
        if (ROOT / s).exists():
            shutil.copy2(ROOT / s, d / s)
    return d / "excubitor.py"


def runner():
    """Command prefix to run GTK, or None. xvfb-run is preferred so no window appears on your desktop."""
    if shutil.which("xvfb-run"):
        return ["xvfb-run", "-a"]
    return [] if (os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY")) else None


def gtk_env(**extra):
    env = dict(os.environ, GSK_RENDERER="cairo", NO_AT_BRIDGE="1", PYTHONDONTWRITEBYTECODE="1", **extra)
    if runner() == ["xvfb-run", "-a"]:
        env.pop("WAYLAND_DISPLAY", None)
        env["GDK_BACKEND"] = "x11"
    return env


def run_child(path):
    home = SCRATCH / "home"
    shutil.rmtree(home, ignore_errors=True)
    home.mkdir(parents=True)
    env = gtk_env(HOME=str(home), XDG_CONFIG_HOME=str(home / "cfg"), XDG_DATA_HOME=str(home / "data"),
                  XDG_CACHE_HOME=str(home / "cache"), PYTHONHASHSEED="0")
    r = subprocess.run(runner() + [sys.executable, str(Path(__file__).resolve()), "--child", str(path)],
                       capture_output=True, text=True, env=env, timeout=120)
    if r.returncode != 0 or not r.stdout.strip():
        return None, r.stderr.strip()[-1500:]
    return json.loads(r.stdout.strip().splitlines()[-1]), ""


def leg_behaviour(old, new):
    try:
        import gi
        gi.require_version("Gtk", "4.0")
        gi.require_version("Adw", "1")
    except (ImportError, ValueError) as e:
        print("SKIP  behaviour and smoke legs: PyGObject with GTK 4 / libadwaita not available (%s)" % e)
        skipped.append("behaviour and smoke")
        return
    if runner() is None:
        print("SKIP  behaviour and smoke legs: no display and no xvfb-run")
        skipped.append("behaviour and smoke")
        return
    po, pn = stage("old", old), stage("new", new)
    a, err = run_child(po)
    if a is None:
        return leg("Behaviour: old file runs under the harness", False, err)
    a2, _ = run_child(po)
    leg("Behaviour control: old vs old gives identical observations (harness is deterministic)", a == a2,
        "" if a == a2 else "differs in: %s" % [k for k in a if a.get(k) != (a2 or {}).get(k)])
    b, err = run_child(pn)
    if b is None:
        return leg("Behaviour: new file runs under the harness", False, err)
    diff = [k for k in sorted(set(a) | set(b)) if a.get(k) != b.get(k)]
    leg("Behaviour: old vs new, %d observation groups identical (%d steps of the window run)"
        % (len(a), len(a.get("window", []))), not diff, "differs in: %s" % diff if diff else "")
    for k in diff:
        print("      %s\n        old: %.300r\n        new: %.300r" % (k, a.get(k), b.get(k)))

    # smoke: --help and a few seconds of --fake
    env = gtk_env(HOME=str(SCRATCH / "home"), XDG_CONFIG_HOME=str(SCRATCH / "home/cfg"))
    res = {}
    for tag, p in (("old", po), ("new", pn)):
        h = subprocess.run(runner() + [sys.executable, str(p), "--help"], capture_output=True, text=True, env=env)
        s = subprocess.run(runner() + ["timeout", "6", sys.executable, str(p), "--fake"], capture_output=True, text=True, env=env)
        res[tag] = (h.returncode, h.stdout, s.returncode, "Traceback" in s.stderr)
    leg("Smoke: --help identical (exit %d)" % res["old"][0], res["old"][:2] == res["new"][:2])
    leg("Smoke: --fake runs 6 s and is still up (exit 124 from timeout), no traceback",
        res["new"][2] == 124 and not res["new"][3] and res["old"][2:] == res["new"][2:],
        "old: exit %s traceback %s / new: exit %s traceback %s" % (res["old"][2], res["old"][3], res["new"][2], res["new"][3]))


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("old", nargs="?", help="the earlier excubitor.py to compare against")
    ap.add_argument("new", nargs="?", default=str(ROOT / "excubitor.py"))
    ap.add_argument("--child", help=argparse.SUPPRESS)
    ap.add_argument("--skip-run", action="store_true", help="AST and line legs only")
    args = ap.parse_args()
    if args.child:
        return child(args.child)
    if not args.old:
        ap.error("give the earlier excubitor.py (git show <commit>:excubitor.py > /tmp/excubitor.old.py)")
    old_text, new_text = Path(args.old).read_text(), Path(args.new).read_text()
    leg_build()
    leg_ast(old_text, new_text)
    leg_lines(old_text, new_text)
    if not args.skip_run:
        leg_behaviour(args.old, args.new)
    note = " (skipped: %s)" % ", ".join(skipped) if skipped else ""
    print("\n%s" % ("ALL LEGS PASSED" + note if not failures else "FAILED: " + "; ".join(failures)))
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
