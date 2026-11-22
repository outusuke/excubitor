#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Excubitor: per-process network monitor (GTK4 + libadwaita).

    python3 excubitor.py          # real data via psutil
    python3 excubitor.py --fake   # fake, constantly changing data for UI work

Deps: PyGObject, GTK 4, libadwaita 1.x, psutil (real mode only).
"""
import argparse
import ipaddress
import json
import os
import random
import re
import shutil
import socket
import subprocess
import sys
import threading
import time

import netdiag
from netresolve import Resolver, split_addr

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Adw, Gdk, Gio, GLib, GObject, Gtk, Pango  # noqa: E402

try:
    import psutil
except ImportError:
    psutil = None


def _exceptor():
    """excapture.py (packet capture), if it sits next to this file."""
    try:
        import excapture
        return excapture
    except ImportError:
        return None


# ------------------------------------------------------------ install / uninstall
APP_FILES = ("excubitor.py", "excubitor-helper.py", "netdiag.py", "netresolve.py", "excapture.py", "LICENSE")
DESKTOP = """[Desktop Entry]
Type=Application
Name=Excubitor
Comment=Per-process network monitor
Exec="%(bin)s"
Icon=network-wired
Terminal=false
Categories=System;Monitor;Network;
StartupWMClass=%(app_id)s
"""


def _paths(app_id):
    data = GLib.get_user_data_dir()
    return {"dir": os.path.join(data, "excubitor"),
            "bin": os.path.expanduser("~/.local/bin/excubitor"),
            "desktop": os.path.join(data, "applications", app_id + ".desktop")}


def is_installed(app_id):
    return os.path.exists(_paths(app_id)["desktop"])


def install_app(app_id):
    """Copy the program to ~/.local/share/excubitor, add a launcher in ~/.local/bin and a menu entry."""
    p = _paths(app_id)
    src = os.path.dirname(os.path.abspath(__file__))
    os.makedirs(p["dir"], exist_ok=True)
    if os.path.realpath(src) != os.path.realpath(p["dir"]):
        for f in APP_FILES:
            if os.path.exists(os.path.join(src, f)):
                shutil.copy2(os.path.join(src, f), p["dir"])
    os.makedirs(os.path.dirname(p["bin"]), exist_ok=True)
    with open(p["bin"], "w") as f:
        f.write('#!/bin/sh\nexec python3 "%s" "$@"\n' % os.path.join(p["dir"], "excubitor.py"))
    os.chmod(p["bin"], 0o755)
    os.makedirs(os.path.dirname(p["desktop"]), exist_ok=True)
    with open(p["desktop"], "w") as f:
        f.write(DESKTOP % {"bin": p["bin"], "app_id": app_id})
    if shutil.which("update-desktop-database"):
        subprocess.run(["update-desktop-database", os.path.dirname(p["desktop"])], capture_output=True)


def uninstall_app(app_id):
    p = _paths(app_id)
    for f in (p["desktop"], p["bin"]):
        try:
            os.remove(f)
        except FileNotFoundError:
            pass
    shutil.rmtree(p["dir"], ignore_errors=True)


# ----------------------------------------------------------------- data model
class Row(GObject.Object):
    """One row: either a process or one of its connections."""

    kind = GObject.Property(type=str, default="process")  # "process" | "conn"
    name = GObject.Property(type=str, default="")  # process name or protocol
    pid = GObject.Property(type=int, default=0)
    local = GObject.Property(type=str, default="")
    remote = GObject.Property(type=str, default="")
    state = GObject.Property(type=str, default="")
    nconn = GObject.Property(type=int, default=0)
    down = GObject.Property(type=float, default=-1.0)  # bytes/s, -1 = unknown
    up = GObject.Property(type=float, default=-1.0)
    nproc = GObject.Property(type=int, default=0)  # processes in an application group
    grouped = GObject.Property(type=bool, default=False)  # shown in "group by application" mode

    def __init__(self, **kw):
        super().__init__(**kw)
        self.children = None  # Gio.ListStore of conn rows (process rows only)
        self.cmap = {}  # connection key -> Row
        self.host = None  # resolved hostname of `remote` (conn rows, when enabled)

    def update(self, **kw):
        """Set only the properties that changed, so we notify as little as possible."""
        for k, v in kw.items():
            if getattr(self, k) != v:
                setattr(self, k, v)


# ------------------------------------------------------------------- backends
# A backend's snapshot() returns:
#   {pid: (process_name, {conn_key: (proto, local, remote, state, down, up)})}
_RX = re.compile(r"bytes_received:(\d+)")
_TX = re.compile(r"bytes_sent:(\d+)")

# UDP has no per-socket byte counters in the kernel, so excubitor-helper reports
# per-process totals. They are shown as one synthetic row per process.
UDP_TOTAL = "(all UDP sockets)"
# TCP bytes of sockets that closed between two polls (live sockets lose their counters on
# close). Shown as one row per process, only when the gap is noticeable (heuristic).
TCP_CLOSED = "(closed TCP connections)"
CLOSED_MIN_BPS = 2048  # ignore gaps below this many bytes/s ...
CLOSED_MIN_SHARE = 0.15  # ... or below this share of the process's TCP rate
HELPER_FILE = "/run/excubitor/udp.json"
HELPER_MAX_AGE = 3.0  # seconds; older than this = helper is dead/hung


INSTALLED_HELPER = "/usr/local/lib/excubitor/excubitor-helper.py"


def trusted_helper():
    """The installed helper if root owns it and its folder and netdiag.py and nobody else can
    write them (so running it through pkexec executes no user-writable code), else None."""
    d = os.path.dirname(INSTALLED_HELPER)
    try:
        for p in (INSTALLED_HELPER, os.path.join(d, "netdiag.py"), d):
            st = os.stat(p)
            if st.st_uid != 0 or st.st_mode & 0o022:
                return None
    except OSError:
        return None
    return INSTALLED_HELPER


STATE_FILE = os.path.join(GLib.get_user_config_dir(), "excubitor", "state.json")


def load_state():
    try:
        with open(STATE_FILE) as f:
            return json.load(f)
    except (OSError, ValueError):
        return {}


def save_state(update):
    """Merge `update` into the saved settings (so one setting never clobbers another)."""
    try:
        state = load_state()
        state.update(update)
        os.makedirs(os.path.dirname(STATE_FILE), exist_ok=True)
        with open(STATE_FILE, "w") as f:
            json.dump(state, f)
    except OSError:
        pass


class UdpHelper:
    """Reads the cumulative per-PID UDP counters written by excubitor-helper.py."""

    def __init__(self, path=HELPER_FILE):
        self.path = path
        self.prev = None
        self.ns = None  # latest "ns" block (sockets in other network namespaces)
        self.ns_prev = None  # (t, {key: (rx, tx)})
        self.ns_cache = []
        self._host_map, self._host_t = {}, None
        self.tcp_rates = {}  # pid -> (down, up) from the helper's TCP probes

    def host_pid(self, proto, local, remote):
        """PID of a host-namespace socket psutil couldn't attribute (other users'
        processes), looked up in the helper's root-level scan. 0 if unknown."""
        d = self.ns
        try:
            t = d["t"]
            if self._host_t != t:
                self._host_map = {(p, l, pe): pid for p, l, pe, pid in d["host"]}
                self._host_t = t
        except (KeyError, TypeError, ValueError):
            return 0
        return self._host_map.get((proto, local, remote), 0)

    def ns_rows(self):
        """Sockets from other network namespaces, as
        [(pid, key, proto, local, remote, state, down, up)]. psutil can't see these."""
        d = self.ns
        try:
            t, socks = float(d["t"]), d["socks"]
        except (KeyError, TypeError, ValueError):
            self.ns_prev, self.ns_cache = None, []
            return []
        if time.time() - t > 10:  # the helper's scanner stalled
            return []
        if self.ns_prev and self.ns_prev[0] == t:
            return self.ns_cache  # same scan as last time
        old_t, old = self.ns_prev or (None, {})
        dt = (t - old_t) if old_t else 0
        new, rows = {}, []
        for s in socks:
            try:
                key = (s["ns"], s["proto"], s["local"], s["peer"])
                down = up = -1.0  # UDP: only per-process totals exist
                if s.get("rx") is not None and s.get("tx") is not None and s.get("ino"):
                    new[s["ino"]] = (s["rx"], s["tx"])
                    prev = old.get(s["ino"])
                    if prev and dt > 0:
                        down = max(0.0, (s["rx"] - prev[0]) / dt)
                        up = max(0.0, (s["tx"] - prev[1]) / dt)
                    else:
                        down = up = 0.0
                shown = f"{s['local']} [ns {s['ns'] % 10000}]"  # tag: not the host namespace
                rows.append((int(s.get("pid") or 0), key, s["proto"], shown, s["peer"],
                             s["state"], down, up))
            except (KeyError, TypeError, ValueError):
                continue
        self.ns_prev, self.ns_cache = (t, new), rows
        return rows

    def rates(self):
        """{pid: (down, up)} in bytes/s, or None if the helper isn't usable."""
        try:
            with open(self.path) as f:
                d = json.load(f)
            t = float(d["t"])
            if time.time() - t > HELPER_MAX_AGE:
                raise ValueError("stale")
            cur = {"t": t,
                   "rx": {int(k): int(v) for k, v in d["rx"].items()},
                   "tx": {int(k): int(v) for k, v in d["tx"].items()},
                   "trx": {int(k): int(v) for k, v in d.get("trx", {}).items()},
                   "ttx": {int(k): int(v) for k, v in d.get("ttx", {}).items()}}
        except (OSError, ValueError, KeyError, TypeError):
            self.prev = None
            self.ns = None
            self.tcp_rates = {}
            return None
        self.ns = d.get("ns")
        prev, self.prev = self.prev, cur
        self.tcp_rates = {}
        if prev is None:
            return {}
        dt = t - prev["t"]  # the helper's clock, so GUI timing jitter doesn't matter
        if dt <= 0:
            self.prev = prev  # same sample again; keep the older baseline
            return {}
        out = {}
        for pid in cur["rx"].keys() | cur["tx"].keys():
            rx = cur["rx"].get(pid, 0) - prev["rx"].get(pid, 0)
            tx = cur["tx"].get(pid, 0) - prev["tx"].get(pid, 0)
            # max(): the counter can go backwards after a helper restart / PID reuse
            out[pid] = (max(0, rx) / dt, max(0, tx) / dt)
        for pid in cur["trx"].keys() | cur["ttx"].keys():
            rx = cur["trx"].get(pid, 0) - prev["trx"].get(pid, 0)
            tx = cur["ttx"].get(pid, 0) - prev["ttx"].get(pid, 0)
            self.tcp_rates[pid] = (max(0, rx) / dt, max(0, tx) / dt)
        return out


class PsutilBackend:
    def __init__(self):
        self.udp = UdpHelper()
        self.helper_ok = False
        self.names = {}  # pid -> (create_time, name)
        self._fresh = set()  # pids whose cache entry was verified this snapshot
        self.prev = {}  # socket inode -> (rx_bytes, tx_bytes) at previous poll
        self.inodes = netdiag.InodeMap()
        try:
            self.diag = netdiag.open_diag()
        except OSError:
            self.diag = None
        self.prev_t = None

    def _name(self, pid):
        # Verified once per snapshot against the process start time, so a reused PID
        # doesn't keep showing the previous owner's name.
        hit = self.names.get(pid)
        if hit is None or pid not in self._fresh:
            try:
                p = psutil.Process(pid)
                ct = p.create_time()
                if hit is None or hit[0] != ct:
                    hit = (ct, p.name())
            except psutil.Error:
                hit = hit or (0.0, f"pid {pid}")
            self.names[pid] = hit
            self._fresh.add(pid)
        return hit[1]

    def snapshot(self):
        out = {}
        self._fresh = set()
        try:
            socks = self.diag.sockets() if self.diag else []
        except OSError:
            socks = []
        udp = self.udp.rates()  # also refreshes the helper's socket/PID tables
        now = time.monotonic()
        dt = (now - self.prev_t) if self.prev_t else 0
        owner = self.inodes.pids({s["ino"] for s in socks})
        counters = {}
        for s in socks:
            proto, local, remote = s["proto"], s["local"], s["peer"]
            pid = owner.get(s["ino"], 0)
            if not pid and udp is not None:  # other user's socket: ask the helper (root)
                pid = self.udp.host_pid(proto, local, remote)
            name = self._name(pid) if pid else "Other users' processes"
            entry = out.setdefault(pid, (name, {}))
            down = up = -1.0  # unknown (UDP, or no counters)
            if s["rx"] is not None and s["tx"] is not None and s["ino"]:
                counters[s["ino"]] = (s["rx"], s["tx"])
                old = self.prev.get(s["ino"])
                if old and dt > 0:
                    down = max(0.0, (s["rx"] - old[0]) / dt)
                    up = max(0.0, (s["tx"] - old[1]) / dt)
                else:
                    down = up = 0.0
            entry[1][(proto, local, remote)] = (proto, local, remote, s["state"], down, up)
        self.helper_ok = udp is not None
        # Sockets in other network namespaces (sandboxes) come from the helper.
        # Added before the UDP totals below so those processes get their rate row.
        for pid, key, proto, local, remote, state, down, up in self.udp.ns_rows():
            name = self._name(pid) if pid else "Other users' processes"
            out.setdefault(pid, (name, {}))[1][key] = (proto, local, remote, state, down, up)
        for pid, (down, up) in (udp or {}).items():
            if pid in out:
                key = ("UDP", UDP_TOTAL, "—")
                out[pid][1][key] = ("UDP", UDP_TOTAL, "—", "", down, up)
        # TCP the helper saw but no live socket accounts for = connections that closed meanwhile.
        for pid, (tdown, tup) in self.udp.tcp_rates.items():
            if pid not in out:
                continue
            live = [v for v in out[pid][1].values() if v[0].startswith("TCP") and v[4] >= 0]
            gdown = tdown - sum(v[4] for v in live)
            gup = tup - sum(v[5] for v in live)
            if (gdown > max(CLOSED_MIN_BPS, CLOSED_MIN_SHARE * tdown)
                    or gup > max(CLOSED_MIN_BPS, CLOSED_MIN_SHARE * tup)):
                out[pid][1][("TCP", TCP_CLOSED, "—")] = (
                    "TCP", TCP_CLOSED, "—", "", max(gdown, 0.0), max(gup, 0.0))
        self.prev, self.prev_t = counters, now
        self.names = {p: n for p, n in self.names.items() if p in out}
        return out


class FakeBackend:
    NAMES = ["firefox", "chromium", "spotify", "slack", "code", "telegram-desktop",
             "systemd-resolved", "sshd", "docker-proxy", "steam", "curl", "NetworkManager",
             "firefox", "firefox", "chromium", "chromium", "chromium"]  # duplicates: for grouping

    fake = True
    helper_ok = True  # fake data already includes UDP rates

    def __init__(self):
        self.procs = {1000 + i * 37: (n, {}) for i, n in enumerate(self.NAMES)}
        self.away = set()
        for _, conns in self.procs.values():
            conns[("TCP", "0.0.0.0:8080", "—")] = ["TCP", "0.0.0.0:8080", "—", "LISTEN", -1.0, -1.0]
            for _ in range(random.randint(1, 5)):
                self._add(conns)

    @staticmethod
    def _add(conns):
        proto = random.choice(["TCP", "TCP", "TCP", "UDP", "TCP6"])
        local = f"192.168.1.23:{random.randint(32768, 60999)}"
        remote = ".".join(str(random.randint(1, 254)) for _ in range(4)) + ":443"
        state = "" if proto == "UDP" else "ESTABLISHED"
        conns[(proto, local, remote)] = [proto, local, remote, state, 0.0, 0.0]

    def snapshot(self):
        if random.random() < 0.1:  # a process appears or vanishes
            self.away ^= {random.choice(list(self.procs))}
        out = {}
        for pid, (name, conns) in self.procs.items():
            if pid in self.away:
                continue
            if random.random() < 0.12:
                self._add(conns)
            if len(conns) > 2 and random.random() < 0.12:
                conns.pop(random.choice(list(conns)))
            for c in conns.values():
                if c[3] == "LISTEN":
                    continue
                busy = random.random() < 0.6
                c[4] = random.random() ** 3 * 3e6 if busy else 0.0
                c[5] = random.random() ** 3 * 4e5 if busy else 0.0
            out[pid] = (name, {k: tuple(v) for k, v in conns.items()})
        return out


# ------------------------------------------------------------ cell formatting
def rate(v):
    if v < 0:
        return "—"
    return GLib.format_size(int(v)) + "/s" if v >= 1 else "0 B/s"


def f_name(r):
    return f"{r.name} ({r.nproc})" if r.kind == "process" and r.nproc > 1 else r.name
def f_pid(r):
    # In grouped mode the connection rows carry their own PID.
    if r.kind == "process" or r.grouped:
        return str(r.pid) if r.pid else ""
    return ""
def f_local(r):
    if r.kind == "process":
        return f"{r.nconn} connection{'s' if r.nconn != 1 else ''}"
    return r.local
def addr_key(s):
    """Sort key for 'ip:port' / '[ip]:port': IP numerically, then port; blanks first."""
    try:
        a = ipaddress.ip_address(split_addr(s))
        return (a.version, int(a), int(s.rsplit(":", 1)[-1]))
    except (ValueError, TypeError):
        return (0, 0, 0)


def f_remote(r):
    if r.kind != "conn":
        return ""
    if r.host:  # reverse-DNS name, keeping the port
        return f"{r.host}:{r.remote.rsplit(':', 1)[-1]}"
    return r.remote
def f_state(r): return r.state if r.kind == "conn" else ""
def f_down(r): return rate(r.down)
def f_up(r): return rate(r.up)


STATE_CSS = {"ESTABLISHED": "success", "LISTEN": "accent",
             "TIME_WAIT": "warning", "CLOSE_WAIT": "warning"}

# title, formatter, sort key, numeric?, expand?, width
COLUMNS = [
    ("Process", f_name, lambda r: r.name.casefold(), False, True, 200),
    ("PID", f_pid, lambda r: r.pid, True, False, 70),
    ("Local", f_local, lambda r: r.local, False, False, 180),
    ("Remote", f_remote, lambda r: addr_key(r.remote), False, True, 180),
    ("State", f_state, lambda r: r.state, False, False, 110),
    ("↓ Down", f_down, lambda r: r.down, True, False, 90),
    ("↑ Up", f_up, lambda r: r.up, True, False, 90),
]


# --------------------------------------------------------------------- window
class MainWindow(Adw.ApplicationWindow):
    def __init__(self, app, backend, interval_ms):
        super().__init__(application=app, title="Network Monitor",
                         default_width=1060, default_height=640)
        self.backend = backend
        self.procs = {}  # pid -> Row
        self.query = ""
        self._busy = False
        self.paused = False
        self.interval_ms = interval_ms
        self._subtitle = ""
        self._notice = None  # failure message shown in the banner
        self._helper_busy = False
        saved = load_state()
        self.dismissed = bool(saved.get("udp_banner_dismissed"))
        self.hide_idle = bool(saved.get("hide_idle"))
        self.group = bool(saved.get("group_apps"))
        self._resolver = Resolver() if saved.get("resolve_names") else None
        self.resolver = self._resolver  # None = names off
        self._last_snap = None
        self._bound = {}  # list item -> (row object, handler id)
        self._cellctx = {}  # list item -> [(row, formatter)] for the right-click menu
        self._ctx = None  # (row, formatter) of the cell the menu was opened on
        self.icons = Gtk.IconTheme.get_for_display(Gdk.Display.get_default())

        # Model stack: root -> filter -> tree -> sort -> selection
        self.root = Gio.ListStore.new(Row)
        self.filter = Gtk.CustomFilter.new(self._match, None)
        filtered = Gtk.FilterListModel.new(self.root, self.filter)
        tree = Gtk.TreeListModel.new(filtered, False, False, self._children)

        self.view = Gtk.ColumnView(show_row_separators=True)
        self.view.add_css_class("data-table")
        first = None
        for i, (title, fmt, key, numeric, expand, width) in enumerate(COLUMNS):
            col = Gtk.ColumnViewColumn.new(title, self._factory(fmt, numeric, i == 0))
            col.set_resizable(True)
            col.set_expand(expand)
            col.set_fixed_width(width)
            col.set_sorter(Gtk.CustomSorter.new(self._cmp(key), None))
            self.view.append_column(col)
            first = first or col
        self.view.sort_by_column(first, Gtk.SortType.ASCENDING)

        self.row_sorter = Gtk.TreeListRowSorter.new(self.view.get_sorter())
        self.sort_model = Gtk.SortListModel.new(tree, self.row_sorter)
        selection = Gtk.SingleSelection.new(self.sort_model)
        selection.set_autoselect(False)
        self.selection = selection
        self.view.set_model(selection)
        self.sort_model.connect("items-changed", lambda *_: self._update_empty())

        # Content: list or empty state
        self.stack = Gtk.Stack()
        self.stack.add_named(Gtk.ScrolledWindow(child=self.view, vexpand=True), "list")
        self.stack.add_named(Adw.StatusPage(icon_name="network-wired-symbolic",
                                            title="No Connections",
                                            description="Nothing matches right now."), "empty")
        self.stack.set_visible_child_name("empty")

        # Header + search
        self.title = Adw.WindowTitle(title="Network Monitor", subtitle="")
        header = Adw.HeaderBar(title_widget=self.title)
        self.search_btn = Gtk.ToggleButton(icon_name="system-search-symbolic",
                                           tooltip_text="Search (Ctrl+F)")
        header.pack_start(self.search_btn)
        self._build_menu(header)
        self._build_copy_actions(app)
        self._build_capture_actions()
        self._build_install_action()
        entry = Gtk.SearchEntry(hexpand=True, placeholder_text="Filter by process, PID, address or state")
        entry.connect("search-changed", self._on_search)
        bar = Gtk.SearchBar(child=entry)
        bar.connect_entry(entry)
        bar.set_key_capture_widget(self)
        self.search_btn.bind_property("active", bar, "search-mode-enabled",
                                      GObject.BindingFlags.BIDIRECTIONAL)
        act = Gio.SimpleAction.new("search", None)
        act.connect("activate", lambda *_: self.search_btn.set_active(not self.search_btn.get_active()))
        self.add_action(act)
        app.set_accels_for_action("win.search", ["<Ctrl>f"])

        toolbar = Adw.ToolbarView(content=self.stack)
        toolbar.add_top_bar(header)
        toolbar.add_top_bar(bar)
        toolbar.add_top_bar(self._build_banner())
        self.toasts = Adw.ToastOverlay(child=toolbar)
        self.set_content(self.toasts)

        # Polling
        self._tick()
        self._timer = GLib.timeout_add(self.interval_ms, self._tick)
        self._update_banner()

    # ---- primary menu
    def _build_menu(self, header):
        menu = Gio.Menu()
        sec = Gio.Menu()
        sec.append("Enhanced Monitoring", "win.udp")
        sec.append("Stop Recordings", "win.stop-rec")
        menu.append_section(None, sec)
        sec = Gio.Menu()
        sec.append("Pause Updates", "win.pause")
        sec.append("Group by Application", "win.group")
        sec.append("Hide Idle Processes", "win.idle")
        sec.append("Resolve Hostnames", "win.resolve")
        iv = Gio.Menu()
        for n in (1, 2, 5):
            iv.append(f"{n} second" + ("s" if n > 1 else ""), f"win.interval::{n}")
        sec.append_submenu("Refresh Interval", iv)
        menu.append_section(None, sec)
        sec = Gio.Menu()
        sec.append("Add to Applications Menu", "win.install")
        sec.append("About Excubitor", "win.about")
        menu.append_section(None, sec)
        header.pack_end(Gtk.MenuButton(icon_name="open-menu-symbolic", menu_model=menu,
                                       primary=True, tooltip_text="Main Menu"))

        self.act_udp = Gio.SimpleAction.new_stateful("udp", None, GLib.Variant.new_boolean(False))
        self.act_udp.connect("change-state", self._on_udp)
        self.act_udp.set_enabled(not getattr(self.backend, "fake", False))
        pause = Gio.SimpleAction.new_stateful("pause", None, GLib.Variant.new_boolean(False))
        pause.connect("change-state", self._on_pause)
        idle = Gio.SimpleAction.new_stateful("idle", None, GLib.Variant.new_boolean(self.hide_idle))
        idle.connect("change-state", self._on_idle)
        group = Gio.SimpleAction.new_stateful("group", None, GLib.Variant.new_boolean(self.group))
        group.connect("change-state", self._on_group)
        resolve = Gio.SimpleAction.new_stateful(
            "resolve", None, GLib.Variant.new_boolean(self.resolver is not None))
        resolve.connect("change-state", self._on_resolve)
        interval = Gio.SimpleAction.new_stateful(
            "interval", GLib.VariantType.new("s"),
            GLib.Variant.new_string(str(self.interval_ms // 1000)))
        interval.connect("change-state", self._on_interval)
        about = Gio.SimpleAction.new("about", None)
        about.connect("activate", self._about)
        for a in (self.act_udp, pause, idle, group, resolve, interval, about):
            self.add_action(a)
        self.get_application().set_accels_for_action("win.pause", ["<Ctrl>p"])

    def _on_pause(self, act, value):
        act.set_state(value)
        self.paused = value.get_boolean()
        if self.paused:
            self.title.set_subtitle(self._subtitle + " · paused")
        else:
            self.title.set_subtitle(self._subtitle)
            self._tick()

    def _on_idle(self, act, value):
        act.set_state(value)
        self.hide_idle = value.get_boolean()
        save_state({"hide_idle": self.hide_idle})
        self.filter.changed(Gtk.FilterChange.DIFFERENT)

    def _on_resolve(self, act, value):
        act.set_state(value)
        on = value.get_boolean()
        if on and self._resolver is None:
            self._resolver = Resolver()  # created once; its threads idle when off
        self.resolver = self._resolver if on else None
        save_state({"resolve_names": on})
        self._refresh_hosts()  # names appear over the next refreshes, vanish at once when off

    def _on_group(self, act, value):
        act.set_state(value)
        self.group = value.get_boolean()
        save_state({"group_apps": self.group})
        # Row identity changes (pid vs application), so rebuild from the last snapshot.
        self.root.remove_all()
        self.procs.clear()
        if self._last_snap is not None:
            self.apply(self._last_snap)

    @staticmethod
    def _group(snap):
        """Merge processes with the same name into one application row.

        Returns (snapshot keyed by ("app", name), {key: (process count, sole pid)}).
        Connection keys get the owning pid prepended so they stay unique.
        """
        out, meta = {}, {}
        for pid, (name, conns) in snap.items():
            # Some daemons retitle forked children, e.g. "smbd[10.0.0.181]" -> "smbd".
            # Cut at the first "[" (the closing bracket can be missing: comm is 15 chars).
            name = name.split("[", 1)[0].rstrip() or name
            key = ("app", name)
            merged = out.setdefault(key, (name, {}))[1]
            for ck, cv in conns.items():
                merged[(pid,) + ck] = cv
            if pid:
                meta.setdefault(key, set()).add(pid)
        meta = {k: (len(v), next(iter(v)) if len(v) == 1 else 0) for k, v in meta.items()}
        return out, meta

    def _on_interval(self, act, value):
        act.set_state(value)
        self.interval_ms = int(value.get_string()) * 1000
        GLib.source_remove(self._timer)
        self._timer = GLib.timeout_add(self.interval_ms, self._tick)

    def _about(self, *_):
        kw = dict(application_name="Excubitor", application_icon="network-wired-symbolic",
                  version="0.1", comments="Per-process network monitor", developer_name="Excubitor")
        if hasattr(Adw, "AboutDialog"):
            Adw.AboutDialog(**kw).present(self)
        else:
            Adw.AboutWindow(transient_for=self, **kw).present()

    # ---- UDP helper banner + install/uninstall (polkit asks for the password)
    BANNER_TEXT = ("Limited view: enable enhanced monitoring to see UDP rates, "
                   "sandboxed apps and other users' processes.")

    def _build_banner(self):
        self.banner_label = Gtk.Label(hexpand=True, xalign=0.0, wrap=True)
        self.spinner = Gtk.Spinner()
        self.enable_btn = Gtk.Button(label="Enable…")
        self.enable_btn.add_css_class("suggested-action")
        self.enable_btn.connect("clicked", lambda *_: self._run_helper("--install"))
        close = Gtk.Button(icon_name="window-close-symbolic", tooltip_text="Dismiss")
        close.add_css_class("flat")
        close.add_css_class("circular")
        close.connect("clicked", self._on_banner_close)
        row = Gtk.Box(spacing=12, margin_start=12, margin_end=12, margin_top=6, margin_bottom=6)
        for w in (self.banner_label, self.spinner, self.enable_btn, close):
            row.append(w)
        self.banner_rev = Gtk.Revealer(child=row)
        return self.banner_rev

    def _update_banner(self):
        ok = self.backend.helper_ok
        fake = getattr(self.backend, "fake", False)
        show = bool(self._notice) or (not ok and not self.dismissed and not fake)
        self.banner_label.set_label(self._notice or self.BANNER_TEXT)
        self.spinner.set_visible(self._helper_busy)
        self.spinner.set_spinning(self._helper_busy)
        self.enable_btn.set_visible(not ok and not self._helper_busy and not fake)
        self.banner_rev.set_reveal_child(show)
        self.act_udp.set_state(GLib.Variant.new_boolean(bool(ok)))

    def _on_banner_close(self, *_):
        if self._notice:
            self._notice = None
        else:  # "don't nag me": the menu stays available
            self.dismissed = True
            save_state({"udp_banner_dismissed": True})
        self._update_banner()

    def _on_udp(self, _act, value):
        self._run_helper("--install" if value.get_boolean() else "--uninstall")

    def _run_helper(self, flag):
        if self._helper_busy:
            return
        helper = os.path.join(os.path.dirname(os.path.abspath(__file__)), "excubitor-helper.py")
        if flag == "--uninstall":
            helper = trusted_helper() or helper
        self._notice = None
        self._helper_busy = True
        self.act_udp.set_enabled(False)
        self._update_banner()
        try:
            proc = Gio.Subprocess.new(
                ["pkexec", sys.executable, helper, flag],
                Gio.SubprocessFlags.STDOUT_PIPE | Gio.SubprocessFlags.STDERR_MERGE)
        except GLib.Error as e:
            self._helper_done(flag, False, f"Could not start pkexec: {e.message}")
            return

        def done(p, res):
            out = ""
            try:
                _ok, out, _err = p.communicate_utf8_finish(res)
            except GLib.Error:
                pass
            code = p.get_exit_status() if p.get_if_exited() else -1
            msg = None
            if code != 0:
                lines = (out or "").strip().splitlines()
                if code in (126, 127) and not lines:
                    msg = "Authentication was cancelled or failed."
                elif lines:
                    msg = f"Could not {'enable' if flag == '--install' else 'disable'} enhanced monitoring: {lines[-1]}"
            self._helper_done(flag, code == 0, msg)

        proc.communicate_utf8_async(None, None, done)

    def _helper_done(self, flag, ok, msg):
        self._helper_busy = False
        self.act_udp.set_enabled(True)
        if not ok:
            self._notice = msg or (f"Could not {'enable' if flag == '--install' else 'disable'} "
                                   f"enhanced monitoring (cancelled or failed). "
                                   f"Try: sudo python3 excubitor-helper.py {flag}")
        elif flag == "--uninstall":
            self.dismissed = True  # they turned it off on purpose; don't nag
            save_state({"udp_banner_dismissed": True})
        self._update_banner()
        if ok:
            installed = flag == "--install"
            self.act_udp.set_state(GLib.Variant.new_boolean(installed))  # next poll corrects it
            self.toasts.add_toast(Adw.Toast.new(
                "Enhanced monitoring enabled" if installed else "Enhanced monitoring disabled"))
            GLib.timeout_add(1500, lambda: (self._tick(), GLib.SOURCE_REMOVE)[1])

    # ---- tree / filter / sort helpers
    def _children(self, row, *_):
        return row.children if row.kind == "process" else None

    def _match(self, row, *_):
        if self.hide_idle and max(row.down, 0.0) + max(row.up, 0.0) <= 0:
            return False
        q = self.query
        if not q:
            return True
        if q in row.name.lower() or q in str(row.pid):
            return True
        return any(q in c.local.lower() or q in c.remote.lower() or q in (c.host or "").lower() or q in str(c.pid)
                   or q in c.state.lower() or q in c.name.lower()
                   for c in row.cmap.values())

    @staticmethod
    def _cmp(key):
        def f(a, b, *_):
            x, y = key(a), key(b)
            return (x > y) - (x < y)
        return f

    def _on_search(self, entry):
        self.query = entry.get_text().strip().lower()
        self.filter.changed(Gtk.FilterChange.DIFFERENT)

    def _update_empty(self):
        self.stack.set_visible_child_name("list" if self.sort_model.get_n_items() else "empty")

    # ---- copying: Ctrl+C = selected row, right-click = cell menu
    def _build_copy_actions(self, app):
        def act(name, fn):
            a = Gio.SimpleAction.new(name, None)
            a.connect("activate", lambda *_: fn())
            self.add_action(a)
        act("copy", lambda: self._copy_row(self._selected()))
        act("copy-row", lambda: self._copy_row(self._ctx[0] if self._ctx else None))
        act("copy-cell", lambda: self._ctx and self._copy(self._ctx[1](self._ctx[0])))
        act("copy-raw", lambda: self._ctx and self._copy(self._ctx[0].remote))
        app.set_accels_for_action("win.copy", ["<Ctrl>c"])

    # ---- install to the applications menu
    def _build_install_action(self):
        on = is_installed(self.get_application().get_application_id())
        act = Gio.SimpleAction.new_stateful("install", None, GLib.Variant.new_boolean(on))
        act.connect("change-state", self._on_install)
        self.add_action(act)

    def _on_install(self, act, value):
        on = value.get_boolean()
        app_id = self.get_application().get_application_id()
        try:
            (install_app if on else uninstall_app)(app_id)
        except OSError as e:
            return self._toast("Could not %s: %s" % ("install" if on else "remove", e))
        act.set_state(value)
        self._toast("Added to the applications menu (command: excubitor)" if on
                    else "Removed from the applications menu")

    # ---- packet capture through exceptor.py
    def _build_capture_actions(self):
        self.recs = []  # (exceptor Capture, name) being saved to a file
        for name, fn in (("capture", lambda *_: self._capture(False)),
                         ("record", lambda *_: self._capture(True)),
                         ("stop-rec", lambda *_: [c.stop() for c, _n in self.recs])):
            a = Gio.SimpleAction.new(name, None)
            a.connect("activate", fn)
            self.add_action(a)
        self.act_stop = self.lookup_action("stop-rec")
        self.act_stop.set_enabled(False)

    @staticmethod
    def _pids(row):
        if row.kind == "conn":
            return {row.pid} if row.pid else set()
        return {row.pid} if row.pid else {c.pid for c in row.cmap.values() if c.pid}

    def _toast(self, msg):
        self.toasts.add_toast(Adw.Toast.new(msg))

    def _capture(self, record):
        ex, item = _exceptor(), (self._ctx[0] if self._ctx else None)
        if ex is None or item is None or getattr(self, "_scanning", False):
            return
        pids = self._pids(item)
        self._scanning = True

        def work():  # exceptor's /proc scan, off the UI thread
            try:
                res = ex.group_for_pids(pids)
            except OSError as e:
                res = e
            GLib.idle_add(self._picked, res, record)
        threading.Thread(target=work, daemon=True).start()

    def _picked(self, groups, record):
        self._scanning = False
        if isinstance(groups, OSError):
            self._toast(str(groups))
        elif not groups:
            self._toast("No capturable sockets")
        elif len(groups) == 1:
            self._start(groups[0], record)
        else:  # the row spans several programs: let the user choose
            groups = groups[:6]
            d = Adw.AlertDialog(heading="Capture which program?",
                                body="This row spans several programs.")
            d.add_response("cancel", "Cancel")
            for i, g in enumerate(groups):
                n = len(g["pids"])
                d.add_response(str(i), "%s (%d process%s)" % (g["name"], n, "" if n == 1 else "es"))
            d.set_close_response("cancel")
            d.connect("response", lambda _d, r: r != "cancel" and self._start(groups[int(r)], record))
            d.present(self)
        return False

    def _start(self, g, record):
        ex = _exceptor()

        def go(path=None):
            try:
                c = ex.launch(g, lambda m: GLib.idle_add(self._toast, m), out=path)
            except (ex.Missing, OSError) as e:
                return self._toast(str(e))
            if path:
                self.recs.append((c, g["name"]))
        if not record:
            return go()
        name = re.sub(r"[^\w.-]+", "_", g["name"]) or "capture"
        dlg = Gtk.FileDialog(title="Save capture as",
                             initial_name="%s-%s.pcapng" % (name, time.strftime("%Y%m%d-%H%M%S")))

        def done(d, res):
            try:
                f = d.save_finish(res)
            except GLib.Error:
                return  # cancelled
            if f and f.get_path():
                go(f.get_path())
        dlg.save(self, None, done)

    def _rec_note(self):
        """Subtitle suffix for running recordings; reports finished ones."""
        for c, name in list(self.recs):
            if c.done.is_set():
                self.recs.remove((c, name))
                if c.size():
                    self._toast("Saved %s" % c.out)
        self.act_stop.set_enabled(bool(self.recs))
        return " \u00b7 \u25cf recording %d" % len(self.recs) if self.recs else ""

    def _selected(self):
        tree_row = self.selection.get_selected_item()
        return tree_row.get_item() if tree_row else None

    def _copy(self, text):
        if not text:
            return
        cb = self.get_clipboard()
        try:
            cb.set(text)
        except (AttributeError, TypeError):  # older PyGObject
            cb.set_content(Gdk.ContentProvider.new_for_value(text))
        self.toasts.add_toast(Adw.Toast.new("Copied"))

    def _copy_row(self, item):
        if item is not None:  # tab-separated, as shown (so it pastes into a spreadsheet)
            self._copy("\t".join(col[1](item) for col in COLUMNS))

    def _on_cell_menu(self, gesture, _n, x, y, holder):
        if not holder[0]:
            return
        self._ctx = holder[0]
        item, fmt = self._ctx
        menu = Gio.Menu()
        menu.append("Copy Value", "win.copy-cell")
        if fmt is f_remote and item.kind == "conn" and item.host:
            menu.append("Copy IP Address", "win.copy-raw")
        menu.append("Copy Row", "win.copy-row")
        if _exceptor() and self._pids(item):
            sec = Gio.Menu()
            sec.append("Capture in Wireshark", "win.capture")
            sec.append("Record to File\u2026", "win.record")
            menu.append_section(None, sec)
        pop = Gtk.PopoverMenu.new_from_model(menu)
        pop.set_parent(gesture.get_widget())
        pop.set_has_arrow(False)
        rect = Gdk.Rectangle()
        rect.x, rect.y, rect.width, rect.height = int(x), int(y), 1, 1
        pop.set_pointing_to(rect)
        pop.connect("closed", lambda p: GLib.idle_add(p.unparent))
        pop.popup()

    # ---- cell factory
    def _factory(self, fmt, numeric, first):
        f = Gtk.SignalListItemFactory()
        f.connect("setup", self._setup, numeric, first)
        f.connect("bind", self._bind, fmt, first)
        f.connect("unbind", self._unbind, first)
        return f

    def _setup(self, _f, li, numeric, first):
        label = Gtk.Label(xalign=0.0, ellipsize=Pango.EllipsizeMode.END)
        if numeric:
            label.add_css_class("numeric")
        if first:
            box = Gtk.Box(spacing=8)
            box.append(Gtk.Image())
            box.append(label)
            expander = Gtk.TreeExpander()
            expander.set_child(box)
            li.set_child(expander)
        else:
            li.set_child(label)
        holder = [None]  # filled in by _bind with (row, formatter)
        click = Gtk.GestureClick(button=3)
        click.connect("pressed", self._on_cell_menu, holder)
        li.get_child().add_controller(click)
        self._cellctx[li] = holder

    def _bind(self, _f, li, fmt, first):
        tree_row = li.get_item()
        item = tree_row.get_item()
        widget = li.get_child()
        self._cellctx[li][0] = (item, fmt)
        if first:
            widget.set_list_row(tree_row)
            icon = widget.get_child().get_first_child()
            label = icon.get_next_sibling()
            if item.kind == "process":
                n = item.name.lower()
                icon.set_from_icon_name(n if self.icons.has_icon(n) else "application-x-executable-symbolic")
                icon.set_visible(True)
            else:
                icon.set_visible(False)
        else:
            label = widget

        def refresh(*_):
            label.set_text(fmt(item))
            if item.kind == "conn":
                label.add_css_class("dim-label")
            else:
                label.remove_css_class("dim-label")
            for css in set(STATE_CSS.values()):
                label.remove_css_class(css)
            if fmt is f_state and item.state in STATE_CSS:
                label.remove_css_class("dim-label")
                label.add_css_class(STATE_CSS[item.state])

        refresh()
        self._bound[li] = (item, item.connect("notify", refresh))

    def _unbind(self, _f, li, first):
        item, hid = self._bound.pop(li)
        item.disconnect(hid)
        self._cellctx[li][0] = None
        if first:
            li.get_child().set_list_row(None)

    # ---- polling (worker thread -> main thread)
    def _tick(self):
        if not self._busy and not self.paused:
            self._busy = True
            threading.Thread(target=self._work, daemon=True).start()
        return True

    def _work(self):
        try:
            snap = self.backend.snapshot()
        except Exception as e:  # keep the UI alive whatever happens
            print("snapshot failed:", e, file=sys.stderr)
            snap = None
        GLib.idle_add(self._done, snap)

    def _done(self, snap):
        self._busy = False
        if snap is not None:
            self.apply(snap)
        return GLib.SOURCE_REMOVE

    # ---- in-place diff
    def apply(self, snap):
        self._last_snap = snap
        meta = {}
        if self.group:
            snap, meta = self._group(snap)
        for pid, (name, conns) in snap.items():
            row = self.procs.get(pid)
            if row is None:
                row = Row(kind="process", name=name, pid=pid if isinstance(pid, int) else 0,
                          grouped=self.group)
                row.children = Gio.ListStore.new(Row)
                self.procs[pid] = row
                self.root.append(row)
            if self.group:
                n, sole = meta.get(pid, (0, 0))
                row.update(nproc=n, pid=sole)
            self._sync_conns(row, conns)
        for pid in [p for p in self.procs if p not in snap]:
            row = self.procs.pop(pid)
            found, pos = self.root.find(row)
            if found:
                self.root.remove(pos)

        self._update_banner()
        total = sum(r.nconn for r in self.procs.values())
        down = sum(max(r.down, 0.0) for r in self.procs.values())
        up = sum(max(r.up, 0.0) for r in self.procs.values())
        self._subtitle = (f"{len(self.procs)} processes · {total} connections · "
                          f"↓ {rate(down)}  ↑ {rate(up)}")
        self.title.set_subtitle(self._subtitle + self._rec_note())
        if self.query or self.hide_idle:
            self.filter.changed(Gtk.FilterChange.DIFFERENT)
        self.row_sorter.changed(Gtk.SorterChange.DIFFERENT)  # re-sort by changed rates

    def _set_host(self, r):
        name = self.resolver.lookup(r.remote) if self.resolver else None
        if name != r.host:
            r.host = name
            r.notify("remote")  # re-render the cell

    def _refresh_hosts(self):
        for prow in self.procs.values():
            for c in prow.cmap.values():
                self._set_host(c)
        self.filter.changed(Gtk.FilterChange.DIFFERENT)

    def _sync_conns(self, prow, conns):
        cmap = prow.cmap
        for key, (proto, local, remote, state, down, up) in conns.items():
            r = cmap.get(key)
            if r is None:
                r = Row(kind="conn", name=proto, pid=key[0] if self.group else prow.pid,
                        local=local, remote=remote, state=state, down=down, up=up,
                        grouped=self.group)
                cmap[key] = r
                prow.children.append(r)
            else:
                r.update(state=state, down=down, up=up)
            self._set_host(r)
        for key in [k for k in cmap if k not in conns]:
            r = cmap.pop(key)
            found, pos = prow.children.find(r)
            if found:
                prow.children.remove(pos)
        rated = [c for c in cmap.values() if c.down >= 0]
        prow.update(nconn=sum(1 for c in cmap.values() if c.local not in (UDP_TOTAL, TCP_CLOSED)),
                    down=sum(c.down for c in rated) if rated else -1.0,
                    up=sum(c.up for c in rated) if rated else -1.0)


class App(Adw.Application):
    def __init__(self, fake):
        super().__init__(application_id="io.github.example.Excubitor")
        self.fake = fake
        quit_ = Gio.SimpleAction.new("quit", None)
        quit_.connect("activate", lambda *_: self.quit())
        self.add_action(quit_)
        self.set_accels_for_action("app.quit", ["<Ctrl>q"])

    def do_activate(self):
        win = self.props.active_window
        if not win:
            backend = FakeBackend() if self.fake else PsutilBackend()
            win = MainWindow(self, backend, 1000 if self.fake else 2000)
        win.present()


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--fake", action="store_true", help="use generated data")
    args = ap.parse_args()
    if not args.fake and psutil is None:
        sys.exit("psutil is missing: pip install psutil (or run with --fake)")
    sys.exit(App(args.fake).run([sys.argv[0]]))
