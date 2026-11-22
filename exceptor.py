#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Exceptor: pick a program, get its packets in Wireshark (GTK4 + libadwaita).

No external downloads: everything comes from distro packages.
- Programs with their own network namespace (Flatpak/bwrap --unshare-net, podman,
  docker bridge...) are captured by entering that namespace with nsenter + dumpcap.
- Programs on the host network are captured with nftables: packets whose socket
  belongs to the program's cgroup get their conntrack entry marked, and every
  packet of a marked connection (both directions) is sent to an nflog group that
  dumpcap reads. A bwrap tree that shares a cgroup with other programs is moved
  into a temporary cgroup while capturing, then moved back.
Both end up piped into `wireshark -k -i -`, or into a pcapng file when recording without Wireshark.
A program can also be started from here: it is held inside a fresh systemd scope
until the capture is listening, so its very first packets are recorded.
Needs: wireshark, wireshark-cli (dumpcap), nftables, iproute (ss), polkit (pkexec);
netdiag.py alongside.
"""
import os
import re
import shlex
import shutil
import subprocess
import threading
import time
from collections import Counter

import netdiag

_inodes = netdiag.InodeMap()

_SHARED = re.compile(r"^(init\.scope|session-.*\.scope|vte-spawn-.*\.scope)$")
_SCOPE_OK = {"xdg-dbus-proxy", "flatpak"}   # may share a Flatpak app's scope
_MARK = "0x4e43"
_READY = "exceptor-ready"   # printed by the capture script once its rules are in place
_GATE_DELAY = 1.0          # seconds to let dumpcap start listening before a gated program is released
_run_n = 0


class Missing(Exception):
    pass


def cgpath(pid):
    try:
        with open("/proc/%d/cgroup" % pid) as f:
            for line in f:
                if line.startswith("0::"):
                    return line[3:].replace(" (deleted)", "").strip().strip("/")
    except OSError:
        pass
    return None


def own_scope(path):
    base = path.rsplit("/", 1)[-1]
    return base.endswith((".scope", ".service")) and not _SHARED.match(base)


def pretty(base):
    m = re.match(r"(docker|libpod|crio|cri-containerd)-([0-9a-f]{12})", base)
    if m:
        return "%s %s" % (m[1], m[2])
    b = re.sub(r"\.(scope|service)$", "", base)
    b = re.sub(r"^app-(flatpak-|snap\.|gnome-|kde-)?", "", b)
    return re.sub(r"-\d+$", "", b)


def scan(want=()):
    """[{name, pids, helpers, conns, sandbox, ns, kind, cg, idle}], busiest first.

    One entry per app: processes sharing a systemd scope are merged, and helper
    processes living in a loopback-only network namespace (browser renderers...)
    are folded into their app's process count instead of listed on their own.
    Processes in `want` are included even when none of their sockets can be seen (other users' / root).
    """
    own = os.readlink("/proc/self/ns/net")
    try:
        socks = netdiag.open_diag().sockets()
    except OSError:
        socks = []
    owner = _inodes.pids({s["ino"] for s in socks})
    conns = Counter(owner[s["ino"]] for s in socks if s["ino"] in owner)
    procs = {}
    for entry in os.listdir("/proc"):
        if not entry.isdigit():
            continue
        pid = int(entry)
        try:
            try:
                ns = os.readlink("/proc/%d/ns/net" % pid)
            except PermissionError:     # root's process: its namespace link is unreadable to us
                if pid not in want:
                    continue
                ns = own                # assume the host network
            with open("/proc/%d/comm" % pid) as f:
                comm = f.read().strip()
            with open("/proc/%d/stat" % pid) as f:
                s = f.read()
            ppid = int(s[s.rindex(")") + 2:].split()[1])
        except (OSError, ValueError, IndexError):
            continue
        procs[pid] = {"comm": comm, "ns": ns, "ppid": ppid, "cg": cgpath(pid)}

    def bwrap_root(pid):
        root, p = None, pid
        for _ in range(64):
            i = procs.get(p)
            if not i:
                break
            if i["comm"] == "bwrap":
                root = p
            p = i["ppid"]
        return root

    net_ok = {}

    def has_net(pid, ns):
        """False for a namespace with only loopback: nothing in it can reach the network."""
        if ns not in net_ok:
            try:
                with open("/proc/%d/net/dev" % pid) as f:
                    net_ok[ns] = any(l.split(":")[0].strip() != "lo" for l in list(f)[2:])
            except OSError:
                net_ok[ns] = True       # can't tell: keep it
        return net_ok[ns]

    groups, bare = {}, []
    for pid, i in procs.items():
        sandbox = i["ns"] != own
        if sandbox and not has_net(pid, i["ns"]):
            bare.append(pid)
            continue
        root = None if sandbox else bwrap_root(pid)
        if sandbox:
            key = ("ns", i["ns"])
        elif root:
            key = ("bwrap", root)
        elif (pid in conns or pid in want) and i["cg"] and own_scope(i["cg"]):
            key = ("cg", i["cg"])
        elif pid in conns or pid in want:
            key = ("name", i["comm"])
        else:
            continue
        g = groups.setdefault(key, {"pids": [], "conns": 0, "sandbox": sandbox, "ns": i["ns"],
                                    "kind": key[0], "cg": None, "name": i["comm"]})
        g["pids"].append(pid)
        g["conns"] += conns.get(pid, 0)

    # one entry per app: merge host-network groups that live in the same systemd scope
    merged = {}
    for key, g in groups.items():
        if not g["sandbox"]:
            cgs = {procs[p]["cg"] for p in g["pids"]}
            c = cgs.pop() if len(cgs) == 1 else None
            if c and own_scope(c):
                key = ("scope", c)
        m = merged.get(key)
        if m is None:
            g["bw"] = g["kind"] == "bwrap"
            merged[key] = g
        else:
            m["pids"] += g["pids"]
            m["conns"] += g["conns"]
            m["bw"] = m["bw"] or g["kind"] == "bwrap"

    skip = {"bwrap"} | _SCOPE_OK
    for key, g in merged.items():
        pids = set(g["pids"])
        real = [p for p in pids if procs[p]["comm"] not in skip] or list(pids)
        busiest = lambda: procs[max(real, key=lambda p: (conns.get(p, 0), p))]["comm"]
        if g["kind"] == "ns":
            g["name"] = procs[max(real)]["comm"]
        elif key[0] == "scope":
            g["cg"] = key[1]                    # the whole scope is the app: match it directly
            if g["bw"]:
                g["kind"], g["name"] = "bwrap", busiest()
            else:
                g["kind"], g["name"] = "cg", pretty(key[1].rsplit("/", 1)[-1])
        elif g["kind"] == "bwrap":
            g["name"] = busiest()
        g["helpers"] = 0
        g["idle"] = not g["sandbox"] and g["conns"] == 0

    # fold loopback-only helper processes into the app that owns them
    pid2g = {p: g for g in merged.values() for p in g["pids"]}
    scope2g = {g["cg"]: g for g in merged.values() if g["cg"]}
    for pid in bare:
        g, p = scope2g.get(procs[pid]["cg"]), pid
        for _ in range(64):
            if g or p not in procs:
                break
            g = pid2g.get(p)
            p = procs[p]["ppid"]
        if g:
            g["helpers"] += 1

    return sorted(merged.values(), key=lambda g: (g["idle"], -g["conns"], g["name"].lower(), g["ns"]))


def group_for_pids(pids):
    """Capture targets (scan() entries) holding any of `pids`. For use by other programs (excubitor)."""
    pids = set(pids)
    return [g for g in scan(pids) if pids & set(g["pids"])]


_NFT_SCRIPT = r'''
t=$1; g=$2; rules=$3; cg=$4; shift 4; pids="$*"
m=0x4e43; cgd=/sys/fs/cgroup; map=$(mktemp)
back() {  # $1 pid, $2 original cgroup path
  d=$2
  while [ -n "$d" ]; do
    echo "$1" > "$cgd/$d/cgroup.procs" 2>/dev/null && return
    mkdir -p "$cgd/$d" 2>/dev/null && echo "$1" > "$cgd/$d/cgroup.procs" 2>/dev/null && return
    case $d in */*) d=${d%/*};; *) d=;; esac
  done
}
cleanup() {
  nft delete table inet $t 2>/dev/null
  if [ -z "$cg" ] && [ -d "$cgd/$t" ]; then
    first=$(head -n1 "$map" | cut -d' ' -f2)
    for p in $(cat "$cgd/$t/cgroup.procs" 2>/dev/null); do
      o=$(awk -v p=$p '$1==p{print $2}' "$map"); back $p "${o:-$first}"
    done
    rmdir "$cgd/$t" 2>/dev/null
  fi
  rm -f "$map"
}
trap cleanup EXIT
trap 'exit 1' INT TERM HUP
[ -z "$cg" ] && { mkdir "$cgd/$t" || exit 1; }
printf '%s\n' "$rules" | nft -f - || exit 1
if [ -z "$cg" ]; then
  for p in $pids; do
    o=$(sed -n 's/^0:://p' /proc/$p/cgroup 2>/dev/null | sed 's/ (deleted)//; s#^/##')
    [ -n "$o" ] && echo "$p $o" >> "$map" && echo $p > "$cgd/$t/cgroup.procs" 2>/dev/null
  done
fi
# sockets that already existed (the cgroup match only sees sockets created after the move)
ports=$(ss -H -tuanpe | WANT="$pids" CG="$cg" awk '
  BEGIN { n = split(ENVIRON["WANT"], a, " "); for (i = 1; i <= n; i++) w[a[i]] = 1; cg = ENVIRON["CG"] }
  { hit = 0; s = $0
    while (match(s, /pid=[0-9]+/)) { if (substr(s, RSTART + 4, RLENGTH - 4) in w) hit = 1; s = substr(s, RSTART + RLENGTH) }
    if (cg != "" && match($0, /cgroup:[^ ]+/)) { c = substr($0, RSTART + 7, RLENGTH - 7)
      if (c == "/" cg || index(c, "/" cg "/") == 1) hit = 1 }
    if (hit) { k = split($5, b, ":"); if (b[k] + 0 > 0) print $1, b[k] } }' | sort -u)
for proto in tcp udp; do
  p=$(printf '%s\n' "$ports" | awk -v p=$proto '$1==p{print $2}' | sort -un | paste -sd, -)
  [ -n "$p" ] || continue
  nft insert rule inet $t input $proto dport "{ $p }" ct mark set ct mark \| $m
  nft insert rule inet $t output $proto sport "{ $p }" ct mark set ct mark \| $m
done
echo exceptor-ready >&2
# Stop when exceptor closes our stdin (wireshark was closed or capture stopped). Without this, an idle
# dumpcap never gets SIGPIPE, so the table/cgroup would linger and block the next capture.
exec 3<&0
dumpcap -q -i nflog:$g -w - &
d=$!
{ cat <&3 >/dev/null; kill $d 2>/dev/null; } &
wait $d
'''


_NS_SCRIPT = r'''
exec 3<&0
nsenter -t "$1" -n dumpcap -q -i any -w - &
d=$!
{ cat <&3 >/dev/null; kill $d 2>/dev/null; } &
wait $d
'''


def ruleset(t, target, group):
    lvl = target.count("/") + 1
    mark = "ct mark set ct mark | %s" % _MARK
    out = ["table inet %s {" % t]
    for hook in ("output", "input"):
        out.append("chain %s { type filter hook %s priority -10; policy accept;" % (hook, hook))
        out.append('socket cgroupv2 level %d "%s" %s' % (lvl, target, mark))
        iface = 'iifname != "lo" ' if hook == "input" else ""   # lo is already logged on output
        out.append("%sct mark & %s == %s log group %d" % (iface, _MARK, _MARK, group))
        out.append("}")
    out.append("}")
    return "\n".join(out)


def build(g):
    """argv (to run as root) that writes a pcapng stream for this group to stdout."""
    if not shutil.which("wireshark"):
        raise Missing("wireshark not found (sudo dnf install wireshark)")
    if not shutil.which("dumpcap"):
        raise Missing("dumpcap not found (sudo dnf install wireshark-cli)")
    if g["sandbox"]:
        pid = next((p for p in g["pids"] if os.path.exists("/proc/%d" % p)), None)
        if pid is None:
            raise Missing("%s has exited" % g["name"])
        if not shutil.which("nsenter"):
            raise Missing("nsenter not found (sudo dnf install util-linux)")
        return ["sh", "-c", _NS_SCRIPT, "exceptor", str(pid)]
    for tool in ("nft", "ss"):
        if not shutil.which(tool):
            raise Missing("%s not found (sudo dnf install nftables iproute)" % tool)
    cg = g.get("cg")
    if cg and ('"' in cg or "\\" in cg):
        cg = None                      # can't be quoted safely for nft: use the move path
    if 1 in g["pids"]:
        raise Missing("%s is in the init process tree; refusing to move it" % g["name"])
    global _run_n
    _run_n += 1
    group = 1000 + (os.getpid() + _run_n) % 60000
    t = "exceptor_%d_%d" % (os.getpid(), _run_n)
    rules = ruleset(t, cg or t, group)
    return ["sh", "-c", _NFT_SCRIPT, "exceptor", t, str(group), rules, cg or ""] + \
           ([] if cg else [str(p) for p in g["pids"]])


class Capture:
    """Handle on a running capture. stop() ends it; done is set once it has fully ended."""

    def __init__(self, p1, out=None):
        self.p1, self.out, self.stopped = p1, out, False
        self.done = threading.Event()

    def stop(self):
        self.stopped = True
        try:
            self.p1.stdin.close()       # tells the root-side script to stop and clean up
        except OSError:
            pass

    def size(self):
        try:
            return os.path.getsize(self.out)
        except (OSError, TypeError):
            return 0


def launch(g, on_error, gate=None, out=None):
    """Start the capture and pipe it into wireshark, or into the file `out` (no wireshark).

    on_error(msg) is called from a thread if capture fails. Returns a Capture.
    gate(True) is called once the capture is listening, gate(False) if it ended without getting there.
    """
    cap = ["pkexec"] + build(g)
    if out:
        with open(out, "wb") as f:      # written by us, so the file belongs to the user, not root
            p1 = subprocess.Popen(cap, stdin=subprocess.PIPE, stdout=f, stderr=subprocess.PIPE)
        c = Capture(p1, out)
    else:
        p1 = subprocess.Popen(cap, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        p2 = subprocess.Popen(["wireshark", "-k", "-i", "-"], stdin=p1.stdout, start_new_session=True)
        p1.stdout.close()
        c = Capture(p1)

        def stop_when_wireshark_exits():
            p2.wait()
            c.stop()
        threading.Thread(target=stop_when_wireshark_exits, daemon=True).start()

    def watch():
        lines = []
        for raw in p1.stderr:
            line = raw.decode(errors="replace").strip()
            if line == _READY:
                if gate:
                    threading.Timer(_GATE_DELAY, gate, [True]).start()
            elif line:
                lines.append(line)
        rc = p1.wait()
        if gate:
            gate(False)                 # no-op if the program was already released
        if out and rc != 0 and c.size() == 0:
            try:
                os.unlink(out)          # failed before writing anything: don't leave an empty file
            except OSError:
                pass
        if rc not in (0, -13, 126) and lines and not c.stopped:  # -13 = SIGPIPE: wireshark was closed
            on_error(lines[-1])
        c.done.set()
    threading.Thread(target=watch, daemon=True).start()
    return c


def spawn_gated(argv):
    """Start argv in a fresh transient systemd scope, held until released. -> (Popen, cgroup path)."""
    global _run_n
    if not shutil.which("systemd-run"):
        raise Missing("systemd-run not found")
    if not shutil.which(argv[0]):
        raise Missing("%s: command not found" % argv[0])
    _run_n += 1
    unit = "exceptor-run-%d-%d" % (os.getpid(), _run_n)
    p = subprocess.Popen(["systemd-run", "--user", "--scope", "--quiet", "--collect", "--unit", unit, "--",
                          "sh", "-c", 'read x || exit 1; exec "$@"', "exceptor-run"] + argv,
                         stdin=subprocess.PIPE, start_new_session=True)
    threading.Thread(target=p.wait, daemon=True).start()     # reap it when it exits
    for _ in range(100):
        cg = cgpath(p.pid)
        if cg and cg.rsplit("/", 1)[-1] == unit + ".scope":
            return p, cg
        if p.poll() is not None:
            break
        time.sleep(0.05)
    try:
        p.stdin.close()
    except OSError:
        pass
    raise Missing("could not start %s in its own cgroup (is the systemd user session running?)" % argv[0])


def run_program(argv, on_error, out=None):
    """Run argv and capture everything its scope sends, from the first packet (to wireshark, or to `out`)."""
    prog, cg = spawn_gated(argv)
    lock, state = threading.Lock(), {"done": False}

    def release(go):
        with lock:
            if state["done"]:
                return
            state["done"] = True
        try:
            if go:
                prog.stdin.write(b"\n")
            prog.stdin.close()          # closing without the newline makes the program exit unstarted
        except (OSError, ValueError):
            pass

    g = {"name": argv[0], "pids": [prog.pid], "conns": 0, "sandbox": False, "cg": cg, "kind": "cg"}
    try:
        return launch(g, on_error, release, out)
    except BaseException:
        release(False)
        raise


def main():
    import gi
    gi.require_version("Gtk", "4.0")
    gi.require_version("Adw", "1")
    from gi.repository import Adw, GLib, Gtk

    class Win(Adw.ApplicationWindow):
        def __init__(self, app):
            super().__init__(application=app, title="Exceptor", default_width=560, default_height=640)
            self.toasts = Adw.ToastOverlay()
            view = Adw.ToolbarView()
            header = Adw.HeaderBar()
            refresh = Gtk.Button(icon_name="view-refresh-symbolic", tooltip_text="Refresh (F5)")
            refresh.connect("clicked", lambda *_: self.refresh())
            header.pack_start(refresh)
            run = Gtk.Button(label="Run\u2026", tooltip_text="Run a program and capture it from its first packet")
            run.connect("clicked", self.ask_run)
            header.pack_start(run)
            self.last_cmd = ""
            self.idle_rows = set()
            self.idle_btn = Gtk.ToggleButton(label="Idle", tooltip_text="Show programs with no connections")
            self.idle_btn.connect("toggled", lambda *_: self.list.invalidate_filter())
            header.pack_end(self.idle_btn)
            self.search = Gtk.SearchEntry(placeholder_text="Filter programs", hexpand=True, margin_start=12,
                                          margin_end=12, margin_top=6, margin_bottom=6)
            self.search.connect("search-changed", lambda *_: self.list.invalidate_filter())
            self.list = Gtk.ListBox(selection_mode=Gtk.SelectionMode.NONE, css_classes=["boxed-list"],
                                    margin_start=12, margin_end=12, margin_bottom=12)
            self.recs = []                 # [(Capture, row)] of captures being saved to a file
            self.rec_list = Gtk.ListBox(selection_mode=Gtk.SelectionMode.NONE, css_classes=["boxed-list"],
                                        margin_start=12, margin_end=12, margin_bottom=12, visible=False)
            self.list.set_filter_func(self.visible)
            self.list.set_placeholder(Gtk.Label(label="No programs with connections. Press Idle to show the rest.",
                                                margin_top=24, margin_bottom=24, css_classes=["dim-label"]))
            box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
            box.append(self.search)
            box.append(self.rec_list)
            box.append(self.list)
            scroll = Gtk.ScrolledWindow(vexpand=True, child=box)
            view.add_top_bar(header)
            view.set_content(scroll)
            self.toasts.set_child(view)
            self.set_content(self.toasts)
            key = Gtk.ShortcutController()
            key.add_shortcut(Gtk.Shortcut(trigger=Gtk.ShortcutTrigger.parse_string("F5"),
                                          action=Gtk.CallbackAction.new(lambda *_: self.refresh() or True)))
            self.add_controller(key)
            GLib.timeout_add_seconds(1, self.tick)
            self.refresh()

        def visible(self, row):
            text = self.search.get_text().lower()
            if text:                       # searching also looks through idle programs
                return text in row.get_title().lower()
            return self.idle_btn.get_active() or row not in self.idle_rows

        def ask_run(self, *_):
            entry = Gtk.Entry(text=self.last_cmd, placeholder_text="e.g. curl https://example.com",
                              activates_default=True)
            d = Adw.AlertDialog(heading="Run and capture",
                                body="Starts the command in its own cgroup and records its traffic from the "
                                     "very first packet. Programs that hand off to an already-running "
                                     "instance (browsers) or that start their own scope (Flatpak) can't be "
                                     "followed this way.")
            d.set_extra_child(entry)
            d.add_response("cancel", "Cancel")
            d.add_response("record", "Run and record\u2026")
            d.add_response("run", "Run and capture")
            d.set_response_appearance("run", Adw.ResponseAppearance.SUGGESTED)
            d.set_default_response("run")
            d.set_close_response("cancel")
            def answer(_d, r):
                text = entry.get_text()
                if r == "run":
                    self.run_command(text)
                elif r == "record":
                    self.pick_file(text.split()[0] if text.split() else "program",
                                   lambda path: self.run_command(text, path))
            d.connect("response", answer)
            d.present(self)

        def run_command(self, text, out=None):
            self.last_cmd = text
            try:
                argv = shlex.split(text)
                if argv:
                    c = run_program(argv, lambda m: GLib.idle_add(self.toast, m), out)
                    if out:
                        self.add_recording(argv[0], c)
            except (Missing, OSError, ValueError) as e:
                self.toast(str(e))

        def pick_file(self, name, then):
            name = re.sub(r"[^\w.-]+", "_", name) or "capture"
            dlg = Gtk.FileDialog(title="Save capture as", initial_name="%s-%s.pcapng" % (name, time.strftime("%Y%m%d-%H%M%S")))

            def done(d, res):
                try:
                    f = d.save_finish(res)
                except GLib.Error:
                    return                  # cancelled
                if f and f.get_path():
                    then(f.get_path())
            dlg.save(self, None, done)

        def add_recording(self, name, c):
            row = Adw.ActionRow(title="Recording: " + name, use_markup=False)
            btn = Gtk.Button(label="Stop", valign=Gtk.Align.CENTER, css_classes=["destructive-action"])
            btn.connect("clicked", lambda *_: c.stop())
            row.add_suffix(btn)
            self.rec_list.append(row)
            self.recs.append((c, row))
            self.rec_list.set_visible(True)
            self.tick()

        def tick(self):
            for c, row in list(self.recs):
                if c.done.is_set():
                    self.recs.remove((c, row))
                    self.rec_list.remove(row)
                    if c.size():
                        self.toast("Saved %s (%s)" % (c.out, self.human(c.size())))
                else:
                    row.set_subtitle("%s \u00b7 %s" % (c.out, self.human(c.size())))
            self.rec_list.set_visible(bool(self.recs))
            return True

        @staticmethod
        def human(n):
            for u in ("B", "KiB", "MiB", "GiB"):
                if n < 1024 or u == "GiB":
                    return "%d %s" % (n, u) if u == "B" else "%.1f %s" % (n, u)
                n /= 1024

        def record(self, _btn, g):
            def go(path):
                try:
                    self.add_recording(g["name"], launch(g, lambda m: GLib.idle_add(self.toast, m), out=path))
                except (Missing, OSError) as e:
                    self.toast(str(e))
            self.pick_file(g["name"], go)

        def toast(self, msg):
            self.toasts.add_toast(Adw.Toast(title=msg, timeout=8))

        def refresh(self):
            while (r := self.list.get_first_child()):
                self.list.remove(r)
            self.idle_rows.clear()
            idle = 0
            for g in scan():
                n = len(g["pids"]) + g["helpers"]
                if g["sandbox"]:
                    sub = "sandboxed: captures its whole network namespace"
                else:
                    sub = "%d connection%s" % (g["conns"], "" if g["conns"] == 1 else "s")
                    if g["kind"] == "bwrap":
                        sub = "bwrap, shared network · " + sub
                row = Adw.ActionRow(title=g["name"], use_markup=False,
                                    subtitle="%s · %d process%s" % (sub, n, "" if n == 1 else "es"))
                rec = Gtk.Button(label="Record", valign=Gtk.Align.CENTER,
                                 tooltip_text="Record to a file, without opening Wireshark")
                rec.connect("clicked", self.record, g)
                row.add_suffix(rec)
                btn = Gtk.Button(label="Capture", valign=Gtk.Align.CENTER, css_classes=["suggested-action"])
                btn.connect("clicked", self.capture, g)
                row.add_suffix(btn)
                if g["idle"]:
                    self.idle_rows.add(row)
                    idle += 1
                self.list.append(row)
            self.idle_btn.set_label("Idle (%d)" % idle)

        def capture(self, _btn, g):
            try:
                launch(g, lambda m: GLib.idle_add(self.toast, m))
            except (Missing, OSError) as e:
                self.toast(str(e))

    app = Adw.Application(application_id="local.exceptor")
    app.connect("activate", lambda a: Win(a).present())
    app.run(None)


if __name__ == "__main__":
    main()
