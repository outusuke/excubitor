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
