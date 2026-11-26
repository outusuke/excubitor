# ----------------------------------------- counters written by the root helper
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
