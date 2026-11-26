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
