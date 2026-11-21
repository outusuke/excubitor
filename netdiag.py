"""netdiag: socket tables straight from the kernel's NETLINK_SOCK_DIAG interface.

Replaces `ss` and `nsenter`. One netlink dump per (family, protocol) returns addresses,
state, socket inode and, for TCP, the cumulative byte counters from tcp_info.
The current namespace needs no privileges; entering another one needs root (setns).
"""
import ctypes
import errno
import os
import socket
import struct
import threading
import time

SOCK_DIAG_BY_FAMILY = 20
NLM_F_REQUEST_DUMP = 0x301  # NLM_F_REQUEST | NLM_F_DUMP
NLMSG_ERROR, NLMSG_DONE = 2, 3
INET_DIAG_INFO = 2
CLONE_NEWNET = 0x40000000
TCP_STATES = {1: "ESTABLISHED", 2: "SYN_SENT", 3: "SYN_RECV", 4: "FIN_WAIT1", 5: "FIN_WAIT2",
              6: "TIME_WAIT", 7: "CLOSE", 8: "CLOSE_WAIT", 9: "LAST_ACK", 10: "LISTEN",
              11: "CLOSING"}
_HDR = struct.Struct("=IHHII")
_REQ = struct.Struct("=BBBBI48x")  # family, protocol, ext, pad, states, zeroed sockid
# offsets inside struct tcp_info (stable kernel ABI)
_RX_OFF, _TX_OFF, _INFO_MIN = 128, 200, 208


def _fmt(family, addr, port):
    ip = socket.inet_ntop(family, addr)
    return "[%s]:%d" % (ip, port) if family == socket.AF_INET6 else "%s:%d" % (ip, port)


def _parse(d, family, proto):
    sport, dport = struct.unpack_from(">HH", d, 4)
    ino = struct.unpack_from("=I", d, 68)[0]
    n = 4 if family == socket.AF_INET else 16
    src, dst = d[8:8 + n], d[24:24 + n]
    tcp = proto == socket.IPPROTO_TCP
    s = {"proto": ("TCP" if tcp else "UDP") + ("6" if family == socket.AF_INET6 else ""),
         "local": _fmt(family, src, sport),
         "peer": _fmt(family, dst, dport) if dport or any(dst) else "—",
         "state": TCP_STATES.get(d[1], "") if tcp else "",
         "ino": ino, "rx": None, "tx": None}
    off = 72
    while tcp and off + 4 <= len(d):
        ln, typ = struct.unpack_from("=HH", d, off)
        if ln < 4:
            break
        if typ == INET_DIAG_INFO and ln - 4 >= _INFO_MIN:
            s["rx"] = struct.unpack_from("=Q", d, off + 4 + _RX_OFF)[0]
            s["tx"] = struct.unpack_from("=Q", d, off + 4 + _TX_OFF)[0]
        off += (ln + 3) & ~3
    return s


def _dump(sock, family, proto):
    ext = 1 << (INET_DIAG_INFO - 1) if proto == socket.IPPROTO_TCP else 0
    sock.send(_HDR.pack(_HDR.size + _REQ.size, SOCK_DIAG_BY_FAMILY, NLM_F_REQUEST_DUMP, 1, 0)
              + _REQ.pack(family, proto, ext, 0, 0xFFFFFFFF))
    out = []
    while True:
        buf = sock.recv(1 << 18)
        if not buf:
            return out
        off = 0
        while off + _HDR.size <= len(buf):
            ln, typ = struct.unpack_from("=IH", buf, off)
            if ln < _HDR.size:  # a zero/short length would make this loop spin forever
                raise OSError(errno.EBADMSG, "bad netlink message length")
            if typ == NLMSG_DONE:
                return out
            if typ == NLMSG_ERROR:
                raise OSError(-struct.unpack_from("=i", buf, off + 16)[0], "sock_diag")
            if typ == SOCK_DIAG_BY_FAMILY:
                out.append(_parse(buf[off + 16:off + ln], family, proto))
            off += (ln + 3) & ~3


class Diag:
    """A sock_diag netlink socket, bound for life to the namespace it was created in."""

    def __init__(self, sock):
        self.sock = sock

    def sockets(self):
        """[{proto, local, peer, state, ino, rx, tx}] for TCP and UDP, IPv4 + IPv6.
        rx/tx are cumulative TCP payload bytes (None for UDP and TIME_WAIT)."""
        out = []
        for fam in (socket.AF_INET, socket.AF_INET6):
            for proto in (socket.IPPROTO_TCP, socket.IPPROTO_UDP):
                try:
                    out += _dump(self.sock, fam, proto)
                except OSError:
                    if fam == socket.AF_INET:
                        raise  # IPv6 may simply be disabled: keep the IPv4 results
        return out

    def close(self):
        self.sock.close()


def _new_socket():
    return socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, 4)  # NETLINK_SOCK_DIAG


def open_diag(pid=None):
    """Diag for our own namespace, or for the network namespace of `pid` (needs root).

    setns() changes only the calling thread, so it runs in a throwaway thread; the
    socket it creates keeps working in that namespace after the thread is gone."""
    if pid is None:
        return Diag(_new_socket())
    res = {}

    def work():
        try:
            fd = os.open("/proc/%d/ns/net" % pid, os.O_RDONLY)
            try:
                if ctypes.CDLL(None, use_errno=True).setns(fd, CLONE_NEWNET) != 0:
                    raise OSError(ctypes.get_errno(), "setns")
                res["d"] = Diag(_new_socket())
            finally:
                os.close(fd)
        except OSError as e:
            res["e"] = e

    t = threading.Thread(target=work)
    t.start()
    t.join()
    if "e" in res:
        raise res["e"]
    return res["d"]


class InodeMap:
    """socket inode -> owning PID. Inodes are unique across namespaces.

    When an unknown inode shows up (at most once per min_gap seconds), first scan only
    processes started since the last walk; do a full walk only if that doesn't resolve
    everything. Inodes still unknown after a full walk (other users' sockets, when not
    root) are remembered so they don't trigger further walks."""

    def __init__(self, min_gap=1.0):
        self.map, self.dead, self.t, self.min_gap = {}, set(), 0.0, min_gap
        self.seen = set()  # pids covered by the last walk

    @staticmethod
    def _scan_pid(pid, m):
        try:
            dfd = os.open("/proc/%d/fd" % pid, os.O_RDONLY | os.O_DIRECTORY)
        except OSError:
            return
        try:
            for fd in os.listdir(dfd):
                try:
                    link = os.readlink(fd, dir_fd=dfd)  # no per-fd path lookup
                except OSError:
                    continue
                if link.startswith("socket:["):
                    m.setdefault(int(link[8:-1]), pid)
        finally:
            os.close(dfd)

    def pids(self, inodes):
        want = {i for i in inodes if i and i not in self.map and i not in self.dead}
        now = time.monotonic()
        if not want or now - self.t < self.min_gap:
            return self.map
        self.t = now
        live = sorted(int(e) for e in os.listdir("/proc") if e.isdigit())
        found = {}
        for pid in live:
            if pid not in self.seen:
                self._scan_pid(pid, found)
        if want <= found.keys():  # new processes explain everything: skip the full walk
            self.map = {**found, **self.map}
        else:
            full = {}
            for pid in live:
                self._scan_pid(pid, full)
            self.map = full  # also drops entries of exited processes
            self.dead = {i for i in want if i not in full}
        self.seen = set(live)
        return self.map
