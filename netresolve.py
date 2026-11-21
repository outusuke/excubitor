"""netresolve: non-blocking, cached reverse DNS for peer addresses.

    r = Resolver()                      # create only if the user enabled "resolve names"
    label = r.lookup("[2606:4700::1]:443") or "[2606:4700::1]:443"

lookup() never blocks: it returns the cached name (or None) right away and queues the
lookup on a few background threads. The name shows up on a later refresh. Failures are
cached too (shorter), so dead IPs aren't retried every second.

Privacy: every lookup sends the peer's IP to your DNS resolver. Keep it opt-in.
"""
import collections
import ipaddress
import queue
import socket
import threading
import time


def split_addr(s):
    """'1.2.3.4:80' or '[::1]:53' -> '1.2.3.4' / '::1'; None for '—' or malformed."""
    if not s or s == "—":
        return None
    if s.startswith("["):
        end = s.find("]")
        if end < 0:
            return None
        ip = s[1:end]
    else:
        ip = s.rsplit(":", 1)[0]
    return ip.split("%")[0] or None


class Resolver:
    def __init__(self, workers=4, ttl=3600, neg_ttl=300, max_entries=4096,
                 max_pending=256, skip_private=True):
        self.ttl, self.neg_ttl, self.max_entries = ttl, neg_ttl, max_entries
        self.skip_private = skip_private  # don't ask DNS about LAN/loopback addresses
        self.cache = collections.OrderedDict()  # ip -> (name or None, expires)
        self.pending = set()
        self.q = queue.Queue(maxsize=max_pending)
        self.lock = threading.Lock()
        for _ in range(workers):
            threading.Thread(target=self._work, daemon=True).start()

    def _wanted(self, ip):
        try:
            a = ipaddress.ip_address(ip)
        except ValueError:
            return False
        if a.is_loopback or a.is_unspecified or a.is_multicast:
            return False
        return not (self.skip_private and (a.is_private or a.is_link_local))

    def lookup(self, addr):
        """Cached hostname for an 'ip:port' / '[ip]:port' string, or None. Never blocks."""
        ip = split_addr(addr)
        if not ip or not self._wanted(ip):
            return None
        now = time.monotonic()
        with self.lock:
            hit = self.cache.get(ip)
            if hit and hit[1] > now:
                self.cache.move_to_end(ip)
                return hit[0]
            stale = hit[0] if hit else None  # keep showing the old name while refreshing
            if ip not in self.pending:
                try:
                    self.q.put_nowait(ip)
                    self.pending.add(ip)
                except queue.Full:
                    pass  # try again on a later refresh
            return stale

    def _work(self):
        while True:
            ip = self.q.get()
            try:
                name = socket.gethostbyaddr(ip)[0]
            except (OSError, UnicodeError):  # herror/gaierror are OSError subclasses
                name = None
            expires = time.monotonic() + (self.ttl if name else self.neg_ttl)
            with self.lock:
                self.cache[ip] = (name, expires)
                self.cache.move_to_end(ip)
                while len(self.cache) > self.max_entries:
                    self.cache.popitem(last=False)
                self.pending.discard(ip)
