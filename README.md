# excubitor

Per-process network monitor for Linux (GTK4 + libadwaita).

```
python3 excubitor.py          # real data
python3 excubitor.py --fake   # generated data, for UI work
```

Needs: PyGObject, GTK 4, libadwaita 1.x, psutil.

## Files

- `excubitor.py`: the GUI. Runs unprivileged.
- `excubitor-helper.py`: root helper. Counts UDP and TCP bytes per PID with bpftrace kprobes, lists sockets in sandbox network namespaces, and writes cumulative counters once a second to `/run/excubitor/udp.json`. The GUI diffs them to get rates.
- `netdiag.py`: socket tables from NETLINK_SOCK_DIAG (replaces `ss` and `nsenter`). Entering another namespace needs root.
- `netresolve.py`: non-blocking cached reverse DNS. Opt-in, since every lookup sends the peer IP to your resolver.

## Helper

Needs `bpftrace`.

```
sudo python3 excubitor-helper.py              # foreground
sudo python3 excubitor-helper.py --install    # systemd service, now + at boot
sudo python3 excubitor-helper.py --uninstall
```

The GUI can also install it through pkexec. To restrict the counters file to a group, create a group named `excubitor` before starting the helper; the file becomes `0640 root:excubitor`.

## Limits

- UDP counts payload only (no headers), and `MSG_PEEK` reads are counted each time.
- Threads are folded into their process.
- Counters of an exited process are dropped.
- Kernel lockdown (Secure Boot) or missing BTF/debugfs can remove the kprobes the helper needs.

## License

GPL-3.0-or-later. See [LICENSE](LICENSE).
