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
- `excapture.py`: packet capture (nftables + dumpcap, piped into Wireshark or a pcapng file). Used by the right-click menu.
- `netdiag.py`: socket tables from NETLINK_SOCK_DIAG (replaces `ss` and `nsenter`). Entering another namespace needs root.
- `netresolve.py`: non-blocking cached reverse DNS. Opt-in, since every lookup sends the peer IP to your resolver.

## Install

Main menu, Add to Applications Menu: copies the program to `~/.local/share/excubitor`, adds a launcher at `~/.local/bin/excubitor` and a menu entry. Untick it to remove them. Tick it again after updating the files to refresh the copy.

## Packet capture

The right-click menu of a process row offers Capture in Wireshark and Record to File (pcapng, no Wireshark). Stop recordings from the main menu. It captures the row's whole program (its systemd scope or network namespace), not just one process, and asks for root through pkexec.

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

## Development

`excubitor.py` is built from the fragments in `src/` by `build.py`, so installing and `python3 excubitor.py` work from a plain checkout. Edit `src/`, then:

```
python3 build.py            # rewrite excubitor.py
python3 build.py --check    # fail if excubitor.py is out of date
python3 build.py --report   # what each layer uses
```

The file name number is the layer (`00_prelude` lowest, `90_app` highest). A fragment may use names from its own layer or a lower one, never a higher one; the build fails if it does. `tools/verify_split.py` compares a built `excubitor.py` with an earlier commit's (AST, lines, behaviour under GTK).

## License

GPL-3.0-or-later. See [LICENSE](LICENSE).
