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
