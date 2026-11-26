# ------------------------- boundary: what is loaded, read and run from outside
def _exceptor():
    """excapture.py (packet capture), if it sits next to this file."""
    try:
        import excapture
        return excapture
    except ImportError:
        return None


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
