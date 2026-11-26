# -------------------------------------------------------------- saved settings
STATE_FILE = os.path.join(GLib.get_user_config_dir(), "excubitor", "state.json")


def load_state():
    try:
        with open(STATE_FILE) as f:
            return json.load(f)
    except (OSError, ValueError):
        return {}


def save_state(update):
    """Merge `update` into the saved settings (so one setting never clobbers another)."""
    try:
        state = load_state()
        state.update(update)
        os.makedirs(os.path.dirname(STATE_FILE), exist_ok=True)
        with open(STATE_FILE, "w") as f:
            json.dump(state, f)
    except OSError:
        pass
