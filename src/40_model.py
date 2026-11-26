# ----------------------------------------------------------------- data model
class Row(GObject.Object):
    """One row: either a process or one of its connections."""

    kind = GObject.Property(type=str, default="process")  # "process" | "conn"
    name = GObject.Property(type=str, default="")  # process name or protocol
    pid = GObject.Property(type=int, default=0)
    local = GObject.Property(type=str, default="")
    remote = GObject.Property(type=str, default="")
    state = GObject.Property(type=str, default="")
    nconn = GObject.Property(type=int, default=0)
    down = GObject.Property(type=float, default=-1.0)  # bytes/s, -1 = unknown
    up = GObject.Property(type=float, default=-1.0)
    nproc = GObject.Property(type=int, default=0)  # processes in an application group
    grouped = GObject.Property(type=bool, default=False)  # shown in "group by application" mode

    def __init__(self, **kw):
        super().__init__(**kw)
        self.children = None  # Gio.ListStore of conn rows (process rows only)
        self.cmap = {}  # connection key -> Row
        self.host = None  # resolved hostname of `remote` (conn rows, when enabled)

    def update(self, **kw):
        """Set only the properties that changed, so we notify as little as possible."""
        for k, v in kw.items():
            if getattr(self, k) != v:
                setattr(self, k, v)
