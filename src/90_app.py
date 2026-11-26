# ----------------------------------------------------------------- application
class App(Adw.Application):
    def __init__(self, fake):
        super().__init__(application_id="io.github.example.Excubitor")
        self.fake = fake
        quit_ = Gio.SimpleAction.new("quit", None)
        quit_.connect("activate", lambda *_: self.quit())
        self.add_action(quit_)
        self.set_accels_for_action("app.quit", ["<Ctrl>q"])

    def do_activate(self):
        win = self.props.active_window
        if not win:
            backend = FakeBackend() if self.fake else PsutilBackend()
            win = MainWindow(self, backend, 1000 if self.fake else 2000)
        win.present()


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--fake", action="store_true", help="use generated data")
    args = ap.parse_args()
    if not args.fake and psutil is None:
        sys.exit("psutil is missing: pip install psutil (or run with --fake)")
    sys.exit(App(args.fake).run([sys.argv[0]]))
