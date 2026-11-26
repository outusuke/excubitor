#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Build excubitor.py, the single installable GUI file, from the fragments in src/.

    python3 build.py            write excubitor.py
    python3 build.py --check    exit 1 if excubitor.py is not what the fragments build
    python3 build.py --report   per fragment: what it uses from lower layers

The fragments are plain slices of one module, joined in file-name order. They are not
modules and are never imported: everything ends up in one file, so installing and the
`python3 excubitor.py` workflow are unchanged.

Layers, lowest first (the number in the file name is the layer):

  00_prelude    imports, gi/Gtk setup, optional psutil. Every other layer may use these names.
  10_boundary   what the GUI loads, reads and runs from outside itself: excapture, the
                helper's counters file, the installed root helper and trusted_helper().
  20_settings   state.json (load_state / save_state)
  30_install    "Add to Applications Menu": copies files, writes a launcher and .desktop file
  40_model      Row, the table row object
  50_udphelper  UdpHelper: parses the counters file the root helper writes
  60_backends   PsutilBackend (real data) and FakeBackend (--fake)
  70_columns    cell formatters and COLUMNS
  80_window     MainWindow
  90_app        App and the command line entry point

Layer rule: a fragment may use names defined in its own layer or a lower one, never a
higher one. The build fails if it does. The check reads each fragment's symbol table
(symtable), so a local variable that shares a name with a higher-layer global is fine.
It sees names, not strings: getattr(obj, "name") or exec/eval are not followed.
"""
import argparse
import re
import symtable
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
SRC = ROOT / "src"
OUT = ROOT / "excubitor.py"
NAME = re.compile(r"^(\d\d)_[a-z0-9_]+\.py$")
SEP = "\n\n\n"  # two blank lines between fragments, as between any two top-level blocks


def load():
    """[(stem, text)] in layer order. Refuses stray files and duplicate layer numbers."""
    files = sorted(SRC.glob("*.py"))
    bad = [f.name for f in files if not NAME.match(f.name)]
    if bad:
        sys.exit("src/: file names must look like NN_name.py, got: " + ", ".join(bad))
    if not files:
        sys.exit("src/ has no fragments")
    nums = [f.name[:2] for f in files]
    dup = sorted({n for n in nums if nums.count(n) > 1})
    if dup:
        sys.exit("src/: two fragments share layer number " + ", ".join(dup))
    return [(f.stem, f.read_text()) for f in files]


def scan(stem, text):
    """(names defined at module level, names used that this fragment does not bind itself)."""
    try:
        top = symtable.symtable(text, stem + ".py", "exec")
    except SyntaxError as e:
        sys.exit("%s.py: %s" % (stem, e))
    defined = {s.get_name() for s in top.get_symbols()
               if s.is_assigned() or s.is_imported() or s.is_namespace()}
    used = set()

    def walk(table, module_level):
        for s in table.get_symbols():
            if not s.is_referenced():
                continue
            if module_level:
                if s.get_name() not in defined:
                    used.add(s.get_name())
            elif s.is_global():  # implicit or declared global; free (closure) names are not
                used.add(s.get_name())
        for child in table.get_children():
            walk(child, False)

    walk(top, True)
    return defined, used


def analyse(frags):
    """-> (problems, per-fragment info). problems is a list of strings; empty means the rules hold."""
    problems, owner, info = [], {}, []
    for i, (stem, text) in enumerate(frags):
        defined, used = scan(stem, text)
        for n in sorted(defined):
            if n in owner:
                problems.append("%s defines %s, already defined in %s" % (stem, n, frags[owner[n]][0]))
            owner.setdefault(n, i)
        info.append((defined, used))
    for i, (stem, _text) in enumerate(frags):
        defined, used = info[i]
        for n in sorted(used - defined):
            j = owner.get(n)
            if j is not None and j > i:
                problems.append("layer rule: %s uses %s, which is defined in the higher layer %s"
                                % (stem, n, frags[j][0]))
    return problems, info, owner


def build(frags):
    text = SEP.join(t.strip("\n") for _s, t in frags) + "\n"
    compile(text, "excubitor.py", "exec")  # syntax check of the whole
    return text


def report(frags, info, owner):
    """For each fragment: its size, and which names it takes from the prelude and from other layers."""
    for i, (stem, text) in enumerate(frags):
        defined, used = info[i]
        from_layer = {}
        for n in sorted(used - defined):
            j = owner.get(n)
            if j is not None and j != i:  # j is None for builtins
                from_layer.setdefault(frags[j][0], []).append(n)
        print("%-13s %4d lines" % (stem, len(text.strip("\n").split("\n"))))
        for layer, names in from_layer.items():
            print("    from %-13s %s" % (layer, ", ".join(names)))


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--check", action="store_true", help="fail if excubitor.py is out of date")
    ap.add_argument("--report", action="store_true", help="show what each fragment uses")
    args = ap.parse_args()

    frags = load()
    problems, info, owner = analyse(frags)
    if problems:
        sys.exit("\n".join(problems))
    text = build(frags)
    if args.report:
        report(frags, info, owner)
        return
    current = OUT.read_text() if OUT.exists() else None
    if args.check:
        if current != text:
            sys.exit("excubitor.py is out of date: run python3 build.py")
        print("excubitor.py matches src/ (%d fragments, %d lines)" % (len(frags), text.count("\n")))
        return
    if current != text:
        OUT.write_text(text)  # an existing file keeps its mode
    print("%s excubitor.py (%d fragments, %d lines)"
          % ("wrote" if current != text else "unchanged", len(frags), text.count("\n")))


if __name__ == "__main__":
    main()
