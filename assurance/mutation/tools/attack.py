#!/usr/bin/env python3
"""Deletion attack over internal/mutdenom.

Every `add(Finding..., Block, ...)` call site in check.go is neutered one at a
time by guarding it with `false &&` on its enclosing condition -- never by
deleting code, because a mutation that breaks compilation proves nothing.
Each neutered checker must turn the polarity suite RED. A check that stays green
when deleted is not evidence; it is decoration.

Mechanism: each BLOCK add(...) is wrapped in `if false { ... }`, which compiles
(Go allows an if-false block; `go vet` is run separately on the pristine tree).
Because the wrapped statement may be a multi-line call, the wrapper is applied
by matching balanced parentheses from the `add(` token.
"""
import os, re, shutil, subprocess, sys, tempfile

ROOT = sys.argv[1]
CHECK = os.path.join(ROOT, "internal/mutdenom/check.go")
FIXTURES = "assurance/mutation/fixtures/cases.json"


def add_call_sites(source):
    """Return (start, end) spans of every `add(Finding..., Block,` statement."""
    spans = []
    for match in re.finditer(r"\badd\(Finding\w+, Block,", source):
        start = match.start()
        depth = 0
        index = source.index("(", start)
        while True:
            char = source[index]
            if char == "(":
                depth += 1
            elif char == ")":
                depth -= 1
                if depth == 0:
                    break
            index += 1
        end = index + 1
        code = source[start:end]
        spans.append((start, end, code))
    return spans


def neuter(source, span):
    start, end, code = span
    # `false && ...` is not usable as a statement guard, so the equivalent
    # statement-level form is used: the call is placed inside `if false { }`.
    # Nothing is deleted; the code still compiles and still type-checks.
    return source[:start] + "if false {\n" + code + "\n}" + source[end:]


def run(cmd):
    proc = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True)
    return proc.returncode, proc.stdout + proc.stderr


def main():
    pristine = open(CHECK).read()
    spans = add_call_sites(pristine)
    print("BLOCK add() call sites found: %d" % len(spans))

    backup = tempfile.NamedTemporaryFile(delete=False, suffix=".go").name
    shutil.copyfile(CHECK, backup)
    survivors = []
    try:
        for index, span in enumerate(spans):
            first_line = span[2].split("\n")[0].strip()
            open(CHECK, "w").write(neuter(pristine, span))
            build_code, build_out = run(["go", "build", "./internal/mutdenom/"])
            if build_code != 0:
                print("[%02d] BUILD-BROKEN %s\n%s" % (index, first_line, build_out[:400]))
                survivors.append((index, first_line, "build broken -- proves nothing"))
                continue
            code, out = run(["go", "run", "./cmd/mutdenomctl",
                             "-replay-fixtures", FIXTURES, "-root", "."])
            verdict = "RED" if code != 0 else "SURVIVED"
            if code == 0:
                survivors.append((index, first_line, "suite stayed green"))
            failing = [line.split()[1].split("=")[1]
                       for line in out.splitlines() if " FAIL " in line]
            print("[%02d] %-8s exit=%d cases_failed=%d %s" %
                  (index, verdict, code, len(failing), first_line))
    finally:
        shutil.copyfile(backup, CHECK)
        os.unlink(backup)

    print("\n=== deletion attack summary ===")
    print("mutations: %d" % len(spans))
    print("survivors: %d" % len(survivors))
    for index, line, why in survivors:
        print("  SURVIVOR [%02d] %s -- %s" % (index, line, why))
    restored = open(CHECK).read()
    print("restored byte-identical: %s" % (restored == pristine))
    return 1 if survivors or restored != pristine else 0


sys.exit(main())
