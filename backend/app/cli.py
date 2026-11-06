"""CLI: python -m app.cli scan <path>. Exits 1 if any finding scores 7 or more."""
import argparse
import sys
from pathlib import Path

from .pipeline import run_scan
from .report.severity import label

RED, YEL, DIM, BOLD, END = "\033[31m", "\033[33m", "\033[2m", "\033[1m", "\033[0m"


def render(f, color: bool) -> str:
    c = (RED if f.severity >= 7 else YEL) if color else ""
    e, d, b = (END, DIM, BOLD) if color else ("", "", "")
    head = f"{c}{b}{f.severity:>4} {label(f.severity).upper():<8}{e} {b}{f.cwe}{e} {f.file}:{f.line}"
    path = f"{d}     path:{e} " + " -> ".join(f.path)
    src = f"{d}     from:{e} {f.source}   {d}[{f.confidence_tier}, {f.detector}]{e}"
    return "\n".join([head, path, src])


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="zerosentinel")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sc = sub.add_parser("scan")
    sc.add_argument("path")
    args = ap.parse_args(argv)
    res = run_scan(Path(args.path).resolve(), "S-cli")
    color = sys.stdout.isatty()
    for f in res["findings"]:
        print(render(f, color) + "\n")
    high = sum(f.severity >= 7 for f in res["findings"])
    print(f"{len(res['findings'])} findings ({high} high or critical) in "
          f"{len(res['files'])} files, {res['duration']:.2f}s")
    return 1 if high else 0


if __name__ == "__main__":
    sys.exit(main())
