"""`python -I -m secmonk_modules serve <module> --stdio` (also `serve --stdio --module <module>`, the form of the
module manifests)."""

from __future__ import annotations

import argparse
import sys

from .registry import MODULE_NAMES, load_module
from .wire import DEFAULT_MAX_FRAME, claim_stdio, run_stdio


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="secmonk_modules", description="sec-monk protocol modules (secmonk-wire/1)")
    sub = ap.add_subparsers(dest="cmd", required=True)
    serve = sub.add_parser("serve", help="serve one module on stdin/stdout")
    serve.add_argument("name", nargs="?", choices=MODULE_NAMES, metavar="MODULE", help=", ".join(MODULE_NAMES))
    serve.add_argument("--module", dest="module", choices=MODULE_NAMES, help="same as the positional MODULE")
    serve.add_argument("--stdio", action="store_true", required=True, help="the only transport of the prototype")
    serve.add_argument("--max-frame", type=int, default=DEFAULT_MAX_FRAME, help="announced max_frame (bytes)")
    args = ap.parse_args(argv)
    name = args.module or args.name
    if not name or (args.module and args.name and args.module != args.name):
        ap.error("name exactly one module")
    claim_stdio()                                   # before anything else can print or read stdin
    return run_stdio(load_module(name), max_frame=args.max_frame)


if __name__ == "__main__":
    sys.exit(main())
