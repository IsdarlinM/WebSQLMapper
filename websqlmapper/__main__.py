from __future__ import annotations

import sys

if sys.version_info < (3, 10):
    print(f"WebSQLMapper requires Python 3.10 or newer; detected {sys.version.split()[0]}.", file=sys.stderr)
    raise SystemExit(1)

from .cli import main

if __name__ == "__main__":
    raise SystemExit(main())
