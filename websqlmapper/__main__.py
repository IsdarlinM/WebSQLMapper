import sys

if sys.version_info < (3, 10):
    print(
        f"WebSQLMapper requires Python 3.10 or newer; detected {sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}.",
        file=sys.stderr,
    )
    raise SystemExit(1)

from .cli import main

raise SystemExit(main())
