"""Entry point for ``python -m ptp``."""

import sys

from .cli import main

if __name__ == "__main__":
    sys.exit(main())
