"""``python -m shareguard`` entry point (also the frozen executable entry)."""

import multiprocessing
import sys

from shareguard.cli import main

if __name__ == "__main__":
    multiprocessing.freeze_support()
    sys.exit(main())
