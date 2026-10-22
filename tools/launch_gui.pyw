"""Start the ShareGuard GUI without a console window.

Run with pythonw.exe (double-clicking a .pyw file does this on Windows), or
use ShareGuard.vbs next to this file.  Also used as the PyInstaller entry
script of the windowed GUI executable.
"""

import multiprocessing
import os
import sys

if __name__ == "__main__":
    # Must run first so spawned scan workers of a frozen build start correctly.
    multiprocessing.freeze_support()
    if not getattr(sys, "frozen", False):
        src = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src")
        if os.path.isdir(src) and src not in sys.path:
            sys.path.insert(0, src)
    from shareguard.gui import main

    raise SystemExit(main())
