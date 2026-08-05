#!/usr/bin/env python3
"""SofiaVault launcher.

Keeps `ln -s .../sofiavault.py ~/.local/bin/sofiavault` installs (setup.sh,
install.py) working after the 0.3.0 package split. The real code lives in
the `sofiavault/` package next to this file.
"""

import sys

try:
    from sofiavault.cli import main
except ImportError:
    print("Missing dependencies. Run:")
    print("  pip install argon2-cffi cryptography rapidfuzz")
    sys.exit(1)

if __name__ == '__main__':
    main()
