"""Make ``src/`` importable without an editable install.

Airlock ships zero runtime deps and no test-time install step is assumed, so we
prepend the package's ``src`` dir to ``sys.path`` for the whole test session.
"""

import os
import sys

_SRC = os.path.join(os.path.dirname(os.path.dirname(__file__)), "src")
if _SRC not in sys.path:
    sys.path.insert(0, _SRC)
