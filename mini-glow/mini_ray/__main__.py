"""Entry point: py -3.14 -X pycache_prefix=%LOCALAPPDATA%\\MiniGlow\\pycache -m mini_ray plan|run TASK ..."""
import os
import sys

from .context import is_inside


def launch_ok(prefix, environ):
    """Mini Ray's own code must not come from a __pycache__ folder inside the repository."""
    local = (environ.get("LOCALAPPDATA") or "").strip()
    return bool(prefix and local and os.path.isabs(local) and is_inside(prefix, os.path.join(local, "MiniGlow")))


if __name__ == "__main__":
    if not launch_ok(sys.pycache_prefix, os.environ):
        print("REFUSED: start Mini Ray with -X pycache_prefix=%LOCALAPPDATA%\\MiniGlow\\pycache")
        sys.exit(2)
    from .cli import main
    sys.exit(main())
