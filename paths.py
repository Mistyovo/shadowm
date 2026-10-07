"""Where ShadowM keeps its state and log files.

Everything durable lives in one per-user directory, %APPDATA%\\ShadowM,
for both dev runs and packaged builds: a PyInstaller onefile build
unpacks to a throwaway _MEIxxxx temp folder, so nothing can live next
to __file__ there, and the exe itself may sit in a read-only location.
Sharing the directory between dev and packaged runs also keeps the
remembered-hidden rules in one place.

Older versions wrote remembered_hidden.json next to the script; that
file is migrated into the state dir once, on startup.
"""

import logging
import os
import shutil
import sys

logger = logging.getLogger("shadowm")

APP_DIR_NAME = "ShadowM"
_REMEMBERED_FILE = "remembered_hidden.json"


def state_dir() -> str:
    """The per-user state directory, created on first call."""
    base = os.environ.get("APPDATA") or os.path.expanduser("~")
    path = os.path.join(base, APP_DIR_NAME)
    try:
        os.makedirs(path, exist_ok=True)
    except OSError:
        logger.warning("could not create state dir %s", path)
    return path


def state_file(name: str) -> str:
    """Full path of a state/log file inside the state directory."""
    return os.path.join(state_dir(), name)


def _legacy_dirs():
    """Directories an older version may have left state files in."""
    dirs = [os.path.dirname(os.path.abspath(__file__))]
    if getattr(sys, "frozen", False):  # PyInstaller build
        dirs.append(os.path.dirname(sys.executable))
    return dirs


def migrate_legacy_files(target_dir=None, legacy_dirs=None):
    """Moves remembered state from pre-APPDATA versions into the state dir.

    Best effort: a file already present in the target, or unreadable,
    is left where it is. Returns the names of the files actually moved.
    """
    target = target_dir or state_dir()
    dirs = legacy_dirs if legacy_dirs is not None else _legacy_dirs()
    dst = os.path.join(target, _REMEMBERED_FILE)
    if os.path.exists(dst):
        return []
    for d in dirs:
        src = os.path.join(d, _REMEMBERED_FILE)
        if not os.path.isfile(src):
            continue
        try:
            os.makedirs(target, exist_ok=True)
            shutil.move(src, dst)
            return [_REMEMBERED_FILE]
        except OSError:
            continue
    return []
