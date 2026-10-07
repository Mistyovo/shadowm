"""Session file: per-window state ShadowM must be able to undo after a crash.

The file lives in the per-user state dir (shadowm_session.json, see
paths.py) and records, for every window this run modified, the original
state needed to undo it: capture affinity (WDA), taskbar extended
styles and layered-window opacity. A boot marker (wall-clock time minus
GetTickCount64, constant within one boot) makes entries from before a
reboot untrusted, since window handles never survive a restart.

On a normal exit everything is restored and the file deleted; after a crash,
the next launch heals whatever is still alive.
"""

import ctypes
import json
import logging
import os
import time

from capture_hider import k32

logger = logging.getLogger("shadowm")

_BOOT_TOLERANCE_MS = 5000

k32.GetTickCount64.restype = ctypes.c_uint64


def boot_marker() -> int:
    """A value that stays constant within one boot and changes on reboot."""
    return int(time.time() * 1000) - int(k32.GetTickCount64())


class SessionState:
    def __init__(self, path: str):
        self.path = path
        self.boot = boot_marker()
        self.capture = {}   # hwnd -> {pid, exe}
        self.taskbar = {}   # hwnd -> {pid, exstyle}
        self.opacity = {}   # hwnd -> {pid, added_layered, original_alpha}
        self._load()

    # ---- groups -----------------------------------------------------------

    def note_capture_hidden(self, hwnd, pid, exe):
        self.capture[hwnd] = {"pid": pid, "exe": exe or ""}
        self.save()

    def clear_capture(self, hwnd):
        if self.capture.pop(hwnd, None) is not None:
            self.save()

    def note_taskbar_hidden(self, hwnd, pid, exstyle):
        self.taskbar[hwnd] = {"pid": pid, "exstyle": exstyle}
        self.save()

    def clear_taskbar(self, hwnd):
        if self.taskbar.pop(hwnd, None) is not None:
            self.save()

    def note_opacity(self, hwnd, pid, added_layered, original_alpha):
        self.opacity[hwnd] = {
            "pid": pid,
            "added_layered": bool(added_layered),
            "original_alpha": original_alpha,
        }
        self.save()

    def clear_opacity(self, hwnd):
        if self.opacity.pop(hwnd, None) is not None:
            self.save()

    def capture_items(self):
        return list(self.capture.items())

    def taskbar_items(self):
        return list(self.taskbar.items())

    def opacity_items(self):
        return list(self.opacity.items())

    def clear_all(self):
        self.capture.clear()
        self.taskbar.clear()
        self.opacity.clear()

    def is_empty(self):
        return not (self.capture or self.taskbar or self.opacity)

    # ---- persistence ------------------------------------------------------

    def _load(self):
        try:
            with open(self.path, "r", encoding="utf-8") as f:
                data = json.load(f)
        except (OSError, ValueError):
            return
        if not isinstance(data, dict):
            return
        try:
            stale_boot = abs(int(data.get("boot", 0)) - self.boot) > _BOOT_TOLERANCE_MS
        except (TypeError, ValueError):
            stale_boot = True
        if stale_boot:
            return  # recorded before a reboot: handles and pids are meaningless
        for group in ("capture", "taskbar", "opacity"):
            entries = data.get(group)
            if isinstance(entries, dict):
                target = getattr(self, group)
                for hwnd, info in entries.items():
                    if isinstance(info, dict):
                        try:
                            target[int(hwnd)] = dict(info)
                        except (TypeError, ValueError):
                            continue

    def save(self):
        data = {
            "boot": self.boot,
            "capture": {str(k): v for k, v in self.capture.items()},
            "taskbar": {str(k): v for k, v in self.taskbar.items()},
            "opacity": {str(k): v for k, v in self.opacity.items()},
        }
        try:
            tmp_path = self.path + ".tmp"
            with open(tmp_path, "w", encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=False, indent=2)
            os.replace(tmp_path, self.path)
        except OSError:
            logger.warning(
                "could not write session state %s", self.path, exc_info=True
            )

    def delete(self):
        try:
            os.remove(self.path)
        except OSError:
            pass
