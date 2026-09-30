"""
Per-window on-screen transparency.

This is purely the transparency the local user sees: it uses the classic
WS_EX_LAYERED + SetLayeredWindowAttributes(LWA_ALPHA) combination, which can
be applied to any top-level window directly (no injection required - unlike
SetWindowDisplayAffinity, these calls are not restricted to the process that
owns the window).

Capture exclusion is completely independent: a window excluded via
WDA_EXCLUDEFROMCAPTURE stays excluded no matter how translucent it looks
locally, while a normally captured window simply shows up translucent in
recordings (captures reflect what the screen looks like).
"""

import ctypes
from ctypes import wintypes

from capture_hider import u32, get_window_pid

GWL_EXSTYLE = -20
WS_EX_LAYERED = 0x00080000
LWA_ALPHA = 0x00000002

if hasattr(u32, "SetWindowLongPtrW"):
    _get_exstyle = u32.GetWindowLongPtrW
    _set_exstyle = u32.SetWindowLongPtrW
    _long_ptr = ctypes.c_ssize_t
else:  # 32-bit Python fallback
    _get_exstyle = u32.GetWindowLongW
    _set_exstyle = u32.SetWindowLongW
    _long_ptr = ctypes.c_long

_get_exstyle.argtypes = [wintypes.HWND, ctypes.c_int]
_get_exstyle.restype = _long_ptr
_set_exstyle.argtypes = [wintypes.HWND, ctypes.c_int, _long_ptr]
_set_exstyle.restype = _long_ptr

u32.SetLayeredWindowAttributes.argtypes = [
    wintypes.HWND,
    wintypes.COLORREF,
    wintypes.BYTE,
    wintypes.DWORD,
]
u32.SetLayeredWindowAttributes.restype = wintypes.BOOL
u32.GetLayeredWindowAttributes.argtypes = [
    wintypes.HWND,
    ctypes.POINTER(wintypes.COLORREF),
    ctypes.POINTER(wintypes.BYTE),
    ctypes.POINTER(wintypes.DWORD),
]
u32.GetLayeredWindowAttributes.restype = wintypes.BOOL


class WindowOpacity:
    # hwnd -> (pid, we_added_layered, original_alpha or None); the pid guards
    # against Windows reusing a hwnd value for a brand-new window
    _state = {}
    # optional SessionState hook so a crashed run's styles can be healed
    _session = None

    @staticmethod
    def set_session(session):
        """Attaches the crash-recovery session file (or None to detach)."""
        WindowOpacity._session = session

    @classmethod
    def set_opacity(cls, hwnd: int, percent: int):
        """Makes hwnd `percent`% opaque on screen (1..100)."""
        if not 1 <= percent <= 100:
            return False, "Opacity must be between 1% and 100%."
        if not u32.IsWindow(hwnd):
            return False, "Window no longer exists."

        pid = get_window_pid(hwnd)
        entry = cls._state.get(hwnd)
        if entry is None or entry[0] != pid:
            # first touch: remember how to undo whatever we are about to do
            style = _get_exstyle(hwnd, GWL_EXSTYLE)
            added_layered = not style & WS_EX_LAYERED
            original_alpha = None
            if not added_layered:
                key = wintypes.COLORREF(0)
                alpha = wintypes.BYTE(0)
                flags = wintypes.DWORD(0)
                if (
                    u32.GetLayeredWindowAttributes(
                        hwnd, ctypes.byref(key), ctypes.byref(alpha), ctypes.byref(flags)
                    )
                    and flags.value & LWA_ALPHA
                ):
                    original_alpha = alpha.value
            cls._state[hwnd] = (pid, added_layered, original_alpha)
            if cls._session is not None:
                cls._session.note_opacity(hwnd, pid, added_layered, original_alpha)

        style = _get_exstyle(hwnd, GWL_EXSTYLE)
        if not style & WS_EX_LAYERED:
            if not _set_exstyle(hwnd, GWL_EXSTYLE, style | WS_EX_LAYERED):
                return False, (
                    f"SetWindowLongPtr failed (Code: {ctypes.get_last_error()})"
                )
        alpha = max(1, round(255 * percent / 100))  # never fully invisible
        if not u32.SetLayeredWindowAttributes(hwnd, 0, alpha, LWA_ALPHA):
            return False, (
                f"SetLayeredWindowAttributes failed "
                f"(Code: {ctypes.get_last_error()})"
            )
        return True, ""

    @classmethod
    def restore(cls, hwnd: int):
        """Returns hwnd to the translucency it had before we touched it."""
        entry = cls._state.get(hwnd)
        if entry is None:
            return True, ""
        pid, added_layered, original_alpha = entry
        if not u32.IsWindow(hwnd) or get_window_pid(hwnd) != pid:
            # dead window, or hwnd already reused by a different process
            cls._forget(hwnd)
            return True, ""
        if added_layered:
            style = _get_exstyle(hwnd, GWL_EXSTYLE)
            _set_exstyle(hwnd, GWL_EXSTYLE, style & ~WS_EX_LAYERED)
        else:
            # window was already layered before us: put its own alpha back
            alpha = original_alpha if original_alpha is not None else 255
            u32.SetLayeredWindowAttributes(hwnd, 0, alpha, LWA_ALPHA)
        cls._forget(hwnd)
        return True, ""

    @classmethod
    def recover_leftover(cls, hwnd: int, added_layered: bool, original_alpha):
        """Startup heal: undoes a change recorded by a crashed run."""
        if not u32.IsWindow(hwnd):
            return True, ""
        if added_layered:
            style = _get_exstyle(hwnd, GWL_EXSTYLE)
            _set_exstyle(hwnd, GWL_EXSTYLE, style & ~WS_EX_LAYERED)
        elif original_alpha is not None:
            u32.SetLayeredWindowAttributes(hwnd, 0, original_alpha, LWA_ALPHA)
        return True, ""

    @classmethod
    def restore_all(cls):
        """Restores every window we ever made translucent."""
        for hwnd in list(cls._state):
            cls.restore(hwnd)

    @classmethod
    def _forget(cls, hwnd: int):
        cls._state.pop(hwnd, None)
        if cls._session is not None:
            cls._session.clear_opacity(hwnd)

    @classmethod
    def get_percent(cls, hwnd: int) -> int:
        """Current on-screen opacity of hwnd (100 if fully opaque)."""
        key = wintypes.COLORREF(0)
        alpha = wintypes.BYTE(0)
        flags = wintypes.DWORD(0)
        if (
            u32.GetLayeredWindowAttributes(
                hwnd, ctypes.byref(key), ctypes.byref(alpha), ctypes.byref(flags)
            )
            and flags.value & LWA_ALPHA
        ):
            return max(1, round(alpha.value * 100 / 255))
        return 100
