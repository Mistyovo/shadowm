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

from capture_hider import u32

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
u32.IsWindow.argtypes = [wintypes.HWND]
u32.IsWindow.restype = wintypes.BOOL


class WindowOpacity:
    _layered_added = set()  # hwnds we gave the WS_EX_LAYERED style ourselves
    _applied = {}           # hwnd -> last opacity percent we set

    @classmethod
    def set_opacity(cls, hwnd: int, percent: int):
        """Makes hwnd `percent`% opaque on screen (1..100)."""
        if not 1 <= percent <= 100:
            return False, "Opacity must be between 1% and 100%."
        if not u32.IsWindow(hwnd):
            return False, "Window no longer exists."
        alpha = max(1, round(255 * percent / 100))  # never fully invisible
        style = _get_exstyle(hwnd, GWL_EXSTYLE)
        if not style & WS_EX_LAYERED:
            if not _set_exstyle(hwnd, GWL_EXSTYLE, style | WS_EX_LAYERED):
                return False, (
                    f"SetWindowLongPtr failed (Code: {ctypes.GetLastError()})"
                )
            cls._layered_added.add(hwnd)
        if not u32.SetLayeredWindowAttributes(hwnd, 0, alpha, LWA_ALPHA):
            return False, (
                f"SetLayeredWindowAttributes failed "
                f"(Code: {ctypes.GetLastError()})"
            )
        cls._applied[hwnd] = percent
        return True, ""

    @classmethod
    def restore(cls, hwnd: int):
        """Returns hwnd to normal rendering (drops our layered style)."""
        if hwnd not in cls._applied and hwnd not in cls._layered_added:
            return True, ""
        if not u32.IsWindow(hwnd):
            cls._applied.pop(hwnd, None)
            cls._layered_added.discard(hwnd)
            return True, ""
        if hwnd in cls._layered_added:
            style = _get_exstyle(hwnd, GWL_EXSTYLE)
            _set_exstyle(hwnd, GWL_EXSTYLE, style & ~WS_EX_LAYERED)
            cls._layered_added.discard(hwnd)
        else:
            # Window was already layered before us: only reset the alpha.
            u32.SetLayeredWindowAttributes(hwnd, 0, 255, LWA_ALPHA)
        cls._applied.pop(hwnd, None)
        return True, ""

    @classmethod
    def restore_all(cls):
        """Restores every window we ever made translucent."""
        for hwnd in list(cls._applied):
            cls.restore(hwnd)

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
