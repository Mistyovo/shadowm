"""
Taskbar / Alt-Tab hiding.

A top-level window stays out of the taskbar and the Alt-Tab / Task View
switcher once WS_EX_TOOLWINDOW is set (and WS_EX_APPWINDOW cleared).
Flipping those extended style bits is a plain SetWindowLongPtrW on the
foreign window plus SetWindowPos(SWP_FRAMECHANGED) so the shell re-reads
the styles. Like the opacity feature this needs no injection: it works
on other processes' windows directly, including 32-bit ones.

This is independent of capture exclusion - a taskbar-hidden window is
still recorded on screen unless its capture checkbox is ticked as well.
"""

import ctypes
from ctypes import wintypes

from capture_hider import u32

GWL_EXSTYLE = -20
WS_EX_APPWINDOW = 0x00040000
WS_EX_TOOLWINDOW = 0x00000080

SWP_NOSIZE = 0x0001
SWP_NOMOVE = 0x0002
SWP_NOZORDER = 0x0004
SWP_NOACTIVATE = 0x0010
SWP_FRAMECHANGED = 0x0020
SWP_NOOWNERZORDER = 0x0200

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

u32.SetWindowPos.argtypes = [
    wintypes.HWND,
    wintypes.HWND,
    ctypes.c_int,
    ctypes.c_int,
    ctypes.c_int,
    ctypes.c_int,
    wintypes.UINT,
]
u32.SetWindowPos.restype = wintypes.BOOL

u32.RegisterHotKey.argtypes = [
    wintypes.HWND,
    ctypes.c_int,
    wintypes.UINT,
    wintypes.UINT,
]
u32.RegisterHotKey.restype = wintypes.BOOL
u32.UnregisterHotKey.argtypes = [wintypes.HWND, ctypes.c_int]
u32.UnregisterHotKey.restype = wintypes.BOOL


class TaskbarHider:
    # global hotkey that flips taskbar hiding for every marked window
    WM_HOTKEY = 0x0312
    HOTKEY_TOGGLE_ALL = 0xB0C1
    MOD_ALT = 0x0001
    MOD_CONTROL = 0x0002
    VK_T = 0x54

    # hwnd -> (exstyle before we hid it, pid of the owning process); the pid
    # guards against Windows reusing a hwnd value for a brand-new window
    _original = {}

    @staticmethod
    def is_window(hwnd: int) -> bool:
        return bool(u32.IsWindow(hwnd))

    @staticmethod
    def register_hotkey(hwnd: int, hotkey_id: int, modifiers: int, vk: int) -> bool:
        return bool(u32.RegisterHotKey(hwnd, hotkey_id, modifiers, vk))

    @staticmethod
    def unregister_hotkey(hwnd: int, hotkey_id: int) -> bool:
        return bool(u32.UnregisterHotKey(hwnd, hotkey_id))

    @staticmethod
    def _pid_of(hwnd: int) -> int:
        pid = wintypes.DWORD()
        u32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
        return pid.value

    @classmethod
    def is_hidden(cls, hwnd: int) -> bool:
        """True while the window stays out of the taskbar and Alt-Tab."""
        style = _get_exstyle(hwnd, GWL_EXSTYLE)
        return bool(style & WS_EX_TOOLWINDOW) and not style & WS_EX_APPWINDOW

    @classmethod
    def hide(cls, hwnd: int):
        """Removes hwnd from the taskbar and the Alt-Tab / Task View list."""
        if not u32.IsWindow(hwnd):
            return False, "Window no longer exists."
        pid = cls._pid_of(hwnd)
        entry = cls._original.get(hwnd)
        if entry is not None and entry[1] != pid:
            cls._original.pop(hwnd, None)  # hwnd was reused: stale entry
            entry = None
        style = _get_exstyle(hwnd, GWL_EXSTYLE)
        # a window that is already hidden (e.g. leftover from a crashed
        # session) stays untracked so restore() can still recover it
        if entry is None and not cls.is_hidden(hwnd):
            cls._original[hwnd] = (style, pid)
        target = (style & ~WS_EX_APPWINDOW) | WS_EX_TOOLWINDOW
        if target == style:
            return True, ""
        if not cls._apply(hwnd, target):
            return False, (
                f"SetWindowLongPtr failed (Code: {ctypes.GetLastError()})"
            )
        return True, ""

    @classmethod
    def restore(cls, hwnd: int):
        """Puts hwnd back into the taskbar and Alt-Tab."""
        if not u32.IsWindow(hwnd):
            cls._original.pop(hwnd, None)
            return True, ""
        entry = cls._original.get(hwnd)
        tracked = entry is not None and entry[1] == cls._pid_of(hwnd)
        style = _get_exstyle(hwnd, GWL_EXSTYLE)
        if tracked:
            target = entry[0]
        elif style & WS_EX_TOOLWINDOW:
            # untracked (native tool window or crash leftover): clearing
            # TOOLWINDOW alone restores the default taskbar behavior
            target = style & ~WS_EX_TOOLWINDOW
        else:
            cls._original.pop(hwnd, None)
            return True, ""
        if not cls._apply(hwnd, target):
            return False, (
                f"SetWindowLongPtr failed (Code: {ctypes.GetLastError()})"
            )
        cls._original.pop(hwnd, None)
        return True, ""

    @classmethod
    def reconcile(cls):
        """Re-hides tracked windows that lost the style; forgets dead hwnds."""
        for hwnd, (_, pid) in list(cls._original.items()):
            if not u32.IsWindow(hwnd) or cls._pid_of(hwnd) != pid:
                cls._original.pop(hwnd, None)
            elif not cls.is_hidden(hwnd):
                style = _get_exstyle(hwnd, GWL_EXSTYLE)
                cls._apply(hwnd, (style & ~WS_EX_APPWINDOW) | WS_EX_TOOLWINDOW)

    @classmethod
    def forget(cls, hwnd: int):
        """Drops tracking for a window that left the list (no style change)."""
        cls._original.pop(hwnd, None)

    @classmethod
    def restore_all(cls):
        """Puts every window we hid this session back into the taskbar."""
        for hwnd in list(cls._original):
            cls.restore(hwnd)

    @classmethod
    def _apply(cls, hwnd: int, exstyle: int) -> bool:
        """Writes the extended style and makes the shell re-read it."""
        if not _set_exstyle(hwnd, GWL_EXSTYLE, exstyle):
            return False
        u32.SetWindowPos(
            hwnd,
            None,
            0,
            0,
            0,
            0,
            SWP_NOMOVE
            | SWP_NOSIZE
            | SWP_NOZORDER
            | SWP_NOACTIVATE
            | SWP_NOOWNERZORDER
            | SWP_FRAMECHANGED,
        )
        return True
