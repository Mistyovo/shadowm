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

SW_RESTORE = 9
u32.ShowWindow.argtypes = [wintypes.HWND, ctypes.c_int]
u32.ShowWindow.restype = wintypes.BOOL
u32.SetForegroundWindow.argtypes = [wintypes.HWND]
u32.SetForegroundWindow.restype = wintypes.BOOL


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
    # optional SessionState hook so a crashed run's styles can be healed
    _session = None

    @staticmethod
    def set_session(session):
        """Attaches the crash-recovery session file (or None to detach)."""
        TaskbarHider._session = session

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
    def show_window(hwnd: int):
        """Un-minimizes hwnd and brings it to the foreground.

        A taskbar-hidden window that got minimized has no way back through
        the system UI (no taskbar button, not in Alt-Tab, Win+D ignores
        it), so the list menu offers this as the way back. Plain win32
        calls on the foreign window, no injection.
        """
        if not u32.IsWindow(hwnd):
            return False, "Window no longer exists."
        u32.ShowWindow(hwnd, SW_RESTORE)
        # foreground activation is privilege-restricted and may be denied;
        # the restore above already brought the window back on screen, so
        # a failure here only means focus stayed where it was
        u32.SetForegroundWindow(hwnd)
        return True, ""

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
    def is_tracked(cls, hwnd: int) -> bool:
        """True while we own this window's taskbar style (hide/restore pair)."""
        entry = cls._original.get(hwnd)
        return entry is not None and cls._pid_of(hwnd) == entry[1]

    @classmethod
    def hide(cls, hwnd: int):
        """Removes hwnd from the taskbar and the Alt-Tab / Task View list."""
        if not u32.IsWindow(hwnd):
            return False, "Window no longer exists."
        pid = cls._pid_of(hwnd)
        entry = cls._original.get(hwnd)
        if entry is not None and entry[1] != pid:
            cls._forget_tracking(hwnd)  # hwnd was reused: stale entry
            entry = None
        style = _get_exstyle(hwnd, GWL_EXSTYLE)
        if entry is None:
            # Remember what to restore. A window that already looks hidden
            # (native tool window, or a leftover from a crashed session) is
            # recorded with TOOLWINDOW presumed ours so a later restore
            # surfaces it in the taskbar again.
            original = style & ~WS_EX_TOOLWINDOW if style & WS_EX_TOOLWINDOW else style
            cls._original[hwnd] = (original, pid)
            if cls._session is not None:
                cls._session.note_taskbar_hidden(hwnd, pid, original)
        target = (style & ~WS_EX_APPWINDOW) | WS_EX_TOOLWINDOW
        if target == style:
            return True, ""
        if not cls._apply(hwnd, target):
            return False, (
                f"SetWindowLongPtr failed (Code: {ctypes.get_last_error()})"
            )
        return True, ""

    @classmethod
    def restore(cls, hwnd: int):
        """Puts hwnd back into the taskbar and Alt-Tab."""
        if not u32.IsWindow(hwnd):
            cls._forget_tracking(hwnd)
            return True, ""
        entry = cls._original.get(hwnd)
        tracked = entry is not None and entry[1] == cls._pid_of(hwnd)
        style = _get_exstyle(hwnd, GWL_EXSTYLE)
        if tracked:
            target = entry[0]
        elif style & WS_EX_TOOLWINDOW:
            # untracked already-hidden window: assume a crashed session (or
            # a previous ShadowM version) left it here and surface it again
            target = style & ~WS_EX_TOOLWINDOW
        else:
            cls._forget_tracking(hwnd)
            return True, ""
        if not cls._apply(hwnd, target):
            return False, (
                f"SetWindowLongPtr failed (Code: {ctypes.get_last_error()})"
            )
        cls._forget_tracking(hwnd)
        return True, ""

    @classmethod
    def recover_leftover(cls, hwnd: int, exstyle: int):
        """Startup heal: re-applies a style recorded by a crashed run."""
        if not u32.IsWindow(hwnd):
            return True, ""
        if not cls._apply(hwnd, exstyle):
            return False, (
                f"SetWindowLongPtr failed (Code: {ctypes.get_last_error()})"
            )
        return True, ""

    @classmethod
    def reconcile(cls):
        """Re-hides tracked windows that lost the style; forgets dead hwnds."""
        for hwnd, (_, pid) in list(cls._original.items()):
            if not u32.IsWindow(hwnd) or cls._pid_of(hwnd) != pid:
                cls._forget_tracking(hwnd)
            elif not cls.is_hidden(hwnd):
                style = _get_exstyle(hwnd, GWL_EXSTYLE)
                cls._apply(hwnd, (style & ~WS_EX_APPWINDOW) | WS_EX_TOOLWINDOW)

    @classmethod
    def forget(cls, hwnd: int):
        """Drops tracking for a window that left the list (no style change)."""
        cls._forget_tracking(hwnd)

    @classmethod
    def restore_all(cls):
        """Puts every window we hid this session back into the taskbar."""
        for hwnd in list(cls._original):
            cls.restore(hwnd)

    @classmethod
    def _forget_tracking(cls, hwnd: int):
        cls._original.pop(hwnd, None)
        if cls._session is not None:
            cls._session.clear_taskbar(hwnd)

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
