"""Win32 roundtrip tests against real windows created by the test process.

Same-process windows exercise the direct (non-injection) code paths used by
the exit-restore and startup-heal logic.
"""

import ctypes
import os
import sys
import unittest
import uuid
from ctypes import wintypes

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from capture_hider import (
    WindowCaptureHider,
    _find_remote_module_base,
    k32,
    u32,
)
from taskbar_hider import (
    GWL_EXSTYLE,
    WS_EX_APPWINDOW,
    WS_EX_TOOLWINDOW,
    TaskbarHider,
    _get_exstyle,
)
from window_opacity import LWA_ALPHA, WS_EX_LAYERED, WindowOpacity

WNDPROC = ctypes.WINFUNCTYPE(
    ctypes.c_ssize_t,
    wintypes.HWND,
    wintypes.UINT,
    wintypes.WPARAM,
    wintypes.LPARAM,
)


class WNDCLASSW(ctypes.Structure):
    _fields_ = [
        ("style", wintypes.UINT),
        ("lpfnWndProc", WNDPROC),
        ("cbClsExtra", ctypes.c_int),
        ("cbWndExtra", ctypes.c_int),
        ("hInstance", wintypes.HINSTANCE),
        ("hIcon", wintypes.HANDLE),
        ("hCursor", wintypes.HANDLE),
        ("hbrBackground", wintypes.HANDLE),
        ("lpszMenuName", wintypes.LPCWSTR),
        ("lpszClassName", wintypes.LPCWSTR),
    ]


u32.DefWindowProcW.argtypes = [wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM]
u32.DefWindowProcW.restype = ctypes.c_ssize_t
u32.RegisterClassW.argtypes = [ctypes.POINTER(WNDCLASSW)]
u32.RegisterClassW.restype = wintypes.ATOM
u32.UnregisterClassW.argtypes = [wintypes.LPCWSTR, wintypes.HINSTANCE]
u32.UnregisterClassW.restype = wintypes.BOOL
u32.CreateWindowExW.argtypes = [
    wintypes.DWORD,
    wintypes.LPCWSTR,
    wintypes.LPCWSTR,
    wintypes.DWORD,
    ctypes.c_int,
    ctypes.c_int,
    ctypes.c_int,
    ctypes.c_int,
    wintypes.HWND,
    wintypes.HMENU,
    wintypes.HINSTANCE,
    wintypes.LPVOID,
]
u32.CreateWindowExW.restype = wintypes.HWND
u32.DestroyWindow.argtypes = [wintypes.HWND]
u32.DestroyWindow.restype = wintypes.BOOL
u32.ShowWindow.argtypes = [wintypes.HWND, ctypes.c_int]
u32.ShowWindow.restype = wintypes.BOOL

WS_OVERLAPPEDWINDOW = 0x00CF0000
SW_SHOWNOACTIVATE = 4


def _wnd_proc(hwnd, msg, wparam, lparam):
    return u32.DefWindowProcW(hwnd, msg, wparam, lparam)


_WND_PROC = WNDPROC(_wnd_proc)  # keep the trampoline alive for the class


def make_window(exstyle=0, title=None, visible=False):
    """Creates a real top-level window owned by the test process."""
    hinst = k32.GetModuleHandleW(None)
    name = f"ShadowMTest_{uuid.uuid4().hex[:8]}"
    wc = WNDCLASSW()
    wc.lpfnWndProc = _WND_PROC
    wc.hInstance = hinst
    wc.lpszClassName = name
    if not u32.RegisterClassW(ctypes.byref(wc)):
        raise ctypes.WinError(ctypes.get_last_error())
    hwnd = u32.CreateWindowExW(
        exstyle,
        name,
        title or name,
        WS_OVERLAPPEDWINDOW,
        100,
        100,
        300,
        200,
        None,
        None,
        hinst,
        None,
    )
    if not hwnd:
        u32.UnregisterClassW(name, hinst)
        raise ctypes.WinError(ctypes.get_last_error())
    if visible:
        u32.ShowWindow(hwnd, SW_SHOWNOACTIVATE)
    return hwnd, name, hinst


def destroy_window(hwnd, name, hinst):
    u32.DestroyWindow(hwnd)
    u32.UnregisterClassW(name, hinst)


def exstyle_of(hwnd):
    return _get_exstyle(hwnd, GWL_EXSTYLE)


def layered_alpha_of(hwnd):
    key = wintypes.COLORREF(0)
    alpha = wintypes.BYTE(0)
    flags = wintypes.DWORD(0)
    if u32.GetLayeredWindowAttributes(
        hwnd, ctypes.byref(key), ctypes.byref(alpha), ctypes.byref(flags)
    ):
        return alpha.value
    return None


class CaptureAffinityTests(unittest.TestCase):
    """The exact primitive the exit-restore and startup-heal paths use."""

    def test_roundtrip_own_process(self):
        hwnd, name, hinst = make_window()
        try:
            ok, _ = WindowCaptureHider.set_window_hidden(hwnd, True)
            self.assertTrue(ok)
            self.assertEqual(
                WindowCaptureHider.get_window_affinity(hwnd),
                WindowCaptureHider.WDA_EXCLUDEFROMCAPTURE,
            )
            ok, _ = WindowCaptureHider.set_window_hidden(hwnd, False)
            self.assertTrue(ok)
            self.assertEqual(
                WindowCaptureHider.get_window_affinity(hwnd),
                WindowCaptureHider.WDA_NONE,
            )
        finally:
            destroy_window(hwnd, name, hinst)


class TaskbarHiderTests(unittest.TestCase):
    def test_hide_restore_roundtrip(self):
        hwnd, name, hinst = make_window()
        try:
            original = exstyle_of(hwnd)
            ok, msg = TaskbarHider.hide(hwnd)
            self.assertTrue(ok, msg)
            self.assertTrue(TaskbarHider.is_hidden(hwnd))
            self.assertTrue(TaskbarHider.is_tracked(hwnd))
            self.assertEqual(exstyle_of(hwnd) & WS_EX_TOOLWINDOW, WS_EX_TOOLWINDOW)
            self.assertEqual(exstyle_of(hwnd) & WS_EX_APPWINDOW, 0)
            ok, msg = TaskbarHider.restore(hwnd)
            self.assertTrue(ok, msg)
            self.assertEqual(exstyle_of(hwnd), original)
            self.assertFalse(TaskbarHider.is_tracked(hwnd))
        finally:
            TaskbarHider.forget(hwnd)
            destroy_window(hwnd, name, hinst)

    def test_native_tool_window_adoption(self):
        # Adopting a window that is a tool window by design records the
        # TOOLWINDOW bit as ours, so restore surfaces it in the taskbar.
        hwnd, name, hinst = make_window(exstyle=WS_EX_TOOLWINDOW)
        try:
            original = exstyle_of(hwnd)
            ok, _ = TaskbarHider.hide(hwnd)
            self.assertTrue(ok)
            self.assertTrue(TaskbarHider.is_tracked(hwnd))
            ok, _ = TaskbarHider.restore(hwnd)
            self.assertTrue(ok)
            self.assertEqual(exstyle_of(hwnd), original & ~WS_EX_TOOLWINDOW)
            # a second cycle keeps round-tripping to the same value
            ok, _ = TaskbarHider.hide(hwnd)
            self.assertTrue(ok)
            ok, _ = TaskbarHider.restore(hwnd)
            self.assertTrue(ok)
            self.assertEqual(exstyle_of(hwnd), original & ~WS_EX_TOOLWINDOW)
        finally:
            TaskbarHider.forget(hwnd)
            destroy_window(hwnd, name, hinst)

    def test_restore_dead_window(self):
        hwnd, name, hinst = make_window()
        ok, _ = TaskbarHider.hide(hwnd)
        self.assertTrue(ok)
        destroy_window(hwnd, name, hinst)
        ok, _ = TaskbarHider.restore(hwnd)
        self.assertTrue(ok)
        self.assertFalse(TaskbarHider.is_tracked(hwnd))


class WindowOpacityTests(unittest.TestCase):
    def test_roundtrip_plain_window(self):
        hwnd, name, hinst = make_window()
        try:
            self.assertEqual(exstyle_of(hwnd) & WS_EX_LAYERED, 0)
            ok, msg = WindowOpacity.set_opacity(hwnd, 50)
            self.assertTrue(ok, msg)
            self.assertEqual(WindowOpacity.get_percent(hwnd), 50)
            self.assertEqual(exstyle_of(hwnd) & WS_EX_LAYERED, WS_EX_LAYERED)
            ok, msg = WindowOpacity.restore(hwnd)
            self.assertTrue(ok, msg)
            self.assertEqual(WindowOpacity.get_percent(hwnd), 100)
            self.assertEqual(exstyle_of(hwnd) & WS_EX_LAYERED, 0)
        finally:
            WindowOpacity.restore(hwnd)
            destroy_window(hwnd, name, hinst)

    def test_pre_layered_alpha_preserved(self):
        hwnd, name, hinst = make_window(exstyle=WS_EX_LAYERED)
        try:
            self.assertTrue(u32.SetLayeredWindowAttributes(hwnd, 0, 128, LWA_ALPHA))
            ok, msg = WindowOpacity.set_opacity(hwnd, 50)
            self.assertTrue(ok, msg)
            self.assertEqual(WindowOpacity.get_percent(hwnd), 50)
            ok, msg = WindowOpacity.restore(hwnd)
            self.assertTrue(ok, msg)
            # the app's own alpha comes back instead of being forced to 255
            self.assertEqual(layered_alpha_of(hwnd), 128)
            self.assertEqual(exstyle_of(hwnd) & WS_EX_LAYERED, WS_EX_LAYERED)
        finally:
            WindowOpacity.restore(hwnd)
            destroy_window(hwnd, name, hinst)

    def test_restore_dead_window(self):
        hwnd, name, hinst = make_window()
        ok, _ = WindowOpacity.set_opacity(hwnd, 50)
        self.assertTrue(ok)
        destroy_window(hwnd, name, hinst)
        ok, _ = WindowOpacity.restore(hwnd)
        self.assertTrue(ok)


class WindowEnumerationTests(unittest.TestCase):
    def test_own_window_listed_shell_windows_filtered(self):
        title = f"ShadowM unittest {uuid.uuid4().hex[:8]}"
        hwnd, name, hinst = make_window(title=title, visible=True)
        try:
            windows = WindowCaptureHider.get_all_windows()
            self.assertIn(hwnd, {w["hwnd"] for w in windows})
            entry = next(w for w in windows if w["hwnd"] == hwnd)
            self.assertEqual(entry["title"], title)
            self.assertEqual(entry["pid"], os.getpid())
            # desktop shell windows are filtered by class, any locale
            titles = {w["title"] for w in windows}
            self.assertNotIn("Program Manager", titles)
        finally:
            destroy_window(hwnd, name, hinst)


class RemoteModuleBaseTests(unittest.TestCase):
    def test_own_process_base_matches_local(self):
        # same process: the snapshot base and GetModuleHandleW must agree;
        # the injection address math builds on exactly this equality
        remote = _find_remote_module_base(os.getpid(), "user32.dll")
        local = k32.GetModuleHandleW("user32.dll")
        self.assertEqual(remote, local)

    def test_unknown_module_returns_none(self):
        self.assertIsNone(
            _find_remote_module_base(os.getpid(), "no_such_dll_42.dll")
        )


if __name__ == "__main__":
    unittest.main()
