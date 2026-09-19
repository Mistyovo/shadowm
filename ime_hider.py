"""
Guards the built-in Windows IME candidate box from screen capture.

The pinyin candidate/composition UI of the Microsoft IME is not drawn by the
application being typed into - it lives in a separate system input process
(TextInputHost.exe on Windows 10 1903+/Windows 11, ChsIME.exe on older
builds). Hiding an application window therefore leaves the candidate box
visible to capture tools.

ImeGuard watches the foreground window: while focus is inside a window that
ShadowM has hidden, every top-level window of the input host process is
tagged WDA_EXCLUDEFROMCAPTURE (through the same remote-thread injection used
for normal windows), and WinEvent hooks arm any window the host creates or
shows later (e.g. a freshly created candidate window). When focus returns to
a normal window, the IME windows are restored to WDA_NONE.
"""

import ctypes
from ctypes import wintypes

from PyQt5.QtCore import QObject, QThread, pyqtSignal

from capture_hider import WindowCaptureHider, EnumWindowsProc, k32, u32

# Processes hosting the UI of the Windows built-in input methods.
IME_HOST_PROCESS_NAMES = {
    "textinputhost.exe",  # Windows 10 1903+ / Windows 11 "Windows Input Experience"
    "chsime.exe",         # Windows 8.x / early Windows 10 simplified Chinese IME
    "chtime.exe",         # traditional Chinese IME host
    "ctfmon.exe",         # legacy CTF monitor (language bar / old-style IME UI)
}

TH32CS_SNAPPROCESS = 0x00000002
INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value

EVENT_SYSTEM_FOREGROUND = 0x0003
EVENT_OBJECT_CREATE = 0x8000
EVENT_OBJECT_DESTROY = 0x8001
EVENT_OBJECT_SHOW = 0x8002
OBJID_WINDOW = 0
GA_ROOT = 2
WINEVENT_OUTOFCONTEXT = 0x0000


class PROCESSENTRY32W(ctypes.Structure):
    _fields_ = [
        ("dwSize", wintypes.DWORD),
        ("cntUsage", wintypes.DWORD),
        ("th32ProcessID", wintypes.DWORD),
        ("th32DefaultHeapID", ctypes.c_size_t),
        ("th32ModuleID", wintypes.DWORD),
        ("cntThreads", wintypes.DWORD),
        ("th32ParentProcessID", wintypes.DWORD),
        ("pcPriClassBase", wintypes.LONG),
        ("dwFlags", wintypes.DWORD),
        ("szExeFile", ctypes.c_wchar * 260),
    ]


k32.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
k32.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
k32.Process32FirstW.argtypes = [wintypes.HANDLE, ctypes.POINTER(PROCESSENTRY32W)]
k32.Process32FirstW.restype = wintypes.BOOL
k32.Process32NextW.argtypes = [wintypes.HANDLE, ctypes.POINTER(PROCESSENTRY32W)]
k32.Process32NextW.restype = wintypes.BOOL

u32.GetForegroundWindow.restype = wintypes.HWND
u32.GetClassNameW.argtypes = [wintypes.HWND, wintypes.LPWSTR, ctypes.c_int]
u32.GetClassNameW.restype = ctypes.c_int
u32.IsWindow.argtypes = [wintypes.HWND]
u32.IsWindow.restype = wintypes.BOOL
u32.GetAncestor.argtypes = [wintypes.HWND, wintypes.UINT]
u32.GetAncestor.restype = wintypes.HWND

WinEventProc = ctypes.WINFUNCTYPE(
    None,
    wintypes.HANDLE,  # hWinEventHook
    wintypes.DWORD,   # event
    wintypes.HWND,    # hwnd
    wintypes.LONG,    # idObject
    wintypes.LONG,    # idChild
    wintypes.DWORD,   # dwEventThread
    wintypes.DWORD,   # dwmsEventTime
)

u32.SetWinEventHook.argtypes = [
    wintypes.UINT,
    wintypes.UINT,
    wintypes.HINSTANCE,
    WinEventProc,
    wintypes.DWORD,
    wintypes.DWORD,
    wintypes.UINT,
]
u32.SetWinEventHook.restype = wintypes.HANDLE
u32.UnhookWinEvent.argtypes = [wintypes.HANDLE]
u32.UnhookWinEvent.restype = wintypes.BOOL


def find_ime_pids():
    """Returns the pids of every running process that hosts built-in IME UI."""
    pids = set()
    snapshot = k32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if not snapshot or snapshot == INVALID_HANDLE_VALUE:
        return pids
    try:
        entry = PROCESSENTRY32W()
        entry.dwSize = ctypes.sizeof(PROCESSENTRY32W)
        has_more = k32.Process32FirstW(snapshot, ctypes.byref(entry))
        while has_more:
            if entry.szExeFile.lower() in IME_HOST_PROCESS_NAMES:
                pids.add(entry.th32ProcessID)
            has_more = k32.Process32NextW(snapshot, ctypes.byref(entry))
    finally:
        k32.CloseHandle(snapshot)
    return pids


def find_ime_windows(pids):
    """Returns {hwnd: class_name} for all top-level windows owned by pids."""
    windows = {}

    def enum_proc(hwnd, _lparam):
        pid = wintypes.DWORD()
        u32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
        if pid.value in pids:
            class_buf = ctypes.create_unicode_buffer(64)
            u32.GetClassNameW(hwnd, class_buf, 64)
            windows[hwnd] = class_buf.value
        return True

    callback = EnumWindowsProc(enum_proc)
    u32.EnumWindows(callback, 0)
    return windows


class _ImeWorker(QThread):
    finished = pyqtSignal(int, bool, bool, str)

    def __init__(self, hwnd, hide, parent=None):
        super().__init__(parent)
        self.hwnd = hwnd
        self.hide = hide

    def run(self):
        success, msg = WindowCaptureHider.set_window_hidden(
            self.hwnd, hidden=self.hide
        )
        self.finished.emit(self.hwnd, self.hide, success, msg)


class ImeGuard(QObject):
    """Excludes the built-in IME candidate windows from screen capture while
    the keyboard focus is inside a window ShadowM has already hidden."""

    active_changed = pyqtSignal(bool)
    error_occurred = pyqtSignal(str)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.enabled = True
        self._hidden_hwnds = set()   # windows ShadowM currently hides
        self._ime_pids = set()
        self._ime_windows = {}       # hwnd -> class name
        self._applied = {}           # hwnd -> affinity state we last applied
        self._desired = False        # True while candidates must be excluded
        self._workers = {}           # hwnd -> running _ImeWorker
        self._failed = set()         # hwnds whose hide injection failed
        self._last_error = ""
        self._healed = False
        self._foreground_hook = None
        self._foreground_proc = None
        self._object_hooks = []
        self._object_hook_procs = []
        self._install_foreground_hook()

    # ---- public API ------------------------------------------------------

    def set_enabled(self, enabled):
        if self.enabled == enabled:
            return
        self.enabled = enabled
        self._failed.clear()
        if enabled:
            self.refresh()
        else:
            if self._desired:
                self._desired = False
                self.active_changed.emit(False)
            self._remove_object_hooks()
            for hwnd in list(self._ime_windows):
                self._apply(hwnd, False, force=True)

    def note_window_state(self, hwnd, hidden, success):
        """Feeds the outcome of every hide/unhide done by the main window."""
        if not success:
            return
        if hidden:
            self._hidden_hwnds.add(hwnd)
        else:
            self._hidden_hwnds.discard(hwnd)
        self.evaluate()

    def forget(self, hwnd):
        """Drops a hidden window from tracking (it was closed)."""
        self._hidden_hwnds.discard(hwnd)
        self.evaluate()

    def refresh(self):
        """Periodic rescan: IME host processes/windows may appear or restart."""
        if not self.enabled:
            return
        pids = find_ime_pids()
        if pids != self._ime_pids:
            self._ime_pids = pids
            self._failed.clear()
            if self._object_hooks:
                self._remove_object_hooks()
        self._ime_windows = find_ime_windows(self._ime_pids)
        self._prune_dead_windows()
        self._update_object_hooks()
        if not self._healed:
            # Restore anything a previous run left excluded (e.g. after a crash
            # or Task Manager kill while typing in a hidden window).
            self._healed = True
            for hwnd in list(self._ime_windows):
                self._apply(hwnd, False, force=True)
        self.evaluate()

    def evaluate(self):
        """(Re)computes whether the IME UI must be excluded right now."""
        foreground = u32.GetForegroundWindow()
        want = (
            self.enabled
            and bool(self._hidden_hwnds)
            and int(foreground or 0) in self._hidden_hwnds
        )
        if want != self._desired:
            self._desired = want
            self._failed.clear()
            self.active_changed.emit(want)
        self._update_object_hooks()
        self._apply_desired()

    def shutdown(self):
        """Synchronously restores everything we armed; called on app exit."""
        self.enabled = False  # blocks refresh()/evaluate() from re-arming
        self._remove_object_hooks()
        self._remove_foreground_hook()
        for worker in list(self._workers.values()):
            try:
                worker.finished.disconnect()
            except TypeError:
                pass
            worker.wait(3000)
        self._workers.clear()
        for hwnd, applied in list(self._applied.items()):
            if applied:
                WindowCaptureHider.set_window_hidden(hwnd, hidden=False)
        self._applied.clear()

    # ---- internals -------------------------------------------------------

    def _apply_desired(self):
        hide = self._desired
        for hwnd in list(self._ime_windows):
            self._apply(hwnd, hide)

    def _apply(self, hwnd, hide, force=False):
        if not u32.IsWindow(hwnd):
            self._ime_windows.pop(hwnd, None)
            self._applied.pop(hwnd, None)
            return
        if hwnd in self._workers:
            # A sweep runs after the worker finishes; no queueing needed.
            return
        if self._applied.get(hwnd) == hide:
            return
        if not hide and not force and self._applied.get(hwnd) is not True:
            # Never touch IME windows we did not arm ourselves.
            return
        if hide and hwnd in self._failed:
            return
        worker = _ImeWorker(hwnd, hide)
        worker.finished.connect(self._on_worker_finished)
        self._workers[hwnd] = worker
        worker.start()

    def _on_worker_finished(self, hwnd, hide, success, msg):
        worker = self._workers.pop(hwnd, None)
        if worker is not None:
            worker.deleteLater()
        if success:
            self._applied[hwnd] = hide
            if hide:
                self._failed.discard(hwnd)
        else:
            self._applied.pop(hwnd, None)
            if hide:
                self._failed.add(hwnd)
                if msg and msg != self._last_error:
                    self._last_error = msg
                    self.error_occurred.emit(msg)
        # Catch up with whatever state was requested while we were busy.
        self._apply_desired()

    def _prune_dead_windows(self):
        for hwnd in list(self._applied):
            if not u32.IsWindow(hwnd):
                self._applied.pop(hwnd, None)
                self._failed.discard(hwnd)

    # ---- WinEvent hooks --------------------------------------------------

    def _install_foreground_hook(self):
        proc = WinEventProc(self._on_foreground_event)
        handle = u32.SetWinEventHook(
            EVENT_SYSTEM_FOREGROUND,
            EVENT_SYSTEM_FOREGROUND,
            None,
            proc,
            0,
            0,
            WINEVENT_OUTOFCONTEXT,
        )
        if handle:
            self._foreground_hook = handle
            self._foreground_proc = proc

    def _update_object_hooks(self):
        wanted = self.enabled and bool(self._hidden_hwnds)
        if wanted and not self._object_hooks and self._ime_pids:
            for pid in self._ime_pids:
                proc = WinEventProc(self._on_ime_object_event)
                handle = u32.SetWinEventHook(
                    EVENT_OBJECT_CREATE,
                    EVENT_OBJECT_SHOW,
                    None,
                    proc,
                    pid,
                    0,
                    WINEVENT_OUTOFCONTEXT,
                )
                if handle:
                    self._object_hooks.append(handle)
                    self._object_hook_procs.append(proc)
        elif not wanted and self._object_hooks:
            self._remove_object_hooks()

    def _remove_object_hooks(self):
        for handle in self._object_hooks:
            u32.UnhookWinEvent(handle)
        self._object_hooks = []
        self._object_hook_procs = []

    def _remove_foreground_hook(self):
        if self._foreground_hook:
            u32.UnhookWinEvent(self._foreground_hook)
            self._foreground_hook = None
            self._foreground_proc = None

    # Delivered on the GUI thread through the Qt message loop.

    def _on_foreground_event(self, _hook, _event, _hwnd, _obj, _child, _tid, _time):
        try:
            self.evaluate()
        except Exception:
            pass

    def _on_ime_object_event(self, _hook, event, hwnd, id_object, id_child, _tid, _time):
        try:
            if id_object != OBJID_WINDOW or id_child != 0:
                return
            if event == EVENT_OBJECT_DESTROY:
                self._ime_windows.pop(hwnd, None)
                self._applied.pop(hwnd, None)
                return
            if u32.GetAncestor(hwnd, GA_ROOT) != hwnd:
                return  # affinity only works on top-level windows
            pid = wintypes.DWORD()
            u32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
            if pid.value not in self._ime_pids:
                return
            if hwnd not in self._ime_windows:
                self._ime_windows[hwnd] = ""
            self._apply(hwnd, self._desired)
        except Exception:
            pass
