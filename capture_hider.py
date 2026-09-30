import ctypes
import platform
import struct
import os
from ctypes import wintypes

# use_last_error=True makes ctypes snapshot the thread's last-error at the
# moment of each call; ctypes.get_last_error() then reads a value no other
# Python-level call can clobber. Reading GetLastError() directly is NOT
# reliable from Python.
k32 = ctypes.WinDLL("kernel32", use_last_error=True)
u32 = ctypes.WinDLL("user32", use_last_error=True)

k32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
k32.OpenProcess.restype = wintypes.HANDLE

k32.GetModuleHandleW.argtypes = [wintypes.LPCWSTR]
k32.GetModuleHandleW.restype = wintypes.HMODULE

k32.GetProcAddress.argtypes = [wintypes.HMODULE, wintypes.LPCSTR]
k32.GetProcAddress.restype = ctypes.c_void_p

k32.VirtualAllocEx.argtypes = [wintypes.HANDLE, ctypes.c_void_p, ctypes.c_size_t, wintypes.DWORD, wintypes.DWORD]
k32.VirtualAllocEx.restype = ctypes.c_void_p

k32.VirtualFreeEx.argtypes = [wintypes.HANDLE, ctypes.c_void_p, ctypes.c_size_t, wintypes.DWORD]
k32.VirtualFreeEx.restype = wintypes.BOOL

k32.WriteProcessMemory.argtypes = [wintypes.HANDLE, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
k32.WriteProcessMemory.restype = wintypes.BOOL

k32.CreateRemoteThread.argtypes = [wintypes.HANDLE, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p, ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
k32.CreateRemoteThread.restype = wintypes.HANDLE

k32.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
k32.WaitForSingleObject.restype = wintypes.DWORD

k32.GetExitCodeThread.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
k32.GetExitCodeThread.restype = wintypes.BOOL

k32.CloseHandle.argtypes = [wintypes.HANDLE]
k32.CloseHandle.restype = wintypes.BOOL

k32.IsWow64Process.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.BOOL)]
k32.IsWow64Process.restype = wintypes.BOOL

k32.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
k32.CreateToolhelp32Snapshot.restype = wintypes.HANDLE

try:
    k32.QueryFullProcessImageNameW.argtypes = [wintypes.HANDLE, wintypes.DWORD, wintypes.LPWSTR, ctypes.POINTER(wintypes.DWORD)]
    k32.QueryFullProcessImageNameW.restype = wintypes.BOOL
except AttributeError:
    pass

u32.GetWindowThreadProcessId.argtypes = [wintypes.HWND, ctypes.POINTER(wintypes.DWORD)]
u32.GetWindowThreadProcessId.restype = wintypes.DWORD

u32.SetWindowDisplayAffinity.argtypes = [wintypes.HWND, wintypes.DWORD]
u32.SetWindowDisplayAffinity.restype = wintypes.BOOL

u32.GetWindowDisplayAffinity.argtypes = [wintypes.HWND, ctypes.POINTER(wintypes.DWORD)]
u32.GetWindowDisplayAffinity.restype = wintypes.BOOL

u32.IsWindow.argtypes = [wintypes.HWND]
u32.IsWindow.restype = wintypes.BOOL

u32.IsWindowVisible.argtypes = [wintypes.HWND]
u32.IsWindowVisible.restype = wintypes.BOOL

u32.GetClassNameW.argtypes = [wintypes.HWND, wintypes.LPWSTR, ctypes.c_int]
u32.GetClassNameW.restype = ctypes.c_int

EnumWindowsProc = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)

MEM_RELEASE = 0x8000
WAIT_OBJECT_0 = 0x0000
TH32CS_SNAPMODULE = 0x00000008
INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value

# Shell scrap windows that must never show up in the window list. Matching
# by window class works on every locale, unlike title matching.
SYSTEM_WINDOW_CLASSES = {"Progman", "WorkerW", "SHELLDLL_DefView"}

DWMWA_CLOAKED = 14
_dwmapi = ctypes.WinDLL("dwmapi", use_last_error=True)
_dwmapi.DwmGetWindowAttribute.argtypes = [wintypes.HWND, wintypes.DWORD, ctypes.c_void_p, wintypes.DWORD]
_dwmapi.DwmGetWindowAttribute.restype = ctypes.c_long


class MODULEENTRY32W(ctypes.Structure):
    _fields_ = [
        ("dwSize", wintypes.DWORD),
        ("th32ModuleID", wintypes.DWORD),
        ("th32ProcessID", wintypes.DWORD),
        ("GlblcntUsage", wintypes.DWORD),
        ("ProccntUsage", wintypes.DWORD),
        ("modBaseAddr", ctypes.c_void_p),
        ("modBaseSize", wintypes.DWORD),
        ("hModule", wintypes.HMODULE),
        ("szModule", ctypes.c_wchar * 256),
        ("szExePath", ctypes.c_wchar * 260),
    ]


k32.Module32FirstW.argtypes = [wintypes.HANDLE, ctypes.POINTER(MODULEENTRY32W)]
k32.Module32FirstW.restype = wintypes.BOOL
k32.Module32NextW.argtypes = [wintypes.HANDLE, ctypes.POINTER(MODULEENTRY32W)]
k32.Module32NextW.restype = wintypes.BOOL


def window_exists(hwnd: int) -> bool:
    return bool(u32.IsWindow(hwnd))


def get_window_pid(hwnd: int) -> int:
    pid = wintypes.DWORD()
    u32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
    return pid.value


def _is_cloaked(hwnd: int) -> bool:
    """True for windows hidden by DWM cloaking (e.g. suspended UWP apps).

    Cloaked windows report IsWindowVisible == True but show nothing, so
    they would otherwise flicker through the list as ghost entries.
    """
    value = wintypes.DWORD(0)
    hr = _dwmapi.DwmGetWindowAttribute(
        hwnd, DWMWA_CLOAKED, ctypes.byref(value), ctypes.sizeof(value)
    )
    return hr == 0 and bool(value.value)


def _find_remote_module_base(pid: int, module_name: str):
    """Base address of `module_name` inside the process `pid`, or None."""
    snapshot = k32.CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid)
    if not snapshot or snapshot == INVALID_HANDLE_VALUE:
        return None
    try:
        entry = MODULEENTRY32W()
        entry.dwSize = ctypes.sizeof(MODULEENTRY32W)
        has_more = k32.Module32FirstW(snapshot, ctypes.byref(entry))
        while has_more:
            if entry.szModule.lower() == module_name.lower():
                return entry.modBaseAddr
            has_more = k32.Module32NextW(snapshot, ctypes.byref(entry))
    finally:
        k32.CloseHandle(snapshot)
    return None


class WindowCaptureHider:
    WDA_NONE = 0x00000000
    WDA_MONITOR = 0x00000001
    WDA_EXCLUDEFROMCAPTURE = 0x00000011

    @classmethod
    def get_window_affinity(cls, hwnd: int):
        """Returns the window's current display affinity, or None on failure."""
        affinity = wintypes.DWORD(0)
        if u32.GetWindowDisplayAffinity(hwnd, ctypes.byref(affinity)):
            return affinity.value
        return None

    @classmethod
    def set_window_hidden(cls, hwnd: int, hidden: bool = True):
        target_pid = wintypes.DWORD()
        u32.GetWindowThreadProcessId(hwnd, ctypes.byref(target_pid))
        target_pid = target_pid.value

        current_pid = os.getpid()

        if target_pid == current_pid:
            affinity = cls.WDA_EXCLUDEFROMCAPTURE if hidden else cls.WDA_NONE
            res = u32.SetWindowDisplayAffinity(hwnd, affinity)
            if res:
                return True, "Current process, successfully set."
            return False, f"Direct call failed (Error Code: {ctypes.get_last_error()})"

        else:
            return cls._inject_to_remote_process(hwnd, target_pid, hidden)

    @classmethod
    def _remote_user32_address(cls, target_pid: int, func_name: bytes):
        """Address of `func_name` inside the target's own user32.dll.

        System DLLs usually share one base address across processes, but
        that assumption breaks under Exploit Protection's force-randomized
        ASLR, where jumping to the local address would crash the target.
        The real base is read from the target's module list instead; the
        export offset (identical for the same DLL image) is added to it.
        """
        local_base = k32.GetModuleHandleW("user32.dll")
        local_addr = k32.GetProcAddress(local_base, func_name)
        if not local_base or not local_addr:
            return None
        remote_base = _find_remote_module_base(target_pid, "user32.dll")
        base = remote_base if remote_base else local_base
        return base + (local_addr - local_base)

    @classmethod
    def _inject_to_remote_process(cls, hwnd: int, target_pid: int, hidden: bool):
        if platform.architecture()[0] != "64bit":
            return False, "Cross-process hiding requires a 64-bit Python interpreter."

        PROCESS_ALL_ACCESS = 0x001F0FFF
        hProcess = k32.OpenProcess(PROCESS_ALL_ACCESS, False, target_pid)
        if not hProcess:
            err = ctypes.get_last_error()
            if err == 5:
                return False, "Access Denied. Please run as Administrator."
            return False, f"OpenProcess failed (Code: {err})"

        try:
            is_wow64 = wintypes.BOOL(False)
            k32.IsWow64Process(hProcess, ctypes.byref(is_wow64))
            if is_wow64.value:
                return False, "Cross-process hiding for 32-bit apps is not supported."

            func_addr = cls._remote_user32_address(
                target_pid, b"SetWindowDisplayAffinity"
            )
            if not func_addr:
                return False, "Cannot locate API function address."

            affinity = cls.WDA_EXCLUDEFROMCAPTURE if hidden else cls.WDA_NONE
            shellcode = bytearray()
            shellcode.extend(b"\x48\xB9" + struct.pack("<Q", hwnd))
            shellcode.extend(b"\x48\xBA" + struct.pack("<Q", affinity))
            shellcode.extend(b"\x48\xB8" + struct.pack("<Q", func_addr))
            shellcode.extend(b"\x48\x83\xEC\x28")
            shellcode.extend(b"\xFF\xD0")
            shellcode.extend(b"\x48\x83\xC4\x28")
            shellcode.extend(b"\xC3")

            MEM_COMMIT = 0x1000
            MEM_RESERVE = 0x2000
            PAGE_EXECUTE_READWRITE = 0x40
            alloc_addr = k32.VirtualAllocEx(hProcess, 0, len(shellcode), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE)
            if not alloc_addr:
                return False, f"VirtualAllocEx failed (Code: {ctypes.get_last_error()})"

            written = ctypes.c_size_t(0)
            shellcode_buffer = (ctypes.c_char * len(shellcode)).from_buffer(shellcode)
            res = k32.WriteProcessMemory(hProcess, alloc_addr, shellcode_buffer, len(shellcode), ctypes.byref(written))
            if not res:
                err = ctypes.get_last_error()
                k32.VirtualFreeEx(hProcess, alloc_addr, 0, MEM_RELEASE)
                return False, f"WriteProcessMemory failed (Code: {err})"

            hThread = k32.CreateRemoteThread(hProcess, None, 0, alloc_addr, None, 0, None)
            if not hThread:
                err = ctypes.get_last_error()
                k32.VirtualFreeEx(hProcess, alloc_addr, 0, MEM_RELEASE)
                return False, f"CreateRemoteThread blocked (Code: {err}). Antivirus interception?"

            wait = k32.WaitForSingleObject(hThread, 2000)
            exit_code = wintypes.DWORD(0)
            k32.GetExitCodeThread(hThread, ctypes.byref(exit_code))
            k32.CloseHandle(hThread)

            if wait != WAIT_OBJECT_0:
                # The thread may still be executing the shellcode; freeing
                # the page under it would crash the target, so this one page
                # is deliberately leaked instead.
                return False, "Remote SetWindowDisplayAffinity call timed out."

            # the thread exit code is SetWindowDisplayAffinity's return value;
            # it can fail on a window caught too early after (re)launch
            ok = bool(exit_code.value)
            k32.VirtualFreeEx(hProcess, alloc_addr, 0, MEM_RELEASE)
            if not ok:
                return False, "Remote SetWindowDisplayAffinity call failed (window may not be ready yet)."
            return True, "Successfully injected and enforced via remote code."

        finally:
            k32.CloseHandle(hProcess)

    @classmethod
    def get_all_windows(cls):
        windows = []
        def enum_win_proc(hwnd, lParam):
            if u32.IsWindowVisible(hwnd):
                length = u32.GetWindowTextLengthW(hwnd)
                if length > 0:
                    class_buf = ctypes.create_unicode_buffer(64)
                    u32.GetClassNameW(hwnd, class_buf, 64)
                    if class_buf.value in SYSTEM_WINDOW_CLASSES:
                        return True
                    if _is_cloaked(hwnd):
                        return True
                    buff = ctypes.create_unicode_buffer(length + 1)
                    u32.GetWindowTextW(hwnd, buff, length + 1)
                    title = buff.value
                    if title:
                        pid = wintypes.DWORD()
                        u32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
                        exe_path = ""
                        try:
                            PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
                            hProc = k32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid.value)
                            if hProc:
                                path_buf = ctypes.create_unicode_buffer(512)
                                size = wintypes.DWORD(512)
                                if k32.QueryFullProcessImageNameW(hProc, 0, path_buf, ctypes.byref(size)):
                                    exe_path = path_buf.value
                                k32.CloseHandle(hProc)
                        except Exception:
                            pass

                        windows.append({'hwnd': hwnd, 'title': title, 'exe_path': exe_path, 'pid': pid.value})
            return True
        enum_func = EnumWindowsProc(enum_win_proc)
        u32.EnumWindows(enum_func, 0)
        return windows
