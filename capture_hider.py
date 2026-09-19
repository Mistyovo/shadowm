import ctypes
import struct
import platform
import os
from ctypes import wintypes

k32 = ctypes.windll.kernel32
u32 = ctypes.windll.user32

k32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
k32.OpenProcess.restype = wintypes.HANDLE

k32.GetModuleHandleW.argtypes = [wintypes.LPCWSTR]
k32.GetModuleHandleW.restype = wintypes.HMODULE

k32.GetProcAddress.argtypes = [wintypes.HMODULE, wintypes.LPCSTR]
k32.GetProcAddress.restype = ctypes.c_void_p

k32.VirtualAllocEx.argtypes = [wintypes.HANDLE, ctypes.c_void_p, ctypes.c_size_t, wintypes.DWORD, wintypes.DWORD]
k32.VirtualAllocEx.restype = ctypes.c_void_p

k32.WriteProcessMemory.argtypes = [wintypes.HANDLE, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
k32.WriteProcessMemory.restype = wintypes.BOOL

k32.CreateRemoteThread.argtypes = [wintypes.HANDLE, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p, ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
k32.CreateRemoteThread.restype = wintypes.HANDLE

k32.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
k32.WaitForSingleObject.restype = wintypes.DWORD

k32.CloseHandle.argtypes = [wintypes.HANDLE]
k32.CloseHandle.restype = wintypes.BOOL

k32.IsWow64Process.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.BOOL)]
k32.IsWow64Process.restype = wintypes.BOOL

try:
    k32.QueryFullProcessImageNameW.argtypes = [wintypes.HANDLE, wintypes.DWORD, wintypes.LPWSTR, ctypes.POINTER(wintypes.DWORD)]
    k32.QueryFullProcessImageNameW.restype = wintypes.BOOL
except AttributeError:
    pass

u32.GetWindowThreadProcessId.argtypes = [wintypes.HWND, ctypes.POINTER(wintypes.DWORD)]
u32.GetWindowThreadProcessId.restype = wintypes.DWORD

u32.SetWindowDisplayAffinity.argtypes = [wintypes.HWND, wintypes.DWORD]
u32.SetWindowDisplayAffinity.restype = wintypes.BOOL

EnumWindowsProc = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)


class WindowCaptureHider:
    WDA_NONE = 0x00000000
    WDA_MONITOR = 0x00000001
    WDA_EXCLUDEFROMCAPTURE = 0x00000011

    # Generic 4-argument remote-call shellcode: loads (rcx, rdx, r8, r9) from
    # a parameter block appended right after the code (RIP-relative via r11),
    # calls func and returns. See remote_call().
    _GENERIC_SHELLCODE_LEN = 37

    @classmethod
    def remote_call(cls, hwnd: int, func_name: str, rcx: int, rdx: int, r8: int = 0, r9: int = 0):
        """Injects func_name(rcx, rdx, r8, r9) into the process that owns hwnd.

        user32.dll is mapped at the same base in every process per boot
        session, so an address resolved locally is valid remotely. Used for
        calls that - unlike SetWindowDisplayAffinity - are not restricted to
        the window owner, e.g. SetLayeredWindowAttributes on the IME
        candidate window.
        """
        target_pid = wintypes.DWORD()
        u32.GetWindowThreadProcessId(hwnd, ctypes.byref(target_pid))
        target_pid = target_pid.value
        if not target_pid:
            return False, "Window does not exist."
        if target_pid == os.getpid():
            return False, "Refusing to inject into the current process."

        PROCESS_ALL_ACCESS = 0x001F0FFF
        hProcess = k32.OpenProcess(PROCESS_ALL_ACCESS, False, target_pid)
        if not hProcess:
            err = k32.GetLastError()
            if err == 5:
                return False, "Access Denied. Please run as Administrator."
            return False, f"OpenProcess failed (Code: {err})"

        try:
            is_wow64 = wintypes.BOOL(False)
            k32.IsWow64Process(hProcess, ctypes.byref(is_wow64))
            if is_wow64.value:
                return False, "Cross-process calls to 32-bit apps are not supported."

            func_addr = k32.GetProcAddress(
                k32.GetModuleHandleW("user32.dll"), func_name.encode()
            )
            if not func_addr:
                return False, f"Cannot locate API function {func_name}."

            n = cls._GENERIC_SHELLCODE_LEN
            mask = 0xFFFFFFFFFFFFFFFF
            sc = bytearray()
            sc.extend(b"\x4C\x8D\x1D" + struct.pack("<i", n - 7))  # lea r11,[rip+params]
            sc.extend(b"\x49\x8B\x4B\x08")                        # mov rcx,[r11+8]
            sc.extend(b"\x49\x8B\x53\x10")                        # mov rdx,[r11+16]
            sc.extend(b"\x4D\x8B\x43\x18")                        # mov r8,[r11+24]
            sc.extend(b"\x4D\x8B\x4B\x20")                        # mov r9,[r11+32]
            sc.extend(b"\x49\x8B\x03")                            # mov rax,[r11+0]
            sc.extend(b"\x48\x83\xEC\x28")                        # sub rsp,0x28
            sc.extend(b"\xFF\xD0")                                # call rax
            sc.extend(b"\x48\x83\xC4\x28")                        # add rsp,0x28
            sc.extend(b"\xC3")                                    # ret
            sc.extend(struct.pack(
                "<QQQQQ", func_addr, rcx & mask, rdx & mask, r8 & mask, r9 & mask
            ))

            MEM_COMMIT = 0x1000
            MEM_RESERVE = 0x2000
            PAGE_EXECUTE_READWRITE = 0x40
            alloc_addr = k32.VirtualAllocEx(hProcess, 0, len(sc), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE)
            if not alloc_addr:
                return False, f"VirtualAllocEx failed (Code: {k32.GetLastError()})"

            written = ctypes.c_size_t(0)
            sc_buffer = (ctypes.c_char * len(sc)).from_buffer(sc)
            if not k32.WriteProcessMemory(hProcess, alloc_addr, sc_buffer, len(sc), ctypes.byref(written)):
                return False, f"WriteProcessMemory failed (Code: {k32.GetLastError()})"

            hThread = k32.CreateRemoteThread(hProcess, None, 0, alloc_addr, None, 0, None)
            if not hThread:
                return False, f"CreateRemoteThread blocked (Code: {k32.GetLastError()}). Antivirus interception?"

            k32.WaitForSingleObject(hThread, 2000)
            k32.CloseHandle(hThread)
            return True, "Remote call injected."

        finally:
            k32.CloseHandle(hProcess)

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
            else:
                return False, f"Direct call failed (Error Code: {ctypes.GetLastError()})"
                
        else:
            return cls._inject_to_remote_process(hwnd, target_pid, hidden)

    @classmethod
    def _inject_to_remote_process(cls, hwnd: int, target_pid: int, hidden: bool):
        if platform.architecture()[0] != '64bit':
            return False, "Cross-process hiding requires a 64-bit Python interpreter."
            
        PROCESS_ALL_ACCESS = 0x001F0FFF
        hProcess = k32.OpenProcess(PROCESS_ALL_ACCESS, False, target_pid)
        if not hProcess:
            err = k32.GetLastError()
            if err == 5:
                return False, "Access Denied. Please run as Administrator."
            return False, f"OpenProcess failed (Code: {err})"
            
        try:
            is_wow64 = wintypes.BOOL(False)
            k32.IsWow64Process(hProcess, ctypes.byref(is_wow64))
            if is_wow64.value:
                return False, "Cross-process hiding for 32-bit apps is not supported."
                
            h_user32 = k32.GetModuleHandleW("user32.dll")
            func_addr = k32.GetProcAddress(h_user32, b"SetWindowDisplayAffinity")
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
                return False, f"VirtualAllocEx failed (Code: {k32.GetLastError()})"
                
            written = ctypes.c_size_t(0)
            shellcode_buffer = (ctypes.c_char * len(shellcode)).from_buffer(shellcode)
            res = k32.WriteProcessMemory(hProcess, alloc_addr, shellcode_buffer, len(shellcode), ctypes.byref(written))
            if not res:
                return False, f"WriteProcessMemory failed (Code: {k32.GetLastError()})"
                
            hThread = k32.CreateRemoteThread(hProcess, None, 0, alloc_addr, None, 0, None)
            if not hThread:
                return False, f"CreateRemoteThread blocked (Code: {k32.GetLastError()}). Antivirus interception?"
                
            k32.WaitForSingleObject(hThread, 2000)
            k32.CloseHandle(hThread)
            
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
                    buff = ctypes.create_unicode_buffer(length + 1)
                    u32.GetWindowTextW(hwnd, buff, length + 1)
                    title = buff.value
                    if title and title not in ("Program Manager", "Settings"):
                        exe_path = ""
                        try:
                            pid = wintypes.DWORD()
                            u32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
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
                        
                        windows.append({'hwnd': hwnd, 'title': title, 'exe_path': exe_path})
            return True
        enum_func = EnumWindowsProc(enum_win_proc)
        u32.EnumWindows(enum_func, 0)
        return windows
