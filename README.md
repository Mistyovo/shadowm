# ShadowM

ShadowM is a standalone Python application built with PyQt5 that transparently hides specific application windows from screen recording software like OBS Studio, Discord screen share, and XSplit.

It uses the native Windows API (`SetWindowDisplayAffinity`) to tag windows as `WDA_EXCLUDEFROMCAPTURE`. For third-party processes, it automatically circumvents OS restrictions by utilizing cross-process x64 Shellcode and Remote Thread Injection (`VirtualAllocEx`, `CreateRemoteThread`) directly into the target application's memory.

## Features
- Real-time updating list of visible system windows
- Asynchronous application hiding with zero UI blocking/freezes
- Extracts native application `.exe` icons
- Double-click toggling
- Optional switch to auto-hide newly detected windows by default
- IME candidate protection: while typing pinyin in a hidden window with the built-in Microsoft IME, the candidate box is excluded from capture too
- Pure memory bypass (no DLLs written to disk)

## Requirements
To successfully inject code into third-party windows, the following strict conditions apply:
1. **64-bit Python Environment**: The payload relies on hardcoded x64 assembly and Windows APIs. A 32-bit Python interpreter will crash or fail.
2. **Administrator Privileges**: You must run the application as an Administrator. `OpenProcess` requires `PROCESS_ALL_ACCESS` rights to foreign binaries.
3. Only hides 64-bit target applications (cross-architecture hiding to 32-bit targets is blocked by WOW64 restrictions).

## Installation
Ensure you have a 64-bit Python 3 installation.
```sh
pip install PyQt5
```

## Usage
Simply run `main.py` with Administrator privileges:
```sh
python main.py
```
> Note: For completely silent execution without a console window, use `pythonw.exe main.py` instead.

Toggle the checkbox next to any window to make it immediately invisible to OBS capture.

## IME Candidate Protection
The pinyin candidate box of the Windows built-in IME is not rendered by the application you type into - it belongs to a separate system input process (`TextInputHost.exe` on Windows 10 1903+/Windows 11, `ChsIME.exe` on older builds). Hiding an application window alone therefore leaves the candidate box visible to screen capture.

When the "Also hide the IME candidate box" option is enabled, ShadowM tracks the foreground window:

- The moment focus enters a window hidden by ShadowM, every top-level window of the input host process is tagged `WDA_EXCLUDEFROMCAPTURE` via the same remote-thread injection used for normal windows.
- `SetWinEventHook` listeners arm any window the input host creates or shows afterwards (e.g. a freshly created candidate popup) within milliseconds.
- When focus returns to a normal window, the IME windows are restored to `WDA_NONE`, so candidates show up in captures again.

Notes:
- Requires the same privileges as regular window hiding (Administrator, 64-bit).
- Only the built-in Microsoft input experience is covered; third-party IMEs (Sogou, Baidu, ...) draw their candidate windows from their own processes and are not targeted.
- If ShadowM is killed abruptly while typing in a hidden window, the IME windows can stay excluded from capture. Simply start ShadowM again - it restores leftover state on launch - or toggle the IME checkbox off and back on.

## Disclaimer
This tool uses techniques typically employed by debugging and reverse engineering software (Read/Write Process Memory). Some aggressive Antivirus solutions might falsely flag the `CreateRemoteThread` action.