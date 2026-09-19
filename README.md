# ShadowM

ShadowM is a standalone Python application built with PyQt5 that transparently hides specific application windows from screen recording software like OBS Studio, Discord screen share, and XSplit.

It uses the native Windows API (`SetWindowDisplayAffinity`) to tag windows as `WDA_EXCLUDEFROMCAPTURE`. For third-party processes, it automatically circumvents OS restrictions by utilizing cross-process x64 Shellcode and Remote Thread Injection (`VirtualAllocEx`, `CreateRemoteThread`) directly into the target application's memory.

## Features
- Real-time updating list of visible system windows
- Asynchronous application hiding with zero UI blocking/freezes
- Extracts native application `.exe` icons
- Double-click toggling
- Optional switch to auto-hide newly detected windows by default
- IME candidate protection: while typing in a hidden window, IME candidate bars (Sogou Pinyin `SoPY_*` windows, classic IME hosts) are excluded from capture too
- Per-window on-screen opacity: make any listed window translucent locally while it stays excluded from capture
- Exit confirmation dialog (itself excluded from capture) to prevent accidental closure
- Remembered hidden windows: applications closed while hidden are re-hidden automatically on next launch
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
Hiding an application window does not hide the IME candidate bar floating above it, so ShadowM protects it separately while the "Also hide the IME candidate box" option is enabled and the foreground window is one ShadowM has hidden:

- **Sogou Pinyin (recommended)**: Sogou renders its UI (composition/candidate bar `SoPY_Comp`, status bar `SoPY_Status`, ...) as normal top-level windows *inside the application you type into*. ShadowM tracks them system-wide, pre-arms them via `SetWinEventHook` the moment they appear, and tags them `WDA_EXCLUDEFROMCAPTURE` through the usual remote-thread injection. They stay fully visible on your own screen but never appear in screenshots or recordings (verified against GDI BitBlt and DXGI desktop duplication), and are restored automatically when focus returns to a normal window.
- Classic out-of-process IME hosts (`ChsIME.exe`, `ctfmon.exe`) are tagged the same way as a best effort.
- **Microsoft Pinyin (modern Windows 11 UI)**: not supported. Its candidate box is a DirectComposition CoreWindow child of an explorer-hosted frame that completely ignores `SetWindowDisplayAffinity` (verified on Win11 24H2+); no per-window mechanism can exclude it from capture while keeping it on screen.

Notes:
- Requires the same privileges as regular window hiding (Administrator, 64-bit).
- In-process IME windows are caught by hooks installed on each hidden window's own process, so protection follows whichever app you are typing into.
- If ShadowM is killed abruptly while typing in a hidden window, an armed candidate window can stay excluded from capture. Start ShadowM again - it restores leftover state on launch - or toggle the IME checkbox off and back on.

## Remembered Hidden Windows
When a window you explicitly hid is closed, ShadowM remembers its application (identified by the executable path) in `remembered_hidden.json`. The next time that application opens a window, ShadowM hides it from capture automatically - you do not have to check it again.

- Only windows *you* checked are remembered; windows hidden merely by the global "hide newly detected windows" toggle are not, so flipping that toggle leaves no lasting rules.
- Unchecking a remembered window removes its rule ("unhide" means "stop remembering").
- Rules are per application: if an executable shows several windows, every new window of it is hidden. `remembered_hidden.json` can be edited by hand to clear rules.

## Window Opacity
The "Opacity" slider adjusts how transparent the selected window looks **on your screen** via `WS_EX_LAYERED` + `SetLayeredWindowAttributes` (these calls work on other processes' windows directly, no injection needed).

It is purely a local visual effect and independent of capture exclusion:

- A window excluded from capture stays excluded no matter how translucent you make it - recordings keep showing the excluded (black/empty) region.
- A window that is *not* excluded will simply show up translucent in recordings, since captures reflect what the screen looks like.

Moving the slider back to 100% fully restores the window (the layered style is removed again; windows that were already layered before only get their alpha reset). All opacities are restored automatically when ShadowM exits normally.

## Disclaimer
This tool uses techniques typically employed by debugging and reverse engineering software (Read/Write Process Memory). Some aggressive Antivirus solutions might falsely flag the `CreateRemoteThread` action.