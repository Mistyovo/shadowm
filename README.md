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
- Taskbar / Alt-Tab hiding: right-click any listed window to strip it from the taskbar and the Alt-Tab / Task View switcher (independent of capture hiding)
- Global hotkey `Ctrl+Alt+T`: toggle taskbar/Alt-Tab hiding for all marked windows at once
- "Show window" menu action: un-minimize and focus any listed window, including taskbar-hidden ones the system UI can no longer reach
- Exit confirmation dialog (itself excluded from capture) to prevent accidental closure
- Remembered hidden windows: applications closed while hidden are re-hidden automatically on next launch
- Clean exit restores *everything* (capture exclusion, taskbar styles, opacity, IME protection)
- Crash self-healing: state left on windows by a killed ShadowM is restored automatically on the next launch
- Single instance guard, administrator pre-check and a persistent hotkey-conflict notice
- Pure memory bypass (no DLLs written to disk)

## Requirements
To successfully inject code into third-party windows, the following strict conditions apply:
1. **64-bit Python Environment**: The payload relies on hardcoded x64 assembly and Windows APIs. A 32-bit Python interpreter will crash or fail.
2. **Administrator Privileges**: You must run the application as an Administrator. `OpenProcess` requires `PROCESS_ALL_ACCESS` rights to foreign binaries. ShadowM warns at startup when it is not elevated.
3. Only hides 64-bit target applications (cross-architecture hiding to 32-bit targets is blocked by WOW64 restrictions).

## Installation
Ensure you have a 64-bit Python 3 installation.
```sh
pip install -r requirements.txt
```

## Usage
Simply run `main.py` with Administrator privileges:
```sh
python main.py
```
> Note: For completely silent execution without a console window, use `pythonw.exe main.py` instead.

Toggle the checkbox next to any window to make it immediately invisible to OBS capture.

Notes:
- Only one ShadowM instance may run at a time; a second launch tells you and exits.
- Lifecycle events (hide/restore results, crash healing) are written to `shadowm.log` next to the script. Only executable names are logged, never window titles.

## Exit Behavior and Crash Recovery
On a normal exit (after the confirmation dialog) ShadowM undoes every change it made: capture exclusion, taskbar/Alt-Tab styles, opacity and IME candidate protection. Windows hidden but no longer listed (e.g. minimized to the tray) are restored too.

If ShadowM is killed abruptly, it cannot restore anything itself - so it records everything it changed in `shadowm_session.json` (next to the script) as it goes. The next launch checks that file, verifies each recorded window is still alive with the same process id, and restores its original state automatically. A boot marker makes entries from before a reboot untrusted, since window handles never survive a restart.

## IME Candidate Protection
Hiding an application window does not hide the IME candidate bar floating above it, so ShadowM protects it separately while the "Also hide the IME candidate box" option is enabled and the foreground window is one ShadowM has hidden:

- **Sogou Pinyin (recommended)**: Sogou renders its UI (composition/candidate bar `SoPY_Comp`, status bar `SoPY_Status`, ...) as normal top-level windows *inside the application you type into*. ShadowM tracks them system-wide, pre-arms them via `SetWinEventHook` the moment they appear, and tags them `WDA_EXCLUDEFROMCAPTURE` through the usual remote-thread injection. They stay fully visible on your own screen but never appear in screenshots or recordings (verified against GDI BitBlt and DXGI desktop duplication), and are restored automatically when focus returns to a normal window.
- Classic out-of-process IME hosts (`ChsIME.exe`, `ctfmon.exe`) are tagged the same way as a best effort.
- **Microsoft Pinyin (modern Windows 11 UI)**: not supported. Its candidate box is a DirectComposition CoreWindow child of an explorer-hosted frame that completely ignores `SetWindowDisplayAffinity` (verified on Win11 24H2+); no per-window mechanism can exclude it from capture while keeping it on screen.

Notes:
- Requires the same privileges as regular window hiding (Administrator, 64-bit).
- In-process IME windows are caught by hooks installed on each hidden window's own process, so protection follows whichever app you are typing into.
- Candidate windows armed when ShadowM was killed are restored by the startup heal described above; toggling the IME checkbox off and back on works too.

## Remembered Hidden Windows
When a window you explicitly hid is closed, ShadowM remembers its application (identified by the executable path) in `remembered_hidden.json`. The next time that application opens a window, ShadowM hides it from capture automatically - you do not have to check it again.

- Only windows *you* checked are remembered; windows hidden merely by the global "hide newly detected windows" toggle are not, so flipping that toggle leaves no lasting rules.
- Unchecking a remembered window removes its rule ("unhide" means "stop remembering").
- Rules are per application: if an executable shows several windows, every new window of it is hidden. `remembered_hidden.json` can be edited by hand to clear rules.
- A window that briefly disappears from the desktop (blanked title, suspended UWP frame) is not treated as closed: removal waits for a second consecutive miss, and windows merely minimized to the tray keep their styles and group membership while they are gone.

## Window Opacity
The "Opacity" slider adjusts how transparent the selected window looks **on your screen** via `WS_EX_LAYERED` + `SetLayeredWindowAttributes` (these calls work on other processes' windows directly, no injection needed).

It is purely a local visual effect and independent of capture exclusion:

- A window excluded from capture stays excluded no matter how translucent you make it - recordings keep showing the excluded (black/empty) region.
- A window that is *not* excluded will simply show up translucent in recordings, since captures reflect what the screen looks like.

Moving the slider back to 100% fully restores the window: the layered style is removed again, and windows that were already translucent before ShadowM touched them get their own original alpha back. All opacities are restored automatically when ShadowM exits normally (and healed on the next launch after a crash).

## Taskbar / Alt-Tab Hiding
Right-click any window in the list and toggle "Hide from taskbar and Alt-Tab" to remove it from the taskbar, Alt-Tab and Task View while it stays fully usable on screen. Marked windows carry a ` [taskbar hidden]` suffix while the hiding is actually active.

This flips the window's extended style bits (`WS_EX_APPWINDOW` removed, `WS_EX_TOOLWINDOW` added) via `SetWindowLongPtrW` + `SetWindowPos(SWP_FRAMECHANGED)`. Like the opacity feature these calls work on other processes' windows directly, without injection - so this also works for 32-bit windows the capture path cannot reach, and it does not require Administrator privileges on its own.

Once windows are marked, the global hotkey `Ctrl+Alt+T` flips the whole group at once: if any marked window is currently back in the taskbar, all of them get hidden; pressing it again brings them all back. Marking (right-click) is group membership, the suffix shows the live state, and unchecking via right-click removes a window from the group. If another application already owns `Ctrl+Alt+T`, ShadowM shows a permanent notice under the status line; the key can be changed via the constants in `TaskbarHider` (`taskbar_hider.py`).

The same right-click menu also offers "Show window" (`ShowWindow(SW_RESTORE)` + `SetForegroundWindow`, no injection): it un-minimizes the window and brings it to the foreground. This is the way back for a taskbar-hidden window that got minimized - with no taskbar button and no Alt-Tab entry there is no system UI left to restore it, and `Win+D` only un-minimizes windows it minimized itself.

Notes:
- Independent of capture exclusion: a taskbar-hidden window still appears in recordings unless its capture checkbox is ticked as well.
- The exact original style is remembered and restored when you toggle back, when the window closes, and on normal ShadowM exit; crash leftovers are healed on the next launch from the session file.
- A window that is a tool window *by design* (floating panels some apps create) is adopted as-is when you explicitly toggle it: restoring it afterwards assumes the tool-window style was ours and surfaces the window in the taskbar.

## Development
```sh
pip install -r requirements.txt
python -m unittest discover -s tests -v
```
The test suite covers the pure logic (session state, remembered rules helpers, single-instance mutex) and exercises the Win32 roundtrips (capture affinity, taskbar styles, layered opacity) against real windows created by the test process.

## Disclaimer
This tool uses techniques typically employed by debugging and reverse engineering software (Read/Write Process Memory). Some aggressive Antivirus solutions might falsely flag the `CreateRemoteThread` action.

## License
Released under the [MIT License](LICENSE).
