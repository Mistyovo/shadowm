# ShadowM

ShadowM is a standalone Python application built with PyQt5 that transparently hides specific application windows from screen recording software like OBS Studio, Discord screen share, and XSplit.

It uses the native Windows API (`SetWindowDisplayAffinity`) to tag windows as `WDA_EXCLUDEFROMCAPTURE`. For third-party processes, it automatically circumvents OS restrictions by utilizing cross-process x64 Shellcode and Remote Thread Injection (`VirtualAllocEx`, `CreateRemoteThread`) directly into the target application's memory.

## Features
- Real-time updating list of visible system windows
- Asynchronous application hiding with zero UI blocking/freezes
- Extracts native application `.exe` icons
- Double-click toggling
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

## Disclaimer
This tool uses techniques typically employed by debugging and reverse engineering software (Read/Write Process Memory). Some aggressive Antivirus solutions might falsely flag the `CreateRemoteThread` action.