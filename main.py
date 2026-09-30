import ctypes
import logging
import logging.handlers
import os
import sys
from ctypes import wintypes

from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import QApplication, QMessageBox

from capture_hider import k32
from ui import WindowHiderUI, CaptureSafeMessageBox

MUTEX_NAME = "ShadowM.SingleInstance"
ERROR_ALREADY_EXISTS = 183

k32.CreateMutexW.argtypes = [ctypes.c_void_p, wintypes.BOOL, wintypes.LPCWSTR]
k32.CreateMutexW.restype = wintypes.HANDLE

logger = logging.getLogger("shadowm")


def acquire_single_instance_mutex(name: str = MUTEX_NAME):
    """Returns the mutex handle, or None if another instance owns it."""
    handle = k32.CreateMutexW(None, False, name)
    if not handle:
        return None
    if ctypes.get_last_error() == ERROR_ALREADY_EXISTS:
        k32.CloseHandle(handle)
        return None
    return handle


def is_admin() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def setup_logging():
    """Logs lifecycle events to shadowm.log next to the script (exe names
    only - window titles are never written, they can be private)."""
    logger.setLevel(logging.INFO)
    logger.propagate = False
    log_path = os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "shadowm.log"
    )
    try:
        handler = logging.handlers.RotatingFileHandler(
            log_path, maxBytes=256 * 1024, backupCount=1, encoding="utf-8"
        )
    except OSError:
        return
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
    logger.addHandler(handler)


def _warn_box(text: str, informative: str = ""):
    """Startup warning that is itself excluded from screen capture."""
    box = CaptureSafeMessageBox()
    box.setWindowTitle("ShadowM")
    box.setIcon(QMessageBox.Warning)
    box.setText(text)
    if informative:
        box.setInformativeText(informative)
    box.setStandardButtons(QMessageBox.Ok)
    box.exec_()


def main():
    setup_logging()
    # must be set before QApplication is constructed
    QApplication.setAttribute(Qt.AA_EnableHighDpiScaling, True)
    QApplication.setAttribute(Qt.AA_UseHighDpiPixmaps, True)
    app = QApplication(sys.argv)

    mutex = acquire_single_instance_mutex()
    if mutex is None:
        logger.warning("already running: second instance rejected")
        _warn_box(
            "ShadowM is already running.",
            "Only one instance can manage window protection - please use "
            "the existing window.",
        )
        return 1

    logger.info("started pid=%d admin=%s", os.getpid(), is_admin())
    if not is_admin():
        _warn_box(
            "ShadowM is not running as Administrator.",
            "Cross-process capture hiding needs administrator rights; "
            "taskbar/Alt-Tab hiding and opacity work without them. "
            "Restart ShadowM elevated to enable everything.",
        )

    window = WindowHiderUI()
    window.show()
    rc = app.exec_()
    logger.info("exited rc=%d", rc)
    return rc


if __name__ == "__main__":
    sys.exit(main())
