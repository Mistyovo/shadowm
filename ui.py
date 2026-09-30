import json
import logging
import os
import time
from ctypes import wintypes
from PyQt5.QtWidgets import (
    QWidget,
    QVBoxLayout,
    QHBoxLayout,
    QCheckBox,
    QLabel,
    QListWidget,
    QListWidgetItem,
    QMenu,
    QMessageBox,
    QSlider,
    QFileIconProvider,
)
from PyQt5.QtCore import Qt, QTimer, QThread, pyqtSignal, QFileInfo
from capture_hider import WindowCaptureHider
from ime_hider import ImeGuard
from session_state import SessionState
from taskbar_hider import TaskbarHider
from window_opacity import WindowOpacity

logger = logging.getLogger("shadowm")

TASKBAR_SUFFIX = "  [taskbar hidden]"

# QListWidgetItem data roles
HwndRole = Qt.UserRole               # window handle
ExeRole = Qt.UserRole + 1            # owning executable path
ExplicitRole = Qt.UserRole + 2       # hidden by the user explicitly
PidRole = Qt.UserRole + 3            # pid at discovery time
TaskbarMemberRole = Qt.UserRole + 4  # taskbar-hide group membership
MissRole = Qt.UserRole + 5           # consecutive refreshes missed


def _strip_taskbar_suffix(text: str) -> str:
    return text[: -len(TASKBAR_SUFFIX)] if text.endswith(TASKBAR_SUFFIX) else text


class HideWorker(QThread):
    finished = pyqtSignal(object, bool, bool, str)

    def __init__(self, hwnd, is_checked, auto=False):
        super().__init__()
        self.hwnd = hwnd
        self.is_checked = is_checked
        self.auto = auto

    def run(self):
        success, msg = WindowCaptureHider.set_window_hidden(
            self.hwnd, hidden=self.is_checked
        )
        self.finished.emit(self.hwnd, self.is_checked, success, msg)


class CaptureSafeMessageBox(QMessageBox):
    """Message box that is itself excluded from screen capture.

    The affinity is set synchronously in showEvent, i.e. before the dialog
    paints its first frame, so it never leaks into a capture.
    """

    def showEvent(self, event):
        super().showEvent(event)
        WindowCaptureHider.set_window_hidden(int(self.winId()), True)


class CaptureSafeMenu(QMenu):
    """Context menu that is itself excluded from screen capture."""

    def showEvent(self, event):
        super().showEvent(event)
        WindowCaptureHider.set_window_hidden(int(self.winId()), True)


class WindowHiderUI(QWidget):
    def __init__(self):
        super().__init__()
        self._is_updating = False
        self._is_syncing_opacity = False
        self.workers = {}
        self._hide_failures = {}
        self._max_hide_failures = 3
        self.icon_provider = QFileIconProvider()

        base_dir = os.path.dirname(os.path.abspath(__file__))
        self._remembered_file = os.path.join(base_dir, "remembered_hidden.json")
        self._remembered = self._load_remembered()

        # crash recovery: whatever a previous run left on windows is undone
        # here, before any new hiding happens
        self.session = SessionState(os.path.join(base_dir, "shadowm_session.json"))
        TaskbarHider.set_session(self.session)
        WindowOpacity.set_session(self.session)
        self._heal_session_leftovers()

        self.ime_guard = ImeGuard(self)
        self.ime_guard.active_changed.connect(self.on_ime_guard_active)
        self.ime_guard.error_occurred.connect(self.on_ime_guard_error)

        self._init_window()
        self._setup_ui()
        self._register_hotkeys()
        self._setup_timer()

    # ---- remembered hidden windows -----------------------------------------

    def _load_remembered(self) -> dict:
        """Loads the exe paths of windows that were hidden when closed."""
        try:
            with open(self._remembered_file, "r", encoding="utf-8") as f:
                data = json.load(f)
            if isinstance(data, dict):
                return data
        except (OSError, ValueError):
            pass
        return {}

    def _save_remembered(self):
        try:
            with open(self._remembered_file, "w", encoding="utf-8") as f:
                json.dump(self._remembered, f, ensure_ascii=False, indent=2)
        except OSError:
            pass

    def _remember_window(self, exe_path, title):
        """Records an application so its windows auto-hide on next launch."""
        if not exe_path:
            return
        self._remembered[exe_path] = {"title": title, "ts": time.time()}
        self._save_remembered()

    def _forget_window(self, exe_path):
        """Drops the auto-hide rule (user unchecked a remembered window)."""
        if exe_path and exe_path in self._remembered:
            del self._remembered[exe_path]
            self._save_remembered()

    # ---- crash recovery ------------------------------------------------------

    def _heal_session_leftovers(self):
        """Restores state a crashed previous run left on windows.

        Entries whose window is still alive with the recorded pid get their
        original style, affinity and opacity back; entries for dead windows
        or stale boots are dropped silently.
        """
        healed = failed = 0

        def alive_with_pid(hwnd, pid):
            return (
                TaskbarHider.is_window(hwnd)
                and pid is not None
                and WindowCaptureHider.get_window_pid(hwnd) == pid
            )

        for hwnd, info in self.session.taskbar_items():
            if alive_with_pid(hwnd, info.get("pid")):
                ok, _ = TaskbarHider.recover_leftover(
                    hwnd, info.get("exstyle", 0)
                )
                if ok:
                    healed += 1
                else:
                    failed += 1
        for hwnd, info in self.session.opacity_items():
            if alive_with_pid(hwnd, info.get("pid")):
                ok, _ = WindowOpacity.recover_leftover(
                    hwnd,
                    bool(info.get("added_layered")),
                    info.get("original_alpha"),
                )
                if ok:
                    healed += 1
                else:
                    failed += 1
        for hwnd, info in self.session.capture_items():
            if alive_with_pid(hwnd, info.get("pid")):
                ok, _ = WindowCaptureHider.set_window_hidden(hwnd, False)
                if ok:
                    healed += 1
                else:
                    failed += 1
        if healed or failed:
            logger.info(
                "startup heal: restored %d leftover window(s), %d failed",
                healed,
                failed,
            )
        self.session.clear_all()
        self.session.delete()

    def _init_window(self):
        self.setWindowTitle("ShadowM - Screen Capture Hider")
        self.resize(400, 300)

    def _setup_ui(self):
        layout = QVBoxLayout(self)
        self.auto_hide_checkbox = QCheckBox("Hide newly detected windows by default")
        self.auto_hide_checkbox.setToolTip(
            "When checked, every window that appears in the list below is "
            "automatically hidden from screen capture."
        )
        layout.addWidget(self.auto_hide_checkbox)

        self.ime_guard_checkbox = QCheckBox(
            "Also hide the IME candidate box while typing in hidden windows"
        )
        self.ime_guard_checkbox.setChecked(True)
        self.ime_guard_checkbox.setToolTip(
            "While the focused window is hidden, the IME candidate windows "
            "(e.g. Sogou Pinyin's SoPY_* bars, rendered by the application "
            "you type into) are also excluded from screen capture. They stay "
            "fully visible on your own screen and are restored when focus "
            "returns to a normal window."
        )
        self.ime_guard_checkbox.toggled.connect(self.ime_guard.set_enabled)
        layout.addWidget(self.ime_guard_checkbox)

        layout.addWidget(
            QLabel(
                "Check the windows below to hide them from screen capture "
                "(right-click one for taskbar / Alt-Tab options):"
            )
        )

        self.list_widget = QListWidget()
        self.list_widget.itemChanged.connect(self.on_item_changed)
        self.list_widget.itemDoubleClicked.connect(self.on_item_double_clicked)
        self.list_widget.currentItemChanged.connect(self.on_current_item_changed)
        self.list_widget.setContextMenuPolicy(Qt.CustomContextMenu)
        self.list_widget.customContextMenuRequested.connect(
            self.on_list_context_menu
        )
        layout.addWidget(self.list_widget)

        opacity_row = QHBoxLayout()
        opacity_row.addWidget(QLabel("Opacity:"))
        self.opacity_slider = QSlider(Qt.Horizontal)
        self.opacity_slider.setRange(1, 100)
        self.opacity_slider.setValue(100)
        self.opacity_slider.setEnabled(False)
        self.opacity_slider.setToolTip(
            "On-screen transparency (1%-100%) of the selected window. This "
            "is a local visual effect only - whether the window is excluded "
            "from capture is controlled by its checkbox above."
        )
        self.opacity_slider.valueChanged.connect(self.on_opacity_changed)
        opacity_row.addWidget(self.opacity_slider)
        self.opacity_value_label = QLabel("100%")
        opacity_row.addWidget(self.opacity_value_label)
        layout.addLayout(opacity_row)

        # persistent (never overwritten) so the user cannot miss it
        self.hotkey_warning_label = QLabel("")
        self.hotkey_warning_label.setWordWrap(True)
        self.hotkey_warning_label.setStyleSheet("color: #b34040;")
        layout.addWidget(self.hotkey_warning_label)

        self.status_label = QLabel("")
        self.status_label.setWordWrap(True)
        layout.addWidget(self.status_label)

    def _setup_timer(self):
        self.timer = QTimer(self)
        self.timer.timeout.connect(self.update_window_list)
        self.timer.timeout.connect(self.ime_guard.refresh)
        self.timer.timeout.connect(TaskbarHider.reconcile)
        self.ime_guard.refresh()
        self.update_window_list()
        self.timer.start(1500)

    def _register_hotkeys(self):
        """Registers the global hotkeys; reports conflicts persistently."""
        self._hotkey_registered = TaskbarHider.register_hotkey(
            int(self.winId()),
            TaskbarHider.HOTKEY_TOGGLE_ALL,
            TaskbarHider.MOD_CONTROL | TaskbarHider.MOD_ALT,
            TaskbarHider.VK_T,
        )
        if not self._hotkey_registered:
            self.hotkey_warning_label.setText(
                "Ctrl+Alt+T is already taken by another application - the "
                "taskbar hotkey is disabled until it is freed."
            )
            logger.warning("Ctrl+Alt+T registration failed (already taken)")

    def nativeEvent(self, eventType, message):
        """Dispatches WM_HOTKEY messages from the global hotkeys."""
        if eventType == b"windows_generic_MSG":
            msg = wintypes.MSG.from_address(int(message))
            if (
                msg.message == TaskbarHider.WM_HOTKEY
                and msg.wParam == TaskbarHider.HOTKEY_TOGGLE_ALL
            ):
                self._toggle_all_taskbar_hidden()
                return True, 0
        return super().nativeEvent(eventType, message)

    def showEvent(self, event):
        super().showEvent(event)
        own_hwnd = int(self.winId())
        WindowCaptureHider.set_window_hidden(own_hwnd, True)
        self.ime_guard.note_window_state(own_hwnd, True, True)
        self.update_window_list()

    def update_window_list(self):
        """Synchronizes the current UI list with actual visible system windows."""
        current_windows = WindowCaptureHider.get_all_windows()
        current_hwnds = {win["hwnd"]: win for win in current_windows}

        self._is_updating = True
        self._remove_stale_or_update_existing_items(current_hwnds)
        self._add_new_items(current_hwnds)
        self._is_updating = False
        self._reconcile_hidden_state()

    def _reconcile_hidden_state(self):
        """Re-applies hiding to checked windows that lost their affinity.

        The display affinity silently drops when an app recreates its window
        (e.g. after close/reopen, possibly reusing the same hwnd value), so
        the real state is verified on every tick instead of trusting the
        checkbox.
        """
        for i in range(self.list_widget.count()):
            item = self.list_widget.item(i)
            hwnd = item.data(HwndRole)
            if item.checkState() != Qt.Checked or hwnd in self.workers:
                continue
            if not WindowCaptureHider.window_exists(hwnd):
                continue
            if self._hide_failures.get(hwnd, 0) >= self._max_hide_failures:
                continue
            affinity = WindowCaptureHider.get_window_affinity(hwnd)
            if affinity == WindowCaptureHider.WDA_EXCLUDEFROMCAPTURE:
                continue
            self._start_hide_worker(hwnd, True, auto=True)

    def _remove_stale_or_update_existing_items(self, current_hwnds: dict):
        """Removes closed windows from UI and updates titles of existing ones.

        A window missing from a single refresh is not treated as closed yet:
        titles can blank out for a moment and tray apps hide their windows
        entirely, so removal (and its bookkeeping) waits for a second
        consecutive miss.
        """
        for i in range(self.list_widget.count() - 1, -1, -1):
            item = self.list_widget.item(i)
            hwnd = item.data(HwndRole)
            known_pid = item.data(PidRole)

            # Windows reuses hwnd values: a same-hwnd window with a different
            # pid is a new window that must go through new-window handling
            same_window = hwnd in current_hwnds and (
                known_pid is None or known_pid == current_hwnds[hwnd]["pid"]
            )

            if not same_window:
                misses = (item.data(MissRole) or 0) + 1
                item.setData(MissRole, misses)
                if misses < 2:
                    continue  # enumeration flicker: re-check next refresh
                if (
                    item.checkState() == Qt.Checked
                    and hwnd != int(self.winId())
                    and item.data(ExplicitRole)
                ):
                    # closed while the user had it hidden: remember for relaunch
                    self._remember_window(
                        item.data(ExeRole),
                        _strip_taskbar_suffix(item.text()),
                    )
                self.list_widget.takeItem(i)
                if not WindowCaptureHider.window_exists(hwnd):
                    # truly gone: drop our bookkeeping for good
                    WindowOpacity.restore(hwnd)
                    TaskbarHider.forget(hwnd)
                # still alive (e.g. minimized to the tray): keep styles and
                # tracking; TaskbarHider.reconcile keeps enforcing them
                self.ime_guard.forget(hwnd)
                self._hide_failures.pop(hwnd, None)
            else:
                item.setData(MissRole, 0)
                expected_text = current_hwnds[hwnd]["title"]
                if item.data(TaskbarMemberRole) and TaskbarHider.is_hidden(hwnd):
                    expected_text += TASKBAR_SUFFIX
                if item.text() != expected_text:
                    item.setText(expected_text)
                del current_hwnds[hwnd]

    def _add_new_items(self, new_hwnds: dict):
        """Creates new list items for recently discovered windows."""
        hide_by_default = self.auto_hide_checkbox.isChecked()
        for hwnd, win_info in new_hwnds.items():
            item = QListWidgetItem(win_info["title"])
            item.setFlags(item.flags() | Qt.ItemIsUserCheckable)

            exe_path = win_info.get("exe_path", "")
            if hwnd == int(self.winId()):
                item.setCheckState(Qt.Checked)
                WindowCaptureHider.set_window_hidden(hwnd, True)
                self.ime_guard.note_window_state(hwnd, True, True)
            elif exe_path and exe_path in self._remembered:
                # this application was hidden when it was last closed
                item.setCheckState(Qt.Checked)
                self._start_hide_worker(hwnd, True, auto=True)
                self.status_label.setText(
                    f"Auto-hidden (remembered): {os.path.basename(exe_path)}"
                )
            else:
                item.setCheckState(Qt.Checked if hide_by_default else Qt.Unchecked)
                if hide_by_default:
                    self._start_hide_worker(hwnd, True, auto=True)

            item.setData(HwndRole, hwnd)
            item.setData(ExeRole, exe_path)
            item.setData(PidRole, win_info.get("pid"))

            if hwnd != int(self.winId()) and TaskbarHider.is_tracked(hwnd):
                # still tracked from before the window left the list (e.g.
                # it was minimized to the tray): re-attach it to the group
                item.setData(TaskbarMemberRole, True)
                self._refresh_item_taskbar_text(item)

            if exe_path:
                icon = self.icon_provider.icon(QFileInfo(exe_path))
                if not icon.isNull():
                    item.setIcon(icon)

            self.list_widget.addItem(item)

    def _get_item_by_hwnd(self, hwnd) -> QListWidgetItem:
        """Helper to find a QListWidgetItem by its associated window handle."""
        for i in range(self.list_widget.count()):
            item = self.list_widget.item(i)
            if item.data(HwndRole) == hwnd:
                return item
        return None

    def _start_hide_worker(self, hwnd, is_checked, auto=False):
        """Starts an async hide operation; returns False if one is already running."""
        if hwnd in self.workers:
            return False
        worker = HideWorker(hwnd, is_checked, auto=auto)
        worker.finished.connect(self.on_hide_finished)
        self.workers[hwnd] = worker
        worker.start()
        return True

    def _revert_item_state(self, item: QListWidgetItem, is_checked: bool):
        """Silently reverts a checkbox state without triggering logic signals."""
        self._is_updating = True
        item.setCheckState(Qt.Unchecked if is_checked else Qt.Checked)
        self._is_updating = False

    def _warn_box(self, text: str):
        """Shows a warning dialog that is itself excluded from capture."""
        box = CaptureSafeMessageBox(self)
        box.setWindowTitle("ShadowM")
        box.setIcon(QMessageBox.Warning)
        box.setText(text)
        box.setStandardButtons(QMessageBox.Ok)
        box.exec_()

    def on_item_double_clicked(self, item):
        current_state = item.checkState()
        new_state = Qt.Checked if current_state == Qt.Unchecked else Qt.Unchecked
        item.setCheckState(new_state)

    def on_list_context_menu(self, pos):
        """Right-click toggle for taskbar / Alt-Tab visibility."""
        item = self.list_widget.itemAt(pos)
        if item is None:
            return
        hwnd = item.data(HwndRole)
        menu = CaptureSafeMenu(self)
        action = menu.addAction("Hide from taskbar and Alt-Tab")
        action.setCheckable(True)
        # membership, not the live style bit: a native tool window we never
        # touched must not be offered as "already hidden by us"
        action.setChecked(TaskbarHider.is_tracked(hwnd))
        menu.addAction("Ctrl+Alt+T toggles all marked windows").setEnabled(False)
        if menu.exec_(self.list_widget.mapToGlobal(pos)) is None:
            return
        was_tracked = TaskbarHider.is_tracked(hwnd)
        if was_tracked:
            success, msg = TaskbarHider.restore(hwnd)
        else:
            success, msg = TaskbarHider.hide(hwnd)
        if not success:
            self.status_label.setText(f"Taskbar toggle failed: {msg}")
            return
        self._mark_taskbar_hidden(item, not was_tracked)
        title = _strip_taskbar_suffix(item.text())
        self.status_label.setText(
            f"Back in the taskbar and Alt-Tab: {title}"
            if was_tracked
            else f"Removed from taskbar/Alt-Tab: {title}"
        )

    def _mark_taskbar_hidden(self, item: QListWidgetItem, hidden: bool):
        """Adds or removes the item from the taskbar-hidden group."""
        self._is_updating = True
        item.setData(TaskbarMemberRole, hidden)
        self._is_updating = False
        self._refresh_item_taskbar_text(item)

    def _refresh_item_taskbar_text(self, item: QListWidgetItem):
        """Syncs the [taskbar hidden] suffix with the live window state.

        Group membership (the item flag) and actual hidden state can differ
        while the hotkey has temporarily restored every marked window.
        """
        hidden = bool(item.data(TaskbarMemberRole)) and TaskbarHider.is_hidden(
            item.data(HwndRole)
        )
        base = _strip_taskbar_suffix(item.text())
        want = base + TASKBAR_SUFFIX if hidden else base
        if want != item.text():
            self._is_updating = True
            item.setText(want)
            self._is_updating = False

    def _toggle_all_taskbar_hidden(self):
        """Ctrl+Alt+T: flip taskbar hiding for every marked window at once.

        If any marked window is currently back in the taskbar, all of them
        get hidden again; if all are hidden, all of them get restored.
        """
        marked = []
        for i in range(self.list_widget.count()):
            item = self.list_widget.item(i)
            hwnd = item.data(HwndRole)
            if item.data(TaskbarMemberRole) and TaskbarHider.is_window(hwnd):
                marked.append(item)
        if not marked:
            self.status_label.setText(
                "No windows marked for taskbar hiding (right-click one first)."
            )
            return
        hide = any(
            not TaskbarHider.is_hidden(item.data(HwndRole)) for item in marked
        )
        failures = 0
        for item in marked:
            hwnd = item.data(HwndRole)
            if hide:
                success, _ = TaskbarHider.hide(hwnd)
            else:
                success, _ = TaskbarHider.restore(hwnd)
            if success:
                self._refresh_item_taskbar_text(item)
            else:
                failures += 1
        self.status_label.setText(
            f"Ctrl+Alt+T: {'hid' if hide else 'restored'} "
            f"{len(marked) - failures} marked window(s)"
            + (f" ({failures} failed)" if failures else "")
        )

    def on_item_changed(self, item):
        if self._is_updating:
            return

        hwnd = item.data(HwndRole)
        is_checked = item.checkState() == Qt.Checked
        if is_checked:
            # setData re-emits itemChanged; suppress the re-entry
            self._is_updating = True
            item.setData(ExplicitRole, True)  # hidden by the user explicitly
            self._is_updating = False

        if not self._start_hide_worker(hwnd, is_checked):
            self._revert_item_state(item, is_checked)
            self.status_label.setText(
                "Another hide operation is still running for this window - "
                "try again in a moment."
            )

    def on_hide_finished(self, hwnd, is_checked, success, msg):
        worker = self.workers.pop(hwnd, None)
        auto = False
        if worker is not None:
            auto = worker.auto
            worker.deleteLater()

        self.ime_guard.note_window_state(hwnd, is_checked, success)

        item = self._get_item_by_hwnd(hwnd)
        own_hwnd = int(self.winId())

        if success:
            self._hide_failures.pop(hwnd, None)
            if is_checked:
                if item is not None and hwnd != own_hwnd:
                    self.session.note_capture_hidden(
                        hwnd, item.data(PidRole), item.data(ExeRole)
                    )
                    exe = item.data(ExeRole) or f"hwnd {hwnd}"
                    logger.info("hidden from capture: %s", os.path.basename(exe))
            else:
                self.session.clear_capture(hwnd)
                # unchecking a remembered window drops its auto-hide rule
                if item is not None:
                    self._forget_window(item.data(ExeRole))
            return

        if not is_checked:
            # restore failed: put the checkbox back so it matches reality
            if item:
                self._revert_item_state(item, is_checked)
            self._warn_box(msg)
            return

        # hide failed: right after (re)launch the target window may not be
        # ready yet - keep the checkbox and let the next sync tick retry
        self._hide_failures[hwnd] = self._hide_failures.get(hwnd, 0) + 1
        give_up = self._hide_failures[hwnd] >= self._max_hide_failures or item is None
        if give_up:
            self._hide_failures.pop(hwnd, None)
            if item:
                self._revert_item_state(item, is_checked)
            if not auto:
                self._warn_box(msg)
            else:
                self.status_label.setText(f"Auto-hide failed: {msg}")
                logger.warning("auto-hide failed for hwnd %s: %s", hwnd, msg)
        else:
            self.status_label.setText(
                f"Retrying hide ({self._hide_failures[hwnd]}): {msg}"
            )

    def closeEvent(self, event):
        if not self._confirm_exit():
            event.ignore()
            return
        self.timer.stop()
        # let in-flight workers finish first: destroying a running QThread
        # aborts the process, and the restores below must see final state
        for worker in list(self.workers.values()):
            worker.wait(3000)
        self.workers.clear()
        self._restore_all_protected_state()
        TaskbarHider.unregister_hotkey(
            int(self.winId()), TaskbarHider.HOTKEY_TOGGLE_ALL
        )
        super().closeEvent(event)

    def _restore_all_protected_state(self):
        """Undoes everything ShadowM applied to other windows (normal exit)."""
        own_hwnd = int(self.winId())
        targets = {}
        for i in range(self.list_widget.count()):
            item = self.list_widget.item(i)
            hwnd = item.data(HwndRole)
            if item.checkState() == Qt.Checked and hwnd != own_hwnd:
                targets[hwnd] = item.data(ExeRole)
        for hwnd, info in self.session.capture_items():
            # covers windows still hidden but no longer listed (tray apps)
            targets.setdefault(hwnd, info.get("exe", ""))

        restored = failed = 0
        for hwnd, exe in targets.items():
            ok, msg = WindowCaptureHider.set_window_hidden(hwnd, False)
            if ok:
                restored += 1
                self.session.clear_capture(hwnd)
            else:
                failed += 1
                logger.warning(
                    "could not restore capture state of %s: %s",
                    os.path.basename(exe) if exe else f"hwnd {hwnd}",
                    msg,
                )

        WindowOpacity.restore_all()
        TaskbarHider.restore_all()
        self.ime_guard.shutdown()

        if self.session.is_empty():
            self.session.delete()
        else:
            self.session.save()  # keep leftovers for next-launch healing
        logger.info("exit: capture restored=%d failed=%d", restored, failed)

    def _confirm_exit(self) -> bool:
        """Asks before quitting so ShadowM is not closed by accident."""
        box = CaptureSafeMessageBox(self)
        box.setWindowTitle("ShadowM")
        box.setIcon(QMessageBox.Question)
        box.setText("Quit ShadowM?")
        box.setInformativeText(
            "All capture-hidden windows will be restored, taskbar-hidden "
            "windows will reappear in the taskbar, and IME candidate "
            "protection will be lifted. Keep ShadowM running to stay "
            "protected."
        )
        box.setStandardButtons(QMessageBox.Yes | QMessageBox.No)
        box.setDefaultButton(QMessageBox.No)
        return box.exec_() == QMessageBox.Yes

    def on_current_item_changed(self, current, _previous):
        """Syncs the opacity slider with the newly selected window."""
        if current is None:
            self.opacity_slider.setEnabled(False)
            return
        hwnd = current.data(HwndRole)
        self.opacity_slider.setEnabled(True)
        self._is_syncing_opacity = True
        self.opacity_slider.setValue(WindowOpacity.get_percent(hwnd))
        self.opacity_value_label.setText(f"{self.opacity_slider.value()}%")
        self._is_syncing_opacity = False

    def on_opacity_changed(self, value):
        self.opacity_value_label.setText(f"{value}%")
        if self._is_syncing_opacity:
            return
        item = self.list_widget.currentItem()
        if item is None:
            return
        hwnd = item.data(HwndRole)
        if value >= 100:
            success, msg = WindowOpacity.restore(hwnd)
        else:
            success, msg = WindowOpacity.set_opacity(hwnd, value)
        if not success:
            self.status_label.setText(f"Opacity change failed: {msg}")

    def on_ime_guard_active(self, active):
        self.status_label.setText(
            "IME candidate windows are excluded from capture."
            if active
            else ""
        )

    def on_ime_guard_error(self, msg):
        self.status_label.setText(
            f"IME candidate protection failed: {msg}"
        )
