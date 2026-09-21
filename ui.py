import json
import os
import sys
import time
from PyQt5.QtWidgets import (
    QWidget,
    QVBoxLayout,
    QHBoxLayout,
    QCheckBox,
    QLabel,
    QListWidget,
    QListWidgetItem,
    QMessageBox,
    QSlider,
    QFileIconProvider,
)
from PyQt5.QtCore import Qt, QTimer, QThread, pyqtSignal, QFileInfo
from capture_hider import WindowCaptureHider
from ime_hider import ImeGuard
from window_opacity import WindowOpacity


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


class WindowHiderUI(QWidget):
    def __init__(self):
        super().__init__()
        self._is_updating = False
        self._is_syncing_opacity = False
        self.workers = {}
        self._hide_failures = {}
        self._max_hide_failures = 3
        self.icon_provider = QFileIconProvider()

        self._remembered_file = os.path.join(
            os.path.dirname(os.path.abspath(__file__)), "remembered_hidden.json"
        )
        self._remembered = self._load_remembered()

        self.ime_guard = ImeGuard(self)
        self.ime_guard.active_changed.connect(self.on_ime_guard_active)
        self.ime_guard.error_occurred.connect(self.on_ime_guard_error)

        self._init_window()
        self._setup_ui()
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
            QLabel("Check the windows below to hide them from screen capture:")
        )

        self.list_widget = QListWidget()
        self.list_widget.itemChanged.connect(self.on_item_changed)
        self.list_widget.itemDoubleClicked.connect(self.on_item_double_clicked)
        self.list_widget.currentItemChanged.connect(self.on_current_item_changed)
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

        self.status_label = QLabel("")
        self.status_label.setWordWrap(True)
        layout.addWidget(self.status_label)

    def _setup_timer(self):
        self.timer = QTimer(self)
        self.timer.timeout.connect(self.update_window_list)
        self.timer.timeout.connect(self.ime_guard.refresh)
        self.ime_guard.refresh()
        self.update_window_list()
        self.timer.start(1500)

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
            hwnd = item.data(Qt.UserRole)
            if item.checkState() != Qt.Checked or hwnd in self.workers:
                continue
            if self._hide_failures.get(hwnd, 0) >= self._max_hide_failures:
                continue
            affinity = WindowCaptureHider.get_window_affinity(hwnd)
            if affinity == WindowCaptureHider.WDA_EXCLUDEFROMCAPTURE:
                continue
            self._start_hide_worker(hwnd, True, auto=True)

    def _remove_stale_or_update_existing_items(self, current_hwnds: dict):
        """Removes closed windows from UI and updates titles of existing ones."""
        for i in range(self.list_widget.count() - 1, -1, -1):
            item = self.list_widget.item(i)
            hwnd = item.data(Qt.UserRole)
            known_pid = item.data(Qt.UserRole + 3)

            # Windows reuses hwnd values: a same-hwnd window with a different
            # pid is a new window that must go through new-window handling
            same_window = hwnd in current_hwnds and (
                known_pid is None or known_pid == current_hwnds[hwnd]["pid"]
            )

            if not same_window:
                if (
                    item.checkState() == Qt.Checked
                    and hwnd != int(self.winId())
                    and item.data(Qt.UserRole + 2)
                ):
                    # closed while the user had it hidden: remember for relaunch
                    self._remember_window(item.data(Qt.UserRole + 1), item.text())
                self.list_widget.takeItem(i)
                WindowOpacity.restore(hwnd)
                self.ime_guard.forget(hwnd)
                self._hide_failures.pop(hwnd, None)
            else:
                expected_text = current_hwnds[hwnd]["title"]
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

            item.setData(Qt.UserRole, hwnd)
            item.setData(Qt.UserRole + 1, exe_path)
            item.setData(Qt.UserRole + 3, win_info.get("pid"))

            if exe_path:
                icon = self.icon_provider.icon(QFileInfo(exe_path))
                if not icon.isNull():
                    item.setIcon(icon)

            self.list_widget.addItem(item)

    def _get_item_by_hwnd(self, hwnd) -> QListWidgetItem:
        """Helper to find a QListWidgetItem by its associated window handle."""
        for i in range(self.list_widget.count()):
            item = self.list_widget.item(i)
            if item.data(Qt.UserRole) == hwnd:
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

    def on_item_double_clicked(self, item):
        current_state = item.checkState()
        new_state = Qt.Checked if current_state == Qt.Unchecked else Qt.Unchecked
        item.setCheckState(new_state)

    def on_item_changed(self, item):
        if self._is_updating:
            return

        hwnd = item.data(Qt.UserRole)
        is_checked = item.checkState() == Qt.Checked
        if is_checked:
            # setData re-emits itemChanged; suppress the re-entry
            self._is_updating = True
            item.setData(Qt.UserRole + 2, True)  # hidden by the user explicitly
            self._is_updating = False

        if not self._start_hide_worker(hwnd, is_checked):
            self._revert_item_state(item, is_checked)

    def on_hide_finished(self, hwnd, is_checked, success, msg):
        worker = self.workers.pop(hwnd, None)
        auto = False
        if worker is not None:
            auto = worker.auto
            worker.deleteLater()

        self.ime_guard.note_window_state(hwnd, is_checked, success)

        if success:
            self._hide_failures.pop(hwnd, None)
            if not is_checked:
                # unchecking a remembered window drops its auto-hide rule
                item = self._get_item_by_hwnd(hwnd)
                if item is not None:
                    self._forget_window(item.data(Qt.UserRole + 1))
            return

        item = self._get_item_by_hwnd(hwnd)
        if not is_checked:
            # restore failed: put the checkbox back so it matches reality
            if item:
                self._revert_item_state(item, is_checked)
            QMessageBox.warning(self, "Operation Failed", msg)
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
                QMessageBox.warning(self, "Operation Failed", msg)
            else:
                self.status_label.setText(f"Auto-hide failed: {msg}")
        else:
            self.status_label.setText(
                f"Retrying hide ({self._hide_failures[hwnd]}): {msg}"
            )

    def closeEvent(self, event):
        if not self._confirm_exit():
            event.ignore()
            return
        WindowOpacity.restore_all()
        self.ime_guard.shutdown()
        super().closeEvent(event)

    def _confirm_exit(self) -> bool:
        """Asks before quitting so ShadowM is not closed by accident."""
        box = CaptureSafeMessageBox(self)
        box.setWindowTitle("ShadowM")
        box.setIcon(QMessageBox.Question)
        box.setText("Quit ShadowM?")
        box.setInformativeText(
            "All capture-hidden windows will be restored and IME candidate "
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
        hwnd = current.data(Qt.UserRole)
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
        hwnd = item.data(Qt.UserRole)
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
