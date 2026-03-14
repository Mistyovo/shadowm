import sys
from PyQt5.QtWidgets import (
    QWidget,
    QVBoxLayout,
    QLabel,
    QListWidget,
    QListWidgetItem,
    QMessageBox,
    QFileIconProvider,
)
from PyQt5.QtCore import Qt, QTimer, QThread, pyqtSignal, QFileInfo
from capture_hider import WindowCaptureHider


class HideWorker(QThread):
    finished = pyqtSignal(object, bool, bool, str)

    def __init__(self, hwnd, is_checked):
        super().__init__()
        self.hwnd = hwnd
        self.is_checked = is_checked

    def run(self):
        success, msg = WindowCaptureHider.set_window_hidden(
            self.hwnd, hidden=self.is_checked
        )
        self.finished.emit(self.hwnd, self.is_checked, success, msg)


class WindowHiderUI(QWidget):
    def __init__(self):
        super().__init__()
        self._is_updating = False
        self.workers = {}
        self.icon_provider = QFileIconProvider()
        
        self._init_window()
        self._setup_ui()
        self._setup_timer()

    def _init_window(self):
        self.setWindowTitle("ShadowM - Screen Capture Hider")
        self.resize(400, 300)

    def _setup_ui(self):
        layout = QVBoxLayout(self)
        layout.addWidget(
            QLabel("Check the windows below to hide them from screen capture:")
        )

        self.list_widget = QListWidget()
        self.list_widget.itemChanged.connect(self.on_item_changed)
        self.list_widget.itemDoubleClicked.connect(self.on_item_double_clicked)
        layout.addWidget(self.list_widget)

    def _setup_timer(self):
        self.timer = QTimer(self)
        self.timer.timeout.connect(self.update_window_list)
        self.update_window_list()
        self.timer.start(1500)

    def showEvent(self, event):
        super().showEvent(event)
        WindowCaptureHider.set_window_hidden(int(self.winId()), True)
        self.update_window_list()

    def update_window_list(self):
        """Synchronizes the current UI list with actual visible system windows."""
        current_windows = WindowCaptureHider.get_all_windows()
        current_hwnds = {win["hwnd"]: win for win in current_windows}

        self._is_updating = True
        self._remove_stale_or_update_existing_items(current_hwnds)
        self._add_new_items(current_hwnds)
        self._is_updating = False

    def _remove_stale_or_update_existing_items(self, current_hwnds: dict):
        """Removes closed windows from UI and updates titles of existing ones."""
        for i in range(self.list_widget.count() - 1, -1, -1):
            item = self.list_widget.item(i)
            hwnd = item.data(Qt.UserRole)
            
            if hwnd not in current_hwnds:
                self.list_widget.takeItem(i)
            else:
                expected_text = current_hwnds[hwnd]["title"]
                if item.text() != expected_text:
                    item.setText(expected_text)
                del current_hwnds[hwnd]

    def _add_new_items(self, new_hwnds: dict):
        """Creates new list items for recently discovered windows."""
        for hwnd, win_info in new_hwnds.items():
            item = QListWidgetItem(win_info["title"])
            item.setFlags(item.flags() | Qt.ItemIsUserCheckable)
            
            if hwnd == int(self.winId()):
                item.setCheckState(Qt.Checked)
                WindowCaptureHider.set_window_hidden(hwnd, True)
            else:
                item.setCheckState(Qt.Unchecked)
                
            item.setData(Qt.UserRole, hwnd)
            
            exe_path = win_info.get("exe_path")
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

        if hwnd in self.workers:
            self._revert_item_state(item, is_checked)
            return

        worker = HideWorker(hwnd, is_checked)
        worker.finished.connect(self.on_hide_finished)
        self.workers[hwnd] = worker
        worker.start()

    def on_hide_finished(self, hwnd, is_checked, success, msg):
        worker = self.workers.pop(hwnd, None)
        if worker is not None:
            worker.deleteLater()

        if not success:
            item = self._get_item_by_hwnd(hwnd)
            if item:
                self._revert_item_state(item, is_checked)
                QMessageBox.warning(self, "Operation Failed", msg)
