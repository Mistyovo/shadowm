import ctypes
import functools
import json
import logging
import os
import time
from ctypes import wintypes
from PyQt5.QtWidgets import (
    QAbstractButton,
    QAbstractItemView,
    QApplication,
    QFileIconProvider,
    QFrame,
    QHBoxLayout,
    QLabel,
    QListWidget,
    QListWidgetItem,
    QMenu,
    QMessageBox,
    QSizePolicy,
    QSlider,
    QStyle,
    QStyleOptionViewItem,
    QStyledItemDelegate,
    QVBoxLayout,
    QWidget,
)
from PyQt5.QtCore import (
    QEasingCurve,
    QEvent,
    QFileInfo,
    QPropertyAnimation,
    QRect,
    QRectF,
    QSize,
    Qt,
    QThread,
    QTimer,
    QVariantAnimation,
    pyqtProperty,
    pyqtSignal,
)
from PyQt5.QtGui import QColor, QFont, QFontMetrics, QIcon, QPainter, QPen, QPixmap
from capture_hider import WindowCaptureHider, get_window_pid, window_exists
from ime_hider import ImeGuard
from paths import state_file
from session_state import SessionState
from taskbar_hider import TaskbarHider
from theme import (
    BG,
    BLUE,
    BLUE_WASH,
    INK,
    LINE,
    MUTED,
    SLATE,
    SLATE_WASH,
    TEXT,
    apply as apply_theme,
    asset as theme_asset,
)
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


def _safe(fn):
    """Wraps a method PyQt5 invokes from C++ so an unexpected exception
    degrades to a log entry instead of aborting the whole process.

    PyQt5 terminates the process (qFatal, 0xC0000409) when an exception
    escapes a slot, a paint override or a mouse/event handler; no bug in
    any such callback may ever reach C++ uncaught.
    """

    @functools.wraps(fn)
    def wrapper(*args, **kwargs):
        try:
            return fn(*args, **kwargs)
        except Exception:
            logger.exception(
                "uncaught error in %s", getattr(fn, "__name__", fn)
            )

    return wrapper


def _system_animations_enabled() -> bool:
    """Respect Windows' "Show animations" accessibility setting."""
    try:
        enabled = ctypes.c_int(1)
        ctypes.windll.user32.SystemParametersInfoW(
            0x1042, 0, ctypes.byref(enabled), 0
        )
        return bool(enabled.value)
    except Exception:
        return True


ANIMATIONS = _system_animations_enabled()

_SWITCH_W = 36
_SWITCH_H = 20
_SWITCH_OFF_TRACK = "#E4E9F2"
_SWITCH_OFF_BORDER = "#CBD5E3"


def _mix(c1, c2, t: float) -> QColor:
    """Linear RGB blend between two colours, t clamped to 0..1."""
    a, b = QColor(c1), QColor(c2)
    t = max(0.0, min(1.0, t))
    return QColor(
        round(a.red() + (b.red() - a.red()) * t),
        round(a.green() + (b.green() - a.green()) * t),
        round(a.blue() + (b.blue() - a.blue()) * t),
    )


def _paint_toggle(painter, rect, t, hovered=False, focused=False):
    """Shared switch rendering: track eases off->blue, knob slides."""
    painter.save()
    painter.setRenderHint(QPainter.Antialiasing)
    if hovered or focused:
        ring = QColor(BLUE)
        ring.setAlpha(90 if focused else 55)
        painter.setPen(QPen(ring, 1.3))
        painter.setBrush(Qt.NoBrush)
        painter.drawRoundedRect(
            QRectF(rect).adjusted(-2.5, -2.5, 2.5, 2.5),
            rect.height() / 2 + 2.5,
            rect.height() / 2 + 2.5,
        )
    track = QRectF(rect).adjusted(0.5, 0.5, -0.5, -0.5)
    painter.setPen(Qt.NoPen)
    painter.setBrush(_mix(_SWITCH_OFF_TRACK, BLUE, t))
    radius = track.height() / 2
    painter.drawRoundedRect(track, radius, radius)
    knob_x = rect.left() + 2 + t * (rect.width() - 20)
    knob = QRectF(knob_x, rect.top() + 2, 16, 16)
    painter.setPen(QPen(_mix(_SWITCH_OFF_BORDER, "#FFFFFF", t), 1))
    painter.setBrush(QColor("#FFFFFF"))
    painter.drawEllipse(knob)
    painter.restore()


def _fade_in(widget, duration=140):
    """Softens a popup/dialog's first frame."""
    if not ANIMATIONS:
        return
    widget.setWindowOpacity(0.0)
    anim = QPropertyAnimation(widget, b"windowOpacity", widget)
    anim.setDuration(duration)
    anim.setStartValue(0.0)
    anim.setEndValue(1.0)
    anim.setEasingCurve(QEasingCurve.OutCubic)
    anim.start()
    widget._fade_anim = anim


class ToggleSwitch(QAbstractButton):
    """Checkable row that paints its own sliding switch and label.

    Unlike a QSS-styled QCheckBox the knob glides and the track colour
    eases between states, so toggling never snaps.
    """

    def __init__(self, text="", parent=None):
        super().__init__(parent)
        self.setText(text)
        self.setCheckable(True)
        self.setCursor(Qt.PointingHandCursor)
        self.setFocusPolicy(Qt.StrongFocus)
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        self.setObjectName("toggleSwitch")
        self._pos = 0.0
        self._hover = 0.0
        self._pos_anim = QPropertyAnimation(self, b"knobPosition", self)
        self._pos_anim.setDuration(180 if ANIMATIONS else 0)
        self._pos_anim.setEasingCurve(QEasingCurve.OutCubic)
        self._hover_anim = QPropertyAnimation(self, b"hoverRatio", self)
        self._hover_anim.setDuration(120 if ANIMATIONS else 0)
        self._hover_anim.setEasingCurve(QEasingCurve.OutCubic)
        self.toggled.connect(self._animate_toggle)

    def _animate_toggle(self, checked):
        target = 1.0 if checked else 0.0
        if not ANIMATIONS or not self.isVisible():
            self._pos_anim.stop()
            self.knobPosition = target
            return
        self._pos_anim.stop()
        self._pos_anim.setStartValue(self._pos)
        self._pos_anim.setEndValue(target)
        self._pos_anim.start()

    def get_knob_position(self):
        return self._pos

    def set_knob_position(self, value):
        self._pos = float(value)
        self.update()

    knobPosition = pyqtProperty(float, get_knob_position, set_knob_position)

    def get_hover_ratio(self):
        return self._hover

    def set_hover_ratio(self, value):
        self._hover = float(value)
        self.update()

    hoverRatio = pyqtProperty(float, get_hover_ratio, set_hover_ratio)

    def enterEvent(self, event):
        self._hover_anim.stop()
        self._hover_anim.setStartValue(self._hover)
        self._hover_anim.setEndValue(1.0)
        self._hover_anim.start()
        super().enterEvent(event)

    def leaveEvent(self, event):
        self._hover_anim.stop()
        self._hover_anim.setStartValue(self._hover)
        self._hover_anim.setEndValue(0.0)
        self._hover_anim.start()
        super().leaveEvent(event)

    def sizeHint(self):
        fm = QFontMetrics(self.font())
        return QSize(
            _SWITCH_W + 18 + fm.horizontalAdvance(self.text()) + 4,
            max(30, fm.height() + 8),
        )

    @_safe
    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)
        top = (self.height() - _SWITCH_H) // 2
        # 3px breathing room keeps the hover/focus ring inside the widget
        track = QRect(3, top, _SWITCH_W, _SWITCH_H)
        _paint_toggle(
            painter,
            track,
            self._pos,
            hovered=self._hover > 0.02,
            focused=self.hasFocus(),
        )
        painter.setFont(self.font())
        painter.setPen(QColor(INK if self.isEnabled() else MUTED))
        text_rect = QRect(
            3 + _SWITCH_W + 11,
            0,
            max(0, self.width() - 3 - _SWITCH_W - 11),
            self.height(),
        )
        fm = QFontMetrics(self.font())
        painter.drawText(
            text_rect,
            Qt.AlignVCenter | Qt.AlignLeft,
            fm.elidedText(self.text(), Qt.ElideRight, text_rect.width()),
        )


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

    @_safe
    def showEvent(self, event):
        super().showEvent(event)
        WindowCaptureHider.set_window_hidden(int(self.winId()), True)
        _fade_in(self, 140)


class CaptureSafeMenu(QMenu):
    """Context menu that is itself excluded from screen capture."""

    @_safe
    def showEvent(self, event):
        super().showEvent(event)
        WindowCaptureHider.set_window_hidden(int(self.winId()), True)
        _fade_in(self, 100)


def _is_elevated() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def _style_native_frame(hwnd):
    """Paints the Windows title bar in the app's white-blue palette.

    DWMWA_CAPTION_COLOR (35) / DWMWA_TEXT_COLOR (36) exist on Win11 22000+;
    older systems silently keep their default chrome.
    """
    try:
        dwm = ctypes.windll.dwmapi
        dwm.DwmSetWindowAttribute.argtypes = [
            wintypes.HWND,
            ctypes.c_uint,
            ctypes.c_void_p,
            ctypes.c_uint,
        ]
        dwm.DwmSetWindowAttribute.restype = ctypes.c_long

        def colorref(hex_color):
            h = hex_color.lstrip("#")
            r, g, b = int(h[0:2], 16), int(h[2:4], 16), int(h[4:6], 16)
            return r | (g << 8) | (b << 16)

        def set_attr(attr, value):
            v = ctypes.c_int(value)
            dwm.DwmSetWindowAttribute(
                wintypes.HWND(hwnd), attr, ctypes.byref(v), ctypes.sizeof(v)
            )

        set_attr(20, 0)              # DWMWA_USE_IMMERSIVE_DARK_MODE: off
        set_attr(35, colorref(BG))   # caption background
        set_attr(36, colorref(INK))  # caption text
        set_attr(34, colorref(LINE)) # window border
    except Exception:
        pass


def _load_logo_pixmap(size: int = 32) -> QPixmap:
    """Header logo from assets/logo.svg, with a painted fallback."""
    pm = QPixmap(theme_asset("logo.svg"))
    if not pm.isNull():
        return pm.scaled(size, size, Qt.KeepAspectRatio, Qt.SmoothTransformation)
    pm = QPixmap(size, size)
    pm.fill(Qt.transparent)
    p = QPainter(pm)
    p.setRenderHint(QPainter.Antialiasing)
    p.setPen(Qt.NoPen)
    p.setBrush(QColor(BLUE))
    p.drawRoundedRect(
        QRectF(size * 0.40, size * 0.10, size * 0.50, size * 0.50),
        size * 0.12,
        size * 0.12,
    )
    pen = QPen(QColor(INK), max(1.5, size * 0.07))
    pen.setJoinStyle(Qt.RoundJoin)
    p.setPen(pen)
    p.setBrush(QColor(BG))
    p.drawRoundedRect(
        QRectF(size * 0.10, size * 0.40, size * 0.50, size * 0.50),
        size * 0.12,
        size * 0.12,
    )
    p.end()
    return pm


class WindowItemDelegate(QStyledItemDelegate):
    """Two-line rows with one capture switch on the right.

    The left checkbox is gone: state lives in the row's switch and the
    list header summarises it, so no per-row status sentence repeats.
    Presentation only: the item text keeps the raw " [taskbar hidden]"
    suffix that all logic depends on; the delegate strips it at paint time.
    """

    _CHIP_TEXT = "taskbar"
    _ROW_HEIGHT = 54
    _SWITCH_W = 36
    _SWITCH_H = 20
    _RIGHT_PAD = 12

    def __init__(self, parent=None):
        super().__init__(parent)
        self._switch_pos = {}
        self._switch_anims = {}
        self._appear = {}
        self._appear_anims = {}
        self._sel = {}
        self._sel_anims = {}

    def forget(self, key):
        """Drops animation state for a row that left the list."""
        for store in (self._switch_pos, self._appear, self._sel):
            store.pop(key, None)
        for store in (self._switch_anims, self._appear_anims, self._sel_anims):
            anim = store.pop(key, None)
            if anim is not None:
                anim.stop()

    def _animated_switch(self, key, target, view):
        """Eases a row's switch towards its new state; returns the value
        to paint right now (animations keep repainting via valueChanged)."""
        pos = self._switch_pos.get(key)
        if pos is None:
            self._switch_pos[key] = target
            return target
        if abs(pos - target) < 1e-4:
            return pos
        anim = self._switch_anims.get(key)
        if (
            anim is not None
            and anim.endValue() is not None
            and abs(float(anim.endValue()) - target) < 1e-4
        ):
            return pos
        if anim is not None:
            anim.stop()
        if not ANIMATIONS:
            self._switch_pos[key] = target
            return target
        anim = QVariantAnimation(self)
        anim.setStartValue(pos)
        anim.setEndValue(float(target))
        anim.setDuration(180)
        anim.setEasingCurve(QEasingCurve.OutCubic)

        def update(value, key=key, view=view):
            self._switch_pos[key] = float(value)
            if view is not None:
                view.viewport().update()

        anim.valueChanged.connect(update)
        anim.finished.connect(
            lambda key=key: self._switch_anims.pop(key, None)
        )
        self._switch_anims[key] = anim
        anim.start()
        return pos

    def _appearance(self, key, view):
        """Fades a row in the first time it is painted."""
        alpha = self._appear.get(key)
        if alpha is not None:
            return alpha
        if not ANIMATIONS:
            self._appear[key] = 1.0
            return 1.0
        self._appear[key] = 0.0
        anim = QVariantAnimation(self)
        anim.setStartValue(0.0)
        anim.setEndValue(1.0)
        anim.setDuration(200)
        anim.setEasingCurve(QEasingCurve.OutCubic)

        def update(value, key=key, view=view):
            self._appear[key] = float(value)
            if view is not None:
                view.viewport().update()

        anim.valueChanged.connect(update)
        anim.finished.connect(
            lambda key=key: self._appear_anims.pop(key, None)
        )
        self._appear_anims[key] = anim
        anim.start()
        return 0.0

    def _animated_selection(self, key, target, view):
        """Cross-fades the selected-row wash instead of hard-switching it."""
        value = self._sel.get(key)
        if value is None:
            self._sel[key] = target
            return target
        if abs(value - target) < 1e-4:
            return value
        anim = self._sel_anims.get(key)
        if (
            anim is not None
            and anim.endValue() is not None
            and abs(float(anim.endValue()) - target) < 1e-4
        ):
            return value
        if anim is not None:
            anim.stop()
        if not ANIMATIONS:
            self._sel[key] = target
            return target
        anim = QVariantAnimation(self)
        anim.setStartValue(value)
        anim.setEndValue(float(target))
        anim.setDuration(140)
        anim.setEasingCurve(QEasingCurve.OutCubic)

        def update(v, key=key, view=view):
            self._sel[key] = float(v)
            if view is not None:
                view.viewport().update()

        anim.valueChanged.connect(update)
        anim.finished.connect(
            lambda key=key: self._sel_anims.pop(key, None)
        )
        self._sel_anims[key] = anim
        anim.start()
        return value

    @classmethod
    def switch_rect(cls, item_rect: QRect) -> QRect:
        x = item_rect.right() - cls._RIGHT_PAD - cls._SWITCH_W
        y = item_rect.center().y() - cls._SWITCH_H // 2
        return QRect(x, y, cls._SWITCH_W, cls._SWITCH_H)

    def sizeHint(self, option, index):
        size = super().sizeHint(option, index)
        size.setHeight(self._ROW_HEIGHT)
        return size

    def editorEvent(self, event, model, option, index):
        # Mouse clicks are handled by WindowListWidget; returning False here
        # keeps the default delegate from toggling a no-longer-drawn
        # left-side check indicator.
        if event.type() in (
            QEvent.MouseButtonPress,
            QEvent.MouseButtonRelease,
            QEvent.MouseButtonDblClick,
            QEvent.MouseMove,
        ):
            return False
        return super().editorEvent(event, model, option, index)

    @_safe
    def paint(self, painter, option, index):
        opt = QStyleOptionViewItem(option)
        self.initStyleOption(opt, index)
        full_text = opt.text
        has_chip = full_text.endswith(TASKBAR_SUFFIX)
        title = full_text[: -len(TASKBAR_SUFFIX)] if has_chip else full_text
        hidden = opt.checkState == Qt.Checked
        opt.text = ""  # drawn manually below
        opt.features = opt.features & ~QStyleOptionViewItem.HasCheckIndicator
        widget = opt.widget
        key = index.data(HwndRole)
        style = widget.style() if widget is not None else QApplication.style()

        if key is not None and widget is not None:
            alpha = self._appearance(key, widget)
            switch_pos = self._animated_switch(
                key, 1.0 if hidden else 0.0, widget
            )
            selected = bool(opt.state & QStyle.State_Selected)
            sel = self._animated_selection(
                key, 1.0 if selected else 0.0, widget
            )
        else:
            alpha = 1.0
            switch_pos = 1.0 if hidden else 0.0
            selected = bool(opt.state & QStyle.State_Selected)
            sel = 1.0 if selected else 0.0
        # the wash is drawn manually so it can cross-fade
        opt.state = opt.state & ~QStyle.State_Selected

        deco_rect = style.subElementRect(
            QStyle.SE_ItemViewItemDecoration, opt, widget
        )
        content_left = max(option.rect.left() + 16, deco_rect.right() + 12)
        rect = option.rect.adjusted(
            content_left - option.rect.left(),
            0,
            -(self._RIGHT_PAD + self._SWITCH_W + 10),
            0,
        )

        title_font = QFont(opt.font)
        title_font.setPointSizeF(9.5)
        title_font.setWeight(QFont.Medium)
        fm = QFontMetrics(title_font)
        title_rect = QRect(rect.left(), rect.top() + 10, rect.width(), 18)

        sub_font = QFont(opt.font)
        sub_font.setPointSizeF(8)
        sfm = QFontMetrics(sub_font)
        sub_rect = QRect(rect.left(), title_rect.bottom() + 2, rect.width(), 14)
        exe_name = os.path.basename(index.data(ExeRole) or "") or "-"
        shown_exe = sfm.elidedText(exe_name, Qt.ElideRight, sub_rect.width())

        painter.save()
        painter.setOpacity(alpha)
        # wash goes under the icon/decoration, otherwise it hides them
        if sel > 0.01:
            wash = QColor(BLUE_WASH)
            wash.setAlpha(round(255 * sel))
            painter.setPen(Qt.NoPen)
            painter.setBrush(wash)
            painter.drawRoundedRect(
                QRectF(option.rect).adjusted(1, 1, -1, -1), 9, 9
            )
        style.drawControl(QStyle.CE_ItemViewItem, opt, painter, widget)
        painter.setRenderHint(QPainter.Antialiasing)
        painter.setFont(title_font)
        painter.setPen(QColor(TEXT))
        painter.drawText(
            title_rect,
            Qt.AlignVCenter,
            fm.elidedText(title, Qt.ElideRight, title_rect.width()),
        )

        painter.setFont(sub_font)
        painter.setPen(QColor(MUTED))
        painter.drawText(sub_rect, Qt.AlignVCenter, shown_exe)

        if has_chip:
            chip_font = QFont(sub_font)
            chip_font.setPointSizeF(7)
            cfm = QFontMetrics(chip_font)
            chip_w = cfm.horizontalAdvance(self._CHIP_TEXT) + 14
            chip_x = rect.left() + sfm.horizontalAdvance(shown_exe) + 8
            chip_x = min(chip_x, rect.right() - chip_w)
            chip_rect = QRectF(chip_x, sub_rect.center().y() - 7, chip_w, 14)
            painter.setPen(Qt.NoPen)
            painter.setBrush(QColor(SLATE_WASH))
            painter.drawRoundedRect(chip_rect, 7, 7)
            painter.setFont(chip_font)
            painter.setPen(QColor(SLATE))
            painter.drawText(chip_rect, Qt.AlignCenter, self._CHIP_TEXT)

        hovered = (
            widget is not None
            and key is not None
            and getattr(widget, "_hover_switch_key", None) == key
        )
        _paint_toggle(
            painter, self.switch_rect(option.rect), switch_pos,
            hovered=hovered,
        )
        painter.restore()


class WindowListWidget(QListWidget):
    """Window list whose rows toggle capture with the right-side switch."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self._hover_switch_key = None

    def _switch_rect_at(self, index) -> QRect:
        return WindowItemDelegate.switch_rect(self.visualRect(index))

    @_safe
    def mousePressEvent(self, event):
        if event.button() == Qt.LeftButton:
            index = self.indexAt(event.pos())
            if index.isValid():
                hit = self._switch_rect_at(index).adjusted(-4, -6, 5, 6)
                if hit.contains(event.pos()):
                    item = self.itemFromIndex(index)
                    if item is not None:
                        item.setCheckState(
                            Qt.Unchecked
                            if item.checkState() == Qt.Checked
                            else Qt.Checked
                        )
                    return
        super().mousePressEvent(event)

    @_safe
    def mouseDoubleClickEvent(self, event):
        index = self.indexAt(event.pos())
        if index.isValid() and self._switch_rect_at(index).contains(event.pos()):
            return  # a double-click on the switch is still one toggle
        super().mouseDoubleClickEvent(event)

    @_safe
    def mouseMoveEvent(self, event):
        index = self.indexAt(event.pos())
        key = None
        if index.isValid() and self._switch_rect_at(index).contains(event.pos()):
            key = index.data(HwndRole)
        if key != self._hover_switch_key:
            self._hover_switch_key = key
            self.viewport().update()
        if key is not None:
            self.viewport().setCursor(Qt.PointingHandCursor)
        else:
            self.viewport().unsetCursor()
        super().mouseMoveEvent(event)

    @_safe
    def leaveEvent(self, event):
        if self._hover_switch_key is not None:
            self._hover_switch_key = None
            self.viewport().update()
        super().leaveEvent(event)


class WindowHiderUI(QWidget):
    def __init__(self):
        super().__init__()
        apply_theme(QApplication.instance())
        self._is_updating = False
        self._is_syncing_opacity = False
        self._shown_once = False
        self.workers = {}
        self._hide_failures = {}
        self._max_hide_failures = 3
        self.icon_provider = QFileIconProvider()

        self._remembered_file = state_file("remembered_hidden.json")
        self._remembered = self._load_remembered()

        # crash recovery: whatever a previous run left on windows is undone
        # here, before any new hiding happens
        self.session = SessionState(state_file("shadowm_session.json"))
        TaskbarHider.set_session(self.session)
        WindowOpacity.set_session(self.session)
        self._heal_failed = 0
        self._heal_session_leftovers()

        self.ime_guard = ImeGuard(self)
        self.ime_guard.active_changed.connect(self.on_ime_guard_active)
        self.ime_guard.error_occurred.connect(self.on_ime_guard_error)

        self._init_window()
        self._setup_ui()
        self._register_hotkeys()
        self._setup_timer()
        if self._heal_failed:
            self.status_label.setText(
                f"Could not undo changes a previous run left on "
                f"{self._heal_failed} window(s). They will be retried on the "
                f"next launch - run ShadowM as Administrator if this keeps "
                f"happening."
            )

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
        original style, affinity and opacity back. Entries for dead windows,
        recycled hwnd values or a previous boot are dropped. Entries whose
        restore fails (typically: ShadowM was relaunched without elevation)
        stay in the session file so a later, properly elevated launch can
        still undo them.
        """
        healed = failed = 0

        def alive_with_pid(hwnd, pid):
            return (
                TaskbarHider.is_window(hwnd)
                and pid is not None
                and get_window_pid(hwnd) == pid
            )

        for hwnd, info in self.session.taskbar_items():
            if alive_with_pid(hwnd, info.get("pid")):
                ok, _ = TaskbarHider.recover_leftover(
                    hwnd, info.get("exstyle", 0)
                )
                if ok:
                    healed += 1
                    self.session.clear_taskbar(hwnd)
                    continue
                failed += 1
            else:
                self.session.clear_taskbar(hwnd)
        for hwnd, info in self.session.opacity_items():
            if alive_with_pid(hwnd, info.get("pid")):
                ok, _ = WindowOpacity.recover_leftover(
                    hwnd,
                    bool(info.get("added_layered")),
                    info.get("original_alpha"),
                )
                if ok:
                    healed += 1
                    self.session.clear_opacity(hwnd)
                    continue
                failed += 1
            else:
                self.session.clear_opacity(hwnd)
        for hwnd, info in self.session.capture_items():
            if alive_with_pid(hwnd, info.get("pid")):
                affinity = WindowCaptureHider.get_window_affinity(hwnd)
                if affinity != WindowCaptureHider.WDA_EXCLUDEFROMCAPTURE:
                    # nothing left to undo (or the app set its own affinity
                    # since): leave the window untouched
                    self.session.clear_capture(hwnd)
                    continue
                ok, _ = WindowCaptureHider.set_window_hidden(hwnd, False)
                if ok:
                    healed += 1
                    self.session.clear_capture(hwnd)
                    continue
                failed += 1
            else:
                self.session.clear_capture(hwnd)
        if healed or failed:
            logger.info(
                "startup heal: restored %d leftover window(s), %d failed",
                healed,
                failed,
            )
        self._heal_failed = failed
        if failed:
            self.session.save()  # keep the failures for the next launch
        else:
            self.session.clear_all()
            self.session.delete()

    def _init_window(self):
        self.setWindowTitle("ShadowM")
        self.setWindowIcon(QIcon(theme_asset("shadowm.ico")))
        self.setMinimumSize(440, 560)
        self.resize(500, 700)

    def _setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(22, 18, 22, 16)
        layout.setSpacing(12)

        layout.addLayout(self._build_header())
        layout.addWidget(self._build_settings_card())
        layout.addLayout(self._build_list_header())

        self.list_widget = WindowListWidget()
        self.list_widget.setObjectName("windowList")
        self.list_widget.setIconSize(QSize(26, 26))
        self.list_widget.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self.list_widget.setVerticalScrollMode(QAbstractItemView.ScrollPerPixel)
        self.list_widget.setUniformItemSizes(True)
        self.list_widget.viewport().setMouseTracking(True)
        self.list_widget.setToolTip(
            "Blue switch: hidden from screen capture. "
            "Click a row to adjust its opacity."
        )
        self.list_widget.setItemDelegate(WindowItemDelegate(self.list_widget))
        self.list_widget.itemChanged.connect(self.on_item_changed)
        self.list_widget.itemDoubleClicked.connect(self.on_item_double_clicked)
        self.list_widget.currentItemChanged.connect(self.on_current_item_changed)
        self.list_widget.setContextMenuPolicy(Qt.CustomContextMenu)
        self.list_widget.customContextMenuRequested.connect(
            self.on_list_context_menu
        )
        layout.addWidget(self.list_widget, 1)

        layout.addLayout(self._build_opacity_row())
        hint = QLabel(
            "Right-click a window for taskbar options · "
            "Ctrl+Alt+T toggles marked windows",
            objectName="caption",
        )
        hint.setWordWrap(True)
        layout.addWidget(hint)

        # persistent (never overwritten) so the user cannot miss it
        self.hotkey_warning_label = QLabel("", objectName="warning")
        self.hotkey_warning_label.setWordWrap(True)
        layout.addWidget(self.hotkey_warning_label)

        self.status_label = QLabel("", objectName="status")
        self.status_label.setWordWrap(True)
        layout.addWidget(self.status_label)

    def _build_header(self):
        header = QHBoxLayout()
        header.setSpacing(12)
        logo = QLabel()
        logo.setPixmap(_load_logo_pixmap(32))
        header.addWidget(logo, 0, Qt.AlignTop)
        titles = QVBoxLayout()
        titles.setSpacing(1)
        titles.addWidget(QLabel("ShadowM", objectName="appTitle"))
        titles.addWidget(QLabel("Screen capture privacy", objectName="appSubtitle"))
        header.addLayout(titles)
        header.addStretch()

        self.admin_pill = QLabel("", objectName="pill")
        if _is_elevated():
            self.admin_pill.setText("Admin")
            self._set_pill_accent(self.admin_pill, "good")
        else:
            self.admin_pill.setText("Not elevated")
            self._set_pill_accent(self.admin_pill, "warn")
        header.addWidget(self.admin_pill, 0, Qt.AlignTop)
        return header

    def _build_settings_card(self):
        card = QFrame(objectName="card")
        box = QVBoxLayout(card)
        box.setContentsMargins(16, 12, 16, 12)
        box.setSpacing(9)

        self.auto_hide_checkbox = ToggleSwitch("Auto-hide new windows")
        self.auto_hide_checkbox.setToolTip(
            "When checked, every window that appears in the list below is "
            "automatically hidden from screen capture."
        )
        self.ime_guard_checkbox = ToggleSwitch("IME candidate protection")
        self.ime_guard_checkbox.setChecked(True)
        self.ime_guard_checkbox.setToolTip(
            "While the focused window is hidden, the IME candidate windows "
            "(e.g. Sogou Pinyin's SoPY_* bars, rendered by the application "
            "you type into) are also excluded from screen capture. They stay "
            "fully visible on your own screen and are restored when focus "
            "returns to a normal window."
        )
        self.ime_guard_checkbox.toggled.connect(self.ime_guard.set_enabled)

        box.addWidget(self.auto_hide_checkbox)
        box.addWidget(self.ime_guard_checkbox)
        return card

    def _build_list_header(self):
        row = QHBoxLayout()
        row.setSpacing(8)
        row.addWidget(QLabel("Windows", objectName="sectionTitle"))
        row.addStretch()
        self.window_count_label = QLabel("", objectName="caption")
        row.addWidget(self.window_count_label)
        return row

    def _build_opacity_row(self):
        row = QHBoxLayout()
        row.setContentsMargins(4, 2, 4, 0)
        row.setSpacing(12)
        row.addWidget(QLabel("Opacity", objectName="caption"))
        self.opacity_slider = QSlider(Qt.Horizontal)
        self.opacity_slider.setRange(1, 100)
        self.opacity_slider.setValue(100)
        self.opacity_slider.setEnabled(False)
        self.opacity_slider.setToolTip(
            "On-screen transparency (1%-100%) of the selected window. This "
            "is a local visual effect only - whether the window is excluded "
            "from capture is controlled by the switch on its row above."
        )
        self.opacity_slider.valueChanged.connect(self.on_opacity_changed)
        row.addWidget(self.opacity_slider, 1)
        self.opacity_value_label = QLabel("100%", objectName="caption")
        self.opacity_value_label.setMinimumWidth(38)
        self.opacity_value_label.setAlignment(Qt.AlignRight | Qt.AlignVCenter)
        row.addWidget(self.opacity_value_label)
        return row

    @staticmethod
    def _set_pill_accent(label, accent):
        """Switches a pill's [accent=...] style; needs a style re-polish."""
        label.setProperty("accent", accent or "")
        label.style().unpolish(label)
        label.style().polish(label)

    def _update_counts(self):
        """Refreshes the header pill and list-header count."""
        own_hwnd = int(self.winId())
        total = hidden = 0
        for i in range(self.list_widget.count()):
            item = self.list_widget.item(i)
            if item.data(HwndRole) == own_hwnd:
                continue
            total += 1
            if item.checkState() == Qt.Checked:
                hidden += 1
        self.window_count_label.setText(f"{hidden} of {total} hidden from capture")

    def _setup_timer(self):
        self.timer = QTimer(self)
        self.timer.timeout.connect(_safe(self.update_window_list))
        self.timer.timeout.connect(_safe(self.ime_guard.refresh))
        self.timer.timeout.connect(_safe(TaskbarHider.reconcile))
        _safe(self.ime_guard.refresh)()
        _safe(self.update_window_list)()
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
        try:
            if eventType == b"windows_generic_MSG":
                msg = wintypes.MSG.from_address(int(message))
                if (
                    msg.message == TaskbarHider.WM_HOTKEY
                    and msg.wParam == TaskbarHider.HOTKEY_TOGGLE_ALL
                ):
                    self._toggle_all_taskbar_hidden()
                    return True, 0
        except Exception:
            logger.exception("handling a native window event failed")
        return super().nativeEvent(eventType, message)

    @_safe
    def showEvent(self, event):
        super().showEvent(event)
        own_hwnd = int(self.winId())
        _style_native_frame(own_hwnd)
        WindowCaptureHider.set_window_hidden(own_hwnd, True)
        self.ime_guard.note_window_state(own_hwnd, True, True)
        if not self._shown_once:
            self._shown_once = True
            _fade_in(self, 180)
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
        self._update_counts()

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
            if not window_exists(hwnd):
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
            in_listing = hwnd in current_hwnds
            same_window = in_listing and (
                known_pid is None or known_pid == current_hwnds[hwnd]["pid"]
            )

            if same_window:
                item.setData(MissRole, 0)
                expected_text = current_hwnds[hwnd]["title"]
                if item.data(TaskbarMemberRole) and TaskbarHider.is_hidden(hwnd):
                    expected_text += TASKBAR_SUFFIX
                if item.text() != expected_text:
                    item.setText(expected_text)
                del current_hwnds[hwnd]
                continue

            if in_listing:
                # the hwnd value now belongs to a different process, so the
                # item's window is gone for good; remove it in this same
                # refresh or the reused hwnd would show up as a duplicate row
                gone_for_good = True
            else:
                misses = (item.data(MissRole) or 0) + 1
                item.setData(MissRole, misses)
                if misses < 2:
                    continue  # enumeration flicker: re-check next refresh
                gone_for_good = not window_exists(hwnd)

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
            delegate = self.list_widget.itemDelegate()
            if hasattr(delegate, "forget"):
                delegate.forget(hwnd)
            self.list_widget.takeItem(i)
            if gone_for_good:
                # truly gone: drop our bookkeeping for good
                WindowOpacity.restore(hwnd)
                TaskbarHider.forget(hwnd)
                self.session.clear_capture(hwnd)
            # still alive (e.g. minimized to the tray): keep styles and
            # tracking; TaskbarHider.reconcile keeps enforcing them
            self.ime_guard.forget(hwnd)
            self._hide_failures.pop(hwnd, None)

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
        box.setIconPixmap(_load_logo_pixmap(36))
        box.setText(text)
        box.setStandardButtons(QMessageBox.Ok)
        box.exec_()

    @_safe
    def on_item_double_clicked(self, item):
        current_state = item.checkState()
        new_state = Qt.Checked if current_state == Qt.Unchecked else Qt.Unchecked
        item.setCheckState(new_state)

    @_safe
    def on_list_context_menu(self, pos):
        """Right-click actions: taskbar / Alt-Tab visibility, show window."""
        item = self.list_widget.itemAt(pos)
        if item is None:
            return
        hwnd = item.data(HwndRole)
        menu = CaptureSafeMenu(self)
        toggle_action = menu.addAction("Hide from taskbar and Alt-Tab")
        toggle_action.setCheckable(True)
        # membership, not the live style bit: a native tool window we never
        # touched must not be offered as "already hidden by us"
        toggle_action.setChecked(TaskbarHider.is_tracked(hwnd))
        show_action = menu.addAction("Show window")
        menu.addAction("Ctrl+Alt+T toggles all marked windows").setEnabled(False)
        chosen = menu.exec_(self.list_widget.mapToGlobal(pos))
        if chosen is None:
            return
        if chosen == show_action:
            self._show_window(item)
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

    def _show_window(self, item: QListWidgetItem):
        """Restores and focuses a window from the list (Show window menu).

        A taskbar-hidden, minimized window has no system entry point back;
        this is the only route that surfaces it again.
        """
        success, msg = TaskbarHider.show_window(item.data(HwndRole))
        if not success:
            self.status_label.setText(f"Show window failed: {msg}")
            return
        self.status_label.setText(
            f"Shown: {_strip_taskbar_suffix(item.text())}"
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

    @_safe
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

    @_safe
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

    @_safe
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
                targets[hwnd] = (item.data(ExeRole), item.data(PidRole))
        for hwnd, info in self.session.capture_items():
            # covers windows still hidden but no longer listed (tray apps)
            targets.setdefault(hwnd, (info.get("exe", ""), info.get("pid")))

        restored = failed = 0
        for hwnd, (exe, pid) in targets.items():
            if not window_exists(hwnd):
                # the window is gone and its display affinity with it
                self.session.clear_capture(hwnd)
                continue
            if pid is not None and get_window_pid(hwnd) != pid:
                # hwnd value was recycled by an unrelated window: leave that
                # window untouched and drop the stale record
                self.session.clear_capture(hwnd)
                continue
            affinity = WindowCaptureHider.get_window_affinity(hwnd)
            if affinity != WindowCaptureHider.WDA_EXCLUDEFROMCAPTURE:
                # not (or no longer) excluded by us - nothing to undo
                self.session.clear_capture(hwnd)
                continue
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
        box.setIconPixmap(_load_logo_pixmap(36))
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

    @_safe
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

    @_safe
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
            if success:
                # 100% means "back to its original alpha": a window that was
                # translucent on its own returns to e.g. 50%, not to opaque
                actual = WindowOpacity.get_percent(hwnd)
                if actual != value:
                    self._is_syncing_opacity = True
                    self.opacity_slider.setValue(actual)
                    self._is_syncing_opacity = False
                    self.opacity_value_label.setText(f"{actual}%")
        else:
            success, msg = WindowOpacity.set_opacity(hwnd, value)
        if not success:
            self.status_label.setText(f"Opacity change failed: {msg}")

    @_safe
    def on_ime_guard_active(self, active):
        self.status_label.setText(
            "IME candidate windows are excluded from capture."
            if active
            else ""
        )

    @_safe
    def on_ime_guard_error(self, msg):
        self.status_label.setText(
            f"IME candidate protection failed: {msg}"
        )
