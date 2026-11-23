"""Visual theme: cool white-blue with ink text.

A paper-white canvas under a clear blue accent; the blue is reserved for
interaction (switches, slider, selection), amber for cautions, and serif
headings (Sitka Display) for an editorial, unhurried tone. Assets resolve
by absolute path so they work in dev runs and inside a PyInstaller onefile
bundle.
"""

import os

from PyQt5.QtCore import Qt
from PyQt5.QtGui import QColor, QFont, QPalette
from PyQt5.QtWidgets import QApplication, QStyleFactory

# ---- palette -------------------------------------------------------------
BG = "#F3F6FB"          # window canvas (cool paper white)
CARD = "#FFFFFF"        # cards, list, menus
FIELD = "#FFFFFF"       # inputs, viewport
INK = "#182132"         # primary text (blue-black)
TEXT = INK              # alias kept for older call sites
MUTED = "#5D6B80"       # secondary text
FAINT = "#8C97A8"       # tertiary text
LINE = "#E3E9F1"        # hairlines
LINE_STRONG = "#C9D3E1"
BLUE = "#2F6BEB"        # interaction accent (checked, selected, slider)
BLUE_DEEP = "#2457C9"
BLUE_WASH = "#E9F0FD"   # selected row / menu highlight
SLATE = "#54637A"       # mode chips (taskbar)
SLATE_WASH = "#EEF2F8"
WARN = "#9A5B00"        # cautions
WARN_WASH = "#FCF2E0"
DANGER = "#BE3A2B"
ACCENT = BLUE           # alias kept for older call sites

_UI_FONTS = '"Segoe UI Variable Text", "Segoe UI"'
_SERIF = '"Sitka Display", "Sitka Text", Georgia, serif'

_THEMED_PROPERTY = "shadowm_themed"


def asset(name: str) -> str:
    """Absolute path to an asset (dev tree or PyInstaller bundle)."""
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), "assets", name)


def _palette() -> QPalette:
    p = QPalette()
    p.setColor(QPalette.Window, QColor(BG))
    p.setColor(QPalette.WindowText, QColor(INK))
    p.setColor(QPalette.Base, QColor(CARD))
    p.setColor(QPalette.AlternateBase, QColor(BG))
    p.setColor(QPalette.Text, QColor(INK))
    p.setColor(QPalette.Button, QColor(CARD))
    p.setColor(QPalette.ButtonText, QColor(INK))
    p.setColor(QPalette.Highlight, QColor(BLUE_WASH))
    p.setColor(QPalette.HighlightedText, QColor(INK))
    p.setColor(QPalette.ToolTipBase, QColor(INK))
    p.setColor(QPalette.ToolTipText, QColor("#F5F8FD"))
    p.setColor(QPalette.PlaceholderText, QColor(FAINT))
    p.setColor(QPalette.Disabled, QPalette.Text, QColor(FAINT))
    p.setColor(QPalette.Disabled, QPalette.ButtonText, QColor(FAINT))
    p.setColor(QPalette.Disabled, QPalette.WindowText, QColor(MUTED))
    return p


def _stylesheet() -> str:
    return f"""
    QWidget {{
        background: {BG};
        color: {INK};
        font-family: {_UI_FONTS};
        font-size: 9pt;
    }}
    QDialog, QMessageBox {{
        background: {BG};
    }}
    QLabel {{
        background: transparent;
    }}
    QLabel#appTitle {{
        font-family: {_SERIF};
        font-size: 15pt;
        font-weight: 600;
        color: {INK};
    }}
    QLabel#appSubtitle {{
        color: {MUTED};
        font-size: 8.5pt;
    }}
    QLabel#sectionTitle {{
        font-family: {_SERIF};
        font-size: 11pt;
        font-weight: 600;
        color: {INK};
    }}
    QLabel#caption, QLabel#status {{
        color: {MUTED};
        font-size: 8.5pt;
    }}
    QLabel#warning {{
        color: {DANGER};
        font-size: 8.5pt;
    }}
    QLabel#pill {{
        border-radius: 9px;
        padding: 3px 10px;
        font-size: 7.5pt;
        font-weight: 600;
        color: {MUTED};
        background: rgba(24, 33, 50, 0.05);
    }}
    QLabel#pill[accent="good"] {{
        color: {BLUE};
        background: {BLUE_WASH};
    }}
    QLabel#pill[accent="warn"] {{
        color: {WARN};
        background: {WARN_WASH};
    }}
    QFrame#card {{
        background: {CARD};
        border: 1px solid {LINE};
        border-radius: 12px;
    }}
    QFrame#card QLabel, QFrame#card QSlider {{
        background: transparent;
    }}
    QAbstractButton#toggleSwitch {{
        background: transparent;
        font-size: 9pt;
    }}
    QListView#windowList {{
        background: {CARD};
        border: 1px solid {LINE};
        border-radius: 14px;
        padding: 5px;
        outline: 0;
    }}
    QListView#windowList::item {{
        padding: 5px 8px;
        border-radius: 9px;
    }}
    QListView#windowList::item:hover {{
        background: rgba(24, 33, 50, 0.035);
    }}
    QListView#windowList::item:selected {{
        background: transparent;
        color: {INK};
    }}
    QSlider::groove:horizontal {{
        height: 4px;
        border-radius: 2px;
        background: {LINE};
    }}
    QSlider::sub-page:horizontal {{
        background: {BLUE};
        border-radius: 2px;
    }}
    QSlider::handle:horizontal {{
        width: 16px;
        height: 16px;
        margin: -6px 0;
        border-radius: 8px;
        background: {FIELD};
        border: 1.5px solid {LINE_STRONG};
    }}
    QSlider::handle:horizontal:hover {{
        border-color: {BLUE};
    }}
    QSlider::handle:horizontal:disabled {{
        background: {BG};
        border-color: {LINE};
    }}
    QMenu {{
        background: {CARD};
        border: 1px solid {LINE};
        border-radius: 10px;
        padding: 5px;
    }}
    QMenu::item {{
        padding: 7px 26px 7px 12px;
        border-radius: 6px;
        font-size: 9pt;
    }}
    QMenu::item:selected {{
        background: {BLUE_WASH};
        color: {INK};
    }}
    QMenu::item:disabled {{
        color: {FAINT};
    }}
    QMenu::separator {{
        height: 1px;
        background: {LINE};
        margin: 5px 8px;
    }}
    QMessageBox QLabel {{
        color: {INK};
        font-size: 9.5pt;
    }}
    QPushButton {{
        background: {CARD};
        color: {INK};
        border: 1px solid {LINE_STRONG};
        border-radius: 8px;
        padding: 6px 18px;
        min-width: 64px;
    }}
    QPushButton:hover {{
        background: {BG};
    }}
    QPushButton:pressed {{
        background: {LINE};
    }}
    QPushButton:default {{
        background: {BLUE};
        border: 1px solid {BLUE};
        color: {FIELD};
        font-weight: 600;
    }}
    QPushButton:default:hover {{
        background: {BLUE_DEEP};
        border-color: {BLUE_DEEP};
    }}
    QScrollBar:vertical {{
        background: transparent;
        width: 9px;
        margin: 2px;
    }}
    QScrollBar::handle:vertical {{
        background: {LINE_STRONG};
        border-radius: 4px;
        min-height: 24px;
    }}
    QScrollBar::handle:vertical:hover {{
        background: {MUTED};
    }}
    QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{
        height: 0;
    }}
    QScrollBar::add-page:vertical, QScrollBar::sub-page:vertical {{
        background: transparent;
    }}
    QToolTip {{
        background: {INK};
        color: #F5F8FD;
        border: none;
        padding: 6px 9px;
        font-size: 8.5pt;
        border-radius: 6px;
    }}
    """


def apply(app: QApplication):
    """Applies the theme once per process; safe to call repeatedly."""
    if app.property(_THEMED_PROPERTY):
        return
    app.setProperty(_THEMED_PROPERTY, True)
    app.setStyle(QStyleFactory.create("Fusion"))
    app.setPalette(_palette())
    font = QFont("Segoe UI Variable Text", 9)
    font.setStyleStrategy(QFont.PreferAntialias)
    app.setFont(font)
    app.setStyleSheet(_stylesheet())
    # keep the (capture-hidden) main window crisp on high-dpi screens
    app.setAttribute(Qt.AA_UseHighDpiPixmaps, True)
