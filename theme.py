"""Visual theme: warm paper, ink and clay.

Inspired by Anthropic's design language: an ivory canvas, near-black ink,
one clay accent reserved for interaction, olive for "off capture", ochre
for cautions, and Sitka Display serif headings. Assets resolve by absolute
path so they work in dev runs and inside a PyInstaller onefile bundle.
"""

import os

from PyQt5.QtCore import Qt
from PyQt5.QtGui import QColor, QFont, QPalette
from PyQt5.QtWidgets import QApplication, QStyleFactory

# ---- palette -------------------------------------------------------------
BG = "#F0EEE6"          # window canvas (warm ivory)
CARD = "#FAF9F5"        # cards, list, menus
FIELD = "#FBF9F4"       # inputs, viewport
INK = "#1F1E1D"         # primary text
TEXT = INK              # alias kept for older call sites
MUTED = "#6E6B62"       # secondary text
FAINT = "#857F73"       # tertiary text
LINE = "#E3DFD4"        # hairlines
LINE_STRONG = "#D2CCBE"
CLAY = "#C15F3C"        # interaction accent (checked, selected, slider)
CLAY_DEEP = "#A94E2E"
CLAY_WASH = "#F2E7DE"   # selected row / menu highlight
OLIVE = "#5A7048"       # off capture (protected)
OLIVE_WASH = "#ECEFE4"
OCHRE = "#8A5F1C"       # warnings
OCHRE_WASH = "#F5ECD9"
DANGER = "#A63A2A"
ACCENT = CLAY           # alias kept for older call sites

_UI_FONTS = '"Segoe UI Variable Text", "Segoe UI"'
_SERIF = '"Sitka Display", "Sitka Text", Georgia, serif'

_THEMED_PROPERTY = "shadowm_themed"


def asset(name: str) -> str:
    """Absolute path to an asset (dev tree or PyInstaller bundle)."""
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), "assets", name)


def _url(name: str) -> str:
    return asset(name).replace("\\", "/")


def _palette() -> QPalette:
    p = QPalette()
    p.setColor(QPalette.Window, QColor(BG))
    p.setColor(QPalette.WindowText, QColor(INK))
    p.setColor(QPalette.Base, QColor(CARD))
    p.setColor(QPalette.AlternateBase, QColor(BG))
    p.setColor(QPalette.Text, QColor(INK))
    p.setColor(QPalette.Button, QColor(CARD))
    p.setColor(QPalette.ButtonText, QColor(INK))
    p.setColor(QPalette.Highlight, QColor(CLAY_WASH))
    p.setColor(QPalette.HighlightedText, QColor(INK))
    p.setColor(QPalette.ToolTipBase, QColor(INK))
    p.setColor(QPalette.ToolTipText, QColor("#F7F4EC"))
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
        background: rgba(31, 30, 29, 0.05);
    }}
    QLabel#pill[accent="good"] {{
        color: {OLIVE};
        background: {OLIVE_WASH};
    }}
    QLabel#pill[accent="warn"] {{
        color: {OCHRE};
        background: {OCHRE_WASH};
    }}
    QFrame#card {{
        background: {CARD};
        border: 1px solid {LINE};
        border-radius: 12px;
    }}
    QFrame#card QLabel, QFrame#card QCheckBox, QFrame#card QSlider {{
        background: transparent;
    }}
    QFrame#hairline {{
        background: {LINE};
        border: none;
        max-height: 1px;
    }}
    QCheckBox {{
        background: transparent;
        spacing: 11px;
        font-size: 9pt;
    }}
    QCheckBox::indicator {{
        width: 34px;
        height: 20px;
        image: url({_url("switch_off.svg")});
    }}
    QCheckBox::indicator:checked {{
        image: url({_url("switch_on.svg")});
    }}
    QListView#windowList {{
        background: {CARD};
        border: 1px solid {LINE};
        border-radius: 14px;
        padding: 5px;
        outline: 0;
    }}
    QListView#windowList::item {{
        padding: 4px 6px;
        border-radius: 8px;
    }}
    QListView#windowList::item:hover {{
        background: rgba(31, 30, 29, 0.045);
    }}
    QListView#windowList::item:selected {{
        background: {CLAY_WASH};
        color: {INK};
    }}
    QListView#windowList::indicator {{
        width: 18px;
        height: 18px;
        image: url({_url("check_off.svg")});
    }}
    QListView#windowList::indicator:checked {{
        image: url({_url("check.svg")});
    }}
    QSlider::groove:horizontal {{
        height: 4px;
        border-radius: 2px;
        background: {LINE};
    }}
    QSlider::sub-page:horizontal {{
        background: {CLAY};
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
        border-color: {CLAY};
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
        background: {CLAY_WASH};
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
        background: {CLAY};
        border: 1px solid {CLAY};
        color: {FIELD};
        font-weight: 600;
    }}
    QPushButton:default:hover {{
        background: {CLAY_DEEP};
        border-color: {CLAY_DEEP};
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
        color: #F7F4EC;
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
