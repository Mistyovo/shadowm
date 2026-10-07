"""Visual theme: dark "stealth utility" skin.

Palette (Minimalism / Swiss, dark): deep slate background, lighter card
panels, one green accent that always means "protected/hidden", muted
text for secondary information. The check asset is resolved by absolute
path so it works in dev runs and inside a PyInstaller onefile bundle.
"""

import os

from PyQt5.QtCore import Qt
from PyQt5.QtGui import QColor, QFont, QPalette
from PyQt5.QtWidgets import QApplication, QStyleFactory

BG = "#0F172A"        # window background
CARD = "#192134"      # list / menu / dialog panels
FIELD = "#131C2E"     # inputs, list viewport
PRIMARY = "#1E3A5F"   # selected rows, buttons
ACCENT = "#22C55E"    # checked = protected
TEXT = "#F1F5F9"
MUTED = "#94A3B8"
DANGER = "#F87171"

_THEMED_PROPERTY = "shadowm_themed"


def _check_image() -> str:
    """QSS image url for the checked indicator, or '' if asset missing."""
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "assets", "check.svg")
    if not os.path.isfile(path):
        return ""
    return path.replace("\\", "/")


def _palette() -> QPalette:
    p = QPalette()
    p.setColor(QPalette.Window, QColor(BG))
    p.setColor(QPalette.WindowText, QColor(TEXT))
    p.setColor(QPalette.Base, QColor(FIELD))
    p.setColor(QPalette.AlternateBase, QColor(CARD))
    p.setColor(QPalette.Text, QColor(TEXT))
    p.setColor(QPalette.Button, QColor(PRIMARY))
    p.setColor(QPalette.ButtonText, QColor(TEXT))
    p.setColor(QPalette.Highlight, QColor(PRIMARY))
    p.setColor(QPalette.HighlightedText, QColor(TEXT))
    p.setColor(QPalette.ToolTipBase, QColor(CARD))
    p.setColor(QPalette.ToolTipText, QColor(TEXT))
    p.setColor(QPalette.PlaceholderText, QColor(MUTED))
    p.setColor(QPalette.Disabled, QPalette.Text, QColor(MUTED))
    p.setColor(QPalette.Disabled, QPalette.ButtonText, QColor(MUTED))
    return p


def _stylesheet() -> str:
    check = _check_image()
    checked_image = f"image: url({check});" if check else ""
    return f"""
    QWidget {{
        background: {BG};
        color: {TEXT};
        font-family: "Segoe UI", "Inter", sans-serif;
        font-size: 9pt;
    }}
    QLabel#caption {{
        color: {MUTED};
        font-size: 8.5pt;
    }}
    QLabel#status {{
        color: {MUTED};
        font-size: 8.5pt;
    }}
    QLabel#warning {{
        color: {DANGER};
        font-size: 8.5pt;
    }}
    QListView#windowList {{
        background: {CARD};
        border: 1px solid rgba(255, 255, 255, 0.08);
        border-radius: 8px;
        padding: 4px;
        outline: 0;
    }}
    QListView#windowList::item {{
        padding: 5px 6px;
        border-radius: 6px;
    }}
    QListView#windowList::item:hover {{
        background: rgba(255, 255, 255, 0.06);
    }}
    QListView#windowList::item:selected {{
        background: {PRIMARY};
        color: {TEXT};
    }}
    QListView#windowList::item:focus {{
        border: 1px solid {ACCENT};
    }}
    QCheckBox, QListView#windowList::item {{
        spacing: 8px;
    }}
    QCheckBox::indicator, QListView::indicator {{
        width: 16px;
        height: 16px;
        border: 1.5px solid rgba(255, 255, 255, 0.35);
        border-radius: 4px;
        background: transparent;
    }}
    QCheckBox::indicator:hover, QListView::indicator:hover {{
        border-color: {ACCENT};
    }}
    QCheckBox::indicator:checked, QListView::indicator:checked {{
        background: {ACCENT};
        border-color: {ACCENT};
        {checked_image}
    }}
    QSlider::groove:horizontal {{
        height: 4px;
        border-radius: 2px;
        background: #334155;
    }}
    QSlider::sub-page:horizontal {{
        background: {ACCENT};
        border-radius: 2px;
    }}
    QSlider::handle:horizontal {{
        width: 14px;
        height: 14px;
        margin: -5px 0;
        border-radius: 7px;
        background: #E2E8F0;
    }}
    QSlider::handle:horizontal:hover {{
        background: #FFFFFF;
    }}
    QSlider::handle:horizontal:disabled {{
        background: #475569;
    }}
    QMenu {{
        background: {CARD};
        border: 1px solid rgba(255, 255, 255, 0.10);
        border-radius: 8px;
        padding: 4px;
    }}
    QMenu::item {{
        padding: 6px 24px 6px 12px;
        border-radius: 4px;
    }}
    QMenu::item:selected {{
        background: {PRIMARY};
    }}
    QMenu::item:disabled {{
        color: #64748B;
    }}
    QMenu::separator {{
        height: 1px;
        background: rgba(255, 255, 255, 0.10);
        margin: 4px 8px;
    }}
    QMessageBox {{
        background: {CARD};
    }}
    QMessageBox QLabel {{
        background: transparent;
        color: {TEXT};
        font-size: 9.5pt;
    }}
    QPushButton {{
        background: {PRIMARY};
        color: {TEXT};
        border: 1px solid rgba(255, 255, 255, 0.12);
        border-radius: 6px;
        padding: 5px 18px;
    }}
    QPushButton:hover {{
        background: #274A77;
    }}
    QPushButton:pressed {{
        background: #16304F;
    }}
    QPushButton:default {{
        border: 1px solid {ACCENT};
    }}
    QScrollBar:vertical {{
        background: transparent;
        width: 8px;
        margin: 2px;
    }}
    QScrollBar::handle:vertical {{
        background: #334155;
        border-radius: 4px;
        min-height: 24px;
    }}
    QScrollBar::handle:vertical:hover {{
        background: #475569;
    }}
    QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{
        height: 0;
    }}
    QScrollBar::add-page:vertical, QScrollBar::sub-page:vertical {{
        background: transparent;
    }}
    """


def apply(app: QApplication):
    """Applies the theme once per process; safe to call repeatedly."""
    if app.property(_THEMED_PROPERTY):
        return
    app.setProperty(_THEMED_PROPERTY, True)
    app.setStyle(QStyleFactory.create("Fusion"))
    app.setPalette(_palette())
    font = QFont("Segoe UI", 9)
    font.setStyleStrategy(QFont.PreferAntialias)
    app.setFont(font)
    app.setStyleSheet(_stylesheet())
    # keep the (capture-hidden) main window crisp on high-dpi screens
    app.setAttribute(Qt.AA_UseHighDpiPixmaps, True)
