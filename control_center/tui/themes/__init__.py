"""Theme engine — supports multiple terminal themes with hot-swap."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

logger = logging.getLogger("control_center.tui.themes")

_THEMES_DIR = Path(__file__).parent

AVAILABLE_THEMES = {
    "dark": "theme_dark.tcss",
    "light": "theme_light.tcss",
    "solarized": "theme_solarized.tcss",
    "monokai": "theme_monokai.tcss",
    "hacker": "theme_hacker.tcss",
}

DEFAULT_THEME = "dark"


def get_theme_path(name: str) -> Path:
    filename = AVAILABLE_THEMES.get(name, AVAILABLE_THEMES[DEFAULT_THEME])
    return _THEMES_DIR / filename


def list_themes() -> list[dict[str, Any]]:
    return [
        {"id": tid, "file": fname, "available": (_THEMES_DIR / fname).exists()}
        for tid, fname in AVAILABLE_THEMES.items()
    ]


def load_theme_css(name: str) -> str:
    path = get_theme_path(name)
    if path.exists():
        return path.read_text()
    return get_theme_path(DEFAULT_THEME).read_text()
