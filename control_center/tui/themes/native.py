"""Native Textual themes (premium dark, low-saturation).

Registers custom themes via Textual's native theming so the whole UI restyles
through theme variables ($primary/$surface/$panel/$accent/...). This is separate
from the legacy ``control_center.tui.themes`` TCSS module (kept untouched for
back-compat); colour is driven here, structure by ``app.tcss``.

``HYDRA_THEMES`` lists the user-selectable themes (custom + a few built-ins).
``DEFAULT_THEME`` is the launch theme.
"""

from __future__ import annotations

from textual.app import App
from textual.theme import Theme

DEFAULT_THEME = "hydra-dark"

# Selectable themes shown in the picker / palette (built-ins resolved by Textual).
HYDRA_THEMES = ["hydra-dark", "claude-dark", "tokyo-night", "nord", "dracula"]

_HYDRA_DARK = Theme(
    name="hydra-dark",
    primary="#7aa2f7",
    secondary="#7dcfff",
    accent="#7dcfff",
    foreground="#c9d1d9",
    background="#0d1117",
    surface="#0d1117",
    panel="#161b22",
    success="#9ece6a",
    warning="#e0af68",
    error="#f7768e",
    dark=True,
    variables={
        "border": "#30363d",
        "scrollbar": "#30363d",
        "footer-key-foreground": "#7dcfff",
    },
)

_CLAUDE_DARK = Theme(
    name="claude-dark",
    primary="#cc785c",
    secondary="#d9a066",
    accent="#d9a066",
    foreground="#e8e6e3",
    background="#1a1714",
    surface="#1a1714",
    panel="#262320",
    success="#7fae6a",
    warning="#d9a066",
    error="#d9685f",
    dark=True,
    variables={
        "border": "#3a352f",
        "scrollbar": "#3a352f",
        "footer-key-foreground": "#d9a066",
    },
)

_CUSTOM = (_HYDRA_DARK, _CLAUDE_DARK)


def register_hydra_themes(app: App) -> None:
    """Register HYDRA's custom themes on an app (idempotent)."""
    for theme in _CUSTOM:
        try:
            app.register_theme(theme)
        except Exception:
            pass


def resolve_theme(name: str) -> str:
    """Map a possibly-legacy theme id onto a valid native theme name."""
    if name in HYDRA_THEMES:
        return name
    # Legacy tcss ids → sensible native equivalents.
    legacy = {
        "dark": "hydra-dark",
        "light": "textual-light",
        "monokai": "monokai",
        "solarized": "solarized-dark",
        "hacker": "hydra-dark",
    }
    return legacy.get(name, DEFAULT_THEME)
