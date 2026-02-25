"""Catppuccin Mocha theme for Rich console output."""

from __future__ import annotations

from rich.theme import Theme

# Catppuccin Mocha palette
MOCHA = {
    "rosewater": "#f5e0dc",
    "flamingo": "#f2cdcd",
    "pink": "#f5c2e7",
    "mauve": "#cba6f7",
    "red": "#f38ba8",
    "maroon": "#eba0ac",
    "peach": "#fab387",
    "yellow": "#f9e2af",
    "green": "#a6e3a1",
    "teal": "#94e2d5",
    "sky": "#89dceb",
    "sapphire": "#74c7ec",
    "blue": "#89b4fa",
    "lavender": "#b4befe",
    "text": "#cdd6f4",
    "subtext1": "#bac2de",
    "subtext0": "#a6adc8",
    "overlay2": "#9399b2",
    "overlay1": "#7f849c",
    "overlay0": "#6c7086",
    "surface2": "#585b70",
    "surface1": "#45475a",
    "surface0": "#313244",
    "base": "#1e1e2e",
    "mantle": "#181825",
    "crust": "#11111b",
}

CATPPUCCIN_MOCHA = Theme(
    {
        # Base text
        "text": MOCHA["text"],
        "text.secondary": MOCHA["subtext1"],
        "text.dim": MOCHA["subtext0"],
        "text.muted": MOCHA["overlay0"],
        # Severity levels
        "severity.critical": f"bold {MOCHA['red']}",
        "severity.high": MOCHA["maroon"],
        "severity.medium": MOCHA["peach"],
        "severity.low": MOCHA["yellow"],
        "severity.info": MOCHA["overlay1"],
        # Semantic
        "success": MOCHA["green"],
        "warning": MOCHA["yellow"],
        "error": MOCHA["red"],
        "info": MOCHA["blue"],
        # Components
        "header": f"bold {MOCHA['blue']}",
        "subheader": MOCHA["lavender"],
        "border": MOCHA["surface1"],
        "panel.title": f"bold {MOCHA['text']}",
        # Domain-specific
        "node": MOCHA["sapphire"],
        "edge": MOCHA["mauve"],
        "path": MOCHA["teal"],
        "owned": f"bold {MOCHA['pink']}",
        "command": MOCHA["green"],
        "count": f"bold {MOCHA['flamingo']}",
        "banner": f"bold {MOCHA['rosewater']}",
        # Progress
        "progress.bar": MOCHA["sky"],
        "progress.label": MOCHA["subtext1"],
        # Table
        "table.header": f"bold {MOCHA['blue']}",
        "table.border": MOCHA["surface1"],
    }
)
