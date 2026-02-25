"""Display and formatting utilities for Runoff.

Provides a themed Rich console singleton and re-exports display functions.
"""

from __future__ import annotations

from rich.console import Console

from runoff.display.theme import CATPPUCCIN_MOCHA

# Themed console singleton — all output goes through this
console = Console(theme=CATPPUCCIN_MOCHA, highlight=False)

# Re-export core types
from runoff.display.colors import Severity  # noqa: E402


# Lazy imports for display functions (avoids circular imports)
def __getattr__(name):
    if name in (
        "print_header",
        "print_subheader",
        "print_warning",
        "print_table",
        "print_node_info",
        "print_severity_summary",
    ):
        from runoff.display import tables

        return getattr(tables, name)
    if name == "print_path":
        from runoff.display.paths import print_path

        return print_path
    if name == "print_banner":
        from runoff.display.banner import print_banner

        return print_banner
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


__all__ = [
    "console",
    "Severity",
    "print_header",
    "print_subheader",
    "print_warning",
    "print_table",
    "print_node_info",
    "print_severity_summary",
    "print_path",
    "print_banner",
]
