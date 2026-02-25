"""Severity levels and color utilities for Runoff display output.

Uses Catppuccin Mocha palette via Rich styles. The legacy `colors` object is
preserved for backward compatibility with query files that reference it, but
new code should use Rich markup via the console singleton.
"""

from __future__ import annotations

from enum import Enum

from runoff.display.theme import MOCHA


def _no_color() -> bool:
    """Check if color output is disabled."""
    from runoff.core.config import config

    return config.no_color


class Severity(Enum):
    """Severity levels for findings with associated Rich styles."""

    CRITICAL = ("CRITICAL", f"bold {MOCHA['red']}", MOCHA["red"])
    HIGH = ("HIGH", MOCHA["maroon"], MOCHA["maroon"])
    MEDIUM = ("MEDIUM", MOCHA["peach"], MOCHA["peach"])
    LOW = ("LOW", MOCHA["yellow"], MOCHA["yellow"])
    INFO = ("INFO", MOCHA["overlay1"], MOCHA["overlay1"])

    @property
    def label(self):
        return self.value[0]

    @property
    def style(self):
        """Rich style string for this severity."""
        return self.value[1]

    @property
    def hex(self):
        """Hex color for this severity."""
        return self.value[2]

    @property
    def color(self):
        """Legacy ANSI color code for backward compatibility with query files."""
        if _no_color():
            return ""
        # Map Catppuccin hex to ANSI approximations for legacy code paths
        _ansi_map = {
            "CRITICAL": "\033[91m\033[1m",
            "HIGH": "\033[91m",
            "MEDIUM": "\033[38;5;208m",
            "LOW": "\033[93m",
            "INFO": "\033[90m",
        }
        return _ansi_map.get(self.label, "")


class Colors:
    """Legacy ANSI color codes for backward compatibility.

    Query files reference `colors.BOLD`, `colors.END`, etc. This class
    preserves that interface. New code should use Rich markup instead.
    """

    _HEADER = "\033[95m"
    _BLUE = "\033[94m"
    _CYAN = "\033[96m"
    _GREEN = "\033[92m"
    _WARNING = "\033[93m"
    _FAIL = "\033[91m"
    _END = "\033[0m"
    _BOLD = "\033[1m"
    _WHITE = "\033[97m"
    _GRAY = "\033[90m"

    @classmethod
    def _c(cls, code: str) -> str:
        return "" if _no_color() else code

    @property
    def HEADER(self) -> str:
        return self._c(self._HEADER)

    @property
    def BLUE(self) -> str:
        return self._c(self._BLUE)

    @property
    def CYAN(self) -> str:
        return self._c(self._CYAN)

    @property
    def GREEN(self) -> str:
        return self._c(self._GREEN)

    @property
    def WARNING(self) -> str:
        return self._c(self._WARNING)

    @property
    def FAIL(self) -> str:
        return self._c(self._FAIL)

    @property
    def END(self) -> str:
        return self._c(self._END)

    @property
    def BOLD(self) -> str:
        return self._c(self._BOLD)

    @property
    def WHITE(self) -> str:
        return self._c(self._WHITE)

    @property
    def GRAY(self) -> str:
        return self._c(self._GRAY)


# Singleton for backward compatibility
colors = Colors()
