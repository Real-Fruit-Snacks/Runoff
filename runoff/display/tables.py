"""Table and header display functions — Rich-based implementation."""

from __future__ import annotations

from typing import Any

from rich import box
from rich.table import Table
from rich.text import Text

from runoff.core.config import config
from runoff.core.utils import format_timestamp, is_unix_timestamp
from runoff.display import console
from runoff.display.colors import Severity
from runoff.display.theme import MOCHA

# ---------------------------------------------------------------------------
# Severity → hex colour mapping (for inline badge markup)
# ---------------------------------------------------------------------------

_SEV_HEX: dict[str, str] = {
    "CRITICAL": MOCHA["red"],
    "HIGH": MOCHA["maroon"],
    "MEDIUM": MOCHA["peach"],
    "LOW": MOCHA["yellow"],
    "INFO": MOCHA["overlay1"],
}


def _sev_style(severity: Severity) -> str:
    """Return a Rich style string for *severity*, matching the theme."""
    if severity == Severity.CRITICAL:
        return f"bold {_SEV_HEX['CRITICAL']}"
    return _SEV_HEX.get(severity.label, MOCHA["overlay1"])


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def print_header(
    text: str, severity: Severity | None = None, result_count: int | None = None
) -> bool:
    """Print a section header with optional severity badge.

    Returns True if output should continue, False if quiet mode and no results,
    or if output format is not table (JSON/CSV/HTML mode).
    """
    if config.output_format != "table":
        return False

    if config.quiet_mode and result_count is not None and result_count == 0:
        return False

    show_severity = (
        severity is not None
        and severity != Severity.INFO
        and result_count is not None
        and result_count > 0
    )

    line = Text()
    line.append("\n[*] ", style="header")

    if show_severity and severity is not None:
        hex_col = _SEV_HEX.get(severity.label, MOCHA["overlay1"])
        sev_style = f"bold {hex_col}" if severity == Severity.CRITICAL else hex_col
        line.append(f"[{severity.label}]", style=sev_style)
        line.append(" ", style="header")

    line.append(text, style="header")
    console.print(line)
    return True


def print_subheader(text: str) -> None:
    """Print a sub-section header (only in table mode)."""
    if config.output_format != "table":
        return
    console.print(f"    {text}", style="subheader")


def print_warning(text: str) -> None:
    """Print a warning message (only in table mode)."""
    if config.output_format != "table":
        return
    console.print(f"    {text}", style="warning")


def print_severity_summary(severity_counts: dict[Severity, int]) -> None:
    """Print summary of findings by severity level (only in table mode)."""
    if config.output_format != "table":
        return

    has_findings = any(count > 0 for sev, count in severity_counts.items() if sev != Severity.INFO)
    if not has_findings:
        console.print("\n[+] No security findings detected", style="success")
        return

    console.print("\n[*] Findings Summary", style="header")
    for sev in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW):
        count = severity_counts.get(sev, 0)
        if count > 0:
            label_word = "query" if count == 1 else "queries"
            style = _sev_style(sev)
            console.print(f"    [{style}]{sev.label}[/{style}]: {count} {label_word} with findings")


def print_table(headers: list[str], rows: list[list[Any]], max_width: int = 65) -> None:
    """Print a Rich-formatted table with owned principal highlighting (only in table mode)."""
    if config.output_format != "table":
        return

    if not rows:
        print_warning("No results found")
        return

    table = Table(
        box=box.ROUNDED,
        border_style="border",
        header_style="table.header",
        show_lines=True,
        expand=False,
    )

    for header in headers:
        table.add_column(header, overflow="fold", max_width=max_width, no_wrap=False)

    for row in rows:
        rich_row: list[Text | str] = []

        for val in row:
            if val is None:
                rich_row.append(Text("-", style="text.muted"))

            elif isinstance(val, list):
                parts = ", ".join(str(v) for v in val[:3])
                if len(val) > 3:
                    parts += f" (+{len(val) - 3} more)"
                rich_row.append(parts)

            elif isinstance(val, bool):
                rich_row.append(Text(str(val), style="success" if val else "error"))

            elif isinstance(val, (int, float)) and is_unix_timestamp(val):
                rich_row.append(format_timestamp(val))

            elif isinstance(val, str):
                _owned_status = config.owned_cache.get(val)
                if _owned_status is not None:
                    is_admin = _owned_status
                    # ♦ prefix: red for admin-owned, pink for non-admin-owned
                    badge_style = "error" if is_admin else "owned"
                    cell = Text()
                    cell.append("♦ ", style=badge_style)
                    display_val = val
                    if len(val) > max_width - 4:
                        truncate_at = max(1, max_width - 7)
                        display_val = val[:truncate_at] + "..."
                    cell.append(display_val)
                    rich_row.append(cell)
                else:
                    display_val = val
                    if len(val) > max_width:
                        truncate_at = max(1, max_width - 3)
                        display_val = val[:truncate_at] + "..."
                    rich_row.append(display_val)

            else:
                rich_row.append(str(val))

        table.add_row(*rich_row)

    console.print(table)


def print_node_info(node_props: dict[str, Any]) -> None:
    """Pretty-print node properties in a Rich table (only in table mode)."""
    if config.output_format != "table":
        return

    labels = node_props.get("_labels") or []
    console.print(f"    [bold]Labels:[/bold] {', '.join(labels)}")
    console.print("    [bold]Properties:[/bold]")

    # Security-relevant properties shown first
    priority_keys = [
        "name",
        "domain",
        "objectid",
        "enabled",
        "admincount",
        "hasspn",
        "dontreqpreauth",
        "unconstraineddelegation",
    ]

    sorted_keys: list[str] = []
    for key in priority_keys:
        if key in node_props:
            sorted_keys.append(key)
    for key in sorted(node_props.keys()):
        if key not in sorted_keys and key != "_labels":
            sorted_keys.append(key)

    prop_table = Table(
        box=box.SIMPLE,
        show_header=False,
        border_style="border",
        padding=(0, 1),
    )
    prop_table.add_column("Key", style="node", no_wrap=True)
    prop_table.add_column("Value", overflow="fold")

    for key in sorted_keys:
        value = node_props[key]

        if value is None:
            val_text = Text("-", style="text.muted")

        elif isinstance(value, list):
            parts = ", ".join(str(v) for v in value[:5])
            if len(value) > 5:
                parts += f" (+{len(value) - 5} more)"
            val_text = Text(parts)

        elif isinstance(value, bool):
            val_text = Text(str(value), style="success" if value else "error")

        elif isinstance(value, (int, float)) and is_unix_timestamp(value):
            val_text = Text(format_timestamp(value))

        else:
            val_text = Text(str(value))

        prop_table.add_row(f"{key}:", val_text)

    console.print(prop_table)
