"""Reusable Rich Panel components for the runoff display system."""

from __future__ import annotations

from typing import Any

from rich import box
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from runoff.display import console
from runoff.display.theme import MOCHA


def print_error(message: str, details: Any = None) -> None:
    """Print a red-bordered error panel.

    Args:
        message: Primary error message shown as panel title content.
        details: Optional extra detail. If a list, rendered as bullet points;
                 otherwise rendered as a plain string below the message.
    """
    content = Text()
    content.append(message, style=f"bold {MOCHA['red']}")

    if details is not None:
        if isinstance(details, list):
            for item in details:
                content.append(f"\n  • {item}", style=MOCHA["text"])
        else:
            content.append(f"\n{details}", style=MOCHA["subtext1"])

    panel = Panel(
        content,
        title="[bold red]Error[/]",
        box=box.ROUNDED,
        border_style="error",
        padding=(0, 1),
    )
    console.print(panel)


def print_info_panel(title: str, content_dict: dict[str, Any]) -> None:
    """Print a panel containing key-value pairs.

    Keys are rendered in subtext1 style, values in text style. Suitable for
    node info, connection status displays, and similar structured output.

    Args:
        title: Panel title.
        content_dict: Ordered mapping of label -> value pairs.
    """
    table = Table(box=None, show_header=False, padding=(0, 1), expand=False)
    table.add_column("key", style="subtext1", no_wrap=True)
    table.add_column("value", style="text")

    for key, value in content_dict.items():
        if value is None:
            value_str = "-"
        elif isinstance(value, bool):
            value_str = "[success]True[/]" if value else "[error]False[/]"
        elif isinstance(value, list):
            value_str = ", ".join(str(v) for v in value[:5])
            if len(value) > 5:
                value_str += f" [text.dim](+{len(value) - 5} more)[/]"
        else:
            value_str = str(value)
        table.add_row(f"{key}:", value_str)

    panel = Panel(
        table,
        title=f"[panel.title]{title}[/]",
        box=box.ROUNDED,
        border_style="border",
        padding=(0, 1),
    )
    console.print(panel)


def print_finding_panel(
    title: str,
    severity: Any,
    count: int,
    content: Any,
) -> None:
    """Print a findings panel with severity badge and result count.

    Args:
        title: Finding name / query title.
        severity: A Severity enum value (provides .label and .style).
        count: Number of results found.
        content: Any Rich renderable (Table, Text, Group, etc.).
    """
    badge = Text()
    badge.append(f" {severity.label} ", style=f"bold {severity.style} on {MOCHA['surface0']}")

    title_text = Text()
    title_text.append_text(badge)
    title_text.append(f"  {title}", style="panel.title")

    count_label = Text(f"{count} result{'s' if count != 1 else ''}", style="count")

    panel = Panel(
        content,
        title=title_text,
        title_align="left",
        subtitle=count_label,
        subtitle_align="right",
        box=box.ROUNDED,
        border_style="border",
        padding=(0, 1),
    )
    console.print(panel)


def print_success(message: str) -> None:
    """Print a green-styled success message with a checkmark.

    Args:
        message: The success message to display.
    """
    text = Text()
    text.append("✓ ", style="success bold")
    text.append(message, style="success")
    console.print(text)


def print_status(label: str, value: str, good: bool = True) -> None:
    """Print a single status line with a pass/fail indicator.

    Renders: "✓" (green) or "✗" (red), followed by label and value.

    Args:
        label: Short description of what is being reported.
        value: The current value or state.
        good: True renders a green checkmark, False renders a red cross.
    """
    text = Text()
    if good:
        text.append("✓ ", style="success bold")
    else:
        text.append("✗ ", style="error bold")
    text.append(f"{label}: ", style="subtext1")
    text.append(value, style="text")
    console.print(text)
