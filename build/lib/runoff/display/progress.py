"""Rich Progress components for query execution display."""

from __future__ import annotations

from rich.progress import (
    BarColumn,
    Progress,
    SpinnerColumn,
    TaskProgressColumn,
    TextColumn,
    TimeRemainingColumn,
)

from runoff.display import console


def create_query_progress() -> Progress:
    """Return a configured Progress instance for query execution.

    Uses SpinnerColumn (sky style), a text description column, a progress bar
    (sky while running, green when complete), task progress, and time remaining.
    The progress bar is transient — it disappears from the terminal when done.
    """
    return Progress(
        SpinnerColumn(style="#89dceb"),
        TextColumn("[progress.label]{task.description}"),
        BarColumn(complete_style="#89dceb", finished_style="#a6e3a1"),
        TaskProgressColumn(),
        TimeRemainingColumn(),
        console=console,
        transient=True,
    )


def print_query_status(current: int, total: int, name: str) -> None:
    """Print a single-line query status for quiet mode.

    Format: [current/total] name

    Args:
        current: Index of the query currently running (1-based).
        total: Total number of queries to run.
        name: Display name of the current query.
    """
    console.print(f"[text.dim]\\[{current}/{total}][/] {name}")
