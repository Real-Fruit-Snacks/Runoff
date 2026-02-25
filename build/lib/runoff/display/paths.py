"""Attack path display functions using Rich Tree and Table."""

from __future__ import annotations

from rich import box
from rich.table import Table
from rich.tree import Tree

from runoff.core.config import config
from runoff.display import console

# Maximum paths to display
MAX_PATHS_DISPLAY = 10


def _format_node_short(node_name: str | None) -> str:
    """Strip domain suffix for compact display."""
    if node_name is None:
        return "Unknown"
    if "@" in node_name:
        return node_name.split("@")[0]
    return node_name


def _format_node_with_owned(node_name: str | None, use_short: bool = True) -> str:
    """Return Rich markup string for a node, adding owned marker if applicable."""
    short_name = _format_node_short(node_name) if use_short else (node_name or "Unknown")

    _owned_status = config.owned_cache.get(node_name) if node_name else None
    if _owned_status is not None:
        is_admin = _owned_status
        if is_admin:
            return f"[owned]♦ {short_name}[/owned]"
        else:
            return f"[owned]{short_name}[/owned]"
    return f"[node]{short_name}[/node]"


def print_paths_grouped(results: list[dict], max_display: int = MAX_PATHS_DISPLAY):
    """Display paths in a table format with full path information.

    Args:
        results: List of path dictionaries from query
        max_display: Maximum number of paths to display (default 10)
    """
    if config.output_format != "table":
        return

    if not results:
        return

    sorted_results = sorted(results, key=lambda p: p.get("path_length", 0))
    display_results = sorted_results[:max_display]
    hidden_count = len(sorted_results) - len(display_results)

    table = Table(
        box=box.SIMPLE,
        show_header=True,
        header_style="table.header",
        border_style="border",
        show_edge=False,
        pad_edge=False,
    )
    table.add_column("Hops", style="count", justify="right", no_wrap=True, min_width=4)
    table.add_column("Attack Path", style="text", no_wrap=False)

    for r in display_results:
        nodes = r.get("nodes") or []
        rels = r.get("relationships") or []
        path_len = r.get("path_length") or (len(nodes) - 1 if nodes else 0)

        if not nodes:
            continue

        # Build Rich markup path string: node -[rel]-> node ...
        parts: list[str] = []
        for i, node in enumerate(nodes):
            parts.append(_format_node_with_owned(node, use_short=True))
            if i < len(rels):
                parts.append(f"[edge] ──[{rels[i]}]──▸ [/edge]")

        path_markup = "".join(parts)
        table.add_row(str(path_len), path_markup)

    console.print(table)

    if hidden_count > 0:
        console.print(f"  [text.muted]... and {hidden_count} more path(s) not shown[/text.muted]")


def print_path(path_data: dict):
    """Pretty-print a single attack path."""
    if config.output_format != "table":
        return

    print_paths_grouped([path_data], max_display=1)


def print_paths_detailed(results: list[dict], max_display: int = 5):
    """Display paths with full detail using Rich Tree for each path.

    Use this for critical paths where users need to see every step.

    Args:
        results: List of path dictionaries from query
        max_display: Maximum number of paths to show in detail
    """
    if config.output_format != "table":
        return

    if not results:
        return

    sorted_results = sorted(results, key=lambda p: p.get("path_length", 0))
    display_results = sorted_results[:max_display]
    hidden_count = len(sorted_results) - len(display_results)

    for idx, r in enumerate(display_results, start=1):
        nodes = r.get("nodes") or []
        node_types = r.get("node_types") or []
        rels = r.get("relationships") or []

        if not nodes:
            continue

        path_len = r.get("path_length", len(nodes) - 1)
        hop_label = "hop" if path_len == 1 else "hops"

        tree = Tree(
            f"[path]Path {idx}[/path] [text.dim]({path_len} {hop_label})[/text.dim]",
            guide_style="border",
        )

        for i, node in enumerate(nodes):
            type_str = f" [text.muted]({node_types[i]})[/text.muted]" if i < len(node_types) else ""
            node_markup = _format_node_with_owned(node, use_short=False) + type_str

            if i < len(rels):
                # Add node as a branch, then attach the relationship arrow as its child
                branch = tree.add(node_markup)
                branch.add(f"[edge]──[{rels[i]}]──▸[/edge]")
            else:
                tree.add(node_markup)

        console.print(tree)

    if hidden_count > 0:
        console.print(f"  [text.muted]... and {hidden_count} more path(s) not shown[/text.muted]")


def print_paths_summary(results: list[dict]):
    """Print a summary table of paths without full details.

    Shows unique starting nodes and their shortest path lengths.
    """
    if config.output_format != "table":
        return

    if not results:
        return

    by_start: dict[str, dict] = {}
    for r in results:
        nodes = r.get("nodes") or []
        if not nodes:
            continue
        start = nodes[0]
        path_len = r.get("path_length") or (len(nodes) - 1)
        target = nodes[-1] if nodes else ""

        if start not in by_start:
            by_start[start] = {"min_hops": path_len, "count": 0, "targets": set()}
        by_start[start]["count"] += 1
        by_start[start]["min_hops"] = min(by_start[start]["min_hops"], path_len)
        by_start[start]["targets"].add(target)

    table = Table(
        box=box.SIMPLE,
        show_header=True,
        header_style="table.header",
        border_style="border",
        show_edge=False,
        pad_edge=False,
    )
    table.add_column("Source", style="text", no_wrap=False)
    table.add_column("Paths", style="count", justify="right", no_wrap=True)
    table.add_column("Shortest", style="path", no_wrap=True)
    table.add_column("Targets", style="count", justify="right", no_wrap=True)

    for start, info in sorted(by_start.items(), key=lambda x: x[1]["min_hops"]):
        source_markup = _format_node_with_owned(start, use_short=True)
        table.add_row(
            source_markup,
            str(info["count"]),
            f"{info['min_hops']} hops",
            str(len(info["targets"])),
        )

    console.print(table)
