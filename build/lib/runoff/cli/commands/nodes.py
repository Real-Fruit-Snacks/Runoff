"""Node exploration commands."""

from __future__ import annotations

import click

from runoff.cli.context import connect, sync_config
from runoff.display import console
from runoff.display.tables import print_header, print_node_info, print_subheader, print_table


@click.command()
@click.argument("node")
@click.pass_context
def info(ctx, node):
    """Show node properties and labels.

    Supports * wildcards for pattern matching.

    Examples:
        runoff info USER@CORP.LOCAL
        runoff info DC01.CORP.LOCAL
        runoff info '*ADMIN*'
    """
    with connect(ctx.obj) as bh:
        sync_config(ctx.obj)
        result = bh.get_node_info(node)

        if result is None:
            console.print(f"[error]Node not found: {node}[/error]")
            console.print("[text.dim]Hint: Use 'runoff search *pattern*' to find nodes[/text.dim]")
            return

        from runoff.core.config import config

        if config.output_format in ("json", "csv", "markdown"):
            from runoff.display.output import emit_structured

            emit_structured(result if isinstance(result, list) else [result])
            bh._structured_emitted = True
            return

        if isinstance(result, list):
            # Wildcard match - show summary table
            if not result:
                console.print(f"[error]No nodes matching: {node}[/error]")
                return

            print_header(f"Nodes matching '{node}'")
            print_subheader(f"Found {len(result)} node(s)")

            rows = [
                [
                    n.get("name", "-"),
                    n.get("_type", "-"),
                    n.get("enabled", "-"),
                    n.get("admincount", False),
                ]
                for n in result
            ]
            print_table(["Name", "Type", "Enabled", "Admin"], rows)
        else:
            # Single node - show detailed info
            print_header(f"Node: {result.get('name', node)}")
            print_node_info(result)


@click.command()
@click.argument("pattern")
@click.option("-l", "--limit", type=int, default=100, help="Maximum results")
@click.pass_context
def search(ctx, pattern, limit):
    """Search nodes by name pattern.

    Supports * wildcards.

    Examples:
        runoff search '*ADMIN*'
        runoff search 'SVC*'
        runoff search '*SQL*'
    """
    with connect(ctx.obj) as bh:
        sync_config(ctx.obj)
        results = bh.search_nodes(pattern)

        if not results:
            console.print(f"[text.dim]No nodes matching: {pattern}[/text.dim]")
            return

        print_header(f"Search: '{pattern}'")
        print_subheader(f"Found {len(results)} result(s)")

        rows = [[r["name"], r["type"], r["enabled"], r.get("domain", "-")] for r in results[:limit]]
        print_table(["Name", "Type", "Enabled", "Domain"], rows)

        if len(results) > limit:
            console.print(f"  [text.dim](showing {limit} of {len(results)})[/text.dim]")


@click.command()
@click.argument("node")
@click.pass_context
def investigate(ctx, node):
    """Comprehensive investigation of a node.

    Shows properties, edges, group memberships, sessions, admin rights,
    and paths to Domain Admins.

    Supports * wildcards for triage mode.

    Examples:
        runoff investigate USER@CORP.LOCAL
        runoff investigate '*ADMIN*'
    """
    with connect(ctx.obj) as bh:
        sync_config(ctx.obj)

        from runoff.core.config import config

        if config.output_format in ("json", "csv", "markdown"):
            _investigate_structured(bh, node)
            bh._structured_emitted = True
            return

        if "*" in node:
            _investigate_triage(bh, node)
        else:
            _investigate_single(bh, node)


def _investigate_triage(bh, pattern: str) -> None:
    """Triage investigation of multiple nodes matching pattern."""
    results = bh.investigate_nodes(pattern)

    if not results:
        console.print(f"[text.dim]No nodes matching: {pattern}[/text.dim]")
        return

    print_header(f"Investigation Triage: '{pattern}'")
    print_subheader(f"Found {len(results)} node(s)")

    rows = []
    for r in results:
        flags = []
        if r.get("admin"):
            flags.append("Admin")
        if r.get("unconstrained"):
            flags.append("Uncon")
        if r.get("laps") is False:
            flags.append("NoLAPS")

        rows.append(
            [
                r["name"],
                r["type"],
                r.get("enabled", "-"),
                ", ".join(flags) if flags else "-",
                r.get("outbound_edges", 0),
                r.get("inbound_edges", 0),
            ]
        )

    print_table(["Name", "Type", "Enabled", "Flags", "Out Edges", "In Edges"], rows)


def _investigate_single(bh, node: str) -> None:
    """Full investigation of a single node."""
    # Get node info
    node_info = bh.get_node_info(node)
    if node_info is None:
        console.print(f"[error]Node not found: {node}[/error]")
        console.print("[text.dim]Hint: Use 'runoff search *pattern*' to find nodes[/text.dim]")
        return

    node_type = node_info.get("_labels", [])
    is_user = "User" in node_type
    is_computer = "Computer" in node_type
    is_group = "Group" in node_type

    # Properties
    print_header(f"Investigation: {node_info.get('name', node)}")
    console.print("\n  [header]Properties:[/header]")
    print_node_info(node_info)

    # Show edges
    _show_outbound_edges(bh, node)
    _show_inbound_edges(bh, node)

    # Show group memberships (for users/computers)
    if is_user or is_computer:
        _show_group_memberships(bh, node)

    # Show sessions (for computers)
    if is_computer:
        _show_sessions(bh, node)

    # Show admin rights (for users)
    if is_user:
        _show_admin_rights(bh, node)
        _show_paths_to_da(bh, node)

    # Show group members (for groups)
    if is_group:
        _show_group_members(bh, node)


def _show_outbound_edges(bh, node: str) -> None:
    """Display outbound attack edges section."""
    edges_out = bh.get_edges_from(node)
    if not edges_out:
        return

    console.print(f"\n  [header]Outbound Attack Edges ({len(edges_out)}):[/header]")
    rows = [
        [r.get("relationship", "-"), r.get("target", "-"), r.get("target_type", "-")]
        for r in edges_out[:20]
    ]
    print_table(["Relationship", "Target", "Type"], rows)
    if len(edges_out) > 20:
        console.print(f"    [warning]... and {len(edges_out) - 20} more[/warning]")


def _show_inbound_edges(bh, node: str) -> None:
    """Display inbound attack edges section."""
    edges_in = bh.get_edges_to(node)
    if not edges_in:
        return

    console.print(f"\n  [header]Inbound Attack Edges ({len(edges_in)}):[/header]")
    rows = [
        [r.get("source", "-"), r.get("source_type", "-"), r.get("relationship", "-")]
        for r in edges_in[:20]
    ]
    print_table(["Source", "Type", "Relationship"], rows)
    if len(edges_in) > 20:
        console.print(f"    [warning]... and {len(edges_in) - 20} more[/warning]")


def _show_group_memberships(bh, node: str) -> None:
    """Display group memberships section."""
    groups = bh.get_member_of(node)
    if not groups:
        return

    console.print(f"\n  [header]Group Memberships ({len(groups)}):[/header]")
    rows = [
        [g.get("group_name", "-"), g.get("tier_zero", "-"), (g.get("description") or "-")[:50]]
        for g in groups[:20]
    ]
    print_table(["Group", "Tier Zero", "Description"], rows)
    if len(groups) > 20:
        console.print(f"    [warning]... and {len(groups) - 20} more[/warning]")


def _show_sessions(bh, node: str) -> None:
    """Display active sessions section (for computers)."""
    sessions = bh.get_computer_sessions(node)
    if not sessions:
        return

    console.print(f"\n  [header]Active Sessions ({len(sessions)}):[/header]")
    rows = [[s.get("user", "-"), s.get("admin", False)] for s in sessions[:10]]
    print_table(["User", "Admin"], rows)


def _show_admin_rights(bh, node: str) -> None:
    """Display admin rights section (for users)."""
    admin_of = bh.get_admin_of(node)
    if not admin_of:
        return

    console.print(f"\n  [header]Admin Rights ({len(admin_of)}):[/header]")
    rows = [[a.get("computer", "-"), a.get("os") or "-"] for a in admin_of[:10]]
    print_table(["Computer", "OS"], rows)
    if len(admin_of) > 10:
        console.print(f"    [warning]... and {len(admin_of) - 10} more[/warning]")


def _show_paths_to_da(bh, node: str) -> None:
    """Display paths to Domain Admins section (for users)."""
    paths = bh.find_path_to_da(node)
    if not paths:
        return

    console.print(f"\n  [header]Paths to Domain Admins ({len(paths)}):[/header]")
    from runoff.display.paths import print_paths_grouped

    print_paths_grouped(paths, max_display=3)


def _show_group_members(bh, node: str) -> None:
    """Display group members section (for groups)."""
    members = bh.get_group_members(node)
    if not members:
        return

    console.print(f"\n  [header]Group Members ({len(members)}):[/header]")
    rows = [
        [m.get("member", "-"), m.get("type", "-"), m.get("enabled", "-"), m.get("admin", False)]
        for m in members[:20]
    ]
    print_table(["Member", "Type", "Enabled", "Admin"], rows)
    if len(members) > 20:
        console.print(f"    [warning]... and {len(members) - 20} more[/warning]")


def _investigate_structured(bh, node: str) -> None:
    """Emit structured JSON/CSV for investigate command."""
    from runoff.display.output import emit_structured

    if "*" in node:
        results = bh.investigate_nodes(node)
        emit_structured(results or [])
        return

    node_info = bh.get_node_info(node)
    if node_info is None:
        emit_structured([])
        return

    data = {
        "properties": node_info,
        "edges_out": bh.get_edges_from(node) or [],
        "edges_in": bh.get_edges_to(node) or [],
    }

    node_type = node_info.get("_labels", [])
    if "User" in node_type or "Computer" in node_type:
        data["group_memberships"] = bh.get_member_of(node) or []
    if "Computer" in node_type:
        data["sessions"] = bh.get_computer_sessions(node) or []
    if "User" in node_type:
        data["admin_rights"] = bh.get_admin_of(node) or []
        data["paths_to_da"] = bh.find_path_to_da(node) or []
    if "Group" in node_type:
        data["members"] = bh.get_group_members(node) or []

    emit_structured(data)
