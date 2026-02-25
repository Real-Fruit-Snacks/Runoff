"""Edge exploration commands."""

from __future__ import annotations

import click

from runoff.cli.context import connect, sync_config
from runoff.display import console
from runoff.display.tables import print_header, print_subheader, print_table


def _is_wildcard_result(results, key: str) -> bool:
    """Check if results contain a wildcard grouping column."""
    return results and key in results[0]


@click.group(invoke_without_command=True)
@click.pass_context
def edges(ctx):
    """List attack edges from/to a node.

    Subcommands:
        from    Outbound edges (what can this node attack)
        to      Inbound edges (who can attack this node)
    """
    if ctx.invoked_subcommand is None:
        console.print(
            "  [header]Usage:[/header] runoff edges [text.dim]COMMAND NODE [OPTIONS][/text.dim]"
        )
        console.print()
        console.print("  [subheader]Subcommands:[/subheader]")
        console.print(
            "    [info]from[/info] [text.secondary]NODE[/text.secondary]   Outbound edges (what can node attack)"
        )
        console.print(
            "    [info]to[/info]   [text.secondary]NODE[/text.secondary]   Inbound edges (who can attack node)"
        )
        console.print()
        console.print("  [subheader]Examples:[/subheader]")
        console.print("    [text.dim]runoff edges from USER@CORP.LOCAL[/text.dim]")
        console.print("    [text.dim]runoff edges to DC01.CORP.LOCAL[/text.dim]")
        console.print("    [text.dim]runoff edges from USER@CORP.LOCAL -t GenericAll[/text.dim]")
        console.print()


# Note: 'from' is a Python keyword, so we use the name parameter
@edges.command("from")
@click.argument("node")
@click.option(
    "-t",
    "--type",
    "edge_type",
    default=None,
    help="Filter by edge type (e.g., GenericAll, AdminTo)",
)
@click.option("-l", "--limit", type=int, default=100, help="Maximum results")
@click.pass_context
def edges_from(ctx, node, edge_type, limit):
    """List outbound attack edges from a node.

    Examples:
        runoff edges from USER@CORP.LOCAL
        runoff edges from USER@CORP.LOCAL -t GenericAll
    """
    with connect(ctx.obj) as bh:
        sync_config(ctx.obj)
        results = bh.get_edges_from(node)

        if not results:
            console.print(f"[text.dim]No outbound attack edges from: {node}[/text.dim]")
            return

        # Filter by type if specified
        if edge_type:
            results = [r for r in results if r.get("relationship", "").upper() == edge_type.upper()]
            if not results:
                console.print(f"[text.dim]No {edge_type} edges from: {node}[/text.dim]")
                return

        print_header(f"Outbound edges from {node}")
        print_subheader(f"Found {len(results)} edge(s)")

        # Check if wildcard (has 'source' column)
        if _is_wildcard_result(results, "source"):
            rows = [
                [
                    r.get("source", "-"),
                    r.get("relationship", "-"),
                    r.get("target", "-"),
                    r.get("target_type", "-"),
                ]
                for r in results[:limit]
            ]
            print_table(["Source", "Relationship", "Target", "Type"], rows)
        else:
            rows = [
                [r.get("relationship", "-"), r.get("target", "-"), r.get("target_type", "-")]
                for r in results[:limit]
            ]
            print_table(["Relationship", "Target", "Type"], rows)

        if len(results) > limit:
            console.print(f"  [text.dim](showing {limit} of {len(results)})[/text.dim]")


@edges.command("to")
@click.argument("node")
@click.option(
    "-t",
    "--type",
    "edge_type",
    default=None,
    help="Filter by edge type (e.g., GenericAll, AdminTo)",
)
@click.option("-l", "--limit", type=int, default=100, help="Maximum results")
@click.pass_context
def edges_to(ctx, node, edge_type, limit):
    """List inbound attack edges to a node.

    Examples:
        runoff edges to DC01.CORP.LOCAL
        runoff edges to 'DOMAIN ADMINS@CORP.LOCAL' -t GenericAll
    """
    with connect(ctx.obj) as bh:
        sync_config(ctx.obj)
        results = bh.get_edges_to(node)

        if not results:
            console.print(f"[text.dim]No inbound attack edges to: {node}[/text.dim]")
            return

        # Filter by type if specified
        if edge_type:
            results = [r for r in results if r.get("relationship", "").upper() == edge_type.upper()]
            if not results:
                console.print(f"[text.dim]No {edge_type} edges to: {node}[/text.dim]")
                return

        print_header(f"Inbound edges to {node}")
        print_subheader(f"Found {len(results)} edge(s)")

        # Check if wildcard (has 'target' column in inbound results)
        if _is_wildcard_result(results, "target"):
            rows = [
                [
                    r.get("target", "-"),
                    r.get("source", "-"),
                    r.get("source_type", "-"),
                    r.get("relationship", "-"),
                ]
                for r in results[:limit]
            ]
            print_table(["Target", "Source", "Type", "Relationship"], rows)
        else:
            rows = [
                [r.get("source", "-"), r.get("source_type", "-"), r.get("relationship", "-")]
                for r in results[:limit]
            ]
            print_table(["Source", "Type", "Relationship"], rows)

        if len(results) > limit:
            console.print(f"  [text.dim](showing {limit} of {len(results)})[/text.dim]")
