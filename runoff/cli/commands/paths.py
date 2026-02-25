"""Path finding commands."""

from __future__ import annotations

import click

from runoff.cli.context import connect, sync_config
from runoff.display import console
from runoff.display.paths import print_paths_detailed, print_paths_grouped
from runoff.display.tables import print_header, print_subheader


@click.group(invoke_without_command=True)
@click.pass_context
def path(ctx):
    """Find shortest paths between nodes.

    Subcommands:
        da    Paths to Domain Admins
        dc    Paths to Domain Controllers
        to    Paths between any two nodes
    """
    if ctx.invoked_subcommand is None:
        console.print("  [header]Usage:[/header] runoff path [text.dim]COMMAND [ARGS][/text.dim]")
        console.print()
        console.print("  [subheader]Subcommands:[/subheader]")
        console.print(
            "    [info]da[/info] [text.secondary]SOURCE[/text.secondary]           Paths to Domain Admins"
        )
        console.print(
            "    [info]dc[/info] [text.secondary]SOURCE[/text.secondary]           Paths to Domain Controllers"
        )
        console.print(
            "    [info]to[/info] [text.secondary]SOURCE TARGET[/text.secondary]    Paths between two nodes"
        )
        console.print()
        console.print("  [subheader]Examples:[/subheader]")
        console.print("    [text.dim]runoff path da USER@CORP.LOCAL[/text.dim]")
        console.print("    [text.dim]runoff path dc SVCACCT@CORP.LOCAL[/text.dim]")
        console.print("    [text.dim]runoff path to USER@CORP.LOCAL DC01.CORP.LOCAL[/text.dim]")
        console.print()


@path.command()
@click.argument("source")
@click.option("-n", "--max-paths", type=int, default=None, help="Maximum paths to display")
@click.option("-d", "--detailed", is_flag=True, help="Detailed view")
@click.pass_context
def da(ctx, source, max_paths, detailed):
    """Find paths to Domain Admins."""
    with connect(ctx.obj) as bh:
        sync_config(ctx.obj)
        from runoff.core.config import config

        max_display = max_paths or config.max_paths

        results = bh.find_path_to_da(source)

        if not results:
            console.print(f"[text.dim]No path to Domain Admins from {source}[/text.dim]")
            return

        print_header(f"Paths to Domain Admins from {source}")
        print_subheader(f"Found {len(results)} path(s)")

        if detailed:
            print_paths_detailed(results, max_display=max_display)
        else:
            print_paths_grouped(results, max_display=max_display)


@path.command()
@click.argument("source")
@click.option("-n", "--max-paths", type=int, default=None, help="Maximum paths to display")
@click.option("-d", "--detailed", is_flag=True, help="Detailed view")
@click.pass_context
def dc(ctx, source, max_paths, detailed):
    """Find paths to Domain Controllers."""
    with connect(ctx.obj) as bh:
        sync_config(ctx.obj)
        from runoff.core.config import config

        max_display = max_paths or config.max_paths

        results = bh.find_path_to_dc(source)

        if not results:
            console.print(f"[text.dim]No path to Domain Controllers from {source}[/text.dim]")
            return

        print_header(f"Paths to Domain Controllers from {source}")
        print_subheader(f"Found {len(results)} path(s)")

        if detailed:
            print_paths_detailed(results, max_display=max_display)
        else:
            print_paths_grouped(results, max_display=max_display)


@path.command()
@click.argument("source")
@click.argument("target")
@click.option("-n", "--max-paths", type=int, default=None, help="Maximum paths to display")
@click.option("-d", "--detailed", is_flag=True, help="Detailed view")
@click.pass_context
def to(ctx, source, target, max_paths, detailed):
    """Find paths between two nodes."""
    with connect(ctx.obj) as bh:
        sync_config(ctx.obj)
        from runoff.core.config import config

        max_display = max_paths or config.max_paths

        results = bh.find_shortest_path(source, target)

        if not results:
            console.print(f"[text.dim]No path found from {source} to {target}[/text.dim]")
            return

        print_header(f"Paths: {source} -> {target}")
        print_subheader(f"Found {len(results)} path(s)")

        if detailed:
            print_paths_detailed(results, max_display=max_display)
        else:
            print_paths_grouped(results, max_display=max_display)
