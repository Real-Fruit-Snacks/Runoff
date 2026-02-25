"""Connection management commands."""

from __future__ import annotations

import click

from runoff.cli.context import connect
from runoff.display import console


@click.command()
@click.pass_context
def status(ctx):
    """Show connection status."""
    try:
        with connect(ctx.obj):
            console.print("  [success]● Connected[/success]")
            console.print(f"  [text.secondary]{'URI':<12}[/text.secondary] {ctx.obj['bolt']}")
            console.print(f"  [text.secondary]{'User':<12}[/text.secondary] {ctx.obj['username']}")
            domain = ctx.obj.get("domain")
            if domain:
                console.print(f"  [text.secondary]{'Domain':<12}[/text.secondary] {domain}")
            from runoff.core.config import config

            owned_count = len(config.owned_cache)
            if owned_count:
                admin_count = sum(1 for v in config.owned_cache.values() if v)
                console.print(
                    f"  [text.secondary]{'Owned':<12}[/text.secondary] {owned_count} principals ({admin_count} admin)"
                )
            console.print()
    except SystemExit:
        console.print("  [error]● Disconnected[/error]")
        console.print(f"  [text.secondary]{'URI':<12}[/text.secondary] {ctx.obj['bolt']}")
        console.print()


@click.command()
@click.pass_context
def domains(ctx):
    """List available domains."""
    with connect(ctx.obj) as bh:
        domain_list = bh.get_domains()
        if not domain_list:
            console.print("[text.dim]No domains found[/text.dim]")
            return
        console.print(f"  [header]Domains[/header] [text.dim]({len(domain_list)} found)[/text.dim]")
        for d in domain_list:
            marker = " *" if d["name"] == ctx.obj.get("domain") else ""
            console.print(f"    [node]{d['name']}{marker}[/node]")
        console.print()
