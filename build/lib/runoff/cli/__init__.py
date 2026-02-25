"""Runoff CLI — BloodHound CE Quick Wins."""

from __future__ import annotations

import click

from runoff.display.banner import VERSION


class RunoffGroup(click.Group):
    """Custom group that shows categorized help."""

    COMMAND_CATEGORIES = {
        "Connection": ["status", "domains"],
        "Security Queries": ["run", "query", "queries", "audit", "quickwins", "stats", "diff"],
        "Quick Filters": [
            "kerberoastable",
            "asrep",
            "unconstrained",
            "nolaps",
            "computers",
            "users",
            "spns",
        ],
        "Node Operations": ["info", "search", "investigate"],
        "Path Finding": ["path"],
        "Marking": ["mark", "unmark", "owned", "tierzero", "clear"],
        "Membership & Admin": ["members", "memberof", "adminto", "adminof", "sessions"],
        "Edges": ["edges"],
        "BloodHound CE API": ["auth", "ingest"],
        "Utilities": ["completion"],
    }

    def format_help(self, ctx, formatter):
        """Rich-formatted categorized help."""
        from runoff.display import console

        console.print()
        console.print(
            f"  [banner]Runoff[/banner] [text.dim]— BloodHound CE Quick Wins v{VERSION}[/text.dim]"
        )
        console.print()
        console.print(
            "  [text.secondary]Usage:[/text.secondary] runoff [text.dim][OPTIONS][/text.dim] COMMAND [text.dim][ARGS]...[/text.dim]"
        )
        console.print()

        # Show categorized commands
        commands = self.list_commands(ctx)
        for category, cmd_names in self.COMMAND_CATEGORIES.items():
            available = [n for n in cmd_names if n in commands]
            if not available:
                continue
            console.print(f"  [subheader]── {category} {'─' * (52 - len(category))}[/subheader]")
            for name in available:
                cmd = self.get_command(ctx, name)
                help_text = cmd.get_short_help_str(limit=50) if cmd else ""
                console.print(
                    f"    [info]{name:<20}[/info] [text.secondary]{help_text}[/text.secondary]"
                )
            console.print()

        # Show global options summary
        console.print(f"  [subheader]── Global Options {'─' * 38}[/subheader]")
        console.print(
            "    [info]-b, --bolt URI[/info]       [text.secondary]Neo4j Bolt URI [default: bolt://127.0.0.1:7687][/text.secondary]"
        )
        console.print(
            "    [info]-u, --username TEXT[/info]   [text.secondary]Neo4j username [default: neo4j][/text.secondary]"
        )
        console.print(
            "    [info]-p, --password TEXT[/info]   [text.secondary]Neo4j password [env: RUNOFF_PASSWORD][/text.secondary]"
        )
        console.print(
            "    [info]-d, --domain TEXT[/info]     [text.secondary]Domain filter[/text.secondary]"
        )
        console.print(
            "    [info]-o, --output FORMAT[/info]   [text.secondary]Output: table|json|csv|html [default: table][/text.secondary]"
        )
        console.print(
            "    [info]-O, --output-file PATH[/info] [text.secondary]Write output to file instead of stdout[/text.secondary]"
        )
        console.print(
            "    [info]-q, --quiet[/info]           [text.secondary]Suppress banner and info output[/text.secondary]"
        )
        console.print(
            "    [info]--no-color[/info]            [text.secondary]Disable color output[/text.secondary]"
        )
        console.print(
            "    [info]--debug[/info]               [text.secondary]Enable debug output[/text.secondary]"
        )
        console.print(
            "    [info]--abuse / --no-abuse[/info]  [text.secondary]Show exploitation commands[/text.secondary]"
        )
        console.print(
            "    [info]--load-plugins[/info]        [text.secondary]Load custom queries from plugin directory[/text.secondary]"
        )
        console.print(
            "    [info]--version[/info]             [text.secondary]Show version[/text.secondary]"
        )
        console.print(
            "    [info]-h, --help[/info]            [text.secondary]Show this help[/text.secondary]"
        )
        console.print()


def _load_default_map() -> dict:
    """Load config file defaults for the CLI group."""
    from runoff.cli.defaults import load_config_defaults

    return load_config_defaults()


@click.group(
    cls=RunoffGroup,
    invoke_without_command=True,
    context_settings={
        "help_option_names": ["-h", "--help"],
        "default_map": _load_default_map(),
    },
)
@click.option(
    "-b", "--bolt", envvar="RUNOFF_BOLT_URI", default="bolt://127.0.0.1:7687", help="Neo4j Bolt URI"
)
@click.option("-u", "--username", envvar="RUNOFF_USERNAME", default="neo4j", help="Neo4j username")
@click.option("-p", "--password", envvar="RUNOFF_PASSWORD", default=None, help="Neo4j password")
@click.option("-d", "--domain", envvar="RUNOFF_DOMAIN", default=None, help="Domain filter")
@click.option(
    "-o",
    "--output",
    "output_format",
    type=click.Choice(["table", "json", "csv", "html", "markdown"]),
    default="table",
    help="Output format",
)
@click.option(
    "-O",
    "--output-file",
    "output_file",
    type=click.Path(),
    default=None,
    help="Write output to file instead of stdout",
)
@click.option("-s", "--severity", default=None, help="Severity filter (comma-separated)")
@click.option("--abuse/--no-abuse", default=False, help="Show exploitation commands")
@click.option("-q", "--quiet", is_flag=True, help="Suppress banner and info output")
@click.option("--no-color", is_flag=True, help="Disable color output")
@click.option("--debug", is_flag=True, help="Enable debug output")
@click.option("--load-plugins", is_flag=True, help="Load custom queries from plugin directory")
@click.version_option(VERSION, prog_name="runoff")
@click.pass_context
def cli(
    ctx,
    bolt,
    username,
    password,
    domain,
    output_format,
    output_file,
    severity,
    abuse,
    quiet,
    no_color,
    debug,
    load_plugins,
):
    """Runoff — BloodHound CE Quick Wins"""
    ctx.ensure_object(dict)
    ctx.obj["bolt"] = bolt
    ctx.obj["username"] = username
    ctx.obj["password"] = password or "bloodhoundcommunityedition"
    ctx.obj["domain"] = domain
    ctx.obj["output_format"] = output_format
    ctx.obj["output_file"] = output_file
    ctx.obj["severity"] = severity
    ctx.obj["abuse"] = abuse
    ctx.obj["quiet"] = quiet
    ctx.obj["no_color"] = no_color
    ctx.obj["debug"] = debug
    ctx.obj["load_plugins"] = load_plugins

    # Configure global state
    from runoff.core.config import config

    config.output_format = output_format
    config.output_file = output_file
    config.quiet_mode = quiet
    config.no_color = no_color
    config.debug_mode = debug
    config.show_abuse = abuse
    config.current_domain = domain
    if severity:
        config.severity_filter = {s.strip().upper() for s in severity.split(",")}

    # Redirect Rich console to stderr for structured output so JSON/CSV/HTML goes to stdout
    if output_format in ("json", "csv", "html", "markdown"):
        import sys

        from runoff.display import console as _console

        _console.file = sys.stderr

    # If no subcommand, show help
    if ctx.invoked_subcommand is None:
        if not quiet:
            from runoff.display.banner import print_banner

            print_banner()
        click.echo(ctx.get_help())


# Register all command groups
from runoff.cli.commands import register_commands  # noqa: E402

register_commands(cli)
