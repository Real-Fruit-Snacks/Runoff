"""Register all CLI commands."""

from __future__ import annotations


def register_commands(cli):
    """Register all command groups with the CLI."""
    from runoff.cli.commands.api import auth, ingest
    from runoff.cli.commands.completion import completion
    from runoff.cli.commands.connection import domains, status
    from runoff.cli.commands.diff import diff
    from runoff.cli.commands.edges import edges
    from runoff.cli.commands.filters import (
        asrep,
        audit,
        computers,
        kerberoastable,
        nolaps,
        quickwins,
        spns,
        stats,
        unconstrained,
        users,
    )
    from runoff.cli.commands.marking import clear, mark, owned, tierzero, unmark
    from runoff.cli.commands.membership import adminof, adminto, memberof, members, sessions
    from runoff.cli.commands.nodes import info, investigate, search
    from runoff.cli.commands.paths import path
    from runoff.cli.commands.queries import queries, query, run

    # Register individual commands
    for cmd in [
        status,
        domains,
        run,
        query,
        queries,
        diff,
        kerberoastable,
        asrep,
        unconstrained,
        nolaps,
        computers,
        users,
        spns,
        quickwins,
        audit,
        stats,
        info,
        search,
        investigate,
        path,
        mark,
        unmark,
        owned,
        tierzero,
        clear,
        members,
        memberof,
        adminto,
        adminof,
        sessions,
        edges,
        auth,
        ingest,
        completion,
    ]:
        cli.add_command(cmd)
