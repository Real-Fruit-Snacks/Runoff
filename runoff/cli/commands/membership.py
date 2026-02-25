"""Membership and admin rights commands."""

from __future__ import annotations

import click

from runoff.cli.context import connect, sync_config
from runoff.display import console
from runoff.display.tables import print_header, print_subheader, print_table


def _is_wildcard_result(results, key: str) -> bool:
    """Check if results contain a wildcard grouping column."""
    return results and key in results[0]


@click.command()
@click.argument("group")
@click.option("-l", "--limit", type=int, default=100, help="Maximum results")
@click.option("-d", "--detailed", is_flag=True, help="Show additional details")
@click.pass_context
def members(ctx, group, limit, detailed):
    """List all members of a group (recursive).

    Examples:
        runoff members 'DOMAIN ADMINS@CORP.LOCAL'
        runoff members '*ADMIN*'
    """
    with connect(ctx.obj) as bh:
        sync_config(ctx.obj)
        results = bh.get_group_members(group)

        if not results:
            console.print(f"[text.dim]No members found for: {group}[/text.dim]")
            return

        print_header(f"Members of {group}")
        print_subheader(f"Found {len(results)} member(s)")

        # Check if wildcard (has 'group' column)
        if _is_wildcard_result(results, "group"):
            if detailed:
                rows = [
                    [
                        r.get("group", "-"),
                        r.get("member", "-"),
                        r.get("type", "-"),
                        r.get("enabled", "-"),
                        r.get("admin", False),
                        r.get("domain") or "-",
                        (r.get("objectid") or "-")[:20],
                    ]
                    for r in results[:limit]
                ]
                print_table(["Group", "Member", "Type", "Enabled", "Admin", "Domain", "SID"], rows)
            else:
                rows = [
                    [
                        r.get("group", "-"),
                        r.get("member", "-"),
                        r.get("type", "-"),
                        r.get("enabled", "-"),
                        r.get("admin", False),
                    ]
                    for r in results[:limit]
                ]
                print_table(["Group", "Member", "Type", "Enabled", "Admin"], rows)
        else:
            if detailed:
                rows = [
                    [
                        r.get("member", "-"),
                        r.get("type", "-"),
                        r.get("enabled", "-"),
                        r.get("admin", False),
                        r.get("domain") or "-",
                        (r.get("objectid") or "-")[:20],
                    ]
                    for r in results[:limit]
                ]
                print_table(["Member", "Type", "Enabled", "Admin", "Domain", "SID"], rows)
            else:
                rows = [
                    [
                        r.get("member", "-"),
                        r.get("type", "-"),
                        r.get("enabled", "-"),
                        r.get("admin", False),
                    ]
                    for r in results[:limit]
                ]
                print_table(["Member", "Type", "Enabled", "Admin"], rows)

        if len(results) > limit:
            console.print(f"  [text.dim](showing {limit} of {len(results)})[/text.dim]")


@click.command()
@click.argument("principal")
@click.option("-d", "--detailed", is_flag=True, help="Show additional details")
@click.pass_context
def memberof(ctx, principal, detailed):
    """List groups a principal belongs to (recursive).

    Examples:
        runoff memberof USER@CORP.LOCAL
        runoff memberof SVCACCT@CORP.LOCAL
    """
    with connect(ctx.obj) as bh:
        sync_config(ctx.obj)
        results = bh.get_member_of(principal)

        if not results:
            console.print(f"[text.dim]No group memberships for: {principal}[/text.dim]")
            return

        print_header(f"Group memberships for {principal}")
        print_subheader(f"Found {len(results)} group(s)")

        # Check if wildcard (has 'principal' column)
        if _is_wildcard_result(results, "principal"):
            if detailed:
                rows = [
                    [
                        r.get("principal", "-"),
                        r.get("group_name", "-"),
                        r.get("tier_zero", "-"),
                        r.get("domain") or "-",
                        (r.get("objectid") or "-")[:20],
                        (r.get("description") or "-")[:30],
                    ]
                    for r in results
                ]
                print_table(
                    ["Principal", "Group", "Tier Zero", "Domain", "SID", "Description"], rows
                )
            else:
                rows = [
                    [
                        r.get("principal", "-"),
                        r.get("group_name", "-"),
                        r.get("tier_zero", "-"),
                        (r.get("description") or "-")[:40],
                    ]
                    for r in results
                ]
                print_table(["Principal", "Group", "Tier Zero", "Description"], rows)
        else:
            if detailed:
                rows = [
                    [
                        r.get("group_name", "-"),
                        r.get("tier_zero", "-"),
                        r.get("domain") or "-",
                        (r.get("objectid") or "-")[:20],
                        (r.get("description") or "-")[:30],
                    ]
                    for r in results
                ]
                print_table(["Group", "Tier Zero", "Domain", "SID", "Description"], rows)
            else:
                rows = [
                    [
                        r.get("group_name", "-"),
                        r.get("tier_zero", "-"),
                        (r.get("description") or "-")[:50],
                    ]
                    for r in results
                ]
                print_table(["Group", "Tier Zero", "Description"], rows)


@click.command()
@click.argument("computer")
@click.pass_context
def adminto(ctx, computer):
    """List who can admin a computer.

    Examples:
        runoff adminto DC01.CORP.LOCAL
        runoff adminto '*SQL*'
    """
    with connect(ctx.obj) as bh:
        sync_config(ctx.obj)
        results = bh.get_admins_to(computer)

        if not results:
            console.print(f"[text.dim]No admin rights found for: {computer}[/text.dim]")
            return

        print_header(f"Admins to {computer}")
        print_subheader(f"Found {len(results)} admin(s)")

        # Check if wildcard (has 'computer' column)
        if _is_wildcard_result(results, "computer"):
            rows = [
                [
                    r.get("computer", "-"),
                    r.get("principal", "-"),
                    r.get("type", "-"),
                    r.get("enabled", "-"),
                ]
                for r in results
            ]
            print_table(["Computer", "Principal", "Type", "Enabled"], rows)
        else:
            rows = [
                [r.get("principal", "-"), r.get("type", "-"), r.get("enabled", "-")]
                for r in results
            ]
            print_table(["Principal", "Type", "Enabled"], rows)


@click.command()
@click.argument("principal")
@click.pass_context
def adminof(ctx, principal):
    """List what computers a principal can admin.

    Examples:
        runoff adminof USER@CORP.LOCAL
        runoff adminof '*ADMIN*'
    """
    with connect(ctx.obj) as bh:
        sync_config(ctx.obj)
        results = bh.get_admin_of(principal)

        if not results:
            console.print(f"[text.dim]No admin rights for: {principal}[/text.dim]")
            return

        print_header(f"Admin rights for {principal}")
        print_subheader(f"Can admin {len(results)} computer(s)")

        # Check if wildcard (has 'principal' column)
        if _is_wildcard_result(results, "principal"):
            rows = [
                [
                    r.get("principal", "-"),
                    r.get("computer", "-"),
                    r.get("os") or "-",
                    r.get("enabled", "-"),
                ]
                for r in results
            ]
            print_table(["Principal", "Computer", "OS", "Enabled"], rows)
        else:
            rows = [
                [r.get("computer", "-"), r.get("os") or "-", r.get("enabled", "-")] for r in results
            ]
            print_table(["Computer", "OS", "Enabled"], rows)


@click.command()
@click.argument("computer")
@click.pass_context
def sessions(ctx, computer):
    """List active sessions on a computer.

    Examples:
        runoff sessions DC01.CORP.LOCAL
        runoff sessions '*SQL*'
    """
    with connect(ctx.obj) as bh:
        sync_config(ctx.obj)
        results = bh.get_computer_sessions(computer)

        if not results:
            console.print(f"[text.dim]No sessions found on: {computer}[/text.dim]")
            return

        print_header(f"Sessions on {computer}")
        print_subheader(f"Found {len(results)} session(s)")

        # Check if wildcard (has 'computer' column)
        if _is_wildcard_result(results, "computer"):
            rows = [
                [
                    r.get("computer", "-"),
                    r.get("user", "-"),
                    r.get("admin", False),
                    r.get("enabled", "-"),
                ]
                for r in results
            ]
            print_table(["Computer", "User", "Admin", "Enabled"], rows)
        else:
            rows = [
                [r.get("user", "-"), r.get("admin", False), r.get("enabled", "-")] for r in results
            ]
            print_table(["User", "Admin", "Enabled"], rows)
