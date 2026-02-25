"""Owned and tier-zero marking commands."""

from __future__ import annotations

import click

from runoff.cli.context import connect, sync_config
from runoff.core.config import config
from runoff.display import console
from runoff.display.tables import print_header, print_subheader, print_table


@click.command()
@click.argument("type_", metavar="TYPE", type=click.Choice(["owned", "tier-zero"]))
@click.argument("nodes", nargs=-1, required=True)
@click.pass_context
def mark(ctx, type_, nodes):
    """Mark nodes as owned or tier-zero.

    Examples:
        runoff mark owned USER@CORP.LOCAL
        runoff mark tier-zero SVCACCT@CORP.LOCAL
        runoff mark owned USER1@CORP.LOCAL USER2@CORP.LOCAL
    """
    with connect(ctx.obj) as bh:
        sync_config(ctx.obj)
        for node in nodes:
            node = node.strip()
            if not node:
                continue
            if type_ == "owned":
                success = bh.mark_owned(node)
                if success:
                    admin_status = _get_node_admin_status(bh, node)
                    cache = config.owned_cache
                    cache[node] = admin_status
                    config.owned_cache = cache
                    console.print(f"  [success][+] Marked owned: {node}[/success]")
                else:
                    console.print(f"  [error]Node not found: {node}[/error]")
            else:  # tier-zero
                success = bh.mark_tier_zero(node)
                if success:
                    console.print(f"  [success][+] Marked tier-zero: {node}[/success]")
                else:
                    console.print(f"  [error]Node not found: {node}[/error]")


def _get_node_admin_status(bh, name: str) -> bool:
    """Query the admin status of a node from the database."""
    query = """
    MATCH (n) WHERE toUpper(n.name) = toUpper($name)
    RETURN COALESCE(n.admincount, false) AS is_admin
    LIMIT 1
    """
    try:
        results = bh.run_query(query, {"name": name})
        if results:
            return bool(results[0]["is_admin"])
    except Exception:
        pass
    return False


@click.command()
@click.argument("type_", metavar="TYPE", type=click.Choice(["owned", "tier-zero"]))
@click.argument("nodes", nargs=-1, required=True)
@click.pass_context
def unmark(ctx, type_, nodes):
    """Remove owned or tier-zero marks.

    Examples:
        runoff unmark owned USER@CORP.LOCAL
        runoff unmark tier-zero SVCACCT@CORP.LOCAL
    """
    with connect(ctx.obj) as bh:
        sync_config(ctx.obj)
        for node in nodes:
            node = node.strip()
            if not node:
                continue
            if type_ == "owned":
                success = bh.unmark_owned(node)
                if success:
                    cache = config.owned_cache
                    cache.pop(node, None)
                    config.owned_cache = cache
                    console.print(f"  [success][+] Unmarked owned: {node}[/success]")
                else:
                    console.print(f"  [error]Node not found: {node}[/error]")
            else:  # tier-zero
                success = bh.unmark_tier_zero(node)
                if success:
                    console.print(f"  [success][+] Unmarked tier-zero: {node}[/success]")
                else:
                    console.print(f"  [error]Node not found: {node}[/error]")


@click.command()
@click.pass_context
def owned(ctx):
    """List all owned principals."""
    with connect(ctx.obj) as bh:
        sync_config(ctx.obj)
        domain = ctx.obj.get("domain")

        # Build query with parameterized domain filter
        params = {}
        if domain:
            domain_filter = "AND toUpper(n.domain) = toUpper($domain)"
            params["domain"] = domain
        else:
            domain_filter = ""

        query = f"""
        MATCH (n)
        WHERE (n:Tag_Owned OR 'owned' IN n.system_tags OR n.owned = true)
        {domain_filter}
        RETURN n.name AS name,
               CASE
                   WHEN 'User' IN labels(n) THEN 'User'
                   WHEN 'Computer' IN labels(n) THEN 'Computer'
                   WHEN 'Group' IN labels(n) THEN 'Group'
                   ELSE head(labels(n))
               END AS type,
               n.enabled AS enabled,
               COALESCE(n.admincount, false) AS admin
        ORDER BY n.admincount DESC, n.name
        """

        try:
            results = bh.run_query(query, params)
        except Exception as e:
            console.print(f"[error]Query failed: {e}[/error]")
            return

        if not results:
            console.print("[text.dim]No owned principals found[/text.dim]")
            return

        print_header("Owned Principals")
        print_subheader(f"Found {len(results)} owned principal(s)")

        rows = [[r["name"], r["type"], r.get("enabled", "-"), r["admin"]] for r in results]
        print_table(["Name", "Type", "Enabled", "Admin"], rows)


@click.command()
@click.pass_context
def tierzero(ctx):
    """List all tier-zero principals."""
    with connect(ctx.obj) as bh:
        sync_config(ctx.obj)
        domain = ctx.obj.get("domain")

        # Build query with parameterized domain filter
        params = {}
        if domain:
            domain_filter = "AND toUpper(n.domain) = toUpper($domain)"
            params["domain"] = domain
        else:
            domain_filter = ""

        query = f"""
        MATCH (n)
        WHERE (n:Tag_Tier_Zero OR 'admin_tier_0' IN n.system_tags)
        {domain_filter}
        RETURN n.name AS name,
               CASE
                   WHEN 'User' IN labels(n) THEN 'User'
                   WHEN 'Computer' IN labels(n) THEN 'Computer'
                   WHEN 'Group' IN labels(n) THEN 'Group'
                   ELSE head(labels(n))
               END AS type,
               n.enabled AS enabled
        ORDER BY type, n.name
        """

        try:
            results = bh.run_query(query, params)
        except Exception as e:
            console.print(f"[error]Query failed: {e}[/error]")
            return

        if not results:
            console.print("[text.dim]No tier-zero principals found[/text.dim]")
            return

        print_header("Tier Zero Principals")
        print_subheader(f"Found {len(results)} tier-zero principal(s)")

        rows = [[r["name"], r["type"], r.get("enabled", "-")] for r in results]
        print_table(["Name", "Type", "Enabled"], rows)


# Valid targets for clear db
CLEAR_DB_TARGETS = ["all", "ad", "azure", "ingest", "quality"]


@click.group(invoke_without_command=True)
@click.pass_context
def clear(ctx):
    """Clear owned markings or database data.

    Subcommands:
        owned    Clear all owned markings from Neo4j
        db       Clear BloodHound CE database via API
    """
    if ctx.invoked_subcommand is None:
        console.print("  [header]Usage:[/header] runoff clear [text.dim]COMMAND [ARGS][/text.dim]")
        console.print()
        console.print("  [subheader]Subcommands:[/subheader]")
        console.print("    [info]owned[/info]              Clear all owned markings")
        console.print(
            "    [info]db[/info] [text.secondary]TARGET...[/text.secondary]     Clear BloodHound CE database"
        )
        console.print()
        console.print("  [subheader]Database targets:[/subheader] all, ad, azure, ingest, quality")
        console.print()
        console.print("  [subheader]Examples:[/subheader]")
        console.print("    [text.dim]runoff clear owned[/text.dim]")
        console.print("    [text.dim]runoff clear db all[/text.dim]")
        console.print("    [text.dim]runoff clear db ad azure[/text.dim]")
        console.print()


@clear.command("owned")
@click.option("-y", "--yes", is_flag=True, help="Skip confirmation")
@click.pass_context
def clear_owned(ctx, yes):
    """Clear all owned markings."""
    with connect(ctx.obj) as bh:
        sync_config(ctx.obj)

        # Get current count
        count = len(config.owned_cache) if config.owned_cache else 0
        if count == 0:
            query = "MATCH (n:Tag_Owned) RETURN count(n) AS count"
            try:
                results = bh.run_query(query)
                count = results[0]["count"] if results else 0
            except Exception as e:
                console.print(f"[error]Failed to query owned count: {e}[/error]")
                return

        if count == 0:
            console.print("[text.dim]No owned principals to clear[/text.dim]")
            return

        # Confirm unless -y
        if not yes:
            if not click.confirm(
                f"This will remove owned status from {count} principal(s). Continue?",
                default=False,
            ):
                console.print("[text.dim]Cancelled[/text.dim]")
                return

        try:
            removed = bh.clear_all_owned()
            config.owned_cache = {}
            console.print(f"  [success][+] Cleared {removed} owned principal(s)[/success]")
        except Exception as e:
            console.print(f"[error]Failed to clear owned markings: {e}[/error]")


@clear.command("db")
@click.argument("targets", nargs=-1)
@click.option("-y", "--yes", is_flag=True, help="Skip confirmation")
@click.pass_context
def clear_db(ctx, targets, yes):
    """Clear BloodHound CE database via API.

    Targets: all, ad, azure, ingest, quality
    """
    from runoff.api.config import APIConfig

    api_config = APIConfig()

    if not api_config.has_credentials():
        console.print("[error]No API credentials. Run 'runoff auth' first.[/error]")
        return

    # Show help if no targets specified
    if not targets:
        console.print(
            "  [header]Usage:[/header] runoff clear db [text.dim]TARGET [TARGET...] [-y][/text.dim]"
        )
        console.print()
        console.print("  [subheader]Targets:[/subheader]")
        console.print("    [info]all[/info]      Delete everything")
        console.print("    [info]ad[/info]       Delete AD graph data")
        console.print("    [info]azure[/info]    Delete Azure graph data")
        console.print("    [info]ingest[/info]   Delete file ingest history")
        console.print("    [info]quality[/info]  Delete data quality history")
        return

    # Validate targets
    target_set = set()
    for t in targets:
        t_lower = t.lower()
        if t_lower not in CLEAR_DB_TARGETS:
            console.print(f"[error]Unknown target: {t}[/error]")
            console.print(f"[text.dim]Valid targets: {', '.join(CLEAR_DB_TARGETS)}[/text.dim]")
            return
        target_set.add(t_lower)

    # Expand 'all'
    delete_all = "all" in target_set
    delete_ad = delete_all or "ad" in target_set
    delete_azure = delete_all or "azure" in target_set
    delete_ingest = delete_all or "ingest" in target_set
    delete_quality = delete_all or "quality" in target_set

    # Confirm unless -y
    if not yes:
        what = []
        if delete_all:
            what.append("ALL DATA")
        else:
            if delete_ad:
                what.append("AD data")
            if delete_azure:
                what.append("Azure data")
            if delete_ingest:
                what.append("ingest history")
            if delete_quality:
                what.append("quality history")

        confirm_msg = f"This will delete: {', '.join(what)}. Type 'DELETE' to confirm"
        response = click.prompt(confirm_msg, default="", show_default=False)
        if response != "DELETE":
            console.print("[text.dim]Cancelled[/text.dim]")
            return

    try:
        url, token_id, token_key = api_config.get_credentials()
    except Exception as e:
        console.print(f"[error]Failed to get API credentials: {e}[/error]")
        return

    try:
        from runoff.api.client import BloodHoundAPI

        api = BloodHoundAPI(url, token_id, token_key)

        if delete_ad:
            api.clear_ad_data()
            console.print("  [success][+] AD data cleared[/success]")

        if delete_azure:
            api.clear_azure_data()
            console.print("  [success][+] Azure data cleared[/success]")

        if delete_ingest:
            api.clear_ingest_history()
            console.print("  [success][+] Ingest history cleared[/success]")

        if delete_quality:
            api.clear_data_quality_history()
            console.print("  [success][+] Quality history cleared[/success]")

    except Exception as e:
        console.print(f"[error]Clear failed: {e}[/error]")
