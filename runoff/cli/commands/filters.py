"""Quick filter commands."""

from __future__ import annotations

import click

from runoff.cli.context import connect, sync_config
from runoff.display import console
from runoff.display.colors import Severity
from runoff.display.tables import print_header, print_subheader, print_table


@click.command()
@click.pass_context
def kerberoastable(ctx):
    """Show Kerberoastable users."""
    with connect(ctx.obj) as bh:
        sync_config(ctx.obj)
        from runoff.queries.credentials.kerberoastable import get_kerberoastable

        get_kerberoastable(bh, domain=ctx.obj.get("domain"), severity=Severity.HIGH)


@click.command()
@click.pass_context
def asrep(ctx):
    """Show AS-REP roastable users."""
    with connect(ctx.obj) as bh:
        sync_config(ctx.obj)
        from runoff.queries.credentials.asrep_roastable import get_asrep_roastable

        get_asrep_roastable(bh, domain=ctx.obj.get("domain"), severity=Severity.HIGH)


@click.command()
@click.pass_context
def unconstrained(ctx):
    """Show systems with unconstrained delegation."""
    with connect(ctx.obj) as bh:
        sync_config(ctx.obj)
        from runoff.queries.delegation.unconstrained_delegation import get_unconstrained_delegation

        get_unconstrained_delegation(bh, domain=ctx.obj.get("domain"), severity=Severity.HIGH)


@click.command()
@click.pass_context
def nolaps(ctx):
    """Show computers without LAPS."""
    with connect(ctx.obj) as bh:
        sync_config(ctx.obj)
        from runoff.queries.hygiene.computers_without_laps import get_computers_without_laps

        get_computers_without_laps(bh, domain=ctx.obj.get("domain"), severity=Severity.MEDIUM)


@click.command()
@click.option("--enabled", is_flag=True, help="Only enabled computers")
@click.option("-l", "--limit", type=int, default=100, help="Maximum results")
@click.pass_context
def computers(ctx, enabled, limit):
    """List all domain computers."""
    with connect(ctx.obj) as bh:
        sync_config(ctx.obj)
        results = bh.get_all_computers(domain=ctx.obj.get("domain"))
        if enabled:
            results = [r for r in results if r.get("enabled")]
        if not results:
            console.print("[text.dim]No computers found[/text.dim]")
            return
        print_header("Domain Computers")
        print_subheader(f"Found {len(results)} computer(s)")
        rows = [
            [
                r.get("name", "-"),
                (r.get("os") or "-")[:30],
                r.get("enabled", "-"),
                "Yes" if r.get("laps") else "No",
                "Yes" if r.get("unconstrained") else "No",
            ]
            for r in results[:limit]
        ]
        print_table(["Name", "OS", "Enabled", "LAPS", "Unconstrained"], rows)
        if len(results) > limit:
            console.print(f"  [text.dim](showing {limit} of {len(results)})[/text.dim]")


@click.command()
@click.option("--enabled", is_flag=True, help="Only enabled users")
@click.option("--admin", is_flag=True, help="Only admin accounts")
@click.option("-l", "--limit", type=int, default=100, help="Maximum results")
@click.pass_context
def users(ctx, enabled, admin, limit):
    """List all domain users."""
    with connect(ctx.obj) as bh:
        sync_config(ctx.obj)
        results = bh.get_all_users(domain=ctx.obj.get("domain"))
        if enabled:
            results = [r for r in results if r.get("enabled")]
        if admin:
            results = [r for r in results if r.get("admin")]
        if not results:
            console.print("[text.dim]No users found[/text.dim]")
            return
        print_header("Domain Users")
        print_subheader(f"Found {len(results)} user(s)")
        rows = [
            [
                r.get("name", "-"),
                r.get("enabled", "-"),
                "Yes" if r.get("admin") else "No",
                "Yes" if r.get("spn") else "No",
                "Yes" if r.get("asrep") else "No",
            ]
            for r in results[:limit]
        ]
        print_table(["Name", "Enabled", "Admin", "SPN", "AS-REP"], rows)
        if len(results) > limit:
            console.print(f"  [text.dim](showing {limit} of {len(results)})[/text.dim]")


@click.command()
@click.option("-l", "--limit", type=int, default=100, help="Maximum results")
@click.pass_context
def spns(ctx, limit):
    """List all Service Principal Names."""
    with connect(ctx.obj) as bh:
        sync_config(ctx.obj)
        results = bh.get_all_spns(domain=ctx.obj.get("domain"))
        if not results:
            console.print("[text.dim]No SPNs found[/text.dim]")
            return
        print_header("Service Principal Names")
        print_subheader(f"Found {len(results)} SPN(s)")
        rows = [
            [
                r.get("account", "-"),
                r.get("spn", "-"),
                r.get("enabled", "-"),
                "Yes" if r.get("admin") else "No",
            ]
            for r in results[:limit]
        ]
        print_table(["Account", "SPN", "Enabled", "Admin"], rows)
        if len(results) > limit:
            console.print(f"  [text.dim](showing {limit} of {len(results)})[/text.dim]")


@click.command()
@click.pass_context
def quickwins(ctx):
    """Show quick win attack paths."""
    with connect(ctx.obj) as bh:
        sync_config(ctx.obj)
        results = bh.get_quick_wins(domain=ctx.obj.get("domain"))

        from runoff.core.config import config

        if config.output_format in ("json", "csv", "markdown"):
            from runoff.display.output import emit_structured

            emit_structured(results)
            bh._structured_emitted = True
            return

        print_header("Quick Wins")

        short_paths = results.get("short_paths_to_da") or []
        if short_paths:
            console.print("\n  [subheader]Short Paths to Domain Admins (1-2 hops)[/subheader]")
            rows = [
                [p.get("principal", "-"), p.get("hops", "-"), " -> ".join(p.get("path") or [])]
                for p in short_paths[:10]
            ]
            print_table(["Principal", "Hops", "Path"], rows)

        kerb_admins = results.get("kerberoastable_admins") or []
        if kerb_admins:
            console.print("\n  [subheader]Kerberoastable Admin Accounts[/subheader]")
            rows = [
                [
                    k.get("account", "-"),
                    k.get("spn") or "-",
                    k.get("password_age_days") or "-",
                    k.get("privilege") or "-",
                ]
                for k in kerb_admins
            ]
            print_table(["Account", "SPN", "Password Age (days)", "Privilege"], rows)

        asrep_list = results.get("asrep_roastable") or []
        if asrep_list:
            console.print("\n  [subheader]AS-REP Roastable Accounts[/subheader]")
            rows = [[a.get("account", "-"), "Yes" if a.get("admin") else "No"] for a in asrep_list]
            print_table(["Account", "Admin"], rows)

        acl_abuse = results.get("direct_acl_abuse") or []
        if acl_abuse:
            console.print("\n  [subheader]Direct ACL Abuse to High-Value Targets[/subheader]")
            rows = [
                [a.get("principal", "-"), a.get("permission", "-"), a.get("target", "-")]
                for a in acl_abuse
            ]
            print_table(["Principal", "Permission", "Target"], rows)

        total = len(short_paths) + len(kerb_admins) + len(asrep_list) + len(acl_abuse)
        if total == 0:
            console.print("\n  [success]No quick wins identified[/success]")
        else:
            console.print(f"\n  [warning]⚠ {total} quick win opportunities identified[/warning]")


@click.command()
@click.pass_context
def audit(ctx):
    """Run consolidated security audit."""
    with connect(ctx.obj) as bh:
        sync_config(ctx.obj)
        results = bh.get_audit_results(domain=ctx.obj.get("domain"))

        from runoff.core.config import config

        if config.output_format in ("json", "csv", "markdown"):
            from runoff.display.output import emit_structured

            emit_structured(results)
            bh._structured_emitted = True
            return

        print_header("Security Audit")

        kerb = results.get("kerberoastable_admins") or []
        if kerb:
            console.print(
                f"\n  [severity.critical]Kerberoastable Admin Accounts ({len(kerb)}):[/severity.critical]"
            )
            rows = [[k.get("name", "-"), k.get("displayname") or "-"] for k in kerb[:10]]
            print_table(["Name", "Display Name"], rows)

        asrep_list = results.get("asrep_roastable") or []
        if asrep_list:
            console.print(
                f"\n  [severity.critical]AS-REP Roastable Users ({len(asrep_list)}):[/severity.critical]"
            )
            rows = [
                [a.get("name", "-"), "Yes" if a.get("admin") else "No"] for a in asrep_list[:10]
            ]
            print_table(["Name", "Admin"], rows)

        uncon = results.get("unconstrained_delegation") or []
        if uncon:
            console.print(
                f"\n  [severity.medium]Unconstrained Delegation (non-DC) ({len(uncon)}):[/severity.medium]"
            )
            rows = [[u.get("name", "-"), u.get("os") or "-"] for u in uncon[:10]]
            print_table(["Name", "OS"], rows)

        old_os = results.get("unsupported_os") or []
        if old_os:
            console.print(
                f"\n  [severity.medium]Unsupported Operating Systems ({len(old_os)}):[/severity.medium]"
            )
            rows = [[o.get("name", "-"), o.get("os") or "-"] for o in old_os[:10]]
            print_table(["Name", "OS"], rows)

        no_laps_count = results.get("no_laps_count") or 0
        if no_laps_count > 0:
            console.print(f"\n  [warning]Computers without LAPS: {no_laps_count}[/warning]")

        guest = results.get("guest_enabled") or []
        if guest:
            console.print(
                f"\n  [severity.critical]Enabled Guest Accounts ({len(guest)}):[/severity.critical]"
            )
            rows = [[g.get("name", "-"), g.get("domain") or "-"] for g in guest]
            print_table(["Name", "Domain"], rows)

        pwd_never = results.get("pwd_never_expires_admins") or []
        if pwd_never:
            console.print(
                f"\n  [severity.medium]Admin Accounts with Password Never Expires ({len(pwd_never)}):[/severity.medium]"
            )
            rows = [[p.get("name", "-")] for p in pwd_never[:10]]
            print_table(["Name"], rows)

        path_count = results.get("users_path_to_da", 0)
        if path_count > 0:
            console.print(f"\n  [warning]Users with Path to Domain Admins: {path_count}[/warning]")

        # Summary
        console.print("\n  [subheader]Audit Summary[/subheader]")
        console.print(f"    Kerberoastable admins:     [count]{len(kerb)}[/count]")
        console.print(f"    AS-REP roastable:          [count]{len(asrep_list)}[/count]")
        console.print(f"    Unconstrained delegation:  [count]{len(uncon)}[/count]")
        console.print(f"    Unsupported OS:            [count]{len(old_os)}[/count]")
        console.print(f"    Without LAPS:              [count]{no_laps_count}[/count]")
        console.print(f"    Guest enabled:             [count]{len(guest)}[/count]")
        console.print(f"    Pwd never expires (admin): [count]{len(pwd_never)}[/count]")
        console.print(f"    Users with path to DA:     [count]{path_count}[/count]")
        console.print()


@click.command()
@click.pass_context
def stats(ctx):
    """Show domain statistics."""
    with connect(ctx.obj) as bh:
        sync_config(ctx.obj)
        from runoff.queries.domain.domain_stats import get_domain_stats

        get_domain_stats(bh, domain=ctx.obj.get("domain"), severity=Severity.INFO)
