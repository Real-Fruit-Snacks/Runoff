"""Query execution commands."""

from __future__ import annotations

import re

import click

from runoff.cli.context import connect, sync_config
from runoff.display import console
from runoff.display.colors import Severity

CATEGORIES = {
    "all": None,
    "acl": "ACL Abuse",
    "adcs": "ADCS",
    "paths": "Attack Paths",
    "azure": "Azure/Hybrid",
    "basic": "Basic Info",
    "groups": "Dangerous Groups",
    "delegation": "Delegation",
    "exchange": "Exchange",
    "gpo": "GPO Abuse",
    "lateral": "Lateral Movement",
    "misc": "Miscellaneous",
    "owned": "Owned",
    "privesc": "Privilege Escalation",
    "hygiene": "Security Hygiene",
}


def _normalize_query_name(name: str) -> str:
    return re.sub(r"[-_\s]", "", name.lower())


@click.command()
@click.argument("categories", nargs=-1)
@click.option(
    "-s", "--severity", "severity_filter", default=None, help="Severity filter (comma-separated)"
)
@click.option("-t", "--tags", "tag_filter", default=None, help="Tag filter (comma-separated)")
@click.pass_context
def run(ctx, categories, severity_filter, tag_filter):
    """Run security queries by category.

    Categories: all, acl, adcs, privesc, delegation, lateral, hygiene,
    owned, basic, groups, paths, azure, exchange, misc
    """
    if not categories:
        console.print(
            "  [header]Usage:[/header] runoff run [text.dim]CATEGORY [CATEGORY...] [-s SEVERITY][/text.dim]"
        )
        console.print()
        console.print("  [subheader]Categories:[/subheader]")
        for name, label in CATEGORIES.items():
            display = label or "All default queries"
            console.print(f"    [info]{name:<14}[/info] [text.secondary]{display}[/text.secondary]")
        console.print()
        return

    # Validate categories
    run_all = False
    registry_categories = set()
    for cat in categories:
        cat_lower = cat.lower()
        if cat_lower == "all":
            run_all = True
        elif cat_lower in CATEGORIES:
            registry_categories.add(CATEGORIES[cat_lower])
        else:
            console.print(f"[error]Unknown category: {cat}[/error]")
            console.print(f"[text.dim]Valid: {', '.join(CATEGORIES.keys())}[/text.dim]")
            return

    # Parse severity filter
    sev_filter = set()
    if severity_filter:
        sev_filter = {s.strip().upper() for s in severity_filter.split(",")}

    with connect(ctx.obj) as bh:
        sync_config(ctx.obj)
        from runoff.core.config import config
        from runoff.queries import get_query_registry

        registry = get_query_registry(allow_plugins=ctx.obj.get("load_plugins", False))

        if run_all:
            query_list = [(q.name, q.func, q.severity, q.category) for q in registry if q.default]
        else:
            query_list = [
                (q.name, q.func, q.severity, q.category)
                for q in registry
                if q.category in registry_categories and q.default
            ]

        if sev_filter:
            query_list = [(n, f, s, c) for n, f, s, c in query_list if s.label in sev_filter]

        # Apply tag filter
        if tag_filter:
            required_tags = {t.strip().lower() for t in tag_filter.split(",")}
            # Rebuild query_list using registry to access tags
            registry_by_name = {q.name: q for q in registry}
            query_list = [
                (n, f, s, c)
                for n, f, s, c in query_list
                if n in registry_by_name
                and required_tags & {t.lower() for t in registry_by_name[n].tags}
            ]

        if not query_list:
            console.print("[text.dim]No queries match the specified criteria[/text.dim]")
            return

        # Sort queries respecting depends_on ordering
        from runoff.queries.base import sort_by_dependencies

        registry_by_name = {q.name: q for q in registry}
        query_meta_list = [
            registry_by_name[n] for n, f, s, c in query_list if n in registry_by_name
        ]
        sorted_meta = sort_by_dependencies(query_meta_list)
        query_list = [(q.name, q.func, q.severity, q.category) for q in sorted_meta]

        total = len(query_list)
        domain = ctx.obj.get("domain")
        structured = config.output_format in ("json", "csv", "html", "markdown")

        from runoff.display.progress import create_query_progress

        severity_counts = dict.fromkeys(Severity, 0)
        all_query_results = [] if structured else None

        with create_query_progress() as progress:
            task = progress.add_task("Running queries...", total=total)

            for i, (name, func, severity, category) in enumerate(query_list, 1):
                progress.update(task, description=f"[text.secondary]{name}[/text.secondary]")
                try:
                    bh.clear_results_cache()
                    result_count = func(bh, domain=domain, severity=severity)
                    if structured:
                        all_query_results.append(
                            {
                                "query": name,
                                "category": category,
                                "severity": severity.label,
                                "count": result_count,
                                "results": bh.accumulated_results.copy(),
                            }
                        )
                    if result_count > 0:
                        severity_counts[severity] += 1
                except KeyboardInterrupt:
                    console.print(f"\n[warning]Interrupted after {i}/{total} queries[/warning]")
                    break
                except Exception as e:
                    console.print(f"[error]Error in '{name}': {e}[/error]")
                    if ctx.obj.get("debug"):
                        import traceback

                        console.print(f"[text.dim]{traceback.format_exc()}[/text.dim]")
                progress.advance(task)

        # Emit structured output for JSON/CSV
        if structured:
            from runoff.display.output import emit_structured

            emit_structured(all_query_results)
            bh._structured_emitted = True
            return

        # Print summary
        from runoff.display.tables import print_severity_summary

        print_severity_summary(severity_counts)

        # Print executive summary for full runs
        if run_all or len(registry_categories) >= 3:
            from runoff.display.summary import print_executive_summary

            print_executive_summary(bh, [], severity_counts, domain=domain)


@click.command()
@click.argument("name", required=False)
@click.option("-l", "--list", "list_queries", is_flag=True, help="List all available queries")
@click.pass_context
def query(ctx, name, list_queries):
    """Run a specific query by name."""
    from runoff.queries import get_query_registry

    registry = get_query_registry(allow_plugins=ctx.obj.get("load_plugins", False))

    if list_queries or not name:
        _list_queries(registry)
        return

    # Find matching queries
    search_normalized = _normalize_query_name(name)
    matches = [q for q in registry if search_normalized in _normalize_query_name(q.name)]

    if not matches:
        console.print(f"[error]No queries matching: {name}[/error]")
        console.print("[text.dim]Use 'runoff query --list' to see available queries[/text.dim]")
        return

    if len(matches) > 1:
        console.print(f"[warning]Multiple matches for '{name}':[/warning]")
        for q in matches[:10]:
            console.print(f"  [info]{q.name}[/info] [text.dim]({q.category})[/text.dim]")
        if len(matches) > 10:
            console.print(f"  [text.dim]... and {len(matches) - 10} more[/text.dim]")
        return

    with connect(ctx.obj) as bh:
        sync_config(ctx.obj)
        q = matches[0]
        try:
            bh.clear_results_cache()
            q.func(bh, domain=ctx.obj.get("domain"), severity=q.severity)
        except KeyboardInterrupt:
            console.print("\n[text.dim]Query interrupted[/text.dim]")
        except Exception as e:
            console.print(f"[error]Query failed: {e}[/error]")
            if ctx.obj.get("debug"):
                import traceback

                console.print(f"[text.dim]{traceback.format_exc()}[/text.dim]")


def _list_queries(registry):
    """List all available queries grouped by category."""
    from collections import defaultdict

    by_category = defaultdict(list)
    for q in registry:
        by_category[q.category].append(q)

    for category in sorted(by_category.keys()):
        console.print(f"\n  [subheader]{category}[/subheader]")
        for q in sorted(by_category[category], key=lambda x: x.name):
            sev_str = (
                f"[{q.severity.style}][{q.severity.label}][/{q.severity.style}]"
                if q.severity != Severity.INFO
                else ""
            )
            default_str = " [text.muted](non-default)[/text.muted]" if not q.default else ""
            tag_str = f" [text.dim][{', '.join(q.tags)}][/text.dim]" if q.tags else ""
            dep_str = (
                f" [text.dim]after: {', '.join(q.depends_on)}[/text.dim]" if q.depends_on else ""
            )
            console.print(f"    {q.name:<45} {sev_str}{default_str}{tag_str}{dep_str}")
    console.print()


@click.command()
@click.pass_context
def queries(ctx):
    """List all available queries."""
    from runoff.queries import get_query_registry

    _list_queries(get_query_registry(allow_plugins=ctx.obj.get("load_plugins", False)))
