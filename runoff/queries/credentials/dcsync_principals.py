"""All DCSync Principals"""

from __future__ import annotations

from typing import TYPE_CHECKING

from runoff.core.cypher import node_type
from runoff.display import console
from runoff.display.colors import Severity
from runoff.display.tables import print_header, print_subheader, print_table, print_warning
from runoff.queries.base import register_query

if TYPE_CHECKING:
    from runoff.core.bloodhound import BloodHoundCE


@register_query(
    name="All DCSync Principals",
    category="Credentials",
    default=True,
    severity=Severity.CRITICAL,
    tags=("quick-win",),
)
def get_dcsync_principals(
    bh: BloodHoundCE, domain: str | None = None, severity: Severity = None
) -> int:
    """Find all principals with DCSync rights (GetChanges + GetChangesAll)"""
    if domain:
        domain_where = "WHERE toUpper(d.name) = toUpper($domain)"
        params = {"domain": domain}
    else:
        domain_where = ""
        params = {}

    query = f"""
    MATCH (n)-[r:DCSync|GetChanges|GetChangesAll]->(d:Domain)
    {domain_where}
    WITH n, d, collect(type(r)) AS rights
    RETURN n.name AS principal, {node_type("n")} AS type,
           d.name AS domain,
           'DCSync' IN rights OR ('GetChanges' IN rights AND 'GetChangesAll' IN rights) AS can_dcsync,
           'GetChanges' IN rights AS has_getchanges,
           'GetChangesAll' IN rights AS has_getchangesall,
           n.enabled AS enabled
    ORDER BY can_dcsync DESC, type, n.name
    """
    results = bh.run_query(query, params)
    result_count = len(results)

    if not print_header("All DCSync Principals", severity, result_count):
        return result_count
    print_subheader(f"Found {result_count} principal(s) with replication rights")

    if results:
        full_dcsync = sum(1 for r in results if r["can_dcsync"])
        partial = result_count - full_dcsync

        if full_dcsync:
            print_warning(f"[!] {full_dcsync} principal(s) can perform FULL DCSync!")
        if partial:
            print_warning(f"    {partial} principal(s) have partial replication rights")
        console.print()

        # Expected principals with DCSync
        console.print("    Expected principals with DCSync:", style="text.dim")
        console.print("    - Domain Controllers (group)", style="text.dim")
        console.print("    - Enterprise Domain Controllers", style="text.dim")
        console.print("    - Administrators", style="text.dim")
        console.print()
        console.print("    Unexpected principals should be investigated!", style="info")
        console.print()

        print_table(
            ["Principal", "Type", "Domain", "Full DCSync", "GetChanges", "GetChangesAll"],
            [
                [
                    r["principal"],
                    r["type"],
                    r["domain"],
                    r["can_dcsync"],
                    r["has_getchanges"],
                    r["has_getchangesall"],
                ]
                for r in results
            ],
        )

    return result_count
