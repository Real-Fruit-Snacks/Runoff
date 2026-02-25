"""Exchange Windows Permissions Group Paths"""

from __future__ import annotations

from typing import TYPE_CHECKING

from runoff.display.colors import Severity
from runoff.display.tables import print_header, print_subheader, print_table, print_warning
from runoff.queries.base import register_query

if TYPE_CHECKING:
    from runoff.core.bloodhound import BloodHoundCE


@register_query(
    name="Exchange Windows Permissions Paths",
    category="Exchange",
    default=True,
    severity=Severity.CRITICAL,
    tags=("quick-win",),
)
def get_exchange_permissions_paths(
    bh: BloodHoundCE, domain: str | None = None, severity: Severity = None
) -> int:
    """Find paths from Exchange Windows Permissions members to Domain Admins"""
    domain_filter = "AND toUpper(m.domain) = toUpper($domain)" if domain else ""
    params = {"domain": domain} if domain else {}

    query = f"""
    MATCH (g:Group)
    WHERE toUpper(g.name) CONTAINS 'EXCHANGE WINDOWS PERMISSIONS'
    MATCH (m)-[:MemberOf*1..]->(g)
    WHERE (m:User OR m:Computer)
    AND m.enabled = true
    {domain_filter}
    WITH m, g
    OPTIONAL MATCH p=shortestPath((m)-[*1..8]->(da:Group))
    WHERE da.objectid ENDS WITH '-512' OR da.objectid ENDS WITH '-519'
    RETURN
        m.name AS member,
        CASE WHEN m:User THEN 'User' ELSE 'Computer' END AS type,
        g.name AS exchange_group,
        da.name AS da_group,
        CASE WHEN p IS NOT NULL THEN length(p) ELSE null END AS path_length
    ORDER BY path_length
    LIMIT 50
    """
    results = bh.run_query(query, params)
    result_count = len(results)

    if not print_header("Exchange Windows Permissions Paths", severity, result_count):
        return result_count
    print_subheader(f"Found {result_count} Exchange Windows Permissions member(s)")

    if results:
        with_paths = sum(1 for r in results if r.get("path_length") is not None)
        if with_paths:
            print_warning(f"[!] {with_paths} member(s) have direct paths to Domain Admins!")
            print_warning("    EWP members can grant themselves DCSync via WriteDacl on domain")
        print_table(
            ["Member", "Type", "Exchange Group", "DA Group", "Hops to DA"],
            [
                [
                    r["member"],
                    r["type"],
                    r["exchange_group"],
                    r.get("da_group", "N/A"),
                    r.get("path_length", "No path"),
                ]
                for r in results
            ],
        )

    return result_count
