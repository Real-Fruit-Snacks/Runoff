"""Exchange Trusted Subsystem Attack Paths"""

from __future__ import annotations

from typing import TYPE_CHECKING

from runoff.display.colors import Severity
from runoff.display.tables import print_header, print_subheader, print_table, print_warning
from runoff.queries.base import register_query

if TYPE_CHECKING:
    from runoff.core.bloodhound import BloodHoundCE


@register_query(
    name="Exchange Trusted Subsystem Paths",
    category="Exchange",
    default=True,
    severity=Severity.CRITICAL,
    tags=("quick-win",),
)
def get_exchange_trusted_subsystem(
    bh: BloodHoundCE, domain: str | None = None, severity: Severity = None
) -> int:
    """Find attack paths from Exchange Trusted Subsystem to high-value targets"""
    domain_filter = "AND toUpper(t.domain) = toUpper($domain)" if domain else ""
    params = {"domain": domain} if domain else {}

    query = f"""
    MATCH (g:Group)
    WHERE toUpper(g.name) CONTAINS 'EXCHANGE TRUSTED SUBSYSTEM'
    MATCH p=shortestPath((g)-[*1..8]->(t))
    WHERE (t:Domain OR t:Group)
    AND (t.objectid ENDS WITH '-512' OR t.objectid ENDS WITH '-519' OR t:Domain)
    AND g <> t
    {domain_filter}
    RETURN
        g.name AS exchange_group,
        t.name AS target,
        CASE WHEN t:Domain THEN 'Domain' ELSE 'Group' END AS target_type,
        length(p) AS path_length
    ORDER BY path_length
    LIMIT 25
    """
    results = bh.run_query(query, params)
    result_count = len(results)

    if not print_header("Exchange Trusted Subsystem Paths", severity, result_count):
        return result_count
    print_subheader(f"Found {result_count} attack path(s) from Exchange Trusted Subsystem")

    if results:
        print_warning("[!] Exchange Trusted Subsystem has excessive privileges by default!")
        print_warning("    Members can escalate to Domain Admin via WriteDacl abuse")
        print_table(
            ["Exchange Group", "Target", "Type", "Hops"],
            [
                [r["exchange_group"], r["target"], r["target_type"], r["path_length"]]
                for r in results
            ],
        )

    return result_count
