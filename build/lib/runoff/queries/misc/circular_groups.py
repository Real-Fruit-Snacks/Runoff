"""Circular Group Memberships"""

from __future__ import annotations

from typing import TYPE_CHECKING

from runoff.display.colors import Severity
from runoff.display.tables import print_header, print_subheader, print_table, print_warning
from runoff.queries.base import register_query

if TYPE_CHECKING:
    from runoff.core.bloodhound import BloodHoundCE


@register_query(
    name="Circular Group Memberships", category="Miscellaneous", default=True, severity=Severity.LOW
)
def get_circular_groups(
    bh: BloodHoundCE, domain: str | None = None, severity: Severity = None
) -> int:
    """Find circular group memberships (misconfigurations)"""
    if domain:
        domain_where = "WHERE toUpper(g.domain) = toUpper($domain)"
        params = {"domain": domain}
    else:
        domain_where = ""
        params = {}

    query = f"""
    MATCH p=(g:Group)-[:MemberOf*2..6]->(g)
    {domain_where}
    RETURN DISTINCT
        g.name AS group_name,
        [n IN nodes(p) | n.name] AS cycle_path,
        length(p) AS cycle_length
    LIMIT 20
    """
    results = bh.run_query(query, params)
    result_count = len(results)

    if not print_header("Circular Group Memberships", severity, result_count):
        return result_count
    print_subheader(f"Found {result_count} circular group membership(s)")

    if results:
        print_warning("Circular group memberships are misconfigurations that should be fixed!")
        print_table(
            ["Group", "Cycle Path", "Cycle Length"],
            [[r["group_name"], r["cycle_path"], r["cycle_length"]] for r in results],
        )

    return result_count
