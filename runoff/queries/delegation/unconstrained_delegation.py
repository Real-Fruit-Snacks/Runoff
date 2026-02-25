"""Unconstrained Delegation"""

from __future__ import annotations

from typing import TYPE_CHECKING

from runoff.abuse import print_abuse_for_query
from runoff.display.colors import Severity
from runoff.display.tables import print_header, print_subheader, print_table
from runoff.queries.base import register_query

if TYPE_CHECKING:
    from runoff.core.bloodhound import BloodHoundCE


@register_query(
    name="Unconstrained Delegation",
    category="Delegation",
    default=True,
    severity=Severity.HIGH,
    tags=("quick-win",),
)
def get_unconstrained_delegation(
    bh: BloodHoundCE, domain: str | None = None, severity: Severity = None
) -> int:
    """Get computers with unconstrained delegation (excluding DCs)"""
    # Use flexible domain filter that handles data inconsistencies
    if domain:
        domain_filter = """AND (
            toUpper(c.domain) = toUpper($domain)
            OR toUpper(c.name) ENDS WITH toUpper($domain_suffix)
        )"""
        params = {"domain": domain, "domain_suffix": f".{domain}"}
    else:
        domain_filter = ""
        params = {}

    query = f"""
    MATCH (c:Computer {{unconstraineddelegation: true}})
    WHERE NOT EXISTS {{
        MATCH (c)-[:MemberOf*1..]->(g:Group)
        WHERE g.objectid ENDS WITH '-516'
    }}
    {domain_filter}
    RETURN
        c.name AS name,
        c.operatingsystem AS os,
        c.enabled AS enabled
    ORDER BY c.name
    """
    results = bh.run_query(query, params)
    result_count = len(results)

    if not print_header("Unconstrained Delegation (Non-DC)", severity, result_count):
        return result_count
    print_subheader(f"Found {result_count} computer(s) with unconstrained delegation")

    if results:
        print_table(
            ["Computer", "Operating System", "Enabled"],
            [[r["name"], r["os"], r["enabled"]] for r in results],
        )
        print_abuse_for_query("unconstrained", results, target_key="name")

    # Also show DCs with unconstrained delegation (INFO only, no severity)
    print_header("Domain Controllers (Unconstrained Delegation)")
    query = f"""
    MATCH (c:Computer {{unconstraineddelegation: true}})-[:MemberOf*1..]->(g:Group)
    WHERE g.objectid ENDS WITH '-516'
    {domain_filter}
    RETURN DISTINCT
        c.name AS name,
        c.operatingsystem AS os
    ORDER BY c.name
    """
    dc_results = bh.run_query(query, params)
    print_subheader(f"Found {len(dc_results)} domain controller(s)")

    if dc_results:
        print_table(
            ["Domain Controller", "Operating System"], [[r["name"], r["os"]] for r in dc_results]
        )

    return result_count
