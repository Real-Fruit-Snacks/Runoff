"""Pre-Windows 2000 Compatible Access Group Members"""

from __future__ import annotations

from typing import TYPE_CHECKING

from runoff.display.colors import Severity
from runoff.display.tables import print_header, print_table, print_warning
from runoff.queries.base import register_query

if TYPE_CHECKING:
    from runoff.core.bloodhound import BloodHoundCE


@register_query(
    name="Pre-Windows 2000 Compatible Access",
    category="Security Hygiene",
    default=True,
    severity=Severity.HIGH,
    tags=("quick-win",),
)
def get_pre_windows_2000(
    bh: BloodHoundCE, domain: str | None = None, severity: Severity = None
) -> int:
    """Get members of the Pre-Windows 2000 Compatible Access group"""
    if domain:
        domain_filter = "AND toUpper(g.domain) = toUpper($domain)"
        params = {"domain": domain}
    else:
        domain_filter = ""
        params = {}

    query = f"""
    MATCH (g:Group)
    WHERE g.name STARTS WITH 'PRE-WINDOWS 2000 COMPATIBLE ACCESS@'
    {domain_filter}
    OPTIONAL MATCH (m)-[:MemberOf*1..]->(g)
    WHERE m.name IS NOT NULL
    RETURN
        g.name AS group_name,
        m.name AS member,
        CASE WHEN m:User THEN 'User' WHEN m:Group THEN 'Group' WHEN m:Computer THEN 'Computer' ELSE 'Other' END AS member_type,
        m.enabled AS enabled
    ORDER BY m.name
    LIMIT 100
    """
    results = bh.run_query(query, params)
    filtered_results = [r for r in results if r.get("member") is not None]
    result_count = len(filtered_results)

    if not print_header("Pre-Windows 2000 Compatible Access", severity, result_count):
        return result_count

    print_warning(
        "Dangerous members include ANONYMOUS LOGON and Authenticated Users, "
        "which grant unauthenticated or low-privilege read access to AD objects."
    )

    if filtered_results:
        print_table(
            ["Group", "Member", "Type", "Enabled"],
            [
                [
                    r["group_name"],
                    r["member"],
                    r["member_type"],
                    str(r["enabled"]) if r["enabled"] is not None else "Unknown",
                ]
                for r in filtered_results
            ],
        )

    return result_count
