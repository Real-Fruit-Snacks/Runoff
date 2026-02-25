"""Unsupported Operating Systems"""

from __future__ import annotations

from typing import TYPE_CHECKING

from runoff.display.colors import Severity
from runoff.display.tables import print_header, print_subheader, print_table, print_warning
from runoff.queries.base import register_query

if TYPE_CHECKING:
    from runoff.core.bloodhound import BloodHoundCE


@register_query(
    name="Unsupported Operating Systems",
    category="Security Hygiene",
    default=True,
    severity=Severity.MEDIUM,
    tags=("stealthy",),
)
def get_unsupported_os(
    bh: BloodHoundCE, domain: str | None = None, severity: Severity = None
) -> int:
    """Find computers running unsupported operating systems"""
    domain_filter = "AND toUpper(c.domain) = toUpper($domain)" if domain else ""
    params = {"domain": domain} if domain else {}

    query = f"""
    MATCH (c:Computer)
    WHERE c.enabled = true
    AND c.operatingsystem IS NOT NULL
    AND (c.operatingsystem =~ '(?i).*(2000|2003|2008|2012|xp|vista|windows 7|windows 8|me).*')
    {domain_filter}
    RETURN c.name AS computer, c.operatingsystem AS os, c.lastlogon AS last_logon
    ORDER BY c.operatingsystem
    LIMIT 100
    """
    results = bh.run_query(query, params)
    result_count = len(results)

    if not print_header("Unsupported Operating Systems", severity, result_count):
        return result_count
    print_subheader(f"Found {result_count} computer(s) with unsupported OS")

    if results:
        print_warning("These systems may be vulnerable to unpatched exploits!")
        print_table(
            ["Computer", "Operating System", "Last Logon"],
            [[r["computer"], r["os"], r["last_logon"]] for r in results],
        )

    return result_count
