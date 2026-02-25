"""LAPS Coverage Gaps (Modern OS)"""

from __future__ import annotations

import time
from typing import TYPE_CHECKING

from runoff.display.colors import Severity
from runoff.display.tables import print_header, print_subheader, print_table, print_warning
from runoff.queries.base import register_query

if TYPE_CHECKING:
    from runoff.core.bloodhound import BloodHoundCE


@register_query(
    name="LAPS Coverage Gaps (Modern OS)",
    category="Security Hygiene",
    default=True,
    severity=Severity.MEDIUM,
    tags=("quick-win",),
)
def get_laps_coverage_gaps(
    bh: BloodHoundCE, domain: str | None = None, severity: Severity = None
) -> int:
    """Get modern OS computers without any LAPS configured"""
    # Use flexible domain filter that handles data inconsistencies
    if domain:
        domain_filter = """WHERE (
            toUpper(c.domain) = toUpper($domain)
            OR toUpper(c.name) ENDS WITH toUpper($domain_suffix)
        )"""
        params = {"domain": domain, "domain_suffix": f".{domain}"}
    else:
        domain_filter = ""
        params = {}

    query = f"""
    MATCH (c:Computer)
    {domain_filter}
    {"AND" if domain_filter else "WHERE"} c.enabled = true
    AND (c.haslaps IS NULL OR c.haslaps = false)
    AND (c.operatingsystem CONTAINS 'Server 2019' OR c.operatingsystem CONTAINS 'Server 2022'
         OR c.operatingsystem CONTAINS 'Server 2025' OR c.operatingsystem CONTAINS 'Windows 10'
         OR c.operatingsystem CONTAINS 'Windows 11')
    RETURN
        c.name AS computer,
        c.operatingsystem AS os,
        c.lastlogontimestamp AS last_logon
    ORDER BY c.operatingsystem, c.name
    LIMIT 100
    """
    results = bh.run_query(query, params)
    result_count = len(results)

    if not print_header("LAPS Coverage Gaps (Modern OS)", severity, result_count):
        return result_count
    print_subheader(f"Found {result_count} modern OS computer(s) without LAPS (limit 100)")

    if results:

        def epoch_to_date(epoch):
            if epoch and epoch > 0:
                try:
                    return time.strftime("%Y-%m-%d", time.localtime(epoch))
                except (ValueError, OSError, OverflowError):
                    return "Unknown"
            return "Never"

        print_table(
            ["Computer", "Operating System", "Last Logon"],
            [
                [
                    r["computer"],
                    r["os"],
                    epoch_to_date(r["last_logon"]),
                ]
                for r in results
            ],
        )
        print_warning(
            "[!] Deploy Windows LAPS on modern OS systems to protect local admin credentials!"
        )

    return result_count
