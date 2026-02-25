"""Windows LAPS Migration Candidates"""

from __future__ import annotations

from typing import TYPE_CHECKING

from runoff.display.colors import Severity
from runoff.display.tables import print_header, print_subheader, print_table
from runoff.queries.base import register_query

if TYPE_CHECKING:
    from runoff.core.bloodhound import BloodHoundCE


@register_query(
    name="Windows LAPS Migration Candidates",
    category="Security Hygiene",
    default=False,
    severity=Severity.LOW,
    tags=("stealthy",),
)
def get_windows_laps_coverage(
    bh: BloodHoundCE, domain: str | None = None, severity: Severity = None
) -> int:
    """Get computers with legacy LAPS on modern OS (Windows LAPS v2 migration candidates)"""
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
    {"AND" if domain_filter else "WHERE"} c.enabled = true AND c.haslaps = true
    AND (c.operatingsystem CONTAINS 'Server 2019' OR c.operatingsystem CONTAINS 'Server 2022'
         OR c.operatingsystem CONTAINS 'Server 2025' OR c.operatingsystem CONTAINS 'Windows 10'
         OR c.operatingsystem CONTAINS 'Windows 11')
    OPTIONAL MATCH (reader)-[:ReadLAPSPassword]->(c)
    RETURN
        c.name AS computer,
        c.operatingsystem AS os,
        collect(DISTINCT reader.name) AS laps_readers,
        size(collect(DISTINCT reader.name)) AS reader_count
    ORDER BY c.name
    LIMIT 100
    """
    results = bh.run_query(query, params)
    result_count = len(results)

    if not print_header("Windows LAPS Migration Candidates", severity, result_count):
        return result_count
    print_subheader(f"Found {result_count} computer(s) with legacy LAPS on modern OS (limit 100)")

    if results:

        def fmt_readers(readers):
            if not readers:
                return "(none)"
            if len(readers) <= 3:
                return ", ".join(readers)
            extra = len(readers) - 3
            return ", ".join(readers[:3]) + f" (+{extra} more)"

        print_table(
            ["Computer", "Operating System", "LAPS Readers", "Reader Count"],
            [
                [
                    r["computer"],
                    r["os"],
                    fmt_readers(r["laps_readers"]),
                    r["reader_count"],
                ]
                for r in results
            ],
        )

    return result_count
