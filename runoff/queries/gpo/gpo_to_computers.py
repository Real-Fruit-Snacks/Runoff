"""GPO Control to Computer Execution"""

from __future__ import annotations

from typing import TYPE_CHECKING

from runoff.display.colors import Severity
from runoff.display.tables import print_header, print_subheader, print_table, print_warning
from runoff.queries.base import register_query

if TYPE_CHECKING:
    from runoff.core.bloodhound import BloodHoundCE


@register_query(
    name="GPO Control to Computer Execution",
    category="GPO Abuse",
    default=True,
    severity=Severity.HIGH,
    tags=("quick-win",),
)
def get_gpo_to_computers(
    bh: BloodHoundCE, domain: str | None = None, severity: Severity = None
) -> int:
    """Find non-admin principals who control GPOs linked to computers"""
    domain_filter = "AND toUpper(gpo.domain) = toUpper($domain)" if domain else ""
    params = {"domain": domain} if domain else {}

    query = f"""
    MATCH (controller)-[r:GenericAll|GenericWrite|WriteDacl|WriteOwner|Owns]->(gpo:GPO)
    WHERE (controller.admincount IS NULL OR controller.admincount = false)
    AND NOT controller.objectid ENDS WITH '-512'
    AND NOT controller.objectid ENDS WITH '-519'
    AND NOT controller.objectid ENDS WITH '-544'
    {domain_filter}
    MATCH (gpo)-[:GpLink]->(ou:OU)
    MATCH (c:Computer)-[:MemberOf|Contains*0..]->(ou)
    WHERE c.enabled = true
    WITH controller, gpo, ou, collect(DISTINCT c.name) AS computers
    RETURN
        controller.name AS principal,
        CASE WHEN controller:User THEN 'User' WHEN controller:Group THEN 'Group' ELSE 'Other' END AS principal_type,
        gpo.name AS gpo_name,
        ou.name AS linked_ou,
        size(computers) AS computer_count,
        computers[0..3] AS sample_computers
    ORDER BY computer_count DESC
    LIMIT 50
    """
    results = bh.run_query(query, params)
    result_count = len(results)

    if not print_header("GPO Control to Computer Execution", severity, result_count):
        return result_count
    print_subheader(f"Found {result_count} GPO control \u2192 computer execution path(s)")

    if results:
        total_computers = sum(r.get("computer_count", 0) for r in results)
        print_warning(f"[!] Non-admin GPO control affects {total_computers} computer(s)!")
        print_warning(
            "    GPO modification enables scheduled tasks, logon scripts, or software deployment"
        )

        def fmt_computers(r):
            samples = r.get("sample_computers", [])
            total = r.get("computer_count", 0)
            if total > 3:
                return ", ".join(samples) + f" (+{total - 3} more)"
            return ", ".join(samples) if samples else "None"

        print_table(
            ["Principal", "Type", "GPO", "Linked OU", "Computers", "Affected"],
            [
                [
                    r["principal"],
                    r["principal_type"],
                    r["gpo_name"],
                    r["linked_ou"],
                    fmt_computers(r),
                    r["computer_count"],
                ]
                for r in results
            ],
        )

    return result_count
