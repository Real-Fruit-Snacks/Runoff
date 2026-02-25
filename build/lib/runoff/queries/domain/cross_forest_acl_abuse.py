"""Cross-Forest ACL Abuse"""

from __future__ import annotations

from typing import TYPE_CHECKING

from runoff.display.colors import Severity
from runoff.display.tables import print_header, print_subheader, print_table, print_warning
from runoff.queries.base import register_query

if TYPE_CHECKING:
    from runoff.core.bloodhound import BloodHoundCE


@register_query(
    name="Cross-Forest ACL Abuse",
    category="Basic Info",
    default=True,
    severity=Severity.CRITICAL,
    tags=("quick-win",),
)
def get_cross_forest_acl_abuse(
    bh: BloodHoundCE, domain: str | None = None, severity: Severity = None
) -> int:
    """Find principals with dangerous ACL edges on objects in a different forest/domain"""
    query = """
    MATCH (attacker)-[r]->(target)
    WHERE type(r) IN ['GenericAll', 'GenericWrite', 'WriteDacl', 'WriteOwner', 'ForceChangePassword', 'AddMember']
    AND toLower(attacker.domain) <> toLower(target.domain)
    AND attacker.domain IS NOT NULL AND attacker.domain <> ''
    AND target.domain IS NOT NULL AND target.domain <> ''
    AND NOT attacker.objectid ENDS WITH '-512'
    AND NOT attacker.objectid ENDS WITH '-519'
    AND NOT attacker.objectid ENDS WITH '-544'
    RETURN
        attacker.name AS attacker,
        attacker.domain AS attacker_domain,
        type(r) AS edge_type,
        target.name AS target_object,
        target.domain AS target_domain,
        CASE WHEN target:User THEN 'User' WHEN target:Group THEN 'Group' WHEN target:Computer THEN 'Computer' WHEN target:GPO THEN 'GPO' ELSE 'Other' END AS target_type
    ORDER BY attacker.domain, target.domain
    LIMIT 50
    """
    results = bh.run_query(query)
    result_count = len(results)

    if not print_header("Cross-Forest ACL Abuse", severity, result_count):
        return result_count
    print_subheader(f"Found {result_count} cross-forest ACL relationship(s)")

    if results:
        print_warning("[!] Principals with dangerous ACL edges across forest/domain boundaries!")
        print_warning("    These edges enable privilege escalation across trust boundaries.")

        print_table(
            ["Attacker", "Attacker Domain", "Edge", "Target", "Target Domain", "Type"],
            [
                [
                    r["attacker"],
                    r["attacker_domain"],
                    r["edge_type"],
                    r["target_object"],
                    r["target_domain"],
                    r["target_type"],
                ]
                for r in results
            ],
        )

    return result_count
