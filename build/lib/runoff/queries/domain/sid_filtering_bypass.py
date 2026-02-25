"""SID Filtering Bypass Paths"""

from __future__ import annotations

from typing import TYPE_CHECKING

from runoff.display.colors import Severity
from runoff.display.tables import print_header, print_subheader, print_table, print_warning
from runoff.queries.base import register_query

if TYPE_CHECKING:
    from runoff.core.bloodhound import BloodHoundCE


@register_query(
    name="SID Filtering Bypass Paths",
    category="Basic Info",
    default=True,
    severity=Severity.CRITICAL,
    tags=("quick-win",),
)
def get_sid_filtering_bypass(
    bh: BloodHoundCE, domain: str | None = None, severity: Severity = None
) -> int:
    """Find trusts with SID filtering disabled and cross-trust attack paths viable for SID history injection"""
    query = """
    MATCH (d1:Domain)-[trust:TrustedBy]->(d2:Domain)
    WHERE trust.sidfilteringenabled = false
    OPTIONAL MATCH (u)-[:MemberOf|HasSIDHistory*1..]->(target)
    WHERE toLower(u.domain) = toLower(d2.name)
    AND toLower(target.domain) = toLower(d1.name)
    AND (target:Group OR target:User)
    RETURN
        d1.name AS trusting_domain,
        d2.name AS trusted_domain,
        COALESCE(trust.trusttype, 'Unknown') AS trust_type,
        u.name AS cross_trust_principal,
        target.name AS target_in_trusting,
        CASE WHEN target:Group THEN 'Group' WHEN target:User THEN 'User' ELSE 'Other' END AS target_type
    ORDER BY d1.name, d2.name
    LIMIT 50
    """
    results = bh.run_query(query)
    # Filter out rows where cross_trust_principal is null (trusts with no cross-trust paths)
    results = [r for r in results if r.get("cross_trust_principal") is not None]
    result_count = len(results)

    if not print_header("SID Filtering Bypass Paths", severity, result_count):
        return result_count
    print_subheader(f"Found {result_count} SID filtering bypass path(s)")

    if results:
        print_warning("[!] Trusts with SID filtering DISABLED and cross-trust attack paths exist!")
        print_warning(
            "    Golden Ticket + SID History injection attacks are viable across these trusts."
        )

        print_table(
            ["Trusting Domain", "Trusted Domain", "Type", "Principal", "Target", "Target Type"],
            [
                [
                    r["trusting_domain"],
                    r["trusted_domain"],
                    r["trust_type"],
                    r["cross_trust_principal"],
                    r["target_in_trusting"],
                    r["target_type"],
                ]
                for r in results
            ],
        )

    return result_count
