"""GPO Links to Tier Zero OUs"""

from __future__ import annotations

from typing import TYPE_CHECKING

from runoff.display.colors import Severity
from runoff.display.tables import print_header, print_subheader, print_table, print_warning
from runoff.queries.base import register_query

if TYPE_CHECKING:
    from runoff.core.bloodhound import BloodHoundCE


@register_query(
    name="GPO Links to Tier Zero",
    category="GPO Abuse",
    default=True,
    severity=Severity.CRITICAL,
    tags=("quick-win",),
)
def get_gpo_to_tier_zero(
    bh: BloodHoundCE, domain: str | None = None, severity: Severity = None
) -> int:
    """Find GPOs linked to OUs containing tier zero assets (DCs, admin groups)"""
    domain_filter = "AND toUpper(gpo.domain) = toUpper($domain)" if domain else ""
    params = {"domain": domain} if domain else {}

    query = f"""
    MATCH (gpo:GPO)-[:GpLink]->(ou)
    WHERE (ou:OU OR ou:Domain)
    {domain_filter}
    MATCH (asset)-[:MemberOf|Contains*0..]->(ou)
    WHERE (asset:Computer AND asset.objectid ENDS WITH '-516')
       OR ('admin_tier_0' IN COALESCE(asset.system_tags, []))
       OR (asset:Group AND (asset.objectid ENDS WITH '-512' OR asset.objectid ENDS WITH '-519'))
    WITH gpo, ou, collect(DISTINCT asset.name) AS tier_zero_assets
    OPTIONAL MATCH (controller)-[r]->(gpo)
    WHERE r.isacl = true AND type(r) IN ['GenericAll', 'WriteDacl', 'WriteOwner', 'Owns', 'GenericWrite']
    AND (controller.admincount IS NULL OR controller.admincount = false)
    RETURN
        gpo.name AS gpo_name,
        ou.name AS linked_to,
        size(tier_zero_assets) AS tier_zero_count,
        tier_zero_assets[0..3] AS sample_assets,
        collect(DISTINCT controller.name) AS non_admin_controllers
    ORDER BY size(tier_zero_assets) DESC
    LIMIT 25
    """
    results = bh.run_query(query, params)
    result_count = len(results)

    if not print_header("GPO Links to Tier Zero", severity, result_count):
        return result_count
    print_subheader(f"Found {result_count} GPO(s) linked to tier zero OUs")

    if results:
        controllable = sum(1 for r in results if r.get("non_admin_controllers"))
        if controllable:
            print_warning(
                f"[!] {controllable} GPO(s) have non-admin controllers \u2014 critical escalation path!"
            )
        print_warning("    GPO modification on tier zero OUs can compromise DCs and admin accounts")

        def fmt_assets(r):
            samples = r.get("sample_assets", [])
            total = r.get("tier_zero_count", 0)
            if total > 3:
                return ", ".join(samples) + f" (+{total - 3} more)"
            return ", ".join(samples) if samples else "None"

        def fmt_controllers(r):
            ctrls = r.get("non_admin_controllers", [])
            if not ctrls:
                return "None (admin-only)"
            return ", ".join(ctrls[:3]) + (f" (+{len(ctrls) - 3} more)" if len(ctrls) > 3 else "")

        print_table(
            ["GPO", "Linked To", "T0 Assets", "Non-Admin Controllers"],
            [[r["gpo_name"], r["linked_to"], fmt_assets(r), fmt_controllers(r)] for r in results],
        )

    return result_count
