"""GPO Weak Link Chains"""

from __future__ import annotations

from typing import TYPE_CHECKING

from runoff.display.colors import Severity
from runoff.display.tables import print_header, print_subheader, print_table, print_warning
from runoff.queries.base import register_query

if TYPE_CHECKING:
    from runoff.core.bloodhound import BloodHoundCE


@register_query(
    name="GPO Weak Link Chains",
    category="GPO Abuse",
    default=True,
    severity=Severity.MEDIUM,
    tags=("stealthy",),
)
def get_gpo_weak_links(
    bh: BloodHoundCE, domain: str | None = None, severity: Severity = None
) -> int:
    """Find GPOs with non-enforced links or disabled links that could be re-enabled"""
    domain_filter = "AND toUpper(gpo.domain) = toUpper($domain)" if domain else ""
    params = {"domain": domain} if domain else {}

    query = f"""
    MATCH (gpo:GPO)-[link:GpLink]->(target)
    WHERE (target:OU OR target:Domain)
    {domain_filter}
    WITH gpo, target, link,
         CASE WHEN link.enforced = true THEN 'Enforced' ELSE 'Not Enforced' END AS enforcement
    OPTIONAL MATCH (controller)-[r]->(gpo)
    WHERE r.isacl = true AND type(r) IN ['GenericAll', 'WriteDacl', 'WriteOwner', 'Owns', 'GenericWrite']
    AND (controller:User OR controller:Group)
    AND (controller.admincount IS NULL OR controller.admincount = false)
    WITH gpo, target, enforcement, collect(DISTINCT controller.name) AS controllers
    WHERE size(controllers) > 0
    RETURN
        gpo.name AS gpo_name,
        target.name AS linked_target,
        enforcement,
        controllers[0..3] AS non_admin_controllers,
        size(controllers) AS controller_count
    ORDER BY enforcement, gpo.name
    LIMIT 50
    """
    results = bh.run_query(query, params)
    result_count = len(results)

    if not print_header("GPO Weak Link Chains", severity, result_count):
        return result_count
    print_subheader(f"Found {result_count} GPO(s) with non-admin controllers")

    if results:
        non_enforced = sum(1 for r in results if r.get("enforcement") == "Not Enforced")
        if non_enforced:
            print_warning(f"[!] {non_enforced} non-enforced GPO(s) controllable by non-admins")
        print_warning("    Non-admin GPO control + link to OU = potential code execution")

        def fmt_controllers(r):
            ctrls = r.get("non_admin_controllers", [])
            total = r.get("controller_count", 0)
            if total > 3:
                return ", ".join(ctrls) + f" (+{total - 3} more)"
            return ", ".join(ctrls) if ctrls else "None"

        print_table(
            ["GPO", "Linked To", "Enforcement", "Non-Admin Controllers"],
            [
                [r["gpo_name"], r["linked_target"], r["enforcement"], fmt_controllers(r)]
                for r in results
            ],
        )

    return result_count
