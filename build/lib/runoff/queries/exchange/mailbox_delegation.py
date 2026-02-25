"""Mailbox Delegation Rights"""

from __future__ import annotations

from typing import TYPE_CHECKING

from runoff.core.cypher import node_type
from runoff.display.colors import Severity
from runoff.display.tables import print_header, print_subheader, print_table, print_warning
from runoff.queries.base import register_query

if TYPE_CHECKING:
    from runoff.core.bloodhound import BloodHoundCE


@register_query(
    name="Mailbox Delegation Rights",
    category="Exchange",
    default=False,
    severity=Severity.MEDIUM,
    tags=("stealthy",),
)
def get_mailbox_delegation(
    bh: BloodHoundCE, domain: str | None = None, severity: Severity = None
) -> int:
    """Find principals with mailbox delegation rights (FullAccess, SendAs, SendOnBehalf)"""
    domain_filter = "AND toUpper(target.domain) = toUpper($domain)" if domain else ""
    params = {"domain": domain} if domain else {}

    query = f"""
    MATCH (src)-[r]->(target:User)
    WHERE type(r) IN ['FullAccess', 'SendAs', 'SendOnBehalf']
    AND src <> target
    AND target.enabled = true
    {domain_filter}
    RETURN
        src.name AS delegate,
        {node_type("src")} AS delegate_type,
        target.name AS mailbox_owner,
        type(r) AS permission,
        target.admincount AS owner_is_admin
    ORDER BY target.admincount DESC, target.name
    LIMIT 100
    """
    results = bh.run_query(query, params)
    result_count = len(results)

    if not print_header("Mailbox Delegation Rights", severity, result_count):
        return result_count
    print_subheader(f"Found {result_count} mailbox delegation relationship(s)")

    if results:
        admin_targets = sum(1 for r in results if r.get("owner_is_admin"))
        if admin_targets:
            print_warning(f"[!] {admin_targets} delegation(s) target admin mailboxes!")
            print_warning("    Delegates can read emails, exfiltrate data, or phish as admins")
        print_table(
            ["Delegate", "Type", "Mailbox Owner", "Permission", "Owner Admin"],
            [
                [
                    r["delegate"],
                    r["delegate_type"],
                    r["mailbox_owner"],
                    r["permission"],
                    r["owner_is_admin"],
                ]
                for r in results
            ],
        )

    return result_count
