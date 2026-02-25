"""AS-REP Roastable Users"""

from __future__ import annotations

from typing import TYPE_CHECKING

from runoff.abuse import print_abuse_for_query
from runoff.display.colors import Severity
from runoff.display.tables import print_header, print_subheader, print_table, print_warning
from runoff.queries.base import register_query

if TYPE_CHECKING:
    from runoff.core.bloodhound import BloodHoundCE


@register_query(
    name="AS-REP Roastable Users",
    category="Privilege Escalation",
    default=True,
    severity=Severity.HIGH,
    tags=("quick-win", "requires-creds"),
)
def get_asrep_roastable(
    bh: BloodHoundCE, domain: str | None = None, severity: Severity = None
) -> int:
    """Get AS-REP roastable users (dontreqpreauth=true)"""
    # Use flexible domain filter that handles data inconsistencies
    if domain:
        domain_filter = """WHERE (
            toUpper(u.domain) = toUpper($domain)
            OR toUpper(u.name) ENDS WITH toUpper($domain_suffix)
        )"""
        params = {"domain": domain, "domain_suffix": f".{domain}"}
    else:
        domain_filter = ""
        params = {}

    query = f"""
    MATCH (u:User {{dontreqpreauth: true}})
    {domain_filter}
    RETURN
        u.name AS name,
        u.displayname AS displayname,
        u.enabled AS enabled,
        u.admincount AS admincount,
        u.description AS description
    ORDER BY u.admincount DESC, u.name
    LIMIT 1000
    """
    results = bh.run_query(query, params)
    result_count = len(results)

    if not print_header("AS-REP Roastable Users (Pre-Auth Disabled)", severity, result_count):
        return result_count
    print_subheader(f"Found {result_count} AS-REP roastable user(s)")

    if results:
        admin_count = sum(1 for r in results if r.get("admincount"))
        if admin_count:
            print_warning(f"[!] {admin_count} are admin accounts!")

        print_table(
            ["Name", "Display Name", "Enabled", "Admin", "Description"],
            [
                [r["name"], r["displayname"], r["enabled"], r["admincount"], r["description"]]
                for r in results
            ],
        )
        print_abuse_for_query("asrep", results)

    return result_count
