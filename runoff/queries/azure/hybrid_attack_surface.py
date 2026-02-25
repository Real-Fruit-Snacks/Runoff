"""Hybrid identity attack surface summary."""

from __future__ import annotations

from typing import TYPE_CHECKING

from runoff.display import console
from runoff.display.colors import Severity
from runoff.display.tables import print_header, print_subheader, print_table, print_warning
from runoff.queries.base import register_query

if TYPE_CHECKING:
    from runoff.core.bloodhound import BloodHoundCE


@register_query(
    name="Hybrid Identity Attack Surface",
    category="Azure/Hybrid",
    default=True,
    severity=Severity.HIGH,
)
def get_hybrid_attack_surface(
    bh: BloodHoundCE, domain: str | None = None, severity: Severity = None
) -> int:
    """Summarize the hybrid identity attack surface.

    Provides an overview of Azure/hybrid components including AAD Connect
    servers, sync accounts, ADFS servers, and related infrastructure.
    """
    # Domain filters for different variable names used in queries
    c_and = "AND toUpper(c.domain) = toUpper($domain)" if domain else ""
    n_and = "AND toUpper(n.domain) = toUpper($domain)" if domain else ""
    params = {"domain": domain} if domain else {}

    # Count different hybrid components
    components = []

    # AAD Connect servers
    aadc_query = f"""
    MATCH (c:Computer)
    WHERE c.name =~ '(?i).*(AADC|AZUREAD|AADCONNECT|DIRSYNC).*'
    {c_and}
    RETURN count(c) AS count
    """
    aadc_result = bh.run_query(aadc_query, params)
    aadc_count = aadc_result[0]["count"] if aadc_result else 0
    if aadc_count > 0:
        components.append(["AAD Connect Servers", aadc_count, "CRITICAL"])

    # Sync accounts
    sync_query = f"""
    MATCH (n)
    WHERE n.name =~ '(?i).*(MSOL_|AAD_|SYNC_|AZUREADSSOACC).*'
    {n_and}
    RETURN count(n) AS count
    """
    sync_result = bh.run_query(sync_query, params)
    sync_count = sync_result[0]["count"] if sync_result else 0
    if sync_count > 0:
        components.append(["Sync Accounts (MSOL/AAD/SYNC)", sync_count, "HIGH"])

    # ADFS servers
    adfs_query = f"""
    MATCH (c:Computer)
    WHERE c.name =~ '(?i).*(ADFS|FEDERATION|STS).*'
    OR ANY(spn IN COALESCE(c.serviceprincipalnames, [])
           WHERE spn =~ '(?i).*(adfs|federation).*')
    {c_and}
    RETURN count(c) AS count
    """
    adfs_result = bh.run_query(adfs_query, params)
    adfs_count = adfs_result[0]["count"] if adfs_result else 0
    if adfs_count > 0:
        components.append(["ADFS/Federation Servers", adfs_count, "HIGH"])

    # Sync accounts with DCSync
    dcsync_query = f"""
    MATCH (n)-[:GetChanges|GetChangesAll|DCSync]->(d:Domain)
    WHERE n.name =~ '(?i).*(MSOL_|AAD_|SYNC_).*'
    {n_and}
    RETURN count(DISTINCT n) AS count
    """
    dcsync_result = bh.run_query(dcsync_query, params)
    dcsync_count = dcsync_result[0]["count"] if dcsync_result else 0
    if dcsync_count > 0:
        components.append(["Sync Accounts with DCSync", dcsync_count, "CRITICAL"])

    result_count = len(components)

    if not print_header("Hybrid Identity Attack Surface", severity, result_count):
        return result_count

    print_subheader(f"Found {result_count} hybrid component type(s)")

    if components:
        print_warning("[!] Hybrid identity components detected - review Azure AD sync security")
        print_table(
            ["Component Type", "Count", "Risk Level"],
            components,
        )
        console.print()
        console.print("    Recommendations:", style="info")
        console.print("    - Restrict access to AAD Connect servers", style="text.secondary")
        console.print("    - Monitor sync account activity", style="text.secondary")
        console.print("    - Enable PHS with password protection", style="text.secondary")
        console.print(
            "    - Consider excluding privileged accounts from sync", style="text.secondary"
        )

    return result_count
