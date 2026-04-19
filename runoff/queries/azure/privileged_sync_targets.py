"""Privileged accounts that may be synced to Azure AD."""

from __future__ import annotations

from typing import TYPE_CHECKING

from runoff.display.colors import Severity
from runoff.display.tables import print_header, print_subheader, print_table, print_warning
from runoff.queries.base import register_query

if TYPE_CHECKING:
    from runoff.core.bloodhound import BloodHoundCE


@register_query(
    name="Privileged Accounts Synced to Azure",
    category="Azure/Hybrid",
    default=True,
    severity=Severity.HIGH,
)
def get_privileged_sync_targets(
    bh: BloodHoundCE, domain: str | None = None, severity: Severity = None
) -> int:
    """Find privileged accounts that appear to be synced to Azure AD.

    Privileged on-prem accounts synced to Azure AD expand the attack surface.
    If Azure is compromised, these accounts become targets for password spray
    or token theft attacks that could impact on-prem infrastructure.
    """
    domain_filter_u = "AND toUpper(u.domain) = toUpper($domain)" if domain else ""
    domain_filter_c = "AND toUpper(c.domain) = toUpper($domain)" if domain else ""
    domain_filter_n = "AND toUpper(n.domain) = toUpper($domain)" if domain else ""
    params = {"domain": domain} if domain else {}

    # First confirm the domain actually has Azure AD sync infrastructure.
    # Previously this finding fired on every privileged user regardless of
    # whether anything in the environment was synced to Azure — producing
    # false-positive HIGH findings in on-prem-only environments.
    # Sync indicators: AAD Connect host, Seamless SSO computer object
    # (AZUREADSSOACC$), or MSOL_/AAD_/SYNC_ accounts.
    sync_probe = f"""
    OPTIONAL MATCH (c:Computer)
    WHERE (c.name =~ '(?i).*(AADC|AZUREAD|AADCONNECT|DIRSYNC).*'
           OR ANY(spn IN COALESCE(c.serviceprincipalnames, [])
                  WHERE toUpper(spn) CONTAINS 'AZUREADSSOACC'))
    {domain_filter_c}
    WITH collect(DISTINCT c.name) AS sync_hosts
    OPTIONAL MATCH (n)
    WHERE (n:User OR n:Computer)
    AND n.name =~ '(?i).*(MSOL_|AAD_|SYNC_|AZUREADSSOACC).*'
    {domain_filter_n}
    RETURN sync_hosts, collect(DISTINCT n.name) AS sync_accounts
    """
    probe = bh.run_query(sync_probe, params)
    sync_hosts = (probe[0].get("sync_hosts") if probe else None) or []
    sync_accounts = (probe[0].get("sync_accounts") if probe else None) or []

    if not sync_hosts and not sync_accounts:
        # No Azure sync infrastructure detected — this finding does not apply.
        # Render the header so the user can see it was checked but avoid a
        # misleading HIGH banner and table.
        if print_header("Privileged Accounts Synced to Azure", severity, 0):
            print_subheader("No Azure AD sync infrastructure detected — skipping")
        return 0

    # Sync infrastructure is present. Now the list of privileged on-prem
    # accounts is legitimately at risk (if they're synced, an Azure compromise
    # reaches them).
    query = f"""
    MATCH (u:User)-[:MemberOf*1..]->(g:Group)
    WHERE (g.highvalue = true OR g:Tag_Tier_Zero OR g.admincount = true
           OR g.objectid ENDS WITH '-512'
           OR g.objectid ENDS WITH '-519'
           OR g.objectid ENDS WITH '-544')
    AND u.enabled = true
    AND NOT u.name STARTS WITH 'KRBTGT@'
    {domain_filter_u}
    WITH DISTINCT u, collect(DISTINCT g.name) AS priv_groups
    RETURN u.name AS user,
           u.displayname AS display_name,
           size(priv_groups) AS priv_group_count,
           priv_groups[0..3] AS sample_groups
    ORDER BY priv_group_count DESC
    LIMIT 50
    """
    results = bh.run_query(query, params)
    result_count = len(results)

    if not print_header("Privileged Accounts Synced to Azure", severity, result_count):
        return result_count

    print_subheader(f"Found {result_count} privileged account(s) at risk from Azure sync")

    if sync_hosts:
        print_warning(f"    Azure sync host(s) detected: {', '.join(sync_hosts[:3])}")
    if sync_accounts:
        print_warning(f"    Sync account(s) detected: {', '.join(sync_accounts[:3])}")

    if results:
        print_warning("[!] These privileged accounts may be synced to Azure AD")
        print_warning("    Consider: Are these accounts excluded from Azure AD sync?")
        print_table(
            ["User", "Display Name", "Priv Groups", "Sample Groups"],
            [
                [
                    r["user"],
                    r.get("display_name") or "N/A",
                    r["priv_group_count"],
                    ", ".join(r.get("sample_groups") or []),
                ]
                for r in results
            ],
        )

    return result_count
