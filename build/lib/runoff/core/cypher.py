"""Cypher query helpers for BloodHound CE"""
from __future__ import annotations

import re


def node_type(var: str = "n") -> str:
    """
    Generate Cypher CASE expression to get semantic node type.
    BloodHound CE nodes have multiple labels (e.g., Base, Group), so we
    check for specific labels in order of preference.
    """
    # Validate variable name to prevent Cypher injection
    if not re.match(r"^[a-zA-Z_]\w*$", var):
        raise ValueError(f"Invalid Cypher variable name: {var}")
    return f"""CASE
        WHEN {var}:User THEN 'User'
        WHEN {var}:Group THEN 'Group'
        WHEN {var}:Computer THEN 'Computer'
        WHEN {var}:Domain THEN 'Domain'
        WHEN {var}:GPO THEN 'GPO'
        WHEN {var}:OU THEN 'OU'
        WHEN {var}:Container THEN 'Container'
        WHEN {var}:EnterpriseCA THEN 'EnterpriseCA'
        WHEN {var}:CertTemplate THEN 'CertTemplate'
        WHEN {var}:NTAuthStore THEN 'NTAuthStore'
        WHEN {var}:RootCA THEN 'RootCA'
        WHEN {var}:AIACA THEN 'AIACA'
        ELSE labels({var})[0]
    END"""


def owned_filter(var: str = "n") -> str:
    """Generate Cypher WHERE clause to filter for owned principals"""
    if not re.match(r"^[a-zA-Z_]\w*$", var):
        raise ValueError(f"Invalid Cypher variable name: {var}")
    return f"({var}:Tag_Owned OR 'owned' IN COALESCE({var}.system_tags, []) OR {var}.owned = true)"


def tier_zero_filter(var: str = "n") -> str:
    """Generate Cypher WHERE clause to filter for Tier Zero principals"""
    if not re.match(r"^[a-zA-Z_]\w*$", var):
        raise ValueError(f"Invalid Cypher variable name: {var}")
    return f"({var}:Tag_Tier_Zero OR 'admin_tier_0' IN COALESCE({var}.system_tags, []))"


def domain_filter(
    var: str = "n",
    domain: str | None = None,
    domain_sid: str | None = None,
    prefix: str = "WHERE",
) -> tuple[str, dict]:
    """Generate flexible domain filter that handles data inconsistencies.

    BloodHound data may have inconsistent domain properties (e.g., objects have
    domain='DC01.DOMAIN.COM' while the Domain node is named 'DOMAIN.COM'). This
    helper generates filters that match by domain SID (most reliable) or by
    name suffix (fallback for compatibility).

    Args:
        var: The Cypher variable name to filter on (e.g., 'n', 'u', 'c')
        domain: The domain name to filter by (e.g., 'DOMAIN.COM')
        domain_sid: The domain SID if known (e.g., 'S-1-5-21-...')
        prefix: 'WHERE' or 'AND' depending on query context

    Returns:
        Tuple of (filter_clause, params_dict)

    Examples:
        >>> clause, params = domain_filter("u", "DOMAIN.COM", "S-1-5-21-123")
        >>> query = f"MATCH (u:User) {clause} RETURN u"
    """
    if not re.match(r"^[a-zA-Z_]\w*$", var):
        raise ValueError(f"Invalid Cypher variable name: {var}")

    if not domain:
        return "", {}

    # Use SID-based matching if available (most reliable)
    # Falls back to name-based matching if domainsid property doesn't exist
    if domain_sid:
        clause = f"""{prefix} (
            {var}.domainsid = $domain_sid
            OR toUpper({var}.domain) = toUpper($domain)
            OR toUpper({var}.name) ENDS WITH toUpper($domain_suffix)
        )"""
        params = {
            "domain_sid": domain_sid,
            "domain": domain,
            "domain_suffix": f".{domain}",
        }
    else:
        # No SID available, use name-based matching with fallback
        clause = f"""{prefix} (
            toUpper({var}.domain) = toUpper($domain)
            OR toUpper({var}.name) ENDS WITH toUpper($domain_suffix)
        )"""
        params = {
            "domain": domain,
            "domain_suffix": f".{domain}",
        }

    return clause, params


def domain_filter_simple(
    var: str = "n",
    domain: str | None = None,
    prefix: str = "WHERE",
) -> str:
    """Generate simple domain filter string (legacy compatibility).

    For queries that use inline domain filtering without external params.
    Prefers exact match on domain property, with fallback to name suffix.

    Args:
        var: The Cypher variable name
        domain: The domain name
        prefix: 'WHERE' or 'AND'

    Returns:
        Filter clause string (empty if no domain)
    """
    if not re.match(r"^[a-zA-Z_]\w*$", var):
        raise ValueError(f"Invalid Cypher variable name: {var}")

    if not domain:
        return ""

    return f"""{prefix} (
        toUpper({var}.domain) = toUpper($domain)
        OR toUpper({var}.name) ENDS WITH toUpper($domain_suffix)
    )"""
