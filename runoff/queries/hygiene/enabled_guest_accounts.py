"""Enabled Guest Accounts"""

from __future__ import annotations

import time
from typing import TYPE_CHECKING

from runoff.display.colors import Severity
from runoff.display.tables import print_header, print_subheader, print_table, print_warning
from runoff.queries.base import register_query

if TYPE_CHECKING:
    from runoff.core.bloodhound import BloodHoundCE


@register_query(
    name="Enabled Guest Accounts", category="Security Hygiene", default=True, severity=Severity.HIGH
)
def get_enabled_guest_accounts(
    bh: BloodHoundCE, domain: str | None = None, severity: Severity = None
) -> int:
    """Find enabled Guest accounts"""
    domain_filter = "AND toUpper(u.domain) = toUpper($domain)" if domain else ""
    params = {"domain": domain} if domain else {}

    query = f"""
    MATCH (u:User)
    WHERE u.objectid ENDS WITH '-501'
    AND u.enabled = true
    {domain_filter}
    RETURN u.name AS account, u.domain AS domain, u.lastlogon AS last_logon
    """
    results = bh.run_query(query, params)
    result_count = len(results)

    if not print_header("Enabled Guest Accounts", severity, result_count):
        return result_count
    print_subheader(f"Found {result_count} enabled Guest account(s)")

    if results:
        # Never-logged-in accounts come back as lastlogon=0 (or None / -1 in
        # older collectors); format these as "Never" rather than the raw
        # epoch float (which renders as "0.0" in the table).
        def _format_logon(epoch) -> str:
            if epoch is None or epoch in (0, -1, 0.0, -1.0):
                return "Never"
            try:
                return time.strftime("%Y-%m-%d", time.localtime(epoch))
            except (ValueError, OSError, OverflowError, TypeError):
                return "Unknown"

        print_warning("Enabled Guest accounts are a security risk!")
        print_table(
            ["Account", "Domain", "Last Logon"],
            [[r["account"], r["domain"], _format_logon(r["last_logon"])] for r in results],
        )

    return result_count
