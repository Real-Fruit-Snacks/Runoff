"""Connection context manager and CLI utilities."""

from __future__ import annotations

import sys
from contextlib import contextmanager

from runoff.core.bloodhound import BloodHoundCE
from runoff.core.config import config
from runoff.display import console


def _extract_host_from_bolt(bolt_uri: str) -> str | None:
    """Extract hostname/IP from a bolt URI for use in abuse commands."""
    from urllib.parse import urlparse

    try:
        parsed = urlparse(bolt_uri)
        host = parsed.hostname
        if host and host not in ("localhost", "127.0.0.1", "::1"):
            return host
    except Exception:
        pass
    return None


@contextmanager
def connect(ctx_obj: dict):
    """Context manager for Neo4j connection lifecycle.

    Usage:
        @click.pass_context
        def my_command(ctx):
            with connect(ctx.obj) as bh:
                results = bh.run_query(...)
    """
    bh = BloodHoundCE(
        ctx_obj["bolt"],
        ctx_obj["username"],
        ctx_obj["password"],
        ctx_obj.get("debug", False),
    )
    bh._structured_emitted = False

    # Populate DC IP from bolt URI for abuse command placeholders
    if not config.dc_ip:
        host = _extract_host_from_bolt(ctx_obj["bolt"])
        if host:
            config.dc_ip = host

    try:
        if not bh.connect():
            console.print("[error]Connection failed[/error]")
            console.print(f"  [text.secondary]URI:[/text.secondary] {ctx_obj['bolt']}")
            console.print(f"  [text.secondary]User:[/text.secondary] {ctx_obj['username']}")
            console.print()
            console.print(
                "[text.dim]Check that Neo4j is running and credentials are correct.[/text.dim]"
            )
            sys.exit(1)

        # Load owned cache, then clear so owned-init results don't pollute output
        _init_owned_cache(bh)
        bh.clear_results_cache()

        yield bh
    except KeyboardInterrupt:
        console.print("\n[text.dim]Interrupted.[/text.dim]")
        sys.exit(130)
    finally:
        # Auto-emit structured output for non-table formats
        if (
            config.output_format in ("json", "csv", "html", "markdown")
            and not bh._structured_emitted
            and bh.accumulated_results
        ):
            from runoff.display.output import emit_structured

            emit_structured(bh.accumulated_results)
        try:
            bh.close()
        except Exception:
            pass


def _init_owned_cache(bh: BloodHoundCE) -> None:
    """Populate owned principals cache from database."""
    query = """
    MATCH (n)
    WHERE (n:Tag_Owned OR 'owned' IN n.system_tags OR n.owned = true)
    RETURN n.name AS name, COALESCE(n.admincount, false) AS is_admin
    """
    try:
        results = bh.run_query(query)
        config.owned_cache = {r["name"]: r["is_admin"] for r in results if r.get("name")}
    except Exception as e:
        from runoff.core.config import config as _cfg

        if _cfg.debug_mode:
            from runoff.display import console

            console.print(f"[text.dim]Debug: owned cache init failed: {e}[/text.dim]")
        config.owned_cache = {}


def sync_config(ctx_obj: dict) -> None:
    """Sync Click context to global config singleton."""
    config.output_format = ctx_obj.get("output_format", "table")
    config.output_file = ctx_obj.get("output_file")
    config.quiet_mode = ctx_obj.get("quiet", False)
    config.no_color = ctx_obj.get("no_color", False)
    config.debug_mode = ctx_obj.get("debug", False)
    config.show_abuse = ctx_obj.get("abuse", False)
    config.current_domain = ctx_obj.get("domain")
    severity = ctx_obj.get("severity")
    if severity:
        config.severity_filter = {s.strip().upper() for s in severity.split(",")}
