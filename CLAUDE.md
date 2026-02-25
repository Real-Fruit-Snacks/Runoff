# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Runoff is a Python CLI tool (Click-based) with Rich output using Catppuccin Mocha theme for extracting quick wins from BloodHound Community Edition's Neo4j database. It identifies Active Directory attack paths, misconfigurations, and privilege escalation opportunities.

**Invocation:**
```bash
# Run all queries
runoff -p 'bloodhoundcommunityedition' run all

# Run specific categories
runoff -p 'pass' run acl adcs -s HIGH

# Quick filters
runoff -p 'pass' kerberoastable
runoff -p 'pass' stats

# Node operations
runoff -p 'pass' info USER@CORP.LOCAL
runoff -p 'pass' search '*ADMIN*'

# Path finding
runoff -p 'pass' path da USER@CORP.LOCAL

# Quiet mode (suppress banner)
runoff -p 'bloodhoundcommunityedition' -q run all
```

## CLI Commands

All commands are one-shot CLI subcommands. Connection is automatic via the `-p` flag (and optionally `-b`, `-u`, `-d` for bolt URI, username, domain).

### Connection & Status
```bash
runoff -p pass status                # Show connection status
runoff -p pass domains               # List available domains
```

### Running Queries
```bash
runoff -p pass run all                      # Run all queries
runoff -p pass run acl adcs privesc         # Run specific categories
runoff -p pass run hygiene -s HIGH          # Run with severity filter
runoff -p pass query kerberoast             # Run single query by name
runoff -p pass query --list                 # List all queries
runoff -p pass queries                      # Alias for query --list
```

**Categories:** `all`, `acl`, `adcs`, `privesc`, `delegation`, `lateral`, `hygiene`, `owned`, `basic`, `groups`, `paths`, `azure`, `exchange`, `misc`

### Quick Filters
```bash
runoff -p pass kerberoastable               # Kerberoastable users
runoff -p pass asrep                        # AS-REP roastable
runoff -p pass unconstrained                # Unconstrained delegation
runoff -p pass nolaps                       # Computers without LAPS
runoff -p pass computers                    # All domain computers
runoff -p pass users                        # All domain users
runoff -p pass spns                         # All SPNs
runoff -p pass quickwins                    # Quick win attack paths
runoff -p pass audit                        # Consolidated security audit
runoff -p pass stats                        # Domain statistics
```

### Node Operations
```bash
runoff -p pass info USER@CORP.LOCAL         # Show node properties
runoff -p pass search '*ADMIN*'             # Search nodes by pattern
runoff -p pass investigate USER@CORP.LOCAL  # Full investigation
runoff -p pass investigate '*.CORP.LOCAL'   # Triage mode
```

### Path Finding
```bash
runoff -p pass path da USER@CORP.LOCAL      # Paths to Domain Admins
runoff -p pass path dc USER@CORP.LOCAL      # Paths to Domain Controllers
runoff -p pass path to USER@CORP.LOCAL DC01.CORP.LOCAL
```

### Membership & Admin Rights
```bash
runoff -p pass members 'DOMAIN ADMINS@CORP.LOCAL'   # Group members
runoff -p pass memberof USER@CORP.LOCAL             # Group memberships
runoff -p pass adminto DC01.CORP.LOCAL              # Who admins this computer
runoff -p pass adminof USER@CORP.LOCAL              # What computers user admins
runoff -p pass sessions DC01.CORP.LOCAL             # Active sessions
```

### Edge Exploration
```bash
runoff -p pass edges from USER@CORP.LOCAL           # Outbound attack edges
runoff -p pass edges to 'DOMAIN ADMINS@CORP.LOCAL'  # Inbound attack edges
```

### Marking
```bash
runoff -p pass mark owned USER@CORP.LOCAL           # Mark as owned
runoff -p pass mark tier-zero SVCACCT@CORP.LOCAL    # Mark as tier-zero
runoff -p pass unmark owned USER@CORP.LOCAL         # Remove owned status
runoff -p pass owned                                # List owned principals
runoff -p pass tierzero                             # List tier-zero principals
runoff -p pass clear owned                          # Clear all owned markings
runoff -p pass clear db all                         # Clear database (API)
```

### Global Options
```bash
runoff -b bolt://10.0.0.5:7687 -u neo4j -p pass run all  # Custom bolt URI and user
runoff -p pass -d CORP.LOCAL run all                      # Filter by domain
runoff -p pass --output json run all                      # Output format: table, json, csv
runoff -p pass -s CRITICAL,HIGH run all                   # Severity filter
runoff -p pass --abuse run all                            # Show exploitation commands
runoff -p pass -q run all                                 # Quiet mode
runoff -p pass --no-color run all                         # Disable color output
runoff -p pass --debug run all                            # Debug mode
```

### BloodHound CE API
```bash
runoff -p pass auth                         # Authenticate to BH CE API
runoff -p pass ingest *.zip                 # Upload collector data
runoff -p pass ingest --history             # View ingest history
runoff -p pass clear db all                 # Delete all data
runoff -p pass clear db ad azure            # Delete AD and Azure data
```

### Testing
```bash
# Run all tests
pytest tests/

# Run CLI-specific tests
pytest tests/test_shell.py

# Run with coverage
pytest tests/ --cov=runoff --cov-report=html
```

## Architecture

### Package Structure
```
runoff/
├── __main__.py                   # Entry point for python -m runoff; calls runoff.cli.cli()
├── cli/
│   ├── __init__.py               # Click group, global options, RunoffGroup
│   ├── context.py                # connect() context manager, sync_config()
│   └── commands/                 # Click command modules
│       ├── __init__.py           # register_commands()
│       ├── connection.py         # status, domains
│       ├── queries.py            # run, query, queries
│       ├── filters.py            # Quick filters (kerberoastable, etc.)
│       ├── nodes.py              # info, search, investigate
│       ├── paths.py              # path da/dc/to
│       ├── marking.py            # mark, unmark, owned, tierzero, clear
│       ├── membership.py         # members, memberof, adminto, adminof, sessions
│       ├── edges.py              # edges from/to
│       └── api.py                # auth, ingest
├── shell/                        # Interactive shell (cmd2-based, legacy)
│   ├── __init__.py               # main() entry point
│   ├── app.py                    # RunoffShell class
│   └── commands/                 # Shell command mixins
├── core/
│   ├── bloodhound.py             # BloodHoundCE class (Neo4j connection)
│   ├── config.py                 # Thread-safe global state singleton
│   ├── cypher.py                 # Domain filter helpers, Cypher utilities
│   ├── scoring.py                # Risk scoring and exposure metrics
│   └── utils.py                  # Shared utilities (extract_domain)
├── display/
│   ├── __init__.py               # Console singleton (Catppuccin Mocha theme)
│   ├── theme.py                  # MOCHA palette, CATPPUCCIN_MOCHA Rich theme
│   ├── colors.py                 # Severity enum, legacy Colors class
│   ├── tables.py                 # print_table(), print_header() (Rich tables)
│   ├── paths.py                  # print_path() (Rich trees)
│   ├── banner.py                 # print_banner() (Rich panel)
│   ├── panels.py                 # print_error(), print_info_panel(), etc.
│   ├── progress.py               # Rich progress bars for query execution
│   ├── report.py                 # HTML report generation
│   └── summary.py                # Executive summary
├── queries/                      # 166 queries in category folders
│   ├── base.py                   # @register_query decorator, QueryMetadata
│   ├── acl/                      # ACL abuse queries
│   ├── adcs/                     # ADCS ESC1-ESC15 queries
│   ├── azure/                    # Azure/hybrid queries
│   ├── credentials/              # Credential access queries
│   ├── delegation/               # Delegation queries
│   ├── domain/                   # Domain analysis queries
│   ├── exchange/                 # Exchange queries
│   ├── groups/                   # Dangerous groups queries
│   ├── hygiene/                  # Security hygiene queries
│   ├── lateral/                  # Lateral movement queries
│   ├── misc/                     # Miscellaneous queries
│   ├── owned/                    # Owned principal queries
│   └── paths/                    # Attack path queries
├── api/
│   ├── auth.py                   # HMAC authentication for BH CE API
│   ├── client.py                 # BloodHoundAPI class (API operations)
│   ├── config.py                 # API credential storage (~/.config/runoff/)
│   └── ingest.py                 # File upload/ingestion logic
└── abuse/
    ├── __init__.py               # print_abuse_section(), print_abuse_for_query()
    ├── loader.py                 # YAML template loading
    └── templates/                # YAML files with attack commands
```

### Key Components

**Entry Point:** `runoff/__main__.py` calls `runoff.cli.cli(standalone_mode=False)`. The pyproject.toml entry point is `runoff = "runoff.cli:cli"`.

**CLI Architecture:** Uses Click framework with command groups:
- `cli` is the root `@click.group` defined in `runoff/cli/__init__.py` (class `RunoffGroup`)
- Global options on the `cli` group: `--bolt-uri`/`-b`, `--username`/`-u`, `--password`/`-p`, `--domain`/`-d`, `--output`, `--severity`/`-s`, `--quiet`/`-q`, `--no-color`, `--debug`, `--abuse`
- `connect()` context manager in `runoff/cli/context.py` handles connection lifecycle; `sync_config()` propagates global options into the `core.config` singleton
- Commands use `@click.pass_context` and access the `BloodHoundCE` instance via `ctx.obj`
- All commands are registered via `register_commands()` in `runoff/cli/commands/__init__.py`

**Query Registration:** Uses `@register_query` decorator pattern:
```python
@register_query(name="Query Name", category="Category", default=True, severity=Severity.HIGH)
def get_example(bh: BloodHoundCE, domain=None, severity=None) -> int:
    ...
```

### Query File Structure
Each query in its own file:
```python
# runoff/queries/credentials/kerberoastable.py
from __future__ import annotations
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from runoff.core.bloodhound import BloodHoundCE

@register_query(name="Kerberoastable Users", category="Privilege Escalation", default=True, severity=Severity.HIGH)
def get_kerberoastable(bh: BloodHoundCE, domain: str | None = None, severity: Severity = None) -> int:
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

    results = bh.run_query(query, params)
    result_count = len(results)

    if not print_header("Kerberoastable Users", severity, result_count):
        return result_count

    # Print results...
    return result_count
```

### Domain Filtering

BloodHound data often has inconsistencies where objects have different `domain` properties than Domain node names. Use flexible OR-based filtering:

```python
# Flexible domain filter pattern
if domain:
    domain_filter = """WHERE (
        toUpper(n.domain) = toUpper($domain)
        OR toUpper(n.name) ENDS WITH toUpper($domain_suffix)
    )"""
    params = {"domain": domain, "domain_suffix": f".{domain}"}
else:
    domain_filter = ""
    params = {}
```

Or use the helper from `runoff.core.cypher`:
```python
from runoff.core.cypher import domain_filter

clause, params = domain_filter(var="n", domain=domain, prefix="WHERE")
```

### BloodHound CE Labels
- Owned: `Tag_Owned` label (not `system_tags` property)
- Tier Zero: `Tag_Tier_Zero` label
- Detection pattern: `WHERE (n:Tag_Owned OR 'owned' IN n.system_tags OR n.owned = true)`

### BloodHoundCE Class Methods

**Query Execution:**
- `run_query(cypher, params)` - Execute Cypher and return results

**Owned Management:**
- `mark_owned(name)` / `unmark_owned(name)` - Add/remove `Tag_Owned` label
- `clear_all_owned()` - Remove ALL `Tag_Owned` labels

**Tier Zero:**
- `mark_tier_zero(name)` / `unmark_tier_zero(name)` - Add/remove `Tag_Tier_Zero` label

**Path Finding:**
- `find_shortest_path(source, target)` - Up to 5 shortest paths
- `find_path_to_da(principal)` - Paths to Domain Admins (RID -512/-519)
- `find_path_to_dc(principal)` - Paths to Domain Controllers (RID -516)

**Node Operations:**
- `get_node_info(name)` - All properties and labels
- `search_nodes(pattern)` - Regex search with `*` wildcard support

**Membership:**
- `get_group_members(group_name)` - Recursive group membership
- `get_member_of(principal)` - Groups a principal belongs to

**Admin Rights:**
- `get_admins_to(computer)` - Who can admin this computer
- `get_admin_of(principal)` - What computers can this principal admin
- `get_computer_sessions(computer)` - Active sessions

**Edges:**
- `get_edges_from(principal)` - Outbound attack edges
- `get_edges_to(principal)` - Inbound attack edges
- Uses `ATTACK_EDGES` constant: `['MemberOf', 'AdminTo', 'HasSession', 'GenericAll', 'GenericWrite', 'WriteDacl', 'WriteOwner', 'ForceChangePassword', 'AddMember', 'DCSync', ...]`

### Cypher Patterns

| Feature | Pattern |
|---------|---------|
| Shortest Path | `MATCH p=shortestPath((s)-[*1..15]->(t))` |
| Domain Admins | `g.objectid ENDS WITH '-512' OR g.objectid ENDS WITH '-519'` |
| Domain Controllers | `g.objectid ENDS WITH '-516'` |
| Tier Zero Label | `SET n:Tag_Tier_Zero` |
| Regex Search | `WHERE n.name =~ '(?i)pattern'` |
| Group Members | `MATCH (m)-[:MemberOf*1..]->(g:Group)` |
| Admin Rights | `MATCH (n)-[:AdminTo\|MemberOf*1..3]->(c:Computer)` |
| Sessions | `MATCH (c)-[:HasSession]->(u:User)` |

### Non-Admin Query Exclusions

When writing queries that filter for "non-admin" principals, always use RID-based exclusions in addition to the `admincount` property check:

```cypher
WHERE (n.admincount IS NULL OR n.admincount = false)
// Admin groups
AND NOT n.objectid ENDS WITH '-512'  // Domain Admins
AND NOT n.objectid ENDS WITH '-519'  // Enterprise Admins
AND NOT n.objectid ENDS WITH '-544'  // Administrators
// Operator groups (elevated privileges by design)
AND NOT n.objectid ENDS WITH '-548'  // Account Operators
AND NOT n.objectid ENDS WITH '-549'  // Server Operators
AND NOT n.objectid ENDS WITH '-550'  // Print Operators
AND NOT n.objectid ENDS WITH '-551'  // Backup Operators
```

### Severity Levels
- `CRITICAL` (bold red): Immediate exploitation paths
- `HIGH` (red): Serious risk
- `MEDIUM` (orange): Concerning misconfiguration
- `LOW` (yellow): Informational/hardening
- `INFO` (gray): Metadata/statistics (no tag shown)

### Abuse Command System

The abuse system displays exploitation commands. Located in `runoff/abuse/`.

**Usage in Queries:**
```python
# For edge-based findings
from runoff.abuse import print_abuse_section
print_abuse_section(results, "GenericAll", "target_type", "target")

# For query-based findings
from runoff.abuse import print_abuse_for_query
print_abuse_for_query("kerberoastable", results, "name")
```

### Category Mapping (for `run` command)
```python
CATEGORIES = {
    "all": None,  # Special: run all queries
    "acl": "ACL Abuse",
    "adcs": "ADCS",
    "paths": "Attack Paths",
    "azure": "Azure/Hybrid",
    "basic": "Basic Info",
    "groups": "Dangerous Groups",
    "delegation": "Delegation",
    "exchange": "Exchange",
    "lateral": "Lateral Movement",
    "misc": "Miscellaneous",
    "owned": "Owned",
    "privesc": "Privilege Escalation",
    "hygiene": "Security Hygiene",
}
```

### Adding New CLI Commands

To add a new command, create a Click command and register it:

```python
# runoff/cli/commands/example.py
import click
from runoff.display import console

@click.command()
@click.argument("target")
@click.option("-v", "--verbose", is_flag=True)
@click.pass_context
def example(ctx, target, verbose):
    """Run example operation."""
    from runoff.cli.context import connect
    with connect(ctx.obj) as bh:
        # Implementation using bh (BloodHoundCE instance)
        console.print(f"Target: [node]{target}[/node]")
```

Then register in `runoff/cli/commands/__init__.py`:
```python
from runoff.cli.commands.example import example

def register_commands(cli):
    cli.add_command(example)
    # ... other commands
```

### Well-Known RID Reference
| RID | Group |
|-----|-------|
| -512 | Domain Admins |
| -516 | Domain Controllers |
| -519 | Enterprise Admins |
| -521 | Read-Only Domain Controllers |
| -544 | Administrators |
| -548 | Account Operators |
| -549 | Server Operators |
| -550 | Print Operators |
| -551 | Backup Operators |
