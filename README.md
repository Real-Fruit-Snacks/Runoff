<div align="center">

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/Real-Fruit-Snacks/Runoff/main/docs/assets/logo-dark.svg">
  <source media="(prefers-color-scheme: light)" srcset="https://raw.githubusercontent.com/Real-Fruit-Snacks/Runoff/main/docs/assets/logo-light.svg">
  <img alt="Runoff" src="https://raw.githubusercontent.com/Real-Fruit-Snacks/Runoff/main/docs/assets/logo-dark.svg" width="520">
</picture>

![Python](https://img.shields.io/badge/language-Python-green.svg)
![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20Windows%20%7C%20macOS-lightgrey)
![License](https://img.shields.io/badge/license-MIT-blue.svg)

**Active Directory security audit tool -- extract quick wins, attack paths, and misconfigurations from BloodHound CE**

Runoff extracts quick wins from BloodHound Community Edition's Neo4j database -- it identifies Active Directory attack paths, misconfigurations, and privilege escalation opportunities across **177 security queries** in 15 categories with exploitation guidance.

> **Authorization Required**: This tool is designed exclusively for authorized security testing with explicit written permission. Unauthorized access to computer systems is illegal and may result in criminal prosecution.

[Quick Start](#quick-start) • [Usage](#usage) • [Query Categories](#query-categories) • [Architecture](#architecture) • [Features](#features) • [Security](#security)

</div>

---

## Highlights

<table>
<tr>
<td width="50%">

**177 Security Queries**
Privilege escalation, ACL abuse, ADCS (ESC1-ESC15), delegation, coercion relay, lateral movement, Azure/hybrid, and credential attacks -- all registered via decorator and runnable by category or individually.

**Node Investigation**
`investigate USER@CORP.LOCAL` shows properties, attack edges, group memberships, admin rights, sessions, and paths to Domain Admins in a single command. Wildcard patterns trigger triage mode.

**Abuse Commands**
Enable `--abuse` to display exploitation commands alongside every finding -- Impacket, Certipy, bloodyAD, Rubeus -- with auto-substituted targets, domains, and OPSEC warnings.

**Catppuccin Terminal UI**
Rich-powered tables, panels, and progress bars styled with the Catppuccin Mocha palette. Severity-coded output, owned principal markers, and executive summaries.

</td>
<td width="50%">

**Multi-Format Output**
Table, JSON, CSV, HTML, and **Markdown** reports from a single run. Structured output goes to stdout (pipe-friendly) while status goes to stderr. Use `-o json` and pipe to `jq`.

**Path Finding**
Shortest paths to Domain Admins, Domain Controllers, or between arbitrary nodes. Tree-view rendering with relationship labels and hop counts.

**Owned Tracking**
Mark compromised accounts with `mark owned`, then run targeted `owned` queries to find escalation paths from your current foothold. Owned principals highlighted throughout all output.

**BloodHound CE API**
Authenticate via HMAC, ingest collector ZIP files, view upload history, and clear database -- all from the CLI. No browser required.

</td>
</tr>
</table>

---

## Quick Start

### Prerequisites

<table>
<tr>
<th>Requirement</th>
<th>Version</th>
<th>Purpose</th>
</tr>
<tr>
<td>Python</td>
<td>3.9+</td>
<td>Runtime</td>
</tr>
<tr>
<td>Neo4j</td>
<td>5.0+</td>
<td>Ships with BloodHound CE</td>
</tr>
<tr>
<td>BloodHound CE</td>
<td>Latest</td>
<td>With ingested AD data</td>
</tr>
</table>

### Build

```bash
# pipx (recommended -- isolated environment, global command)
pipx install git+https://github.com/Real-Fruit-Snacks/Runoff.git

# Or standard pip
pip install git+https://github.com/Real-Fruit-Snacks/Runoff.git

# Or from source
git clone https://github.com/Real-Fruit-Snacks/Runoff.git
cd Runoff && pip install -e .
```

### Verification

```bash
# Run all 177 queries
runoff -p 'bloodhoundcommunityedition' run all

# Quick wins summary
runoff -p 'bloodhoundcommunityedition' quickwins

# Investigate a specific node
runoff -p 'bloodhoundcommunityedition' investigate USER@CORP.LOCAL
```

> The default Neo4j URI is `bolt://127.0.0.1:7687` with username `neo4j`. Override with `-b` and `-u`. The password can also be set via `RUNOFF_PASSWORD`.

---

## Usage

### Running Queries

```bash
# All default queries
runoff -p pass run all

# Specific categories (acl, adcs, privesc, delegation, lateral, hygiene, owned, basic, groups, paths, azure, exchange, gpo, misc)
runoff -p pass run acl adcs privesc

# Severity filter
runoff -p pass run hygiene -s HIGH,CRITICAL

# Single query by name
runoff -p pass query kerberoast

# List all available queries
runoff -p pass queries
```

### Quick Filters

```bash
# One-shot commands for common findings
runoff -p pass kerberoastable
runoff -p pass asrep
runoff -p pass unconstrained
runoff -p pass nolaps
runoff -p pass computers --enabled
runoff -p pass users --admin
runoff -p pass quickwins
runoff -p pass audit
runoff -p pass stats
```

### Node Operations

```bash
# Properties and labels
runoff -p pass info USER@CORP.LOCAL

# Wildcard search
runoff -p pass search '*ADMIN*'

# Full investigation (edges, groups, sessions, paths to DA)
runoff -p pass investigate USER@CORP.LOCAL

# Triage mode for multiple nodes
runoff -p pass investigate '*SQL*'
```

### Path Finding

```bash
# Paths to Domain Admins
runoff -p pass path da USER@CORP.LOCAL

# Paths to Domain Controllers
runoff -p pass path dc USER@CORP.LOCAL

# Paths between two nodes
runoff -p pass path to USER@CORP.LOCAL DC01.CORP.LOCAL
```

### Structured Output

```bash
# JSON to stdout (pipe to jq)
runoff -p pass -o json run all | jq '.[] | select(.count > 0)'

# CSV export
runoff -p pass -o csv kerberoastable > kerb.csv

# Quiet mode suppresses banner
runoff -p pass -q -o json stats
```

---

## Command Reference

### Global Options

<table>
<tr>
<th>Flag</th>
<th>Description</th>
<th>Default</th>
</tr>
<tr><td><code>-b, --bolt &lt;uri&gt;</code></td><td>Neo4j Bolt URI</td><td><code>bolt://127.0.0.1:7687</code></td></tr>
<tr><td><code>-u, --username &lt;user&gt;</code></td><td>Neo4j username</td><td><code>neo4j</code></td></tr>
<tr><td><code>-p, --password &lt;pass&gt;</code></td><td>Neo4j password</td><td>--</td></tr>
<tr><td><code>-d, --domain &lt;domain&gt;</code></td><td>Filter queries by domain</td><td>All domains</td></tr>
<tr><td><code>-o, --output &lt;fmt&gt;</code></td><td>Output format: <code>table json csv html markdown</code></td><td><code>table</code></td></tr>
<tr><td><code>-s, --severity &lt;sev&gt;</code></td><td>Severity filter (comma-separated)</td><td>All</td></tr>
<tr><td><code>--abuse / --no-abuse</code></td><td>Show exploitation commands</td><td><code>false</code></td></tr>
<tr><td><code>-q, --quiet</code></td><td>Suppress banner and info output</td><td><code>false</code></td></tr>
<tr><td><code>--no-color</code></td><td>Disable color output</td><td><code>false</code></td></tr>
<tr><td><code>--debug</code></td><td>Enable debug output</td><td><code>false</code></td></tr>
<tr><td><code>-O, --output-file &lt;path&gt;</code></td><td>Write output to file</td><td>--</td></tr>
<tr><td><code>-t, --tags &lt;tags&gt;</code></td><td>Filter queries by tag (comma-separated)</td><td>All</td></tr>
<tr><td><code>--load-plugins</code></td><td>Load custom queries from plugin directory</td><td><code>false</code></td></tr>
</table>

### Commands

<table>
<tr>
<th>Command</th>
<th>Description</th>
</tr>
<tr><td><code>run &lt;categories&gt;</code></td><td>Run queries by category (<code>all</code>, <code>acl</code>, <code>adcs</code>, <code>privesc</code>, etc.)</td></tr>
<tr><td><code>query &lt;name&gt;</code></td><td>Run a single query by name</td></tr>
<tr><td><code>queries</code></td><td>List all available queries</td></tr>
<tr><td><code>info &lt;node&gt;</code></td><td>Show node properties and labels</td></tr>
<tr><td><code>search &lt;pattern&gt;</code></td><td>Search nodes by name pattern</td></tr>
<tr><td><code>investigate &lt;node&gt;</code></td><td>Full node investigation</td></tr>
<tr><td><code>path da|dc|to &lt;args&gt;</code></td><td>Find shortest attack paths</td></tr>
<tr><td><code>members &lt;group&gt;</code></td><td>Recursive group membership</td></tr>
<tr><td><code>memberof &lt;principal&gt;</code></td><td>Groups a principal belongs to</td></tr>
<tr><td><code>adminto &lt;computer&gt;</code></td><td>Who can admin this computer</td></tr>
<tr><td><code>adminof &lt;principal&gt;</code></td><td>What computers this principal admins</td></tr>
<tr><td><code>sessions &lt;computer&gt;</code></td><td>Active sessions on computer</td></tr>
<tr><td><code>edges from|to &lt;node&gt;</code></td><td>Outbound or inbound attack edges</td></tr>
<tr><td><code>mark owned|tier-zero &lt;node&gt;</code></td><td>Mark node as owned or tier-zero</td></tr>
<tr><td><code>unmark owned|tier-zero &lt;node&gt;</code></td><td>Remove marking</td></tr>
<tr><td><code>owned</code></td><td>List all owned principals</td></tr>
<tr><td><code>tierzero</code></td><td>List all tier-zero principals</td></tr>
<tr><td><code>clear owned|db</code></td><td>Clear owned markings or database</td></tr>
<tr><td><code>kerberoastable</code></td><td>Kerberoastable users</td></tr>
<tr><td><code>asrep</code></td><td>AS-REP roastable users</td></tr>
<tr><td><code>unconstrained</code></td><td>Unconstrained delegation</td></tr>
<tr><td><code>nolaps</code></td><td>Computers without LAPS</td></tr>
<tr><td><code>computers</code></td><td>List domain computers</td></tr>
<tr><td><code>users</code></td><td>List domain users</td></tr>
<tr><td><code>spns</code></td><td>List Service Principal Names</td></tr>
<tr><td><code>quickwins</code></td><td>Quick win attack paths</td></tr>
<tr><td><code>audit</code></td><td>Consolidated security audit</td></tr>
<tr><td><code>stats</code></td><td>Domain statistics</td></tr>
<tr><td><code>status</code></td><td>Connection status</td></tr>
<tr><td><code>domains</code></td><td>List available domains</td></tr>
<tr><td><code>auth</code></td><td>Authenticate to BloodHound CE API</td></tr>
<tr><td><code>ingest &lt;files&gt;</code></td><td>Upload collector data</td></tr>
<tr><td><code>diff &lt;file1&gt; &lt;file2&gt;</code></td><td>Compare two saved JSON result files</td></tr>
<tr><td><code>completion bash|zsh|fish</code></td><td>Generate shell completion script</td></tr>
</table>

---

## Query Categories

<table>
<tr>
<th>Category</th>
<th>Queries</th>
<th>Command</th>
<th>Focus</th>
</tr>
<tr><td>ACL Abuse</td><td>25</td><td><code>run acl</code></td><td>GenericAll, WriteDacl, WriteOwner, ForceChangePassword, AddMember</td></tr>
<tr><td>Security Hygiene</td><td>23</td><td><code>run hygiene</code></td><td>LAPS, SMB signing, AdminSDHolder, stale passwords, Pre-Windows 2000</td></tr>
<tr><td>ADCS</td><td>18</td><td><code>run adcs</code></td><td>ESC1-ESC15, golden certs, ManageCA, ManageCertificates</td></tr>
<tr><td>Privilege Escalation</td><td>18</td><td><code>run privesc</code></td><td>Kerberoasting, DCSync, shadow creds, service account security</td></tr>
<tr><td>Lateral Movement</td><td>18</td><td><code>run lateral</code></td><td>RDP, DCOM, PSRemote, SQL, coercion relay</td></tr>
<tr><td>Domain Analysis</td><td>16</td><td><code>run basic</code></td><td>Trusts, functional level, cross-forest ACL abuse, SID filtering</td></tr>
<tr><td>Owned Principals</td><td>11</td><td><code>run owned</code></td><td>Paths from compromised accounts</td></tr>
<tr><td>Delegation</td><td>11</td><td><code>run delegation</code></td><td>Constrained, unconstrained, RBCD, S4U2Self</td></tr>
<tr><td>Dangerous Groups</td><td>10</td><td><code>run groups</code></td><td>DNSAdmins, Backup Ops, RODC replication</td></tr>
<tr><td>Azure/Hybrid</td><td>9</td><td><code>run azure</code></td><td>AAD Connect, sync accounts, hybrid attack surface</td></tr>
<tr><td>Attack Paths</td><td>6</td><td><code>run paths</code></td><td>Shortest paths, attack chains</td></tr>
<tr><td>Exchange</td><td>5</td><td><code>run exchange</code></td><td>Exchange groups, trusted subsystem, mailbox delegation</td></tr>
<tr><td>GPO Abuse</td><td>3</td><td><code>run gpo</code></td><td>GPO control to computers, tier-zero links, weak chains</td></tr>
<tr><td>Miscellaneous</td><td>3</td><td><code>run misc</code></td><td>Circular groups, duplicate SPNs</td></tr>
<tr><td>Credentials</td><td>1</td><td><code>run privesc</code></td><td>Password attribute exposure</td></tr>
</table>

---

## ADCS Coverage

Comprehensive ESC1-ESC15 vulnerability detection:

<table>
<tr>
<th>ESC</th>
<th>Severity</th>
<th>Description</th>
</tr>
<tr><td>ESC1</td><td>CRITICAL</td><td>Vulnerable certificate templates (enrollee supplies SAN)</td></tr>
<tr><td>ESC2/3</td><td>HIGH</td><td>Any Purpose / Certificate Request Agent templates</td></tr>
<tr><td>ESC3</td><td>CRITICAL</td><td>Enrollment agent abuse</td></tr>
<tr><td>ESC4</td><td>HIGH</td><td>Template ACL abuse (modify template)</td></tr>
<tr><td>ESC5</td><td>HIGH</td><td>PKI object control</td></tr>
<tr><td>ESC6</td><td>CRITICAL</td><td>EDITF_ATTRIBUTESUBJECTALTNAME2 flag</td></tr>
<tr><td>ESC7</td><td>CRITICAL</td><td>ManageCA rights</td></tr>
<tr><td>ESC8</td><td>HIGH</td><td>NTLM relay to web enrollment</td></tr>
<tr><td>ESC9</td><td>HIGH</td><td>No security extension</td></tr>
<tr><td>ESC10</td><td>HIGH</td><td>Weak certificate mapping</td></tr>
<tr><td>ESC11</td><td>HIGH</td><td>SAN enabled on CA</td></tr>
<tr><td>ESC13</td><td>HIGH</td><td>Issuance policy abuse</td></tr>
<tr><td>ESC15</td><td>HIGH</td><td>CVE-2024-49019</td></tr>
</table>

---

## Abuse Commands

Enable with `--abuse` to display exploitation commands alongside findings:

```bash
$ runoff -p pass --abuse run acl

[*] [HIGH] ForceChangePassword Targets
    Found 1 ForceChangePassword relationship(s)
+------------------------------+------+-----------------------------+
| Principal                    | Type | Target User                 |
+------------------------------+------+-----------------------------+
| R.HAGGARD@BUILDINGMAGIC.LOCAL| User | H.POTCH@BUILDINGMAGIC.LOCAL |
+------------------------------+------+-----------------------------+

    [ABUSE COMMANDS]
    ==================================================

    Target Type: User via ForceChangePassword
    --------------------------------------------------

    [1] Force password change (bloodyAD)
        bloodyAD -d BUILDINGMAGIC.LOCAL -u <USERNAME> -p '<PASSWORD>'
          --host 127.0.0.1 set password H.POTCH 'Passw0rd!2025'

    OPSEC:
      - Password change creates Event ID 4724
```

**Auto-Substitution:** Abuse commands automatically fill in known values:

<table>
<tr>
<th>Placeholder</th>
<th>Source</th>
</tr>
<tr><td><code>&lt;TARGET&gt;</code></td><td>Target principal name</td></tr>
<tr><td><code>&lt;DOMAIN&gt;</code></td><td>Extracted from principal or <code>--domain</code> flag</td></tr>
<tr><td><code>&lt;DC_IP&gt;</code></td><td>Configurable via settings</td></tr>
<tr><td><code>&lt;USERNAME&gt;</code></td><td><em>Your credentials -- not stored</em></td></tr>
<tr><td><code>&lt;PASSWORD&gt;</code></td><td><em>Your credentials -- not stored</em></td></tr>
</table>

---

## Architecture

Runoff follows a layered architecture: CLI commands connect to Neo4j, execute Cypher queries via the core engine, and render results through the display layer.

```
Runoff/
├── cli/                           # Click CLI framework
│   ├── __init__.py               # Root group, global options, RunoffGroup
│   ├── context.py                # connect() context manager, config sync
│   └── commands/                 # Command modules
│       ├── queries.py            # run, query, queries
│       ├── filters.py            # kerberoastable, asrep, quickwins, audit, etc.
│       ├── nodes.py              # info, search, investigate
│       ├── paths.py              # path da/dc/to
│       ├── marking.py            # mark, unmark, owned, tierzero, clear
│       ├── membership.py         # members, memberof, adminto, adminof, sessions
│       ├── edges.py              # edges from/to
│       ├── connection.py         # status, domains
│       ├── api.py                # auth, ingest
│       ├── completion.py         # Shell completion generation
│       └── diff.py               # Result comparison
│
├── core/                          # Business logic
│   ├── bloodhound.py             # BloodHoundCE class (Neo4j driver, queries, paths)
│   ├── config.py                 # Thread-safe global config singleton
│   ├── cypher.py                 # Domain filter helpers, Cypher utilities
│   ├── constants.py              # Attack edge types, well-known RIDs
│   ├── scoring.py                # Risk scoring and exposure metrics
│   └── utils.py                  # Timestamp formatting, domain extraction
│
├── display/                       # Presentation layer
│   ├── __init__.py               # Console singleton (Catppuccin Mocha theme)
│   ├── theme.py                  # MOCHA palette, Rich theme definition
│   ├── colors.py                 # Severity enum (CRITICAL -> INFO)
│   ├── tables.py                 # print_table(), print_header(), print_node_info()
│   ├── paths.py                  # Attack path tree rendering
│   ├── banner.py                 # ASCII banner panel
│   ├── panels.py                 # Error/info panels
│   ├── progress.py               # Query execution progress bars
│   ├── report.py                 # HTML report generation
│   ├── output.py                 # Structured JSON/CSV emitter
│   └── summary.py                # Executive summary
│
├── queries/                       # 177 queries in category folders
│   ├── base.py                   # @register_query decorator, QueryMetadata
│   ├── acl/                      # 25 ACL abuse queries
│   ├── adcs/                     # 18 ADCS ESC1-ESC15 queries
│   ├── credentials/              # 18 privilege escalation + 1 credential query
│   ├── delegation/               # 11 delegation queries
│   ├── domain/                   # 16 domain analysis queries
│   ├── groups/                   # 10 dangerous groups queries
│   ├── gpo/                      # 3 GPO abuse queries
│   ├── hygiene/                  # 23 security hygiene queries
│   ├── lateral/                  # 18 lateral movement queries
│   ├── owned/                    # 11 owned principal queries
│   ├── paths/                    # 6 attack path queries
│   ├── azure/                    # 9 Azure/hybrid queries
│   ├── exchange/                 # 5 Exchange queries
│   └── misc/                     # 3 miscellaneous queries
│
├── abuse/                         # Exploitation guidance
│   ├── loader.py                 # YAML template loader
│   └── templates/                # YAML files with attack commands per technique
│
├── api/                           # BloodHound CE API integration
│   ├── auth.py                   # HMAC authentication
│   ├── client.py                 # API operations (ingest, clear, history)
│   └── config.py                 # Credential storage (~/.config/runoff/)
│
├── docs/                          # ── GitHub Pages ──
│   ├── index.html                # Project website
│   └── assets/
│       ├── logo-dark.svg         # Logo for dark theme
│       └── logo-light.svg        # Logo for light theme
│
└── .github/
    └── workflows/
        └── ci.yml                # CI pipeline
```

### Data Flow

```
CLI Command  ->  connect() context manager  ->  BloodHoundCE (Neo4j)
                                                     |
                                              Cypher query execution
                                                     |
                                              Display layer (Rich tables/trees)
                                              Structured output (JSON/CSV)
                                              HTML report generation
```

### Query Registration

Queries self-register via `@register_query` at import time. Each query defines its name, category, severity, and whether it runs by default. The registry is enumerated by `run` and `query` commands.

---

## Tech Stack

<table>
<tr>
<th>Layer</th>
<th>Technology</th>
</tr>
<tr><td><strong>Language</strong></td><td>Python 3.9+ with <code>from __future__ import annotations</code></td></tr>
<tr><td><strong>CLI</strong></td><td>Click (groups, commands, options, context passing)</td></tr>
<tr><td><strong>Database</strong></td><td>Neo4j via <code>neo4j</code> Python driver (Bolt protocol)</td></tr>
<tr><td><strong>Terminal UI</strong></td><td>Rich (tables, panels, trees, progress bars)</td></tr>
<tr><td><strong>Theming</strong></td><td>Catppuccin Mocha (hex color constants)</td></tr>
<tr><td><strong>API Auth</strong></td><td>HMAC-SHA256 (BloodHound CE API)</td></tr>
<tr><td><strong>Config</strong></td><td>YAML (abuse templates), JSON (API credentials)</td></tr>
<tr><td><strong>Testing</strong></td><td>pytest with mocked Neo4j driver</td></tr>
</table>

---

## Features

<table>
<tr>
<th>Feature</th>
<th>Description</th>
</tr>
<tr><td><strong>177 security queries</strong></td><td>Registered via decorator, runnable by category or individually</td></tr>
<tr><td><strong>Severity system</strong></td><td>CRITICAL, HIGH, MEDIUM, LOW, INFO -- filterable with <code>-s</code></td></tr>
<tr><td><strong>Domain filtering</strong></td><td>Flexible OR-based matching handles BloodHound data inconsistencies</td></tr>
<tr><td><strong>Owned tracking</strong></td><td>Mark principals, run targeted queries, highlighted in all output</td></tr>
<tr><td><strong>Tier-zero marking</strong></td><td>Tag high-value targets for focused analysis</td></tr>
<tr><td><strong>Node investigation</strong></td><td>Properties, edges, groups, sessions, admin rights, paths to DA</td></tr>
<tr><td><strong>Path finding</strong></td><td>Shortest paths to DA, DC, or between arbitrary nodes</td></tr>
<tr><td><strong>Wildcard search</strong></td><td><code>*</code> patterns in info, search, investigate commands</td></tr>
<tr><td><strong>Abuse commands</strong></td><td>Exploitation guidance with auto-substituted targets and OPSEC notes</td></tr>
<tr><td><strong>Executive summary</strong></td><td>Automatic domain profile, security posture, prioritized next steps</td></tr>
<tr><td><strong>Multi-format output</strong></td><td>Table, JSON, CSV, HTML -- structured output to stdout</td></tr>
<tr><td><strong>Markdown output</strong></td><td>Pipe-delimited markdown tables via <code>-o markdown</code></td></tr>
<tr><td><strong>Pipe-friendly</strong></td><td>JSON/CSV to stdout, status to stderr -- works with <code>jq</code>, <code>csvtool</code></td></tr>
<tr><td><strong>BloodHound CE API</strong></td><td>Ingest data, view history, clear database -- no browser needed</td></tr>
<tr><td><strong>ADCS ESC1-ESC15</strong></td><td>Comprehensive certificate abuse detection</td></tr>
<tr><td><strong>Coercion relay</strong></td><td>NTLM relay chain analysis (SMB, LDAP, LDAPS, ADCS)</td></tr>
<tr><td><strong>Azure/hybrid</strong></td><td>AAD Connect, sync accounts, hybrid attack surface</td></tr>
<tr><td><strong>Environment variables</strong></td><td><code>RUNOFF_PASSWORD</code>, <code>RUNOFF_BOLT_URI</code>, <code>RUNOFF_USERNAME</code>, <code>RUNOFF_DOMAIN</code></td></tr>
<tr><td><strong>Query tagging</strong></td><td>Filter queries by tags like <code>quick-win</code>, <code>stealthy</code> with <code>--tags</code></td></tr>
<tr><td><strong>Diff mode</strong></td><td>Compare two saved JSON results to track new/resolved findings</td></tr>
<tr><td><strong>Plugin system</strong></td><td>Drop <code>.py</code> files in <code>~/.config/runoff/queries/</code> for custom checks</td></tr>
<tr><td><strong>Shell completion</strong></td><td><code>runoff completion bash|zsh|fish</code> for tab completion</td></tr>
</table>

---

## Development

### Adding a New Query

1. Create `runoff/queries/<category>/your_query.py`
2. Use the `@register_query` decorator:

```python
@register_query(name="Query Name", category="Category", default=True, severity=Severity.HIGH)
def get_your_query(bh: BloodHoundCE, domain=None, severity=None) -> int:
    # Use flexible domain filtering
    clause, params = domain_filter(var="n", domain=domain, prefix="WHERE")
    results = bh.run_query(f"MATCH (n:User) {clause} RETURN n.name", params)
    # Display and return count
    return len(results)
```

3. Import the module in the category's `__init__.py`
4. Add abuse templates to `runoff/abuse/templates/` if applicable

### Testing

```bash
pytest                          # All tests
pytest --cov=runoff             # With coverage
pytest tests/test_queries.py    # Single file
```

---

## Troubleshooting

<table>
<tr>
<th>Problem</th>
<th>Solution</th>
</tr>
<tr><td><code>Connection failed</code></td><td>Check Neo4j is running: <code>nc -zv 127.0.0.1 7687</code></td></tr>
<tr><td><code>Authentication failed</code></td><td>BloodHound CE web creds differ from Neo4j. Check docker-compose.yml</td></tr>
<tr><td>No results returned</td><td>Run <code>runoff -p pass domains</code> to check data exists</td></tr>
<tr><td>Domain filter issues</td><td>Clear filter with <code>-d ""</code> or check available domains</td></tr>
<tr><td><code>ModuleNotFoundError</code></td><td>Ensure install completed: <code>pip install -e .</code></td></tr>
<tr><td>Garbled output in pipe</td><td>Use <code>--no-color</code> or <code>-o json</code> for piped output</td></tr>
</table>

---

## Platform Support

<table>
<tr>
<th>Capability</th>
<th>Linux</th>
<th>macOS</th>
<th>Windows</th>
</tr>
<tr>
<td>CLI</td>
<td>Full</td>
<td>Full</td>
<td>Full</td>
</tr>
<tr>
<td>Neo4j Connection</td>
<td>Full (Bolt)</td>
<td>Full (Bolt)</td>
<td>Full (Bolt)</td>
</tr>
<tr>
<td>Rich Terminal UI</td>
<td>Full</td>
<td>Full</td>
<td>Full (Windows Terminal recommended)</td>
</tr>
<tr>
<td>BloodHound CE API</td>
<td>Full</td>
<td>Full</td>
<td>Full</td>
</tr>
<tr>
<td>Shell Completion</td>
<td>bash, zsh, fish</td>
<td>bash, zsh, fish</td>
<td>Limited</td>
</tr>
<tr>
<td>JSON/CSV Export</td>
<td>Full</td>
<td>Full</td>
<td>Full</td>
</tr>
<tr>
<td>HTML Reports</td>
<td>Full</td>
<td>Full</td>
<td>Full</td>
</tr>
</table>

---

## Security

### Vulnerability Reporting

**Report security issues via:**
- GitHub Security Advisories (preferred)
- Private disclosure to maintainers
- Responsible disclosure timeline (90 days)

**Do NOT:**
- Open public GitHub issues for vulnerabilities
- Disclose before coordination with maintainers
- Exploit vulnerabilities in unauthorized contexts

### Threat Model

**In scope:**
- Querying BloodHound CE data with proper authorization
- Generating exploitation guidance for authorized assessments
- Handling Neo4j credentials securely

**Out of scope:**
- Direct exploitation of Active Directory environments
- Credential storage for target domains
- Network scanning or active reconnaissance

### What Runoff Does NOT Do

Runoff is an **AD security audit tool**, not an exploitation framework:

- **Not an attack tool** -- Queries data already collected by BloodHound, does not touch Active Directory
- **Not a credential harvester** -- Does not store or exfiltrate domain credentials
- **Not a scanner** -- Does not perform network scanning or active reconnaissance
- **Not a C2 framework** -- No implant management or remote execution

---

## License

MIT License

Copyright &copy; 2026 Real-Fruit-Snacks

```
THIS SOFTWARE IS PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND.
THE AUTHORS ARE NOT LIABLE FOR ANY DAMAGES ARISING FROM USE.
USE AT YOUR OWN RISK AND ONLY WITH PROPER AUTHORIZATION.
```

---

## Resources

- **GitHub**: [github.com/Real-Fruit-Snacks/Runoff](https://github.com/Real-Fruit-Snacks/Runoff)
- **Documentation**: [real-fruit-snacks.github.io/Runoff](https://real-fruit-snacks.github.io/Runoff)
- **Issues**: [Report a Bug](https://github.com/Real-Fruit-Snacks/Runoff/issues)
- **Security**: [SECURITY.md](SECURITY.md)
- **Contributing**: [CONTRIBUTING.md](CONTRIBUTING.md)
- **Changelog**: [CHANGELOG.md](CHANGELOG.md)

---

<div align="center">

**Part of the Real-Fruit-Snacks water-themed security toolkit**

[Aquifer](https://github.com/Real-Fruit-Snacks/Aquifer) • [Cascade](https://github.com/Real-Fruit-Snacks/Cascade) • [Conduit](https://github.com/Real-Fruit-Snacks/Conduit) • [Flux](https://github.com/Real-Fruit-Snacks/Flux) • [HydroShot](https://github.com/Real-Fruit-Snacks/HydroShot) • [Riptide](https://github.com/Real-Fruit-Snacks/Riptide) • **Runoff** • [Seep](https://github.com/Real-Fruit-Snacks/Seep) • [Slipstream](https://github.com/Real-Fruit-Snacks/Slipstream) • [Tidepool](https://github.com/Real-Fruit-Snacks/Tidepool) • [Undertow](https://github.com/Real-Fruit-Snacks/Undertow) • [Whirlpool](https://github.com/Real-Fruit-Snacks/Whirlpool)

*Remember: With great power comes great responsibility.*

</div>
