<div align="center">

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/Real-Fruit-Snacks/Runoff/main/docs/assets/logo-dark.svg">
  <source media="(prefers-color-scheme: light)" srcset="https://raw.githubusercontent.com/Real-Fruit-Snacks/Runoff/main/docs/assets/logo-light.svg">
  <img alt="Runoff" src="https://raw.githubusercontent.com/Real-Fruit-Snacks/Runoff/main/docs/assets/logo-dark.svg" width="420">
</picture>

![Python](https://img.shields.io/badge/Python-3.9+-3776AB?logo=python&logoColor=white)
![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20Windows%20%7C%20macOS-lightgrey)
![License](https://img.shields.io/badge/license-MIT-blue.svg)

**Active Directory security audit tool -- extract quick wins, attack paths, and misconfigurations from BloodHound CE**

Runoff connects to BloodHound Community Edition's Neo4j database over Bolt and runs 183 Cypher queries across 15 categories to surface AD attack paths, misconfigurations, and privilege escalation opportunities. Results come with severity ratings, exploitation commands, and multi-format reporting.

> **Authorization Required**: Designed exclusively for authorized security testing with explicit written permission.

</div>

---

## Quick Start

### Prerequisites

- **Python** 3.9+
- **Neo4j** with BloodHound CE data loaded (default Bolt port 7687)
- **pip** or **pipx**

### Install

```bash
# pipx (recommended -- isolated environment)
pipx install git+https://github.com/Real-Fruit-Snacks/Runoff.git

# Or from a local clone
git clone https://github.com/Real-Fruit-Snacks/Runoff.git
cd Runoff && pip install -e .
```

### Run

```bash
# Run all 183 queries against the local BloodHound database
runoff -p 'bloodhoundcommunityedition' run all

# Quick wins -- high-impact findings only
runoff -p 'pass' quickwins

# Run specific categories with abuse commands
runoff -p 'pass' --abuse run acl adcs delegation

# Filter by severity
runoff -p 'pass' -s critical,high run all

# Investigate a specific node -- properties, edges, memberships, paths
runoff -p 'pass' investigate USER@CORP.LOCAL

# JSON output piped to jq
runoff -p 'pass' -o json run all | jq '.[] | select(.count > 0)'
```

---

## How It Works

Runoff queries the Neo4j database that BloodHound CE populates from SharpHound/AzureHound collection data. It does **not** touch Active Directory directly -- it only reads what's already in the graph.

```
SharpHound/AzureHound  -->  BloodHound CE  -->  Neo4j (Bolt:7687)  -->  Runoff
     (collection)           (ingestion)          (graph database)       (analysis)
```

1. **Connect** to Neo4j over the Bolt protocol (default `bolt://127.0.0.1:7687`)
2. **Execute** Cypher queries that traverse the BloodHound graph looking for attack paths
3. **Render** results as tables, JSON, CSV, HTML, or Markdown with severity ratings

---

## Features

### 183 Security Queries

Queries span 15 categories, each registered via `@register_query` decorator. Run by category, individually, or filter by severity and tags:

```bash
# Run specific categories
runoff -p 'pass' run acl adcs delegation privesc

# Filter by severity
runoff -p 'pass' -s critical,high run all

# Filter by tags (e.g. quick-win, stealthy, requires-creds)
runoff -p 'pass' run all -t quick-win

# Run a single query by name
runoff -p 'pass' query "Kerberoastable Users"

# List all available queries
runoff -p 'pass' query -l
```

**Run categories**: `acl`, `adcs`, `privesc`, `hygiene`, `lateral`, `delegation`, `basic`, `groups`, `owned`, `azure`, `paths`, `exchange`, `gpo`, `misc` (or `all` for everything).

### Quick Filters

Shortcut commands for the most common checks -- no need to remember query names:

```bash
runoff -p 'pass' kerberoastable     # Kerberoastable users
runoff -p 'pass' asrep              # AS-REP roastable accounts
runoff -p 'pass' unconstrained      # Unconstrained delegation
runoff -p 'pass' nolaps             # Computers without LAPS
runoff -p 'pass' spns               # Service principal names
runoff -p 'pass' quickwins          # High-impact quick wins
runoff -p 'pass' stats              # Domain statistics overview
runoff -p 'pass' audit              # Full security audit
```

### Node Investigation

Properties, attack edges, group memberships, admin rights, sessions, and paths to Domain Admins in a single command:

```bash
# Full node investigation
runoff -p 'pass' investigate USER@CORP.LOCAL

# Wildcard triage mode -- investigate all service accounts
runoff -p 'pass' investigate 'SVC_*@CORP.LOCAL'

# Node details
runoff -p 'pass' info USER@CORP.LOCAL

# Search by pattern
runoff -p 'pass' search 'ADMIN*'
```

### Path Finding

Shortest path queries to high-value targets:

```bash
# Paths to Domain Admins
runoff -p 'pass' path da USER@CORP.LOCAL

# Paths to Domain Controllers
runoff -p 'pass' path dc USER@CORP.LOCAL

# Paths between any two nodes
runoff -p 'pass' path to USER@CORP.LOCAL 'DOMAIN ADMINS@CORP.LOCAL'

# Show up to 5 paths with detailed edge info
runoff -p 'pass' path da USER@CORP.LOCAL -n 5 -d
```

### Owned Tracking

Mark compromised principals and run targeted queries from your current foothold:

```bash
# Mark a principal as owned
runoff -p 'pass' mark owned USER@CORP.LOCAL

# Mark as tier zero
runoff -p 'pass' mark tier-zero DC01.CORP.LOCAL

# List all owned principals
runoff -p 'pass' owned

# List tier zero assets
runoff -p 'pass' tierzero

# Unmark
runoff -p 'pass' unmark owned USER@CORP.LOCAL

# Clear all owned markings
runoff -p 'pass' clear owned

# Run queries that leverage owned principals
runoff -p 'pass' run owned
```

### Abuse Commands

Exploitation commands alongside every finding -- Impacket, Certipy, bloodyAD, Rubeus -- loaded from YAML templates with auto-substituted targets and domains:

```bash
# Enable abuse commands for any query run
runoff -p 'pass' --abuse run acl adcs
```

9 template files cover ACL abuse, ADCS attacks, credential attacks, delegation, coercion, GPO abuse, group abuse, and lateral movement.

### Membership & Session Queries

```bash
# Group members (recursive)
runoff -p 'pass' members 'DOMAIN ADMINS@CORP.LOCAL'

# What groups does a user belong to
runoff -p 'pass' memberof USER@CORP.LOCAL

# Where does a user have admin rights
runoff -p 'pass' adminto USER@CORP.LOCAL

# Who has admin rights on a machine
runoff -p 'pass' adminof DC01.CORP.LOCAL

# Active sessions
runoff -p 'pass' sessions DC01.CORP.LOCAL

# Attack edges from/to a node
runoff -p 'pass' edges from USER@CORP.LOCAL
runoff -p 'pass' edges to DC01.CORP.LOCAL
```

### Multi-Format Output

Table, JSON, CSV, HTML, and Markdown reports. Structured output goes to stdout, status/progress to stderr for clean piping:

```bash
# JSON export
runoff -p 'pass' -o json run all > results.json

# CSV for spreadsheet analysis
runoff -p 'pass' -o csv run all > results.csv

# HTML report
runoff -p 'pass' -o html run all > report.html

# Markdown tables
runoff -p 'pass' -o markdown run all

# Write to file directly
runoff -p 'pass' -o json -O results.json run all
```

### Diff Between Runs

Compare two JSON result files to track remediation progress:

```bash
runoff -p 'pass' -o json run all > before.json
# ... remediation happens ...
runoff -p 'pass' -o json run all > after.json
runoff diff before.json after.json
```

### BloodHound CE API Integration

Ingest SharpHound data and view collection history without opening a browser. Uses HMAC-authenticated requests to the BloodHound CE REST API (separate from the Neo4j Bolt connection used for queries).

```bash
# Set up API authentication (stores token in ~/.config/runoff/runoff.ini)
runoff auth

# Ingest SharpHound/AzureHound data
runoff ingest files data.zip

# View ingestion history
runoff ingest history
```

### Plugin System

Drop custom query files in `~/.config/runoff/queries/` for organization-specific checks:

```bash
# Enable plugin loading
runoff -p 'pass' --load-plugins run all
```

Custom queries use the same `@register_query` decorator as built-in queries.

---

## Configuration

### Config File

Save defaults to `~/.config/runoff/config.yaml` so you don't repeat flags:

```yaml
bolt_uri: bolt://127.0.0.1:7687
username: neo4j
password: bloodhoundcommunityedition
domain: CORP.LOCAL
output_format: table
severity: critical,high
abuse: true
```

### Environment Variables

| Variable | Description |
|----------|-------------|
| `RUNOFF_BOLT_URI` | Neo4j Bolt URI |
| `RUNOFF_USERNAME` | Neo4j username |
| `RUNOFF_PASSWORD` | Neo4j password |
| `RUNOFF_DOMAIN` | Domain filter |
| `XDG_CONFIG_HOME` | Override config directory base |

Priority: CLI flags > environment variables > config file > defaults.

---

## Command Reference

### Global Options

| Flag | Description | Default |
|------|-------------|---------|
| `-b, --bolt` | Neo4j Bolt URI | `bolt://127.0.0.1:7687` |
| `-u, --username` | Neo4j username | `neo4j` |
| `-p, --password` | Neo4j password | `bloodhoundcommunityedition` |
| `-d, --domain` | Domain filter | all domains |
| `-o, --output` | Output format (table, json, csv, html, markdown) | `table` |
| `-O, --output-file` | Write output to file | stdout |
| `-s, --severity` | Severity filter (comma-separated) | all |
| `--abuse / --no-abuse` | Show exploitation commands | off |
| `-q, --quiet` | Suppress banner and info | off |
| `--no-color` | Disable color output | off |
| `--debug` | Enable debug output | off |
| `--load-plugins` | Load custom queries from plugin dir | off |

### Commands

| Command | Description |
|---------|-------------|
| `run <categories...>` | Run queries by category (e.g. `run all`, `run acl adcs`) |
| `query [name]` | Run a single query by name, or list queries with `-l` |
| `queries` | List all registered queries with metadata |
| `audit` | Full security audit |
| `quickwins` | High-impact quick wins |
| `stats` | Domain statistics overview |
| `diff <file1> <file2>` | Compare two JSON result files |
| `kerberoastable` | Kerberoastable users |
| `asrep` | AS-REP roastable accounts |
| `unconstrained` | Unconstrained delegation |
| `nolaps` | Computers without LAPS |
| `computers` | All domain computers |
| `users` | All domain users |
| `spns` | Service principal names |
| `info <node>` | Node properties and details |
| `search <pattern>` | Search nodes by name pattern |
| `investigate <node>` | Full node investigation (supports `*` wildcards) |
| `path da <source>` | Shortest path to Domain Admins |
| `path dc <source>` | Shortest path to Domain Controllers |
| `path to <source> <target>` | Shortest path between two nodes |
| `mark <type> <nodes...>` | Mark nodes as `owned` or `tierzero` |
| `unmark <type> <nodes...>` | Remove markings |
| `owned` | List all owned principals |
| `tierzero` | List tier zero assets |
| `clear owned` | Clear all owned markings |
| `clear db` | Clear entire database |
| `members <group>` | Recursive group members |
| `memberof <node>` | Group memberships |
| `adminto <node>` | Where a user has admin rights |
| `adminof <node>` | Who has admin rights on a machine |
| `sessions <node>` | Active sessions on a machine |
| `edges from <node>` | Outbound attack edges |
| `edges to <node>` | Inbound attack edges |
| `status` | Test Neo4j connection |
| `domains` | List all domains in the database |
| `auth` | Set up BloodHound CE API credentials |
| `ingest files <file...>` | Upload SharpHound data to BloodHound CE |
| `ingest history` | View ingestion history |
| `completion` | Generate shell completion (bash/zsh/fish) |

---

## Architecture

```
runoff/
├── cli/                          # Click CLI -- 33 commands across 11 modules
│   ├── commands/                 # Command implementations
│   │   ├── queries.py            # run, query, queries
│   │   ├── filters.py            # kerberoastable, asrep, quickwins, etc.
│   │   ├── nodes.py              # info, search, investigate
│   │   ├── paths.py              # path da/dc/to
│   │   ├── marking.py            # mark, unmark, owned, tierzero, clear
│   │   ├── membership.py         # members, memberof, adminto, adminof, sessions
│   │   ├── edges.py              # edges from/to
│   │   ├── connection.py         # status, domains
│   │   ├── api.py                # auth, ingest
│   │   └── diff.py               # diff
│   ├── context.py                # Neo4j connection management
│   └── defaults.py               # Config file loading
├── core/                         # Neo4j integration
│   ├── bloodhound.py             # BloodHoundCE class -- Bolt driver, Cypher queries, path finding
│   ├── config.py                 # Global config singleton
│   └── cypher.py                 # Cypher query utilities
├── queries/                      # 183 queries in 15 category folders
│   ├── base.py                   # @register_query decorator, QUERY_REGISTRY
│   ├── acl/                      # ACL abuse, shadow admins, LAPS readers
│   ├── adcs/                     # ADCS ESC1-15, certificate templates
│   ├── azure/                    # AAD Connect, hybrid attack surface
│   ├── credentials/              # Kerberoasting, AS-REP, DCSync, GMSA
│   ├── delegation/               # Unconstrained, constrained, RBCD
│   ├── domain/                   # Trusts, functional levels, domain stats
│   ├── exchange/                 # Exchange permissions, delegation
│   ├── gpo/                      # GPO abuse, tier-zero GPOs
│   ├── groups/                   # Dangerous groups, protected users
│   ├── hygiene/                  # Stale accounts, signing, LAPS coverage
│   ├── lateral/                  # RDP, PSRemote, DCOM, sessions
│   ├── misc/                     # Duplicate SPNs, circular groups
│   ├── owned/                    # Paths from owned principals
│   └── paths/                    # Attack paths, busiest paths
├── abuse/                        # YAML exploitation templates (9 files)
│   └── templates/                # ACL, ADCS, credentials, delegation, coercion, GPO, groups, lateral, Azure
├── display/                      # Rich output rendering (Catppuccin Mocha)
│   ├── tables.py                 # Table formatting
│   ├── panels.py                 # Panel helpers
│   ├── report.py                 # HTML report generation
│   ├── output.py                 # JSON, CSV, HTML, Markdown emitters
│   └── summary.py                # Executive summary
└── api/                          # BloodHound CE REST API (ingestion only)
    ├── client.py                 # HMAC-authenticated HTTP client
    ├── config.py                 # API credentials (~/.config/runoff/runoff.ini)
    └── ingest.py                 # File upload
```

---

## Platform Support

| Capability | Linux | macOS | Windows |
|---|---|---|---|
| CLI | Full | Full | Full |
| Neo4j Connection (Bolt) | Full | Full | Full |
| Rich Terminal UI | Full | Full | Full (Windows Terminal recommended) |
| BloodHound CE API | Full | Full | Full |
| Shell Completion | bash, zsh, fish | bash, zsh, fish | Limited |
| JSON/CSV/HTML Export | Full | Full | Full |

---

## Security

Report security issues via [GitHub Security Advisories](https://github.com/Real-Fruit-Snacks/Runoff/security/advisories/new). Responsible disclosure timeline: 90 days.

Runoff does **not**:

- Touch Active Directory -- queries data already collected by BloodHound
- Store or exfiltrate domain credentials
- Perform network scanning or active reconnaissance
- Execute commands remotely or manage implants

---

## License

[MIT](LICENSE) -- Copyright 2026 Real-Fruit-Snacks
