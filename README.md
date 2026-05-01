<picture>
  <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/Real-Fruit-Snacks/Runoff/main/docs/assets/logo-dark.svg">
  <source media="(prefers-color-scheme: light)" srcset="https://raw.githubusercontent.com/Real-Fruit-Snacks/Runoff/main/docs/assets/logo-light.svg">
  <img alt="Runoff" src="https://raw.githubusercontent.com/Real-Fruit-Snacks/Runoff/main/docs/assets/logo-dark.svg" width="100%">
</picture>

> [!IMPORTANT]
> **Active Directory security audit tool for BloodHound CE.** 183 Cypher queries across 15 AD attack categories — ACL abuse, ADCS, delegation, Kerberoasting, and more. Path finding, owned tracking, diff between runs, abuse command templates, and multi-format export from a single Neo4j Bolt connection.

> *Runoff is water that flows over saturated ground, carrying whatever it collected downstream. Felt fitting for a tool that drains everything BloodHound swept up — attack paths, misconfigurations, and privilege escalation routes — ready to use.*

---

## §1 / Premise

Runoff is a **BloodHound Community Edition analysis tool** that queries the Neo4j graph database over Bolt and surfaces AD attack paths, misconfigurations, and privilege escalation opportunities. It runs 183 Cypher queries across 15 categories — ACL abuse, ADCS ESC1–15, delegation, Kerberoasting, AS-REP roasting, GPO abuse, lateral movement, and more — against the data SharpHound or AzureHound already collected.

Beyond bulk query execution, Runoff provides surgical investigation: shortest-path queries to Domain Admins or Domain Controllers, full node investigation with properties, edges, memberships, and admin rights, owned principal tracking, and wildcard triage mode for sweeping through service accounts. Every finding can include exploitation commands auto-populated from YAML templates covering impacket, Certipy, bloodyAD, and Rubeus.

Output is table, JSON, CSV, HTML, or Markdown — structured output to stdout, status to stderr for clean piping. Diff two JSON result files to track remediation progress. A plugin system lets you drop custom query files in `~/.config/runoff/queries/` for organization-specific checks.

**Authorization Required**: Designed exclusively for authorized security testing with explicit written permission.

---

## §2 / Specs

| KEY        | VALUE                                                                       |
|------------|-----------------------------------------------------------------------------|
| QUERIES    | **183 Cypher** · 15 AD categories · severity-filtered · tag-filtered        |
| CATEGORIES | **acl · adcs · privesc · delegation · lateral** · gpo · azure · owned + more |
| ABUSE      | **9 YAML templates** · impacket · Certipy · bloodyAD · Rubeus · auto-filled  |
| OUTPUT     | **5 formats** · table/JSON/CSV/HTML/markdown · diff between runs             |
| FEATURES   | **Path finding** · owned tracking · node investigation · plugin system       |
| PLATFORM   | **Python 3.9+** · Linux · macOS · Windows · pipx install                    |
| STACK      | **neo4j-driver · Rich · Click** · Catppuccin Mocha · MIT licensed           |

Architecture in §5 below.

---

## §3 / Quickstart

```bash
# pipx (recommended)
pipx install git+https://github.com/Real-Fruit-Snacks/Runoff.git

# Or from a local clone
git clone https://github.com/Real-Fruit-Snacks/Runoff.git
cd Runoff && pip install -e .
```

```bash
# Run all 183 queries against the local BloodHound database
runoff -p 'bloodhoundcommunityedition' run all

# Quick wins — high-impact findings only
runoff -p 'pass' quickwins

# Run specific categories with abuse commands
runoff -p 'pass' --abuse run acl adcs delegation

# Filter by severity
runoff -p 'pass' -s critical,high run all

# Investigate a specific node — properties, edges, memberships, paths
runoff -p 'pass' investigate USER@CORP.LOCAL

# JSON output piped to jq
runoff -p 'pass' -o json run all | jq '.[] | select(.count > 0)'
```

Requires Python 3.9+ and a Neo4j instance with BloodHound CE data loaded (default Bolt port 7687).

---

## §4 / Reference

```
GLOBAL OPTIONS

  -b, --bolt       Neo4j Bolt URI (default: bolt://127.0.0.1:7687)
  -u, --username   Neo4j username (default: neo4j)
  -p, --password   Neo4j password
  -d, --domain     Domain filter (default: all domains)
  -o, --output     Output format: table json csv html markdown
  -O, --output-file Write output to file (default: stdout)
  -s, --severity   Severity filter: critical,high,medium,low
  --abuse          Show exploitation commands
  -q, --quiet      Suppress banner and info
  --no-color       Disable color output
  --load-plugins   Load custom queries from plugin directory

COMMANDS

  run <categories>    Run queries by category (run all, run acl adcs)
  query [name]        Run a single query by name, list with -l
  audit               Full security audit
  quickwins           High-impact quick wins
  stats               Domain statistics overview
  diff <f1> <f2>      Compare two JSON result files
  kerberoastable      Kerberoastable users
  asrep               AS-REP roastable accounts
  unconstrained       Unconstrained delegation
  nolaps              Computers without LAPS
  investigate <node>  Full node investigation (supports * wildcards)
  path da <source>    Shortest path to Domain Admins
  path dc <source>    Shortest path to Domain Controllers
  path to <s> <t>     Shortest path between two nodes
  mark <type> <node>  Mark nodes as owned or tierzero
  unmark <type> <n>   Remove markings
  members <group>     Recursive group members
  memberof <node>     Group memberships
  adminto <computer>  Who has admin rights on a machine
  adminof <principal> What computers a principal can admin
  sessions <node>     Active sessions on a machine
  edges from <node>   Outbound attack edges
  edges to <node>     Inbound attack edges
  auth                Set up BloodHound CE API credentials
  ingest files <f>    Upload SharpHound data to BloodHound CE
  ingest history      View ingestion history

RUN CATEGORIES

  acl · adcs · privesc · hygiene · lateral · delegation
  basic · groups · owned · azure · paths · exchange · gpo · misc
  (or: all)
```

---

## §5 / Architecture

```
runoff/
├── cli/
│   ├── commands/
│   │   ├── queries.py       run, query, queries
│   │   ├── filters.py       kerberoastable, asrep, quickwins, etc.
│   │   ├── nodes.py         info, search, investigate
│   │   ├── paths.py         path da/dc/to
│   │   ├── marking.py       mark, unmark, owned, tierzero, clear
│   │   ├── membership.py    members, memberof, adminto, adminof, sessions
│   │   ├── edges.py         edges from/to
│   │   ├── connection.py    status, domains
│   │   ├── api.py           auth, ingest
│   │   └── diff.py          diff
│   ├── context.py           Neo4j connection management
│   └── defaults.py          Config file loading
├── core/
│   ├── bloodhound.py        BloodHoundCE — Bolt driver, Cypher, path finding
│   ├── config.py            Global config singleton
│   └── cypher.py            Cypher query utilities
├── queries/                 183 queries in 15 category folders
│   ├── base.py              @register_query decorator, QUERY_REGISTRY
│   ├── acl/ adcs/ azure/    Category-organized query modules
│   ├── credentials/ delegation/ domain/ exchange/
│   ├── gpo/ groups/ hygiene/ lateral/ misc/ owned/ paths/
├── abuse/
│   └── templates/           9 YAML exploitation template files
└── display/
    ├── tables.py  panels.py  report.py  output.py  summary.py
```

| Layer        | Implementation                                                  |
|--------------|-----------------------------------------------------------------|
| **Database** | Neo4j Bolt · neo4j-driver · Cypher query execution              |
| **CLI**      | Click · 33 commands across 11 modules                           |
| **Queries**  | `@register_query` decorator · QUERY_REGISTRY · 15 category folders |
| **Abuse**    | YAML templates · auto-substituted targets and domains           |
| **Output**   | Rich (Catppuccin Mocha) · table/JSON/CSV/HTML/Markdown          |
| **API**      | BloodHound CE REST · HMAC-authenticated · ingestion only        |
| **Plugins**  | Drop-in `~/.config/runoff/queries/` — same decorator system     |

---

## §6 / Platform Support

| Capability | Linux | macOS | Windows |
|------------|-------|-------|---------|
| CLI | Full | Full | Full |
| Neo4j Connection (Bolt) | Full | Full | Full |
| Rich Terminal UI | Full | Full | Full (Windows Terminal) |
| BloodHound CE API | Full | Full | Full |
| Shell Completion | bash · zsh · fish | bash · zsh · fish | Limited |
| JSON/CSV/HTML Export | Full | Full | Full |

---

[License: MIT](LICENSE) · Part of [Real-Fruit-Snacks](https://github.com/Real-Fruit-Snacks) — building offensive security tools, one wave at a time.
