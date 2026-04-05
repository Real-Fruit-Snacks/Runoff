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

Runoff queries BloodHound Community Edition's Neo4j database to identify Active Directory attack paths, misconfigurations, and privilege escalation opportunities across 177 security queries in 15 categories with exploitation guidance, severity ratings, and multi-format reporting.

> **Authorization Required**: This tool is designed exclusively for authorized security testing with explicit written permission. Unauthorized access to computer systems is illegal and may result in criminal prosecution.

</div>

---

## Quick Start

### Prerequisites

- **Python** 3.9+
- **Neo4j** with BloodHound CE data loaded
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
# Run all 177 queries
runoff -p 'bloodhoundcommunityedition' run all

# Quick wins summary
runoff -p 'pass' quickwins

# Investigate a specific node
runoff -p pass investigate USER@CORP.LOCAL

# Run with abuse commands
runoff -p pass --abuse run acl adcs

# JSON output piped to jq
runoff -p pass -o json run all | jq '.[] | select(.count > 0)'
```

---

## Features

### 177 Security Queries

Queries span 15 categories registered via `@register_query` decorator, runnable by category or individually:

```bash
# Run specific categories
runoff -p pass run acl adcs delegation

# Filter by severity
runoff -p pass -s critical,high run all

# Filter by tags
runoff -p pass --tags quick-win run all
```

Categories include ACL abuse, ADCS ESC1-ESC15, delegation, coercion relay, lateral movement, Azure/hybrid, credential attacks, Kerberoasting, DCSync, GPO abuse, and Exchange.

### Node Investigation

Properties, attack edges, group memberships, admin rights, sessions, and paths to Domain Admins in a single command:

```bash
# Full node investigation
runoff -p pass investigate USER@CORP.LOCAL

# Wildcard triage mode
runoff -p pass investigate 'SVC_*@CORP.LOCAL'

# Shortest path to Domain Admins
runoff -p pass path USER@CORP.LOCAL 'DOMAIN ADMINS@CORP.LOCAL'
```

### Abuse Commands

Exploitation commands alongside every finding -- Impacket, Certipy, bloodyAD, Rubeus -- with auto-substituted targets, domains, and OPSEC warnings:

```bash
# Enable abuse commands
runoff -p pass --abuse run acl

# Commands include tool invocations, flags, and target substitution
```

### Multi-Format Output

Table, JSON, CSV, HTML, and Markdown reports from a single run. Structured output to stdout, status to stderr:

```bash
# JSON export
runoff -p pass -o json run all > results.json

# CSV for spreadsheet analysis
runoff -p pass -o csv run all > results.csv

# HTML report
runoff -p pass -o html run all > report.html

# Markdown tables
runoff -p pass -o markdown run all
```

### Owned Tracking

Mark compromised accounts and run targeted queries from your current foothold:

```bash
# Mark a principal as owned
runoff -p pass own add USER@CORP.LOCAL

# Run queries from owned principals
runoff -p pass run --from-owned
```

### Executive Summary

Automatic domain profile, security posture assessment, and prioritized next steps:

```bash
runoff -p pass summary
```

### BloodHound CE API Integration

Ingest data, view history, and manage the database without a browser:

```bash
# Ingest SharpHound data
runoff -p pass api ingest data.zip

# View collection history
runoff -p pass api history
```

### Plugin System

Drop custom query files for organization-specific checks:

```bash
# Custom queries in ~/.config/runoff/queries/
runoff -p pass run custom
```

---

## Architecture

```
runoff/
├── cli/                          # Click CLI with 11 command modules
├── core/                         # BloodHoundCE class, Neo4j driver, Cypher utilities
├── queries/                      # 177 queries in 15 category folders (@register_query)
├── abuse/                        # YAML exploitation templates per technique
├── display/                      # Rich tables, panels, trees (Catppuccin Mocha theme)
├── api/                          # BloodHound CE API integration (HMAC auth)
└── tests/                        # Test suite
```

The CLI connects to Neo4j, executes Cypher queries via the core engine, and renders results through the display layer. Queries self-register via decorator and are discoverable at runtime.

---

## Platform Support

| Capability | Linux | macOS | Windows |
|---|---|---|---|
| CLI | Full | Full | Full |
| Neo4j Connection | Full (Bolt) | Full (Bolt) | Full (Bolt) |
| Rich Terminal UI | Full | Full | Full (Windows Terminal recommended) |
| BloodHound CE API | Full | Full | Full |
| Shell Completion | bash, zsh, fish | bash, zsh, fish | Limited |
| JSON/CSV/HTML Export | Full | Full | Full |

---

## Security

Report security issues via [GitHub Security Advisories](https://github.com/Real-Fruit-Snacks/Runoff/security/advisories/new) (preferred) or private disclosure to maintainers. Responsible disclosure timeline: 90 days. Do not open public issues for vulnerabilities.

Runoff does **not**:

- Touch Active Directory -- queries data already collected by BloodHound
- Store or exfiltrate domain credentials
- Perform network scanning or active reconnaissance
- Manage implants or execute commands remotely

---

## License

[MIT](LICENSE) -- Copyright 2026 Real-Fruit-Snacks
