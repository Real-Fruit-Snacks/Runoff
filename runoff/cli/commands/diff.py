"""Diff command — compare two saved JSON result files."""

from __future__ import annotations

import json

import click

from runoff.display import console


def _load_results(path: str) -> list[dict]:
    """Load and validate a runoff JSON results file."""
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    if not isinstance(data, list):
        raise click.BadParameter(f"{path} is not a list of query results")
    return data


def _results_by_query(data: list[dict]) -> dict[str, dict]:
    """Index results list by query name."""
    return {entry["query"]: entry for entry in data if isinstance(entry, dict) and "query" in entry}


def _result_keys(results: list[dict]) -> set[str]:
    """Extract a set of identifying keys from result rows.

    Uses the 'name' field if present, otherwise falls back to a
    JSON-serialised representation of each row for comparison.
    """
    keys = set()
    for r in results:
        if not isinstance(r, dict):
            continue
        # Use 'name' or 'principal' or 'user' or 'computer' as identifier
        for field in ("name", "principal", "user", "computer", "target"):
            if field in r and r[field]:
                keys.add(str(r[field]))
                break
        else:
            # Fallback: deterministic JSON string
            keys.add(json.dumps(r, sort_keys=True, default=str))
    return keys


@click.command()
@click.argument("baseline", type=click.Path(exists=True))
@click.argument("current", type=click.Path(exists=True))
@click.option("--json-output", "json_out", is_flag=True, help="Output diff as JSON")
def diff(baseline, current, json_out):
    """Compare two saved JSON result files and show changes.

    BASELINE is the older results file, CURRENT is the newer one.

    \b
    Example:
      runoff -p pass -o json -O baseline.json run all
      # ... time passes ...
      runoff -p pass -o json -O current.json run all
      runoff diff baseline.json current.json
    """
    try:
        old_data = _load_results(baseline)
        new_data = _load_results(current)
    except (json.JSONDecodeError, OSError) as e:
        console.print(f"[error]Failed to load file: {e}[/error]")
        return
    except click.BadParameter as e:
        console.print(f"[error]{e}[/error]")
        return

    old_by_query = _results_by_query(old_data)
    new_by_query = _results_by_query(new_data)

    all_queries = sorted(set(old_by_query) | set(new_by_query))

    new_findings = []  # Queries that appeared (count 0 -> >0, or entirely new)
    resolved = []  # Queries that disappeared (count >0 -> 0, or removed)
    changed = []  # Queries with different counts
    unchanged = []  # Same count

    for qname in all_queries:
        old_entry = old_by_query.get(qname)
        new_entry = new_by_query.get(qname)

        old_count = old_entry["count"] if old_entry else 0
        new_count = new_entry["count"] if new_entry else 0
        severity = (new_entry or old_entry or {}).get("severity", "")
        category = (new_entry or old_entry or {}).get("category", "")

        if old_count == new_count:
            unchanged.append({"query": qname, "count": new_count, "severity": severity})
        elif old_count == 0 and new_count > 0:
            new_findings.append(
                {
                    "query": qname,
                    "severity": severity,
                    "category": category,
                    "count": new_count,
                }
            )
        elif old_count > 0 and new_count == 0:
            resolved.append(
                {
                    "query": qname,
                    "severity": severity,
                    "category": category,
                    "old_count": old_count,
                }
            )
        else:
            delta = new_count - old_count
            changed.append(
                {
                    "query": qname,
                    "severity": severity,
                    "category": category,
                    "old_count": old_count,
                    "new_count": new_count,
                    "delta": delta,
                }
            )

    # JSON output mode
    if json_out:
        import sys

        json.dump(
            {
                "new_findings": new_findings,
                "resolved": resolved,
                "changed": changed,
                "unchanged_count": len(unchanged),
            },
            sys.stdout,
            indent=2,
            default=str,
        )
        sys.stdout.write("\n")
        return

    # Rich table output
    from runoff.display.tables import print_table

    console.print()
    console.print("  [banner]Runoff Diff[/banner]")
    console.print(f"  [text.secondary]Baseline:[/text.secondary] {baseline}")
    console.print(f"  [text.secondary]Current:[/text.secondary]  {current}")
    console.print()

    # Summary line
    console.print(
        f"  [info]{len(new_findings)}[/info] new  "
        f"[info]{len(resolved)}[/info] resolved  "
        f"[info]{len(changed)}[/info] changed  "
        f"[text.dim]{len(unchanged)} unchanged[/text.dim]"
    )
    console.print()

    if new_findings:
        console.print("  [subheader]New Findings[/subheader]")
        print_table(
            ["Query", "Severity", "Count"],
            [[f["query"], f["severity"], f["count"]] for f in new_findings],
        )

    if resolved:
        console.print("  [subheader]Resolved[/subheader]")
        print_table(
            ["Query", "Severity", "Was"],
            [[f["query"], f["severity"], f["old_count"]] for f in resolved],
        )

    if changed:
        console.print("  [subheader]Changed[/subheader]")
        print_table(
            ["Query", "Severity", "Before", "After", "Delta"],
            [
                [
                    f["query"],
                    f["severity"],
                    f["old_count"],
                    f["new_count"],
                    f"+{f['delta']}" if f["delta"] > 0 else str(f["delta"]),
                ]
                for f in changed
            ],
        )

    if not new_findings and not resolved and not changed:
        console.print("  [text.dim]No differences found.[/text.dim]")
    console.print()
