"""Structured output (JSON/CSV/HTML) for non-table output modes."""

from __future__ import annotations

import csv
import json
import sys
from contextlib import contextmanager
from typing import IO, Any


@contextmanager
def _open_output() -> IO[str]:
    """Return the output stream: a file if ``config.output_file`` is set, else stdout."""
    from runoff.core.config import config

    path = config.output_file
    if path:
        fh = open(path, "w", encoding="utf-8")
        try:
            yield fh
        finally:
            fh.close()
    else:
        yield sys.stdout


def emit_json(data: Any) -> None:
    """Emit data as JSON to stdout or the configured output file."""
    with _open_output() as out:
        json.dump(data, out, indent=2, default=str)
        out.write("\n")
        out.flush()


def emit_csv(data: Any) -> None:
    """Emit data as CSV to stdout or the configured output file.

    Accepts a list of dicts (flat rows) or a list of dicts with nested
    'results' lists (per-query output from 'run' command).
    """
    rows = _normalize_rows(data)
    if not rows:
        return

    # Collect all unique keys preserving insertion order
    fieldnames: list[str] = []
    seen: set = set()
    for row in rows:
        for key in row:
            if key not in seen:
                fieldnames.append(key)
                seen.add(key)

    if not fieldnames:
        return

    with _open_output() as out:
        writer = csv.DictWriter(out, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            writer.writerow({k: _csv_value(v) for k, v in row.items()})
        out.flush()


def emit_html(data: Any) -> None:
    """Emit data as an HTML report to stdout or the configured output file."""
    from runoff.core.config import config
    from runoff.display.report import generate_html_report

    # If output_file is set, write directly to it
    if config.output_file:
        generate_html_report(data, config.output_file)
        return

    # Otherwise write to stdout via a temp file
    import os
    import tempfile

    fd, tmp_path = tempfile.mkstemp(suffix=".html")
    try:
        os.close(fd)
        generate_html_report(data, tmp_path)
        with open(tmp_path) as f:
            sys.stdout.write(f.read())
        sys.stdout.flush()
    finally:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass


def emit_markdown(data: Any) -> None:
    """Emit data as Markdown to stdout or the configured output file."""
    rows = _normalize_rows(data)
    if not rows:
        return

    # Collect all unique keys preserving insertion order
    fieldnames: list[str] = []
    seen: set = set()
    for row in rows:
        for key in row:
            if key not in seen:
                fieldnames.append(key)
                seen.add(key)

    if not fieldnames:
        return

    with _open_output() as out:
        # Header row
        out.write("| " + " | ".join(fieldnames) + " |\n")
        # Separator row
        out.write("| " + " | ".join("---" for _ in fieldnames) + " |\n")
        # Data rows
        for row in rows:
            values = [_md_escape(str(row.get(k, ""))) for k in fieldnames]
            out.write("| " + " | ".join(values) + " |\n")
        out.flush()


def _md_escape(text: str) -> str:
    """Escape pipe characters for markdown table cells."""
    return text.replace("|", "\\|").replace("\n", " ")


def emit_structured(data: Any) -> None:
    """Emit structured output based on current config format."""
    from runoff.core.config import config

    fmt = config.output_format
    if fmt == "json":
        emit_json(data)
    elif fmt == "csv":
        emit_csv(data)
    elif fmt == "html":
        emit_html(data)
    elif fmt == "markdown":
        emit_markdown(data)

    # Notify user when output was written to a file
    if config.output_file:
        from runoff.display import console

        console.print(f"  [info]Output written to:[/info] {config.output_file}")


def _csv_value(val: Any) -> str:
    """Format a value for CSV output."""
    if val is None:
        return ""
    if isinstance(val, list):
        return "; ".join(str(v) for v in val)
    if isinstance(val, dict):
        return json.dumps(val, default=str)
    return str(val)


def _normalize_rows(data: Any) -> list[dict[str, Any]]:
    """Normalize various data shapes into flat list of dicts for CSV."""
    if isinstance(data, list):
        # Check if this is per-query structured output (from 'run' command)
        if data and isinstance(data[0], dict) and "results" in data[0]:
            return _flatten_query_results(data)
        # Already flat list of dicts
        return [row for row in data if isinstance(row, dict)]
    if isinstance(data, dict):
        return _flatten_dict(data)
    return []


def _flatten_query_results(queries: list[dict]) -> list[dict[str, Any]]:
    """Flatten per-query results into flat rows with query metadata."""
    rows = []
    for entry in queries:
        query_name = entry.get("query", "")
        severity = entry.get("severity", "")
        category = entry.get("category", "")
        for result in entry.get("results", []):
            if isinstance(result, dict):
                row = {"_query": query_name, "_severity": severity, "_category": category}
                row.update(result)
                rows.append(row)
    return rows


def _flatten_dict(data: dict) -> list[dict[str, Any]]:
    """Flatten a dict of lists into rows with a _section key."""
    rows = []
    for key, value in data.items():
        if isinstance(value, list):
            for item in value:
                if isinstance(item, dict):
                    row = {"_section": key}
                    row.update(item)
                    rows.append(row)
        elif isinstance(value, (int, float, str, bool)):
            rows.append({"_section": key, "value": value})
    return rows
