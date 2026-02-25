"""Tests for runoff/display/report.py and runoff/display/output.py"""

from __future__ import annotations

import json

import pytest

# ---------------------------------------------------------------------------
# Sample data
# ---------------------------------------------------------------------------

SAMPLE_RESULTS = [
    {
        "query": "Kerberoastable Users",
        "category": "Privilege Escalation",
        "severity": "HIGH",
        "count": 2,
        "results": [
            {"name": "SVC_SQL@DOMAIN.COM", "enabled": True},
            {"name": "SVC_WEB@DOMAIN.COM", "enabled": True},
        ],
    },
    {
        "query": "AS-REP Roastable",
        "category": "Privilege Escalation",
        "severity": "HIGH",
        "count": 0,
        "results": [],
    },
]


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def reset_config():
    """Reset config singleton around each test."""
    from runoff.core.config import config

    original_output_format = config.output_format
    original_output_file = config.output_file
    config.output_format = "table"
    config.output_file = None

    yield config

    config.output_format = original_output_format
    config.output_file = original_output_file


# ===========================================================================
# HTML Report — generate_html_report
# ===========================================================================


class TestGenerateHtmlReport:
    """Tests for generate_html_report()."""

    def test_generate_html_report_creates_file(self, tmp_path):
        """generate_html_report writes an HTML file at output_path."""
        from runoff.display.report import generate_html_report

        out = tmp_path / "report.html"
        generate_html_report(SAMPLE_RESULTS, str(out))

        assert out.exists()
        assert out.stat().st_size > 0

    def test_generate_html_report_contains_findings(self, tmp_path):
        """Generated HTML includes query names and result counts for positive hits."""
        from runoff.display.report import generate_html_report

        out = tmp_path / "report.html"
        generate_html_report(SAMPLE_RESULTS, str(out))

        content = out.read_text(encoding="utf-8")
        # Only the query with count > 0 should appear as a finding
        assert "Kerberoastable Users" in content
        assert "2 finding" in content
        # Zero-count query should not appear as a finding section
        assert "AS-REP Roastable" not in content.split("Findings")[1] or "0 finding" not in content

    def test_generate_html_report_severity_classes(self, tmp_path):
        """Generated HTML contains the expected severity CSS classes."""
        from runoff.display.report import generate_html_report

        results = [
            {"query": "Crit Query", "severity": "CRITICAL", "count": 1, "results": [{"item": "x"}]},
            {"query": "High Query", "severity": "HIGH", "count": 1, "results": [{"item": "x"}]},
            {"query": "Med Query", "severity": "MEDIUM", "count": 1, "results": [{"item": "x"}]},
            {"query": "Low Query", "severity": "LOW", "count": 1, "results": [{"item": "x"}]},
        ]
        out = tmp_path / "report.html"
        generate_html_report(results, str(out))

        content = out.read_text(encoding="utf-8")
        assert 'class="critical"' in content
        assert 'class="high"' in content
        assert 'class="medium"' in content
        assert 'class="low"' in content

    def test_generate_html_report_empty_results(self, tmp_path):
        """Empty results list produces a 'No security findings' message."""
        from runoff.display.report import generate_html_report

        out = tmp_path / "report.html"
        generate_html_report([], str(out))

        content = out.read_text(encoding="utf-8")
        assert "No security findings" in content

    def test_generate_html_report_escapes_html(self, tmp_path):
        """XSS characters in result data are HTML-escaped."""
        from runoff.display.report import generate_html_report

        results = [
            {
                "query": "XSS Test",
                "severity": "HIGH",
                "count": 1,
                "results": [{"name": "<script>alert('xss')</script>"}],
            }
        ]
        out = tmp_path / "report.html"
        generate_html_report(results, str(out))

        content = out.read_text(encoding="utf-8")
        # The injected data should be escaped, not rendered as raw HTML
        assert "&lt;script&gt;alert(&#x27;xss&#x27;)&lt;/script&gt;" in content


# ===========================================================================
# HTML Escaping — _escape_html
# ===========================================================================


class TestEscapeHtml:
    """Tests for _escape_html()."""

    def test_escape_html_special_chars(self):
        """<, >, &, \", ' are all escaped."""
        from runoff.display.report import _escape_html

        result = _escape_html("<>&\"' test")
        assert "<" not in result
        assert ">" not in result
        assert "&amp;" in result
        assert "&lt;" in result
        assert "&gt;" in result
        assert "&quot;" in result or "&#x27;" in result or "&#34;" in result

    def test_escape_html_normal_text(self):
        """Normal alphanumeric text is returned unchanged."""
        from runoff.display.report import _escape_html

        text = "Hello World 123"
        assert _escape_html(text) == text

    def test_escape_html_none(self):
        """None input returns empty string."""
        from runoff.display.report import _escape_html

        assert _escape_html(None) == ""


# ===========================================================================
# Output Functions — emit_json / emit_csv / emit_html / emit_structured
# ===========================================================================


class TestEmitJson:
    """Tests for emit_json()."""

    def test_emit_json_writes_stdout(self, capsys):
        """emit_json serialises data as JSON to stdout."""
        from runoff.display.output import emit_json

        data = {"key": "value", "count": 42}
        emit_json(data)

        captured = capsys.readouterr()
        parsed = json.loads(captured.out)
        assert parsed["key"] == "value"
        assert parsed["count"] == 42


class TestEmitCsv:
    """Tests for emit_csv()."""

    def test_emit_csv_writes_stdout(self, capsys):
        """emit_csv writes CSV headers and rows to stdout."""
        from runoff.display.output import emit_csv

        data = [
            {"name": "ALICE@CORP.LOCAL", "enabled": True},
            {"name": "BOB@CORP.LOCAL", "enabled": False},
        ]
        emit_csv(data)

        captured = capsys.readouterr()
        lines = captured.out.strip().splitlines()
        assert len(lines) == 3  # header + 2 rows
        assert "name" in lines[0]
        assert "ALICE@CORP.LOCAL" in captured.out
        assert "BOB@CORP.LOCAL" in captured.out

    def test_emit_csv_empty_data(self, capsys):
        """emit_csv with empty list produces no output."""
        from runoff.display.output import emit_csv

        emit_csv([])

        captured = capsys.readouterr()
        assert captured.out == ""


class TestEmitHtml:
    """Tests for emit_html()."""

    def test_emit_html_writes_stdout(self, capsys):
        """emit_html writes HTML content to stdout."""
        from runoff.display.output import emit_html

        emit_html(SAMPLE_RESULTS)

        captured = capsys.readouterr()
        assert "<!DOCTYPE html>" in captured.out
        assert "<html>" in captured.out


class TestEmitMarkdown:
    """Tests for emit_markdown()."""

    def test_emit_markdown_writes_stdout(self, capsys):
        """emit_markdown writes markdown table to stdout."""
        from runoff.display.output import emit_markdown

        data = [{"name": "USER@D.COM", "type": "User", "enabled": True}]
        emit_markdown(data)

        captured = capsys.readouterr()
        assert "| name | type | enabled |" in captured.out
        assert "| --- | --- | --- |" in captured.out
        assert "| USER@D.COM | User | True |" in captured.out

    def test_emit_markdown_empty_data(self, capsys):
        """emit_markdown does nothing on empty data."""
        from runoff.display.output import emit_markdown

        emit_markdown([])
        captured = capsys.readouterr()
        assert captured.out == ""

    def test_emit_markdown_escapes_pipes(self, capsys):
        """emit_markdown escapes pipe characters in values."""
        from runoff.display.output import emit_markdown

        data = [{"name": "A|B", "value": "test"}]
        emit_markdown(data)

        captured = capsys.readouterr()
        assert "A\\|B" in captured.out

    def test_emit_markdown_to_file(self, tmp_path, reset_config):
        """emit_markdown writes to output file when configured."""
        from runoff.display.output import emit_markdown

        out_file = tmp_path / "output.md"
        reset_config.output_file = str(out_file)

        data = [{"query": "test", "count": 1}]
        emit_markdown(data)

        content = out_file.read_text()
        assert "| query | count |" in content
        assert "| test | 1 |" in content


class TestEmitStructured:
    """Tests for emit_structured()."""

    def test_emit_structured_json(self, capsys, reset_config):
        """output_format='json' routes through emit_json."""
        from runoff.display.output import emit_structured

        reset_config.output_format = "json"
        emit_structured({"x": 1})

        captured = capsys.readouterr()
        parsed = json.loads(captured.out)
        assert parsed["x"] == 1

    def test_emit_structured_csv(self, capsys, reset_config):
        """output_format='csv' routes through emit_csv."""
        from runoff.display.output import emit_structured

        reset_config.output_format = "csv"
        emit_structured([{"col": "val"}])

        captured = capsys.readouterr()
        assert "col" in captured.out
        assert "val" in captured.out

    def test_emit_structured_html(self, capsys, reset_config):
        """output_format='html' routes through emit_html."""
        from runoff.display.output import emit_structured

        reset_config.output_format = "html"
        emit_structured(SAMPLE_RESULTS)

        captured = capsys.readouterr()
        assert "<!DOCTYPE html>" in captured.out

    def test_emit_structured_markdown(self, capsys, reset_config):
        """output_format='markdown' routes through emit_markdown."""
        from runoff.display.output import emit_structured

        reset_config.output_format = "markdown"
        emit_structured([{"col": "val"}])

        captured = capsys.readouterr()
        assert "| col |" in captured.out
        assert "| val |" in captured.out


# ===========================================================================
# CSV Helpers — _csv_value
# ===========================================================================


class TestCsvValue:
    """Tests for _csv_value()."""

    def test_csv_value_none(self):
        """None returns empty string."""
        from runoff.display.output import _csv_value

        assert _csv_value(None) == ""

    def test_csv_value_list(self):
        """List items are joined with '; '."""
        from runoff.display.output import _csv_value

        assert _csv_value(["a", "b", "c"]) == "a; b; c"

    def test_csv_value_dict(self):
        """Dict is serialised as a JSON string."""
        from runoff.display.output import _csv_value

        result = _csv_value({"key": "val"})
        parsed = json.loads(result)
        assert parsed["key"] == "val"

    def test_csv_value_string(self):
        """Plain string is returned as-is."""
        from runoff.display.output import _csv_value

        assert _csv_value("hello") == "hello"

    def test_csv_value_int(self):
        """Integer is converted to its string representation."""
        from runoff.display.output import _csv_value

        assert _csv_value(42) == "42"

    def test_csv_value_bool(self):
        """Boolean is converted to its string representation."""
        from runoff.display.output import _csv_value

        assert _csv_value(True) == "True"


# ===========================================================================
# Row Normalisation — _normalize_rows
# ===========================================================================


class TestNormalizeRows:
    """Tests for _normalize_rows()."""

    def test_normalize_rows_flat_list(self):
        """A list of plain dicts passes through unchanged."""
        from runoff.display.output import _normalize_rows

        data = [{"a": 1}, {"b": 2}]
        result = _normalize_rows(data)
        assert result == data

    def test_normalize_rows_query_results(self):
        """Per-query format is flattened with _query, _severity, _category keys."""
        from runoff.display.output import _normalize_rows

        rows = _normalize_rows(SAMPLE_RESULTS)

        # Only the query with actual result rows contributes rows
        assert len(rows) == 2
        for row in rows:
            assert row["_query"] == "Kerberoastable Users"
            assert row["_severity"] == "HIGH"
            assert row["_category"] == "Privilege Escalation"
            assert "name" in row

    def test_normalize_rows_dict(self):
        """A dict of lists is flattened with a _section key per item."""
        from runoff.display.output import _normalize_rows

        data = {
            "users": [{"name": "ALICE"}, {"name": "BOB"}],
            "computers": [{"name": "DC01"}],
        }
        rows = _normalize_rows(data)
        assert len(rows) == 3
        sections = {r["_section"] for r in rows}
        assert "users" in sections
        assert "computers" in sections

    def test_normalize_rows_empty_list(self):
        """Empty list returns empty list."""
        from runoff.display.output import _normalize_rows

        assert _normalize_rows([]) == []

    def test_normalize_rows_non_dict_items_skipped(self):
        """Non-dict items in a flat list are skipped."""
        from runoff.display.output import _normalize_rows

        data = [{"a": 1}, "string", 42, None]
        rows = _normalize_rows(data)
        assert rows == [{"a": 1}]


# ===========================================================================
# _flatten_query_results
# ===========================================================================


class TestFlattenQueryResults:
    """Tests for _flatten_query_results()."""

    def test_flatten_adds_metadata_columns(self):
        """Each result row gets _query, _severity, _category prepended."""
        from runoff.display.output import _flatten_query_results

        queries = [
            {
                "query": "My Query",
                "severity": "CRITICAL",
                "category": "ACL Abuse",
                "results": [{"name": "X"}, {"name": "Y"}],
            }
        ]
        rows = _flatten_query_results(queries)
        assert len(rows) == 2
        assert rows[0]["_query"] == "My Query"
        assert rows[0]["_severity"] == "CRITICAL"
        assert rows[0]["_category"] == "ACL Abuse"
        assert rows[0]["name"] == "X"

    def test_flatten_skips_non_dict_results(self):
        """Non-dict entries inside results are skipped."""
        from runoff.display.output import _flatten_query_results

        queries = [
            {
                "query": "Q",
                "severity": "LOW",
                "category": "Misc",
                "results": [{"name": "A"}, "bad-string", 99],
            }
        ]
        rows = _flatten_query_results(queries)
        assert len(rows) == 1
        assert rows[0]["name"] == "A"

    def test_flatten_empty_results_list(self):
        """Query with empty results list contributes no rows."""
        from runoff.display.output import _flatten_query_results

        queries = [{"query": "Q", "severity": "INFO", "category": "X", "results": []}]
        assert _flatten_query_results(queries) == []


# ===========================================================================
# Output File — --output-file / -O flag
# ===========================================================================


class TestOutputFile:
    """Tests for --output-file (-O) flag that writes output to a file."""

    def test_emit_json_to_file(self, tmp_path, reset_config):
        """emit_json writes JSON to file when output_file is set."""
        from runoff.display.output import emit_json

        out = tmp_path / "output.json"
        reset_config.output_file = str(out)

        emit_json({"key": "value", "count": 42})

        assert out.exists()
        parsed = json.loads(out.read_text())
        assert parsed["key"] == "value"
        assert parsed["count"] == 42

    def test_emit_csv_to_file(self, tmp_path, reset_config):
        """emit_csv writes CSV to file when output_file is set."""
        from runoff.display.output import emit_csv

        out = tmp_path / "output.csv"
        reset_config.output_file = str(out)

        emit_csv(
            [
                {"name": "ALICE@CORP.LOCAL", "enabled": True},
                {"name": "BOB@CORP.LOCAL", "enabled": False},
            ]
        )

        assert out.exists()
        content = out.read_text()
        lines = content.strip().splitlines()
        assert len(lines) == 3  # header + 2 rows
        assert "name" in lines[0]
        assert "ALICE@CORP.LOCAL" in content

    def test_emit_html_to_file(self, tmp_path, reset_config):
        """emit_html writes HTML directly to file when output_file is set."""
        from runoff.display.output import emit_html

        out = tmp_path / "report.html"
        reset_config.output_file = str(out)

        emit_html(SAMPLE_RESULTS)

        assert out.exists()
        content = out.read_text()
        assert "<!DOCTYPE html>" in content or "<html>" in content

    def test_emit_structured_to_file(self, tmp_path, reset_config):
        """emit_structured routes to file based on format and output_file."""
        from runoff.display.output import emit_structured

        out = tmp_path / "output.json"
        reset_config.output_format = "json"
        reset_config.output_file = str(out)

        emit_structured({"data": [1, 2, 3]})

        assert out.exists()
        parsed = json.loads(out.read_text())
        assert parsed["data"] == [1, 2, 3]

    def test_emit_json_to_stdout_when_no_file(self, capsys, reset_config):
        """emit_json still writes to stdout when output_file is None."""
        from runoff.display.output import emit_json

        reset_config.output_file = None
        emit_json({"key": "value"})

        captured = capsys.readouterr()
        parsed = json.loads(captured.out)
        assert parsed["key"] == "value"

    def test_emit_csv_to_stdout_when_no_file(self, capsys, reset_config):
        """emit_csv still writes to stdout when output_file is None."""
        from runoff.display.output import emit_csv

        reset_config.output_file = None
        emit_csv([{"col": "val"}])

        captured = capsys.readouterr()
        assert "col" in captured.out
        assert "val" in captured.out

    def test_output_file_overwrites_existing(self, tmp_path, reset_config):
        """Output file overwrites existing file content."""
        from runoff.display.output import emit_json

        out = tmp_path / "output.json"
        out.write_text("old content")

        reset_config.output_file = str(out)
        emit_json({"new": True})

        content = out.read_text()
        assert "old content" not in content
        parsed = json.loads(content)
        assert parsed["new"] is True
