"""Tests for runoff diff command."""

from __future__ import annotations

import json

from click.testing import CliRunner

from runoff.cli import cli

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _write_json(path, data):
    """Write JSON data to a file."""
    path.write_text(json.dumps(data, indent=2))


def _make_results(*entries):
    """Build a list of query result entries.

    Each entry is a tuple of (query_name, severity, category, count, results).
    """
    out = []
    for name, severity, category, count, results in entries:
        out.append(
            {
                "query": name,
                "severity": severity,
                "category": category,
                "count": count,
                "results": results,
            }
        )
    return out


BASELINE = _make_results(
    (
        "Kerberoastable Users",
        "HIGH",
        "Privilege Escalation",
        2,
        [{"name": "SVC1@D.COM"}, {"name": "SVC2@D.COM"}],
    ),
    ("AS-REP Roastable", "HIGH", "Privilege Escalation", 0, []),
    ("Unconstrained Delegation", "CRITICAL", "Delegation", 1, [{"name": "SRV01@D.COM"}]),
    (
        "Stale Accounts",
        "LOW",
        "Security Hygiene",
        3,
        [{"name": "U1@D.COM"}, {"name": "U2@D.COM"}, {"name": "U3@D.COM"}],
    ),
)

CURRENT = _make_results(
    (
        "Kerberoastable Users",
        "HIGH",
        "Privilege Escalation",
        3,
        [{"name": "SVC1@D.COM"}, {"name": "SVC2@D.COM"}, {"name": "SVC3@D.COM"}],
    ),
    ("AS-REP Roastable", "HIGH", "Privilege Escalation", 1, [{"name": "ASREP_USER@D.COM"}]),
    ("Unconstrained Delegation", "CRITICAL", "Delegation", 0, []),
    (
        "Stale Accounts",
        "LOW",
        "Security Hygiene",
        3,
        [{"name": "U1@D.COM"}, {"name": "U2@D.COM"}, {"name": "U3@D.COM"}],
    ),
)


# ===========================================================================
# diff command tests
# ===========================================================================


class TestDiffCommand:
    """Test runoff diff command."""

    def test_diff_shows_new_findings(self, tmp_path):
        """New findings (0 -> >0) are shown."""
        baseline = tmp_path / "baseline.json"
        current = tmp_path / "current.json"
        _write_json(baseline, BASELINE)
        _write_json(current, CURRENT)

        runner = CliRunner()
        result = runner.invoke(cli, ["diff", str(baseline), str(current)])

        assert result.exit_code == 0
        assert "New Findings" in result.output
        assert "AS-REP Roastable" in result.output

    def test_diff_shows_resolved(self, tmp_path):
        """Resolved findings (>0 -> 0) are shown."""
        baseline = tmp_path / "baseline.json"
        current = tmp_path / "current.json"
        _write_json(baseline, BASELINE)
        _write_json(current, CURRENT)

        runner = CliRunner()
        result = runner.invoke(cli, ["diff", str(baseline), str(current)])

        assert result.exit_code == 0
        assert "Resolved" in result.output
        assert "Unconstrained Delegation" in result.output

    def test_diff_shows_changed(self, tmp_path):
        """Changed counts are shown."""
        baseline = tmp_path / "baseline.json"
        current = tmp_path / "current.json"
        _write_json(baseline, BASELINE)
        _write_json(current, CURRENT)

        runner = CliRunner()
        result = runner.invoke(cli, ["diff", str(baseline), str(current)])

        assert result.exit_code == 0
        assert "Changed" in result.output
        assert "Kerberoastable Users" in result.output

    def test_diff_summary_counts(self, tmp_path):
        """Summary line shows correct counts."""
        baseline = tmp_path / "baseline.json"
        current = tmp_path / "current.json"
        _write_json(baseline, BASELINE)
        _write_json(current, CURRENT)

        runner = CliRunner()
        result = runner.invoke(cli, ["diff", str(baseline), str(current)])

        assert result.exit_code == 0
        # 1 new (AS-REP), 1 resolved (Unconstrained), 1 changed (Kerb), 1 unchanged (Stale)
        assert "1 new" in result.output
        assert "1 resolved" in result.output
        assert "1 changed" in result.output
        assert "1 unchanged" in result.output

    def test_diff_no_changes(self, tmp_path):
        """Identical files show no differences."""
        baseline = tmp_path / "baseline.json"
        current = tmp_path / "current.json"
        _write_json(baseline, BASELINE)
        _write_json(current, BASELINE)  # Same data

        runner = CliRunner()
        result = runner.invoke(cli, ["diff", str(baseline), str(current)])

        assert result.exit_code == 0
        assert "No differences found" in result.output

    def test_diff_json_output(self, tmp_path):
        """--json-output flag produces JSON."""
        baseline = tmp_path / "baseline.json"
        current = tmp_path / "current.json"
        _write_json(baseline, BASELINE)
        _write_json(current, CURRENT)

        runner = CliRunner()
        result = runner.invoke(cli, ["diff", "--json-output", str(baseline), str(current)])

        assert result.exit_code == 0
        parsed = json.loads(result.output)
        assert "new_findings" in parsed
        assert "resolved" in parsed
        assert "changed" in parsed
        assert len(parsed["new_findings"]) == 1
        assert len(parsed["resolved"]) == 1
        assert len(parsed["changed"]) == 1
        assert parsed["unchanged_count"] == 1

    def test_diff_missing_file(self, tmp_path):
        """Missing file gives an error."""
        baseline = tmp_path / "baseline.json"
        _write_json(baseline, BASELINE)

        runner = CliRunner()
        result = runner.invoke(cli, ["diff", str(baseline), str(tmp_path / "missing.json")])

        assert result.exit_code != 0

    def test_diff_invalid_json(self, tmp_path):
        """Invalid JSON gives an error."""
        baseline = tmp_path / "baseline.json"
        bad = tmp_path / "bad.json"
        _write_json(baseline, BASELINE)
        bad.write_text("not json {{{")

        runner = CliRunner()
        result = runner.invoke(cli, ["diff", str(baseline), str(bad)])

        assert result.exit_code == 0  # Handled gracefully
        assert "Failed to load file" in result.output

    def test_diff_non_list_json(self, tmp_path):
        """Non-list JSON gives a descriptive error."""
        baseline = tmp_path / "baseline.json"
        bad = tmp_path / "bad.json"
        _write_json(baseline, BASELINE)
        bad.write_text('{"not": "a list"}')

        runner = CliRunner()
        result = runner.invoke(cli, ["diff", str(baseline), str(bad)])

        assert result.exit_code == 0
        assert "not a list" in result.output

    def test_diff_empty_files(self, tmp_path):
        """Empty result lists show no differences."""
        baseline = tmp_path / "baseline.json"
        current = tmp_path / "current.json"
        _write_json(baseline, [])
        _write_json(current, [])

        runner = CliRunner()
        result = runner.invoke(cli, ["diff", str(baseline), str(current)])

        assert result.exit_code == 0
        assert "No differences found" in result.output

    def test_diff_new_query_in_current(self, tmp_path):
        """A query only in current file shows as new finding."""
        baseline = tmp_path / "baseline.json"
        current = tmp_path / "current.json"
        _write_json(baseline, [])
        _write_json(
            current,
            _make_results(
                (
                    "Brand New Query",
                    "MEDIUM",
                    "ACL Abuse",
                    5,
                    [{"name": f"N{i}@D.COM"} for i in range(5)],
                ),
            ),
        )

        runner = CliRunner()
        result = runner.invoke(cli, ["diff", str(baseline), str(current)])

        assert result.exit_code == 0
        assert "Brand New Query" in result.output
        assert "New Findings" in result.output

    def test_diff_removed_query_in_current(self, tmp_path):
        """A query only in baseline (with count>0) shows as resolved."""
        baseline = tmp_path / "baseline.json"
        current = tmp_path / "current.json"
        _write_json(
            baseline,
            _make_results(
                ("Old Query", "HIGH", "Credentials", 2, [{"name": "A@D.COM"}, {"name": "B@D.COM"}]),
            ),
        )
        _write_json(current, [])

        runner = CliRunner()
        result = runner.invoke(cli, ["diff", str(baseline), str(current)])

        assert result.exit_code == 0
        assert "Old Query" in result.output
        assert "Resolved" in result.output


# ===========================================================================
# Internal helpers
# ===========================================================================


class TestDiffHelpers:
    """Test diff internal helper functions."""

    def test_results_by_query(self):
        from runoff.cli.commands.diff import _results_by_query

        indexed = _results_by_query(BASELINE)
        assert "Kerberoastable Users" in indexed
        assert indexed["Kerberoastable Users"]["count"] == 2

    def test_results_by_query_skips_invalid(self):
        from runoff.cli.commands.diff import _results_by_query

        data = [{"query": "Valid", "count": 1}, "not-a-dict", {"no_query_key": True}]
        indexed = _results_by_query(data)
        assert len(indexed) == 1
        assert "Valid" in indexed

    def test_result_keys_uses_name(self):
        from runoff.cli.commands.diff import _result_keys

        results = [{"name": "A@D.COM"}, {"name": "B@D.COM"}]
        keys = _result_keys(results)
        assert keys == {"A@D.COM", "B@D.COM"}

    def test_result_keys_uses_principal(self):
        from runoff.cli.commands.diff import _result_keys

        results = [{"principal": "USER@D.COM", "type": "User"}]
        keys = _result_keys(results)
        assert "USER@D.COM" in keys

    def test_result_keys_fallback_json(self):
        from runoff.cli.commands.diff import _result_keys

        results = [{"custom_field": "value"}]
        keys = _result_keys(results)
        assert len(keys) == 1
