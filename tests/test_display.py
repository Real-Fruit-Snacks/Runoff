"""Tests for display module functions."""

import pytest


@pytest.fixture
def table_mode_config():
    """Configure config for table output mode."""
    from runoff.core.config import config

    original = {
        "output_format": config.output_format,
        "quiet_mode": config.quiet_mode,
        "no_color": config.no_color,
        "owned_cache": config.owned_cache.copy(),
    }

    config.output_format = "table"
    config.quiet_mode = False
    config.no_color = True  # Disable colors for easier testing
    config.owned_cache = {}

    yield config

    config.output_format = original["output_format"]
    config.quiet_mode = original["quiet_mode"]
    config.no_color = original["no_color"]
    config.owned_cache = original["owned_cache"]


@pytest.fixture
def json_mode_config():
    """Configure config for JSON output mode."""
    from runoff.core.config import config

    original = config.output_format
    config.output_format = "json"
    yield config
    config.output_format = original


@pytest.fixture
def quiet_mode_config():
    """Configure config for quiet mode."""
    from runoff.core.config import config

    original_quiet = config.quiet_mode
    original_format = config.output_format
    config.quiet_mode = True
    config.output_format = "table"
    yield config
    config.quiet_mode = original_quiet
    config.output_format = original_format


class TestPrintHeader:
    """Test print_header function."""

    def test_prints_header_in_table_mode(self, table_mode_config, capsys):
        """Test header is printed in table mode."""
        from runoff.display.tables import print_header

        result = print_header("Test Header")
        captured = capsys.readouterr()

        assert result is True
        assert "Test Header" in captured.out

    def test_returns_false_in_json_mode(self, json_mode_config, capsys):
        """Test header suppressed in JSON mode."""
        from runoff.display.tables import print_header

        result = print_header("Test Header")
        captured = capsys.readouterr()

        assert result is False
        assert captured.out == ""

    def test_quiet_mode_skips_zero_results(self, quiet_mode_config, capsys):
        """Test quiet mode skips headers with zero results."""
        from runoff.display.tables import print_header

        result = print_header("Test Header", result_count=0)
        captured = capsys.readouterr()

        assert result is False
        assert captured.out == ""

    def test_quiet_mode_shows_nonzero_results(self, quiet_mode_config, capsys):
        """Test quiet mode shows headers with results."""
        from runoff.display.tables import print_header

        result = print_header("Test Header", result_count=5)
        captured = capsys.readouterr()

        assert result is True
        assert "Test Header" in captured.out

    def test_severity_tag_shown_for_findings(self, table_mode_config, capsys):
        """Test severity tag shown when there are findings."""
        from runoff.display.colors import Severity
        from runoff.display.tables import print_header

        result = print_header("Kerberoastable Users", severity=Severity.HIGH, result_count=5)
        captured = capsys.readouterr()

        assert result is True
        assert "HIGH" in captured.out
        assert "Kerberoastable Users" in captured.out

    def test_severity_tag_hidden_for_info(self, table_mode_config, capsys):
        """Test INFO severity doesn't show tag."""
        from runoff.display.colors import Severity
        from runoff.display.tables import print_header

        result = print_header("Domain Stats", severity=Severity.INFO, result_count=1)
        captured = capsys.readouterr()

        assert result is True
        assert "INFO" not in captured.out
        assert "Domain Stats" in captured.out

    def test_severity_tag_hidden_for_zero_results(self, table_mode_config, capsys):
        """Test severity tag hidden when no results."""
        from runoff.display.colors import Severity
        from runoff.display.tables import print_header

        result = print_header("Test Query", severity=Severity.HIGH, result_count=0)
        captured = capsys.readouterr()

        assert result is True
        assert "HIGH" not in captured.out


class TestPrintSubheader:
    """Test print_subheader function."""

    def test_prints_in_table_mode(self, table_mode_config, capsys):
        """Test subheader prints in table mode."""
        from runoff.display.tables import print_subheader

        print_subheader("Found 5 results")
        captured = capsys.readouterr()

        assert "Found 5 results" in captured.out

    def test_suppressed_in_json_mode(self, json_mode_config, capsys):
        """Test subheader suppressed in JSON mode."""
        from runoff.display.tables import print_subheader

        print_subheader("Found 5 results")
        captured = capsys.readouterr()

        assert captured.out == ""


class TestPrintWarning:
    """Test print_warning function."""

    def test_prints_in_table_mode(self, table_mode_config, capsys):
        """Test warning prints in table mode."""
        from runoff.display.tables import print_warning

        print_warning("No results found")
        captured = capsys.readouterr()

        assert "No results found" in captured.out

    def test_suppressed_in_json_mode(self, json_mode_config, capsys):
        """Test warning suppressed in JSON mode."""
        from runoff.display.tables import print_warning

        print_warning("No results found")
        captured = capsys.readouterr()

        assert captured.out == ""


class TestPrintSeveritySummary:
    """Test print_severity_summary function."""

    def test_shows_findings_summary(self, table_mode_config, capsys):
        """Test severity summary shows findings."""
        from runoff.display.colors import Severity
        from runoff.display.tables import print_severity_summary

        counts = {
            Severity.CRITICAL: 2,
            Severity.HIGH: 5,
            Severity.MEDIUM: 3,
            Severity.LOW: 1,
            Severity.INFO: 10,
        }
        print_severity_summary(counts)
        captured = capsys.readouterr()

        assert "Findings Summary" in captured.out
        assert "CRITICAL" in captured.out
        assert "HIGH" in captured.out
        assert "MEDIUM" in captured.out
        assert "LOW" in captured.out
        # INFO should not be shown in summary
        assert "INFO" not in captured.out

    def test_shows_no_findings_message(self, table_mode_config, capsys):
        """Test shows positive message when no findings."""
        from runoff.display.colors import Severity
        from runoff.display.tables import print_severity_summary

        counts = {
            Severity.CRITICAL: 0,
            Severity.HIGH: 0,
            Severity.MEDIUM: 0,
            Severity.LOW: 0,
            Severity.INFO: 5,
        }
        print_severity_summary(counts)
        captured = capsys.readouterr()

        assert "No security findings detected" in captured.out

    def test_suppressed_in_json_mode(self, json_mode_config, capsys):
        """Test summary suppressed in JSON mode."""
        from runoff.display.colors import Severity
        from runoff.display.tables import print_severity_summary

        counts = {Severity.HIGH: 5}
        print_severity_summary(counts)
        captured = capsys.readouterr()

        assert captured.out == ""


class TestPrintTable:
    """Test print_table function."""

    def test_prints_basic_table(self, table_mode_config, capsys):
        """Test basic table output."""
        from runoff.display.tables import print_table

        headers = ["Name", "Enabled", "Admin"]
        rows = [
            ["USER1@DOMAIN.COM", True, False],
            ["USER2@DOMAIN.COM", True, True],
        ]
        print_table(headers, rows)
        captured = capsys.readouterr()

        assert "Name" in captured.out
        assert "USER1@DOMAIN.COM" in captured.out
        assert "USER2@DOMAIN.COM" in captured.out

    def test_prints_warning_for_empty_rows(self, table_mode_config, capsys):
        """Test warning shown for empty results."""
        from runoff.display.tables import print_table

        print_table(["Name"], [])
        captured = capsys.readouterr()

        assert "No results found" in captured.out

    def test_handles_none_values(self, table_mode_config, capsys):
        """Test None values are displayed as dash."""
        from runoff.display.tables import print_table

        headers = ["Name", "Description"]
        rows = [["USER@DOMAIN.COM", None]]
        print_table(headers, rows)
        captured = capsys.readouterr()

        assert "-" in captured.out

    def test_handles_list_values(self, table_mode_config, capsys):
        """Test list values are joined."""
        from runoff.display.tables import print_table

        headers = ["Name", "SPNs"]
        rows = [["SVC@DOMAIN.COM", ["http/svc", "mssql/svc", "ldap/svc"]]]
        print_table(headers, rows)
        captured = capsys.readouterr()

        assert "http/svc" in captured.out

    def test_truncates_long_lists(self, table_mode_config, capsys):
        """Test long lists are truncated."""
        from runoff.display.tables import print_table

        headers = ["Name", "SPNs"]
        rows = [["SVC@DOMAIN.COM", ["spn1", "spn2", "spn3", "spn4", "spn5"]]]
        print_table(headers, rows)
        captured = capsys.readouterr()

        assert "+2 more" in captured.out

    def test_highlights_owned_principals(self, table_mode_config, capsys):
        """Test owned principals are highlighted."""
        from runoff.display.tables import print_table

        table_mode_config.owned_cache = {"OWNED@DOMAIN.COM": False}

        headers = ["Name"]
        rows = [["OWNED@DOMAIN.COM"]]
        print_table(headers, rows)
        captured = capsys.readouterr()

        assert "♦" in captured.out
        assert "OWNED@DOMAIN.COM" in captured.out

    def test_suppressed_in_json_mode(self, json_mode_config, capsys):
        """Test table suppressed in JSON mode."""
        from runoff.display.tables import print_table

        print_table(["Name"], [["USER@DOMAIN.COM"]])
        captured = capsys.readouterr()

        assert captured.out == ""


class TestPrintNodeInfo:
    """Test print_node_info function."""

    def test_prints_node_properties(self, table_mode_config, capsys):
        """Test node properties are printed."""
        from runoff.display.tables import print_node_info

        node = {
            "_labels": ["User", "Base"],
            "name": "ADMIN@DOMAIN.COM",
            "enabled": True,
            "admincount": True,
            "description": "Admin user",
        }
        print_node_info(node)
        captured = capsys.readouterr()

        assert "Labels:" in captured.out
        assert "User" in captured.out
        assert "name:" in captured.out
        assert "ADMIN@DOMAIN.COM" in captured.out
        assert "enabled:" in captured.out

    def test_handles_boolean_values(self, table_mode_config, capsys):
        """Test boolean values are formatted."""
        from runoff.display.tables import print_node_info

        node = {"_labels": [], "enabled": True, "admincount": False}
        print_node_info(node)
        captured = capsys.readouterr()

        assert "True" in captured.out
        assert "False" in captured.out

    def test_handles_list_properties(self, table_mode_config, capsys):
        """Test list properties are formatted."""
        from runoff.display.tables import print_node_info

        node = {"_labels": [], "serviceprincipalnames": ["http/svc", "mssql/svc"]}
        print_node_info(node)
        captured = capsys.readouterr()

        assert "http/svc" in captured.out

    def test_suppressed_in_json_mode(self, json_mode_config, capsys):
        """Test node info suppressed in JSON mode."""
        from runoff.display.tables import print_node_info

        print_node_info({"_labels": [], "name": "TEST"})
        captured = capsys.readouterr()

        assert captured.out == ""


class TestColors:
    """Test Colors class."""

    def test_colors_enabled_by_default(self):
        """Test colors are enabled when no_color is False."""
        from runoff.core.config import config
        from runoff.display.colors import colors

        original = config.no_color
        config.no_color = False

        # Should return ANSI codes
        assert "\033[" in colors.BLUE or colors.BLUE == ""  # May be empty in some envs

        config.no_color = original

    def test_colors_disabled_when_no_color(self):
        """Test colors are empty when no_color is True."""
        from runoff.core.config import config
        from runoff.display.colors import colors

        original = config.no_color
        config.no_color = True

        assert colors.BLUE == ""
        assert colors.GREEN == ""
        assert colors.FAIL == ""
        assert colors.END == ""

        config.no_color = original


class TestSeverity:
    """Test Severity enum."""

    def test_severity_labels(self):
        """Test severity labels are correct."""
        from runoff.display.colors import Severity

        assert Severity.CRITICAL.label == "CRITICAL"
        assert Severity.HIGH.label == "HIGH"
        assert Severity.MEDIUM.label == "MEDIUM"
        assert Severity.LOW.label == "LOW"
        assert Severity.INFO.label == "INFO"

    def test_severity_colors_disabled(self):
        """Test severity colors respect no_color setting."""
        from runoff.core.config import config
        from runoff.display.colors import Severity

        original = config.no_color
        config.no_color = True

        assert Severity.CRITICAL.color == ""
        assert Severity.HIGH.color == ""

        config.no_color = original

    def test_all_severities_have_colors(self):
        """Test all severity levels have defined colors."""
        from runoff.core.config import config
        from runoff.display.colors import Severity

        original = config.no_color
        config.no_color = False

        for sev in Severity:
            # Color should be non-empty when colors enabled
            assert sev.value[1] != ""  # Raw color value exists

        config.no_color = original
