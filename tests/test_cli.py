"""CLI integration tests using Click's CliRunner with mocked BloodHoundCE."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest
from click.testing import CliRunner

from runoff.cli import cli

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def runner():
    return CliRunner()


@pytest.fixture
def mock_connect():
    """Mock the connect context manager to avoid real Neo4j connections."""
    mock_bh = MagicMock()
    mock_bh.connect.return_value = True
    mock_bh.run_query.return_value = []
    mock_bh._accumulated_results = []
    mock_bh.accumulated_results = []
    mock_bh._structured_emitted = False
    mock_bh.clear_results_cache = MagicMock()

    with patch("runoff.cli.context.BloodHoundCE") as MockBH:
        MockBH.return_value = mock_bh
        with patch("runoff.cli.context._init_owned_cache"):
            yield mock_bh


# ---------------------------------------------------------------------------
# 1. Root group tests
# ---------------------------------------------------------------------------


def test_help_shows_categories(runner, mock_config):
    result = runner.invoke(cli, ["--help"])
    assert result.exit_code == 0
    assert "Connection" in result.output


def test_version(runner):
    result = runner.invoke(cli, ["--version"])
    assert result.exit_code == 0
    assert "3.1.0" in result.output


def test_no_command_shows_help(runner, mock_config):
    result = runner.invoke(cli, [])
    assert result.exit_code == 0


# ---------------------------------------------------------------------------
# 2. Connection commands
# ---------------------------------------------------------------------------


def test_status_connected(runner, mock_connect, mock_config):
    result = runner.invoke(cli, ["-p", "pass", "status"])
    assert result.exit_code == 0
    assert "Connected" in result.output


def test_status_disconnected(runner, mock_config):
    """When connect() can't connect, status shows Disconnected."""
    with patch("runoff.cli.context.BloodHoundCE") as MockBH:
        mock_bh = MagicMock()
        mock_bh._structured_emitted = False
        mock_bh.accumulated_results = []
        mock_bh.connect.return_value = False
        MockBH.return_value = mock_bh
        with patch("runoff.cli.context._init_owned_cache"):
            result = runner.invoke(cli, ["-p", "pass", "status"])
    assert "Disconnected" in result.output


def test_domains_lists_results(runner, mock_connect, mock_config):
    mock_connect.get_domains.return_value = [
        {"name": "CORP.LOCAL"},
        {"name": "CHILD.CORP.LOCAL"},
    ]
    result = runner.invoke(cli, ["-p", "pass", "domains"])
    assert result.exit_code == 0
    assert "CORP.LOCAL" in result.output
    assert "CHILD.CORP.LOCAL" in result.output


def test_domains_no_results(runner, mock_connect, mock_config):
    mock_connect.get_domains.return_value = []
    result = runner.invoke(cli, ["-p", "pass", "domains"])
    assert result.exit_code == 0
    assert "No domains found" in result.output


# ---------------------------------------------------------------------------
# 3. Query commands
# ---------------------------------------------------------------------------


def test_run_no_args_shows_categories(runner, mock_config):
    result = runner.invoke(cli, ["-p", "pass", "run"])
    assert result.exit_code == 0
    assert "Categories" in result.output or "all" in result.output


def test_run_invalid_category(runner, mock_connect, mock_config):
    result = runner.invoke(cli, ["-p", "pass", "run", "invalidcat"])
    assert result.exit_code == 0
    assert "Unknown category" in result.output or "invalid" in result.output.lower()


def test_run_all_executes_queries(runner, mock_connect, mock_config):
    """run all should call query functions from the registry."""
    fake_func = MagicMock(return_value=0)
    fake_query = MagicMock()
    fake_query.name = "Test Query"
    fake_query.func = fake_func
    fake_query.severity = MagicMock()
    fake_query.severity.label = "HIGH"
    fake_query.category = "ACL Abuse"
    fake_query.default = True

    with patch("runoff.queries.get_query_registry", return_value=[fake_query]):
        result = runner.invoke(cli, ["-p", "pass", "run", "all"])

    assert result.exit_code == 0
    fake_func.assert_called_once()


def test_run_category_filter(runner, mock_connect, mock_config):
    """run acl should only execute queries in 'ACL Abuse' category."""
    acl_func = MagicMock(return_value=0)
    acl_query = MagicMock()
    acl_query.name = "ACL Query"
    acl_query.func = acl_func
    acl_query.severity = MagicMock()
    acl_query.severity.label = "HIGH"
    acl_query.category = "ACL Abuse"
    acl_query.default = True

    other_func = MagicMock(return_value=0)
    other_query = MagicMock()
    other_query.name = "Other Query"
    other_query.func = other_func
    other_query.severity = MagicMock()
    other_query.severity.label = "LOW"
    other_query.category = "ADCS"
    other_query.default = True

    with patch(
        "runoff.queries.get_query_registry",
        return_value=[acl_query, other_query],
    ):
        result = runner.invoke(cli, ["-p", "pass", "run", "acl"])

    assert result.exit_code == 0
    acl_func.assert_called_once()
    other_func.assert_not_called()


def test_query_list(runner, mock_config):
    """query --list should display registered queries."""
    fake_query = MagicMock()
    fake_query.name = "Kerberoastable Users"
    fake_query.category = "Privilege Escalation"
    fake_query.default = True
    fake_query.severity = MagicMock()
    fake_query.severity.label = "HIGH"
    fake_query.severity.style = "severity.high"

    with patch("runoff.queries.get_query_registry", return_value=[fake_query]):
        result = runner.invoke(cli, ["-p", "pass", "query", "--list"])

    assert result.exit_code == 0
    assert "Kerberoastable Users" in result.output


def test_query_not_found(runner, mock_config):
    with patch("runoff.queries.get_query_registry", return_value=[]):
        result = runner.invoke(cli, ["-p", "pass", "query", "nonexistentquery"])
    assert result.exit_code == 0
    assert "No queries matching" in result.output


def test_queries_alias(runner, mock_config):
    """'runoff queries' is an alias for 'runoff query --list'."""
    fake_query = MagicMock()
    fake_query.name = "Shadow Admins"
    fake_query.category = "ACL Abuse"
    fake_query.default = True
    fake_query.severity = MagicMock()
    fake_query.severity.label = "CRITICAL"
    fake_query.severity.style = "severity.critical"

    with patch("runoff.queries.get_query_registry", return_value=[fake_query]):
        result = runner.invoke(cli, ["-p", "pass", "queries"])

    assert result.exit_code == 0
    assert "Shadow Admins" in result.output


# ---------------------------------------------------------------------------
# 4. Quick filter commands
# ---------------------------------------------------------------------------


def test_kerberoastable_calls_query(runner, mock_connect, mock_config):
    with patch(
        "runoff.queries.credentials.kerberoastable.get_kerberoastable", return_value=0
    ) as mock_kerb:
        result = runner.invoke(cli, ["-p", "pass", "kerberoastable"])
    assert result.exit_code == 0
    mock_kerb.assert_called_once()


def test_stats_calls_query(runner, mock_connect, mock_config):
    with patch("runoff.queries.domain.domain_stats.get_domain_stats", return_value=0) as mock_stats:
        result = runner.invoke(cli, ["-p", "pass", "stats"])
    assert result.exit_code == 0
    mock_stats.assert_called_once()


# ---------------------------------------------------------------------------
# 5. Node commands
# ---------------------------------------------------------------------------


def test_info_shows_properties(runner, mock_connect, mock_config):
    mock_connect.get_node_info.return_value = {
        "name": "ADMIN@CORP.LOCAL",
        "_type": "User",
        "_labels": ["User"],
        "enabled": True,
        "admincount": True,
    }
    result = runner.invoke(cli, ["-p", "pass", "info", "ADMIN@CORP.LOCAL"])
    assert result.exit_code == 0
    mock_connect.get_node_info.assert_called_once_with("ADMIN@CORP.LOCAL")


def test_info_node_not_found(runner, mock_connect, mock_config):
    mock_connect.get_node_info.return_value = None
    result = runner.invoke(cli, ["-p", "pass", "info", "GHOST@CORP.LOCAL"])
    assert result.exit_code == 0
    assert "not found" in result.output.lower()


def test_search_shows_results(runner, mock_connect, mock_config):
    mock_connect.search_nodes.return_value = [
        {"name": "SVCADMIN@CORP.LOCAL", "type": "User", "enabled": True, "domain": "CORP.LOCAL"},
        {"name": "SQLADMIN@CORP.LOCAL", "type": "User", "enabled": True, "domain": "CORP.LOCAL"},
    ]
    result = runner.invoke(cli, ["-p", "pass", "search", "*ADMIN*"])
    assert result.exit_code == 0
    mock_connect.search_nodes.assert_called_once_with("*ADMIN*")
    assert "SVCADMIN@CORP.LOCAL" in result.output


def test_search_no_results(runner, mock_connect, mock_config):
    mock_connect.search_nodes.return_value = []
    result = runner.invoke(cli, ["-p", "pass", "search", "*GHOST*"])
    assert result.exit_code == 0
    assert "No nodes matching" in result.output


# ---------------------------------------------------------------------------
# 6. Marking commands
# ---------------------------------------------------------------------------


def test_mark_owned_success(runner, mock_connect, mock_config):
    mock_connect.mark_owned.return_value = True
    mock_connect.run_query.return_value = [{"is_admin": False}]
    result = runner.invoke(cli, ["-p", "pass", "mark", "owned", "USER@CORP.LOCAL"])
    assert result.exit_code == 0
    mock_connect.mark_owned.assert_called_once_with("USER@CORP.LOCAL")
    assert "Marked owned" in result.output


def test_mark_owned_not_found(runner, mock_connect, mock_config):
    mock_connect.mark_owned.return_value = False
    result = runner.invoke(cli, ["-p", "pass", "mark", "owned", "GHOST@CORP.LOCAL"])
    assert result.exit_code == 0
    assert "not found" in result.output.lower()


def test_mark_tier_zero_success(runner, mock_connect, mock_config):
    mock_connect.mark_tier_zero.return_value = True
    result = runner.invoke(cli, ["-p", "pass", "mark", "tier-zero", "SVCACCT@CORP.LOCAL"])
    assert result.exit_code == 0
    mock_connect.mark_tier_zero.assert_called_once_with("SVCACCT@CORP.LOCAL")
    assert "Marked tier-zero" in result.output


def test_unmark_owned(runner, mock_connect, mock_config):
    mock_connect.unmark_owned.return_value = True
    result = runner.invoke(cli, ["-p", "pass", "unmark", "owned", "USER@CORP.LOCAL"])
    assert result.exit_code == 0
    mock_connect.unmark_owned.assert_called_once_with("USER@CORP.LOCAL")
    assert "Unmarked owned" in result.output


def test_unmark_owned_not_found(runner, mock_connect, mock_config):
    mock_connect.unmark_owned.return_value = False
    result = runner.invoke(cli, ["-p", "pass", "unmark", "owned", "GHOST@CORP.LOCAL"])
    assert result.exit_code == 0
    assert "not found" in result.output.lower()


def test_owned_list(runner, mock_connect, mock_config):
    mock_connect.run_query.return_value = [
        {"name": "USER@CORP.LOCAL", "type": "User", "enabled": True, "admin": False},
        {"name": "ADMIN@CORP.LOCAL", "type": "User", "enabled": True, "admin": True},
    ]
    result = runner.invoke(cli, ["-p", "pass", "owned"])
    assert result.exit_code == 0
    assert "USER@CORP.LOCAL" in result.output
    assert "ADMIN@CORP.LOCAL" in result.output


def test_owned_list_empty(runner, mock_connect, mock_config):
    mock_connect.run_query.return_value = []
    result = runner.invoke(cli, ["-p", "pass", "owned"])
    assert result.exit_code == 0
    assert "No owned principals" in result.output


def test_tierzero_list(runner, mock_connect, mock_config):
    mock_connect.run_query.return_value = [
        {"name": "DC01@CORP.LOCAL", "type": "Computer", "enabled": True},
        {"name": "DOMAIN ADMINS@CORP.LOCAL", "type": "Group", "enabled": True},
    ]
    result = runner.invoke(cli, ["-p", "pass", "tierzero"])
    assert result.exit_code == 0
    assert "DC01@CORP.LOCAL" in result.output


def test_tierzero_list_empty(runner, mock_connect, mock_config):
    mock_connect.run_query.return_value = []
    result = runner.invoke(cli, ["-p", "pass", "tierzero"])
    assert result.exit_code == 0
    assert "No tier-zero principals" in result.output


# ---------------------------------------------------------------------------
# 7. Membership commands
# ---------------------------------------------------------------------------


def test_members_shows_results(runner, mock_connect, mock_config):
    mock_connect.get_group_members.return_value = [
        {"member": "USER@CORP.LOCAL", "type": "User", "enabled": True, "admin": False},
        {"member": "SVC@CORP.LOCAL", "type": "User", "enabled": True, "admin": True},
    ]
    result = runner.invoke(cli, ["-p", "pass", "members", "DOMAIN ADMINS@CORP.LOCAL"])
    assert result.exit_code == 0
    mock_connect.get_group_members.assert_called_once_with("DOMAIN ADMINS@CORP.LOCAL")
    assert "USER@CORP.LOCAL" in result.output


def test_members_no_results(runner, mock_connect, mock_config):
    mock_connect.get_group_members.return_value = []
    result = runner.invoke(cli, ["-p", "pass", "members", "EMPTY GROUP@CORP.LOCAL"])
    assert result.exit_code == 0
    assert "No members found" in result.output


def test_memberof_shows_results(runner, mock_connect, mock_config):
    mock_connect.get_member_of.return_value = [
        {"group_name": "DOMAIN ADMINS@CORP.LOCAL", "tier_zero": True, "description": ""},
    ]
    result = runner.invoke(cli, ["-p", "pass", "memberof", "USER@CORP.LOCAL"])
    assert result.exit_code == 0
    mock_connect.get_member_of.assert_called_once_with("USER@CORP.LOCAL")
    assert "DOMAIN ADMINS@CORP.LOCAL" in result.output


def test_memberof_no_results(runner, mock_connect, mock_config):
    mock_connect.get_member_of.return_value = []
    result = runner.invoke(cli, ["-p", "pass", "memberof", "ORPHAN@CORP.LOCAL"])
    assert result.exit_code == 0
    assert "No group memberships" in result.output


# ---------------------------------------------------------------------------
# 8. Output format tests
# ---------------------------------------------------------------------------


def test_json_output_format(runner, mock_config):
    """With -o json the Rich console is redirected to stderr."""
    with patch("runoff.cli.context.BloodHoundCE") as MockBH:
        mock_bh = MagicMock()
        mock_bh.connect.return_value = True
        mock_bh._structured_emitted = False
        mock_bh.accumulated_results = []
        mock_bh.run_query.return_value = []
        mock_bh.clear_results_cache = MagicMock()
        MockBH.return_value = mock_bh

        with patch("runoff.cli.context._init_owned_cache"):
            result = runner.invoke(cli, ["-p", "pass", "-o", "json", "status"])

    assert result.exit_code == 0


def test_csv_output_format(runner, mock_config):
    with patch("runoff.cli.context.BloodHoundCE") as MockBH:
        mock_bh = MagicMock()
        mock_bh.connect.return_value = True
        mock_bh._structured_emitted = False
        mock_bh.accumulated_results = []
        mock_bh.run_query.return_value = []
        mock_bh.clear_results_cache = MagicMock()
        MockBH.return_value = mock_bh

        with patch("runoff.cli.context._init_owned_cache"):
            result = runner.invoke(cli, ["-p", "pass", "-o", "csv", "status"])

    assert result.exit_code == 0


def test_html_output_format(runner, mock_config):
    with patch("runoff.cli.context.BloodHoundCE") as MockBH:
        mock_bh = MagicMock()
        mock_bh.connect.return_value = True
        mock_bh._structured_emitted = False
        mock_bh.accumulated_results = []
        mock_bh.run_query.return_value = []
        mock_bh.clear_results_cache = MagicMock()
        MockBH.return_value = mock_bh

        with patch("runoff.cli.context._init_owned_cache"):
            result = runner.invoke(cli, ["-p", "pass", "-o", "html", "status"])

    assert result.exit_code == 0


# ---------------------------------------------------------------------------
# 9. Global options
# ---------------------------------------------------------------------------


def test_quiet_suppresses_banner(runner, mock_connect, mock_config):
    """The -q flag sets config.quiet_mode."""
    from runoff.core.config import config as _cfg

    mock_connect.get_domains.return_value = []
    result = runner.invoke(cli, ["-p", "pass", "-q", "domains"])
    assert result.exit_code == 0
    assert _cfg.quiet_mode is True


def test_debug_flag_set(runner, mock_connect, mock_config):
    from runoff.core.config import config as _cfg

    mock_connect.get_domains.return_value = []
    result = runner.invoke(cli, ["-p", "pass", "--debug", "domains"])
    assert result.exit_code == 0
    assert _cfg.debug_mode is True


def test_domain_filter(runner, mock_connect, mock_config):
    """The -d flag passes domain into context and config."""
    mock_connect.get_domains.return_value = [{"name": "CORP.LOCAL"}]
    result = runner.invoke(cli, ["-p", "pass", "-d", "CORP.LOCAL", "domains"])
    assert result.exit_code == 0
    assert "CORP.LOCAL" in result.output


def test_domain_filter_sets_config(runner, mock_config):
    """Verify -d sets config.current_domain."""
    from runoff.core.config import config as _cfg

    with patch("runoff.cli.context.BloodHoundCE") as MockBH:
        mock_bh = MagicMock()
        mock_bh.connect.return_value = True
        mock_bh._structured_emitted = False
        mock_bh.accumulated_results = []
        mock_bh.run_query.return_value = []
        mock_bh.clear_results_cache = MagicMock()
        mock_bh.get_domains.return_value = []
        MockBH.return_value = mock_bh

        with patch("runoff.cli.context._init_owned_cache"):
            runner.invoke(cli, ["-p", "pass", "-d", "TEST.LOCAL", "domains"])

    assert _cfg.current_domain == "TEST.LOCAL"


def test_severity_filter(runner, mock_config):
    """The -s flag sets config.severity_filter."""
    from runoff.core.config import config as _cfg

    with patch("runoff.cli.context.BloodHoundCE") as MockBH:
        mock_bh = MagicMock()
        mock_bh.connect.return_value = True
        mock_bh._structured_emitted = False
        mock_bh.accumulated_results = []
        mock_bh.run_query.return_value = []
        mock_bh.clear_results_cache = MagicMock()
        MockBH.return_value = mock_bh

        with patch("runoff.cli.context._init_owned_cache"):
            with patch("runoff.queries.get_query_registry", return_value=[]):
                runner.invoke(cli, ["-p", "pass", "-s", "HIGH,CRITICAL", "queries"])

    assert "HIGH" in _cfg.severity_filter
    assert "CRITICAL" in _cfg.severity_filter


def test_no_color_flag(runner, mock_connect, mock_config):
    """--no-color flag sets config.no_color."""
    from runoff.core.config import config as _cfg

    mock_connect.get_domains.return_value = []
    result = runner.invoke(cli, ["-p", "pass", "--no-color", "domains"])

    assert result.exit_code == 0
    assert _cfg.no_color is True


# ---------------------------------------------------------------------------
# 10. Edge cases
# ---------------------------------------------------------------------------


def test_password_defaults_when_not_provided(runner, mock_connect, mock_config):
    """Bare invocation without -p uses the default password."""
    mock_connect.get_domains.return_value = []
    result = runner.invoke(cli, ["domains"])
    assert result.exit_code == 0


def test_run_no_matching_queries_for_severity(runner, mock_connect, mock_config):
    """When severity filter removes all queries, show informational message."""
    from runoff.display.colors import Severity

    fake_query = MagicMock()
    fake_query.name = "Low Query"
    fake_query.func = MagicMock(return_value=0)
    fake_query.severity = Severity.LOW
    fake_query.category = "ACL Abuse"
    fake_query.default = True

    with patch("runoff.queries.get_query_registry", return_value=[fake_query]):
        result = runner.invoke(cli, ["-p", "pass", "run", "acl", "-s", "CRITICAL"])

    assert result.exit_code == 0
    assert "No queries match" in result.output


def test_query_multiple_matches(runner, mock_connect, mock_config):
    """When multiple queries match the name, list them instead of running."""
    fake_q1 = MagicMock()
    fake_q1.name = "Kerberoastable Users"
    fake_q1.category = "Privilege Escalation"

    fake_q2 = MagicMock()
    fake_q2.name = "Kerberoastable with Admin"
    fake_q2.category = "Privilege Escalation"

    with patch(
        "runoff.queries.get_query_registry",
        return_value=[fake_q1, fake_q2],
    ):
        result = runner.invoke(cli, ["-p", "pass", "query", "kerberoastable"])

    assert result.exit_code == 0
    assert "Multiple matches" in result.output


# ---------------------------------------------------------------------------
# 11. Completion command
# ---------------------------------------------------------------------------


class TestCompletion:
    """Tests for shell completion command."""

    def test_bash_completion(self, runner):
        result = runner.invoke(cli, ["completion", "bash"])
        assert result.exit_code == 0
        assert "_RUNOFF_COMPLETE=bash_source" in result.output

    def test_zsh_completion(self, runner):
        result = runner.invoke(cli, ["completion", "zsh"])
        assert result.exit_code == 0
        assert "_RUNOFF_COMPLETE=zsh_source" in result.output

    def test_fish_completion(self, runner):
        result = runner.invoke(cli, ["completion", "fish"])
        assert result.exit_code == 0
        assert "_RUNOFF_COMPLETE=fish_source" in result.output

    def test_invalid_shell(self, runner):
        result = runner.invoke(cli, ["completion", "powershell"])
        assert result.exit_code != 0

    def test_no_shell_argument(self, runner):
        result = runner.invoke(cli, ["completion"])
        assert result.exit_code != 0
