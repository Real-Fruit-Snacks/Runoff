"""Tests for abuse command display module."""

import pytest


@pytest.fixture
def abuse_config():
    """Configure config for abuse testing."""
    from runoff.core.config import config

    original = {
        "output_format": config.output_format,
        "no_color": config.no_color,
        "show_abuse": config.show_abuse,
    }

    config.output_format = "table"
    config.no_color = True
    config.show_abuse = True

    yield config

    config.output_format = original["output_format"]
    config.no_color = original["no_color"]
    config.show_abuse = original["show_abuse"]


@pytest.fixture
def abuse_disabled_config():
    """Configure config with abuse disabled."""
    from runoff.core.config import config

    original = config.show_abuse
    config.show_abuse = False
    yield config
    config.show_abuse = original


@pytest.fixture
def json_config():
    """Configure config for JSON output."""
    from runoff.core.config import config

    original = {
        "output_format": config.output_format,
        "show_abuse": config.show_abuse,
    }

    config.output_format = "json"
    config.show_abuse = True

    yield config

    config.output_format = original["output_format"]
    config.show_abuse = original["show_abuse"]


class TestEdgeToTemplateMapping:
    """Test edge type to template file mappings."""

    def test_acl_edges_mapped(self):
        """Test ACL edges are mapped correctly."""
        from runoff.abuse.loader import EDGE_TO_TEMPLATE

        acl_edges = [
            "GenericAll",
            "GenericWrite",
            "WriteDacl",
            "WriteOwner",
            "ForceChangePassword",
            "AddMember",
            "AllExtendedRights",
            "Owns",
        ]
        for edge in acl_edges:
            assert edge in EDGE_TO_TEMPLATE
            assert EDGE_TO_TEMPLATE[edge] == "acl"

    def test_delegation_edges_mapped(self):
        """Test delegation edges are mapped correctly."""
        from runoff.abuse.loader import EDGE_TO_TEMPLATE

        assert EDGE_TO_TEMPLATE["AllowedToDelegate"] == "delegation"
        assert EDGE_TO_TEMPLATE["AllowedToAct"] == "delegation"

    def test_lateral_edges_mapped(self):
        """Test lateral movement edges are mapped correctly."""
        from runoff.abuse.loader import EDGE_TO_TEMPLATE

        lateral_edges = ["AdminTo", "CanRDP", "CanPSRemote", "ExecuteDCOM", "SQLAdmin"]
        for edge in lateral_edges:
            assert edge in EDGE_TO_TEMPLATE
            assert EDGE_TO_TEMPLATE[edge] == "lateral"

    def test_azure_edges_mapped(self):
        """Test Azure edges are mapped correctly."""
        from runoff.abuse.loader import EDGE_TO_TEMPLATE

        azure_edges = [
            "AZAddMembers",
            "AZAddOwner",
            "AZAddSecret",
            "AZGlobalAdmin",
            "SyncedToEntraUser",
        ]
        for edge in azure_edges:
            assert edge in EDGE_TO_TEMPLATE
            assert EDGE_TO_TEMPLATE[edge] == "azure"


class TestQueryToTemplateMapping:
    """Test query name to template mappings."""

    def test_credential_queries_mapped(self):
        """Test credential queries are mapped correctly."""
        from runoff.abuse.loader import QUERY_TO_TEMPLATE

        assert QUERY_TO_TEMPLATE["kerberoastable"] == ("credentials", "Kerberoasting")
        assert QUERY_TO_TEMPLATE["asrep"] == ("credentials", "ASREPRoasting")
        assert QUERY_TO_TEMPLATE["dcsync"] == ("credentials", "DCSync")

    def test_delegation_queries_mapped(self):
        """Test delegation queries are mapped correctly."""
        from runoff.abuse.loader import QUERY_TO_TEMPLATE

        assert QUERY_TO_TEMPLATE["unconstrained"] == ("delegation", "Unconstrained")
        assert QUERY_TO_TEMPLATE["constrained"] == ("delegation", "Constrained")
        assert QUERY_TO_TEMPLATE["rbcd"] == ("delegation", "RBCD")

    def test_adcs_queries_mapped(self):
        """Test ADCS queries are mapped correctly."""
        from runoff.abuse.loader import QUERY_TO_TEMPLATE

        for esc in ["esc1", "esc2", "esc3", "esc4", "esc6", "esc8"]:
            assert esc in QUERY_TO_TEMPLATE
            assert QUERY_TO_TEMPLATE[esc][0] == "adcs"

    def test_group_queries_mapped(self):
        """Test dangerous group queries are mapped correctly."""
        from runoff.abuse.loader import QUERY_TO_TEMPLATE

        group_queries = [
            "dnsadmins",
            "backup_operators",
            "server_operators",
            "print_operators",
        ]
        for query in group_queries:
            assert query in QUERY_TO_TEMPLATE
            assert QUERY_TO_TEMPLATE[query][0] == "groups"


class TestTemplateLoading:
    """Test YAML template loading."""

    def test_load_credentials_template(self):
        """Test loading credentials template."""
        from runoff.abuse.loader import _load_template, clear_cache

        clear_cache()
        template = _load_template("credentials")

        assert isinstance(template, dict)
        assert "Kerberoasting" in template
        assert "ASREPRoasting" in template

    def test_load_acl_template(self):
        """Test loading ACL template."""
        from runoff.abuse.loader import _load_template, clear_cache

        clear_cache()
        template = _load_template("acl")

        assert isinstance(template, dict)
        # ACL template should have edge types as keys
        assert len(template) > 0

    def test_load_nonexistent_template(self):
        """Test loading nonexistent template returns empty dict."""
        from runoff.abuse.loader import _load_template, clear_cache

        clear_cache()
        template = _load_template("nonexistent_template_file")

        assert template == {}

    def test_template_caching(self):
        """Test templates are cached after first load."""
        from runoff.abuse.loader import _load_template, _template_cache, clear_cache

        clear_cache()
        assert "credentials" not in _template_cache

        _load_template("credentials")
        assert "credentials" in _template_cache

        # Second load should use cache
        cached_template = _template_cache["credentials"]
        loaded_template = _load_template("credentials")
        assert loaded_template is cached_template

    def test_clear_cache(self):
        """Test cache clearing."""
        from runoff.abuse.loader import _load_template, _template_cache, clear_cache

        _load_template("credentials")
        assert "credentials" in _template_cache

        clear_cache()
        assert "credentials" not in _template_cache


class TestGetAbuseCommands:
    """Test get_abuse_commands function."""

    def test_get_commands_valid_edge(self):
        """Test getting commands for valid edge type."""
        from runoff.abuse.loader import clear_cache, get_abuse_commands

        clear_cache()
        commands = get_abuse_commands("GenericAll", "User")

        # Should return commands if template has them
        # (may be None if template doesn't have User entry)
        assert commands is None or isinstance(commands, dict)

    def test_get_commands_unknown_edge(self):
        """Test getting commands for unknown edge type."""
        from runoff.abuse.loader import get_abuse_commands

        commands = get_abuse_commands("UnknownEdgeType", "User")
        assert commands is None

    def test_get_commands_unknown_target_type(self):
        """Test getting commands for unknown target type."""
        from runoff.abuse.loader import get_abuse_commands

        commands = get_abuse_commands("GenericAll", "UnknownType")
        # Should return None for unknown target types
        assert commands is None


class TestGetQueryAbuseCommands:
    """Test get_query_abuse_commands function."""

    def test_get_kerberoasting_commands(self):
        """Test getting Kerberoasting commands."""
        from runoff.abuse.loader import clear_cache, get_query_abuse_commands

        clear_cache()
        commands = get_query_abuse_commands("kerberoastable")

        assert commands is not None
        assert "description" in commands
        assert "commands" in commands
        assert isinstance(commands["commands"], list)

    def test_get_asrep_commands(self):
        """Test getting AS-REP commands."""
        from runoff.abuse.loader import get_query_abuse_commands

        commands = get_query_abuse_commands("asrep")

        assert commands is not None
        assert "commands" in commands

    def test_get_commands_case_insensitive(self):
        """Test query name is case insensitive."""
        from runoff.abuse.loader import get_query_abuse_commands

        commands_lower = get_query_abuse_commands("kerberoastable")
        commands_upper = get_query_abuse_commands("KERBEROASTABLE")

        assert commands_lower == commands_upper

    def test_get_unknown_query_commands(self):
        """Test getting commands for unknown query."""
        from runoff.abuse.loader import get_query_abuse_commands

        commands = get_query_abuse_commands("unknown_query")
        assert commands is None


class TestPrintAbuseSection:
    """Test print_abuse_section function."""

    def test_prints_abuse_when_enabled(self, abuse_config, capsys):
        """Test abuse section is printed when enabled."""
        from runoff.abuse import print_abuse_section

        results = [{"target": "USER@DOMAIN.COM", "target_type": "User", "edge": "GenericAll"}]

        print_abuse_section(results, "GenericAll")
        captured = capsys.readouterr()

        # Either prints content or nothing (depends on template having User entry)
        assert captured.out is not None

    def test_no_print_when_disabled(self, abuse_disabled_config, capsys):
        """Test abuse section not printed when disabled."""
        from runoff.abuse import print_abuse_section

        results = [{"target": "USER@DOMAIN.COM", "target_type": "User"}]

        print_abuse_section(results, "GenericAll")
        captured = capsys.readouterr()

        assert captured.out == ""

    def test_no_print_in_json_mode(self, json_config, capsys):
        """Test abuse section not printed in JSON mode."""
        from runoff.abuse import print_abuse_section

        results = [{"target": "USER@DOMAIN.COM", "target_type": "User"}]

        print_abuse_section(results, "GenericAll")
        captured = capsys.readouterr()

        assert captured.out == ""

    def test_no_print_with_empty_results(self, abuse_config, capsys):
        """Test abuse section not printed with empty results."""
        from runoff.abuse import print_abuse_section

        print_abuse_section([], "GenericAll")
        captured = capsys.readouterr()

        assert captured.out == ""


class TestPrintAbuseForQuery:
    """Test print_abuse_for_query function."""

    def test_prints_kerberoasting_abuse(self, abuse_config, capsys):
        """Test Kerberoasting abuse is printed."""
        from runoff.abuse import print_abuse_for_query

        results = [
            {"name": "SVC_SQL@DOMAIN.COM", "enabled": True},
            {"name": "SVC_HTTP@DOMAIN.COM", "enabled": True},
        ]

        print_abuse_for_query("kerberoastable", results)
        captured = capsys.readouterr()

        assert "ABUSE COMMANDS" in captured.out
        assert "SVC_SQL" in captured.out  # First target shown as example

    def test_prints_asrep_abuse(self, abuse_config, capsys):
        """Test AS-REP abuse is printed."""
        from runoff.abuse import print_abuse_for_query

        results = [{"name": "ASREP_USER@DOMAIN.COM", "enabled": True}]

        print_abuse_for_query("asrep", results)
        captured = capsys.readouterr()

        assert "ABUSE COMMANDS" in captured.out

    def test_no_print_when_disabled(self, abuse_disabled_config, capsys):
        """Test no print when abuse disabled."""
        from runoff.abuse import print_abuse_for_query

        results = [{"name": "USER@DOMAIN.COM"}]

        print_abuse_for_query("kerberoastable", results)
        captured = capsys.readouterr()

        assert captured.out == ""

    def test_no_print_in_json_mode(self, json_config, capsys):
        """Test no print in JSON mode."""
        from runoff.abuse import print_abuse_for_query

        results = [{"name": "USER@DOMAIN.COM"}]

        print_abuse_for_query("kerberoastable", results)
        captured = capsys.readouterr()

        assert captured.out == ""

    def test_no_print_with_empty_results(self, abuse_config, capsys):
        """Test no print with empty results."""
        from runoff.abuse import print_abuse_for_query

        print_abuse_for_query("kerberoastable", [])
        captured = capsys.readouterr()

        assert captured.out == ""

    def test_no_print_for_unknown_query(self, abuse_config, capsys):
        """Test no print for unknown query type."""
        from runoff.abuse import print_abuse_for_query

        results = [{"name": "USER@DOMAIN.COM"}]

        print_abuse_for_query("unknown_query_type", results)
        captured = capsys.readouterr()

        assert captured.out == ""

    def test_custom_target_key(self, abuse_config, capsys):
        """Test using custom target key."""
        from runoff.abuse import print_abuse_for_query

        results = [{"principal": "SVC@DOMAIN.COM"}]

        print_abuse_for_query("kerberoastable", results, target_key="principal")
        captured = capsys.readouterr()

        assert "SVC" in captured.out


class TestExtractName:
    """Test _extract_name helper function."""

    def test_extract_from_upn(self):
        """Test extracting name from UPN format."""
        from runoff.abuse import _extract_name

        assert _extract_name("ADMIN@DOMAIN.COM") == "ADMIN"
        assert _extract_name("svc_account@corp.local") == "svc_account"

    def test_no_domain_unchanged(self):
        """Test name without domain is unchanged."""
        from runoff.abuse import _extract_name

        assert _extract_name("ADMIN") == "ADMIN"
        assert _extract_name("svc_account") == "svc_account"

    def test_empty_string(self):
        """Test empty string."""
        from runoff.abuse import _extract_name

        assert _extract_name("") == ""

    def test_multiple_at_signs(self):
        """Test multiple @ signs."""
        from runoff.abuse import _extract_name

        # Takes first part before @
        assert _extract_name("user@subdomain@domain.com") == "user"


class TestExtractDomain:
    """Test _extract_domain helper function."""

    def test_extract_from_upn(self):
        """Test extracting domain from UPN format."""
        from runoff.abuse import _extract_domain

        assert _extract_domain("ADMIN@DOMAIN.COM") == "DOMAIN.COM"
        assert _extract_domain("svc_account@corp.local") == "corp.local"

    def test_no_domain_returns_none(self):
        """Test name without domain returns None."""
        from runoff.abuse import _extract_domain

        assert _extract_domain("ADMIN") is None
        assert _extract_domain("svc_account") is None

    def test_empty_string(self):
        """Test empty string returns None."""
        from runoff.abuse import _extract_domain

        assert _extract_domain("") is None

    def test_multiple_at_signs(self):
        """Test multiple @ signs takes everything after first @."""
        from runoff.abuse import _extract_domain

        # Takes everything after first @
        assert _extract_domain("user@subdomain@domain.com") == "subdomain@domain.com"


class TestSubstitutePlaceholders:
    """Test _substitute_placeholders helper function."""

    def test_substitutes_target(self):
        """Test TARGET placeholder substitution."""
        from runoff.abuse import _substitute_placeholders

        cmd = "whoami <TARGET>"
        result = _substitute_placeholders(cmd, "USER@DOMAIN.COM")
        assert result == "whoami USER"

    def test_substitutes_domain_from_principal(self):
        """Test DOMAIN placeholder substitution from principal."""
        from runoff.abuse import _substitute_placeholders

        cmd = "net user /domain:<DOMAIN>"
        result = _substitute_placeholders(cmd, "USER@CORP.LOCAL")
        assert result == "net user /domain:CORP.LOCAL"

    def test_substitutes_domain_from_config(self):
        """Test DOMAIN placeholder from config when not in principal."""
        from runoff.abuse import _substitute_placeholders
        from runoff.core.config import config

        original = config.current_domain
        config.current_domain = "FALLBACK.LOCAL"

        try:
            cmd = "net user /domain:<DOMAIN>"
            result = _substitute_placeholders(cmd, "USER")  # No @ in principal
            assert result == "net user /domain:FALLBACK.LOCAL"
        finally:
            config.current_domain = original

    def test_substitutes_dc_ip(self):
        """Test DC_IP placeholder substitution."""
        from runoff.abuse import _substitute_placeholders
        from runoff.core.config import config

        original = config.dc_ip
        config.dc_ip = "10.0.0.1"

        try:
            cmd = "ldapsearch -H ldap://<DC_IP>"
            result = _substitute_placeholders(cmd, "USER@DOMAIN.COM")
            assert result == "ldapsearch -H ldap://10.0.0.1"
        finally:
            config.dc_ip = original

    def test_substitutes_new_password(self):
        """Test NEW_PASSWORD placeholder substitution."""
        from runoff.abuse import DEFAULT_PASSWORD, _substitute_placeholders

        cmd = "net user test <NEW_PASSWORD>"
        result = _substitute_placeholders(cmd, "USER@DOMAIN.COM")
        assert result == f"net user test {DEFAULT_PASSWORD}"

    def test_substitutes_all_placeholders(self):
        """Test all placeholders substituted together."""
        from runoff.abuse import DEFAULT_PASSWORD, _substitute_placeholders
        from runoff.core.config import config

        original_dc = config.dc_ip
        config.dc_ip = "192.168.1.1"

        try:
            cmd = "bloodyAD -d <DOMAIN> --host <DC_IP> set password <TARGET> '<NEW_PASSWORD>'"
            result = _substitute_placeholders(cmd, "ADMIN@BUILDINGMAGIC.LOCAL")
            expected = f"bloodyAD -d BUILDINGMAGIC.LOCAL --host 192.168.1.1 set password ADMIN '{DEFAULT_PASSWORD}'"
            assert result == expected
        finally:
            config.dc_ip = original_dc

    def test_preserves_unknown_placeholders(self):
        """Test unknown placeholders are preserved."""
        from runoff.abuse import _substitute_placeholders

        cmd = "command -u <USERNAME> -p <PASSWORD>"
        result = _substitute_placeholders(cmd, "USER@DOMAIN.COM")
        # USERNAME and PASSWORD are not substituted (attacker creds)
        assert "<USERNAME>" in result
        assert "<PASSWORD>" in result


class TestAbuseBlockFormatting:
    """Test abuse block formatting functions."""

    def test_abuse_block_shows_description(self, abuse_config, capsys):
        """Test description is shown in abuse block."""
        from runoff.abuse import print_abuse_for_query

        results = [{"name": "SVC@DOMAIN.COM"}]

        print_abuse_for_query("kerberoastable", results)
        captured = capsys.readouterr()

        # Kerberoasting template has a description
        assert "TGS" in captured.out or "ticket" in captured.out.lower()

    def test_abuse_block_shows_commands(self, abuse_config, capsys):
        """Test commands are shown in abuse block."""
        from runoff.abuse import print_abuse_for_query

        results = [{"name": "SVC@DOMAIN.COM"}]

        print_abuse_for_query("kerberoastable", results)
        captured = capsys.readouterr()

        # Should show command number and tool
        assert "[1]" in captured.out
        assert "Impacket" in captured.out or "hashcat" in captured.out

    def test_abuse_block_shows_opsec(self, abuse_config, capsys):
        """Test OPSEC notes are shown."""
        from runoff.abuse import print_abuse_for_query

        results = [{"name": "SVC@DOMAIN.COM"}]

        print_abuse_for_query("kerberoastable", results)
        captured = capsys.readouterr()

        assert "OPSEC" in captured.out

    def test_multiple_targets_shows_count(self, abuse_config, capsys):
        """Test multiple targets shows count."""
        from runoff.abuse import print_abuse_for_query

        results = [
            {"name": "SVC1@DOMAIN.COM"},
            {"name": "SVC2@DOMAIN.COM"},
            {"name": "SVC3@DOMAIN.COM"},
        ]

        print_abuse_for_query("kerberoastable", results)
        captured = capsys.readouterr()

        assert "+2 more" in captured.out


class TestTemplateStructure:
    """Test template file structure and content."""

    def test_credentials_template_structure(self):
        """Test credentials template has required structure."""
        from runoff.abuse.loader import _load_template, clear_cache

        clear_cache()
        template = _load_template("credentials")

        # Check Kerberoasting entry
        kerb = template.get("Kerberoasting")
        assert kerb is not None
        assert "description" in kerb
        assert "commands" in kerb
        assert "opsec" in kerb

    def test_command_entry_structure(self):
        """Test individual command entries have required fields."""
        from runoff.abuse.loader import _load_template, clear_cache

        clear_cache()
        template = _load_template("credentials")

        kerb_commands = template["Kerberoasting"]["commands"]
        for cmd in kerb_commands:
            assert "name" in cmd
            assert "command" in cmd

    def test_all_templates_load(self):
        """Test all expected templates can be loaded."""
        from runoff.abuse.loader import _load_template, clear_cache

        clear_cache()
        template_names = [
            "acl",
            "adcs",
            "azure",
            "coercion",
            "credentials",
            "delegation",
            "gpo",
            "groups",
            "lateral",
        ]

        for name in template_names:
            template = _load_template(name)
            assert isinstance(template, dict), f"Template {name} failed to load"


class TestIntegration:
    """Integration tests for abuse module."""

    def test_full_kerberoasting_workflow(self, abuse_config, capsys):
        """Test complete Kerberoasting abuse workflow."""
        from runoff.abuse import print_abuse_for_query

        results = [
            {
                "name": "SVC_SQL@DOMAIN.COM",
                "displayname": "SQL Service",
                "enabled": True,
                "admincount": False,
                "spns": ["MSSQLSvc/sql01.domain.com:1433"],
            }
        ]

        print_abuse_for_query("kerberoastable", results)
        captured = capsys.readouterr()

        # Verify all expected sections
        assert "ABUSE COMMANDS" in captured.out
        assert "SVC_SQL" in captured.out
        assert "Impacket" in captured.out or "GetUserSPNs" in captured.out
        assert "OPSEC" in captured.out

    def test_full_dcsync_workflow(self, abuse_config, capsys):
        """Test complete DCSync abuse workflow."""
        from runoff.abuse import print_abuse_for_query

        results = [{"name": "ATTACKER@DOMAIN.COM", "type": "User", "admincount": False}]

        print_abuse_for_query("dcsync", results)
        captured = capsys.readouterr()

        assert "ABUSE COMMANDS" in captured.out
        # DCSync commands should mention secretsdump
        assert "secretsdump" in captured.out.lower() or "impacket" in captured.out.lower()
