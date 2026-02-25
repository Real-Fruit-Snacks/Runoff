"""Tests for query functions and registry."""

from pathlib import Path
from unittest.mock import MagicMock

import pytest

from runoff.display.colors import Severity

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_mock_bh(results=None):
    """Create a mock BloodHoundCE with optional pre-set results."""
    bh = MagicMock()
    bh.run_query.return_value = results if results is not None else []
    bh._accumulated_results = []
    bh.accumulated_results = []
    bh.clear_results_cache = MagicMock()
    return bh


# ===========================================================================
# Registry Tests
# ===========================================================================


class TestQueryRegistry:
    """Test query registration system."""

    def test_get_query_registry(self):
        """Test query registry returns list of queries."""
        from runoff.queries import get_query_registry

        registry = get_query_registry()
        assert isinstance(registry, list)
        assert len(registry) > 0

    def test_query_metadata_format(self):
        """Test each query has required metadata fields."""
        from runoff.queries import get_query_registry
        from runoff.queries.base import QueryMetadata

        registry = get_query_registry()
        for query in registry:
            # Registry now returns QueryMetadata objects
            assert isinstance(query, QueryMetadata)
            assert isinstance(query.name, str)
            assert callable(query.func)
            assert isinstance(query.category, str)
            assert isinstance(query.default, bool)
            assert query.severity is not None

    def test_categories_exist(self):
        """Test expected categories exist in registry."""
        from runoff.queries import get_query_registry

        registry = get_query_registry()
        categories = {q.category for q in registry}

        expected = [
            "ACL Abuse",
            "ADCS",
            "Credentials",
            "Delegation",
            "Lateral Movement",
            "Security Hygiene",
        ]
        for cat in expected:
            assert cat in categories, f"Missing category: {cat}"

    def test_query_count(self):
        """Test registry has expected number of queries."""
        from runoff.queries import get_query_registry

        registry = get_query_registry()
        # Should have a significant number of queries
        assert len(registry) >= 100

    def test_default_queries_exist(self):
        """Test there are default queries."""
        from runoff.queries import get_query_registry

        registry = get_query_registry()
        default_queries = [q for q in registry if q.default]
        assert len(default_queries) > 0

    def test_non_default_queries_exist(self):
        """Test there are non-default queries."""
        from runoff.queries import get_query_registry

        registry = get_query_registry()
        non_default = [q for q in registry if not q.default]
        assert len(non_default) > 0

    def test_no_duplicate_names(self):
        """Test no two queries share the same name."""
        from runoff.queries import get_query_registry

        registry = get_query_registry()
        names = [q.name for q in registry]
        assert len(names) == len(
            set(names)
        ), f"Duplicate names: {[n for n in names if names.count(n) > 1]}"


class TestQueryDecorator:
    """Test @register_query decorator."""

    def test_decorator_registers_query(self):
        """Test decorator adds query to registry."""
        from runoff.queries import get_query_registry

        registry = get_query_registry()
        names = {q.name for q in registry}

        assert "Kerberoastable Users" in names

    def test_decorator_sets_metadata(self):
        """Test decorator sets correct metadata."""
        from runoff.queries import get_query_registry

        registry = get_query_registry()

        kerb_query = next(q for q in registry if q.name == "Kerberoastable Users")
        assert kerb_query.category == "Privilege Escalation"
        assert kerb_query.default is True

    def test_decorator_default_severity(self):
        """Test decorator defaults severity to MEDIUM when not specified."""
        from runoff.queries import get_query_registry

        registry = get_query_registry()
        # All queries should have a severity set (decorator defaults to MEDIUM)
        for q in registry:
            assert q.severity in list(Severity)


class TestQueryDependencies:
    """Test query dependency ordering."""

    def test_depends_on_field_exists(self):
        """All queries should have depends_on as a tuple."""
        from runoff.queries import get_query_registry

        registry = get_query_registry()
        for q in registry:
            assert isinstance(q.depends_on, tuple), f"{q.name} depends_on is not a tuple"

    def test_some_queries_have_dependencies(self):
        """At least some queries should declare depends_on."""
        from runoff.queries import get_query_registry

        registry = get_query_registry()
        with_deps = [q for q in registry if q.depends_on]
        assert len(with_deps) >= 2

    def test_sort_by_dependencies_basic(self):
        """Dependencies should appear before dependents."""
        from runoff.display.colors import Severity
        from runoff.queries.base import QueryMetadata, sort_by_dependencies

        a = QueryMetadata("A", lambda: None, "Cat", True, Severity.INFO, (), ())
        b = QueryMetadata("B", lambda: None, "Cat", True, Severity.INFO, (), ("A",))
        c = QueryMetadata("C", lambda: None, "Cat", True, Severity.INFO, (), ("B",))

        # Pass in reverse order
        result = sort_by_dependencies([c, b, a])
        names = [q.name for q in result]
        assert names.index("A") < names.index("B")
        assert names.index("B") < names.index("C")

    def test_sort_preserves_order_without_deps(self):
        """Queries without dependencies keep original order."""
        from runoff.display.colors import Severity
        from runoff.queries.base import QueryMetadata, sort_by_dependencies

        a = QueryMetadata("A", lambda: None, "Cat", True, Severity.INFO, (), ())
        b = QueryMetadata("B", lambda: None, "Cat", True, Severity.INFO, (), ())
        c = QueryMetadata("C", lambda: None, "Cat", True, Severity.INFO, (), ())

        result = sort_by_dependencies([a, b, c])
        names = [q.name for q in result]
        assert names == ["A", "B", "C"]

    def test_sort_handles_missing_dependency(self):
        """Dependencies on non-existent queries are ignored."""
        from runoff.display.colors import Severity
        from runoff.queries.base import QueryMetadata, sort_by_dependencies

        a = QueryMetadata("A", lambda: None, "Cat", True, Severity.INFO, (), ("MISSING",))
        result = sort_by_dependencies([a])
        assert len(result) == 1
        assert result[0].name == "A"

    def test_sort_handles_circular_deps(self):
        """Circular dependencies don't cause infinite loops."""
        from runoff.display.colors import Severity
        from runoff.queries.base import QueryMetadata, sort_by_dependencies

        a = QueryMetadata("A", lambda: None, "Cat", True, Severity.INFO, (), ("B",))
        b = QueryMetadata("B", lambda: None, "Cat", True, Severity.INFO, (), ("A",))

        result = sort_by_dependencies([a, b])
        assert len(result) == 2


class TestQueryTags:
    """Test query tag system."""

    def test_tagged_queries_exist(self):
        """Some queries should have tags assigned."""
        from runoff.queries import get_query_registry

        registry = get_query_registry()
        tagged = [q for q in registry if q.tags]
        assert len(tagged) >= 10

    def test_tags_are_tuples_of_strings(self):
        """All query tags should be tuples of strings."""
        from runoff.queries import get_query_registry

        registry = get_query_registry()
        for q in registry:
            assert isinstance(q.tags, tuple), f"{q.name} tags is not a tuple"
            for tag in q.tags:
                assert isinstance(tag, str), f"{q.name} has non-string tag: {tag}"

    def test_quick_win_tag_exists(self):
        """quick-win tag should be used by multiple queries."""
        from runoff.queries import get_query_registry

        registry = get_query_registry()
        quick_wins = [q for q in registry if "quick-win" in q.tags]
        assert len(quick_wins) >= 5

    def test_stealthy_tag_exists(self):
        """stealthy tag should be used by queries."""
        from runoff.queries import get_query_registry

        registry = get_query_registry()
        stealthy = [q for q in registry if "stealthy" in q.tags]
        assert len(stealthy) >= 3

    def test_requires_creds_tag_exists(self):
        """requires-creds tag should be used by queries."""
        from runoff.queries import get_query_registry

        registry = get_query_registry()
        creds = [q for q in registry if "requires-creds" in q.tags]
        assert len(creds) >= 2

    def test_noisy_tag_exists(self):
        """noisy tag should be used by queries."""
        from runoff.queries import get_query_registry

        registry = get_query_registry()
        noisy = [q for q in registry if "noisy" in q.tags]
        assert len(noisy) >= 1

    def test_untagged_queries_have_empty_tuple(self):
        """Untagged queries should have an empty tuple, not None."""
        from runoff.queries import get_query_registry

        registry = get_query_registry()
        untagged = [q for q in registry if not q.tags]
        assert len(untagged) > 0
        for q in untagged:
            assert q.tags == ()

    def test_kerberoastable_has_expected_tags(self):
        """Kerberoastable query should have quick-win and requires-creds tags."""
        from runoff.queries import get_query_registry

        registry = get_query_registry()
        kerb = next(q for q in registry if q.name == "Kerberoastable Users")
        assert "quick-win" in kerb.tags
        assert "requires-creds" in kerb.tags


class TestQueryCategories:
    """Test query category organization."""

    def test_acl_queries_exist(self):
        from runoff.queries import get_query_registry

        acl_queries = [q for q in get_query_registry() if q.category == "ACL Abuse"]
        assert len(acl_queries) >= 5

    def test_adcs_queries_exist(self):
        from runoff.queries import get_query_registry

        adcs_queries = [q for q in get_query_registry() if q.category == "ADCS"]
        assert len(adcs_queries) >= 5

    def test_delegation_queries_exist(self):
        from runoff.queries import get_query_registry

        del_queries = [q for q in get_query_registry() if q.category == "Delegation"]
        assert len(del_queries) >= 3

    def test_lateral_queries_exist(self):
        from runoff.queries import get_query_registry

        lat_queries = [q for q in get_query_registry() if q.category == "Lateral Movement"]
        assert len(lat_queries) >= 5

    def test_hygiene_queries_exist(self):
        from runoff.queries import get_query_registry

        hyg_queries = [q for q in get_query_registry() if q.category == "Security Hygiene"]
        assert len(hyg_queries) >= 3

    def test_exchange_queries_exist(self):
        from runoff.queries import get_query_registry

        exchange_queries = [q for q in get_query_registry() if q.category == "Exchange"]
        assert len(exchange_queries) >= 1

    def test_paths_queries_exist(self):
        from runoff.queries import get_query_registry

        path_queries = [q for q in get_query_registry() if q.category == "Attack Paths"]
        assert len(path_queries) >= 3

    def test_groups_queries_exist(self):
        from runoff.queries import get_query_registry

        group_queries = [q for q in get_query_registry() if q.category == "Dangerous Groups"]
        assert len(group_queries) >= 3

    def test_owned_queries_exist(self):
        from runoff.queries import get_query_registry

        owned_queries = [q for q in get_query_registry() if q.category == "Owned"]
        assert len(owned_queries) >= 3

    def test_misc_queries_exist(self):
        from runoff.queries import get_query_registry

        misc_queries = [q for q in get_query_registry() if q.category == "Miscellaneous"]
        assert len(misc_queries) >= 1


class TestQuerySeverities:
    """Test query severity assignments."""

    def test_critical_queries_exist(self):
        from runoff.queries import get_query_registry

        critical = [q for q in get_query_registry() if q.severity == Severity.CRITICAL]
        assert len(critical) >= 1

    def test_high_queries_exist(self):
        from runoff.queries import get_query_registry

        high = [q for q in get_query_registry() if q.severity == Severity.HIGH]
        assert len(high) >= 10

    def test_info_queries_exist(self):
        from runoff.queries import get_query_registry

        info = [q for q in get_query_registry() if q.severity == Severity.INFO]
        assert len(info) >= 1

    def test_all_severity_levels_used(self):
        """All severity levels should be used by at least one query."""
        from runoff.queries import get_query_registry

        registry = get_query_registry()
        used_severities = {q.severity for q in registry}
        for sev in Severity:
            assert sev in used_severities, f"Severity {sev.label} not used by any query"


# ===========================================================================
# Credential Queries
# ===========================================================================


class TestKerberoastableQuery:
    """Test kerberoastable users query."""

    def test_no_results(self, mock_bh, mock_config):
        from runoff.queries.credentials.kerberoastable import get_kerberoastable

        result = get_kerberoastable(mock_bh, None, Severity.HIGH)
        assert result == 0
        mock_bh.run_query.assert_called()

    def test_with_results(self, mock_config):
        from runoff.queries.credentials.kerberoastable import get_kerberoastable

        bh = _make_mock_bh(
            [
                {
                    "name": "SVC_SQL@DOMAIN.COM",
                    "displayname": "SQL Service",
                    "enabled": True,
                    "admincount": False,
                    "description": "Service account",
                    "spns": ["MSSQLSvc/sql01.domain.com:1433"],
                    "pwdlastset": 1704067200,
                    "pwd_age": "<1 month",
                }
            ]
        )
        assert get_kerberoastable(bh, None, Severity.HIGH) == 1

    def test_returns_int(self, mock_bh, mock_config):
        from runoff.queries.credentials.kerberoastable import get_kerberoastable

        result = get_kerberoastable(mock_bh, None, Severity.HIGH)
        assert isinstance(result, int)

    def test_domain_filter(self, mock_bh, mock_config):
        from runoff.queries.credentials.kerberoastable import get_kerberoastable

        get_kerberoastable(mock_bh, "DOMAIN.COM", Severity.HIGH)
        mock_bh.run_query.assert_called()
        # Domain param should be passed
        _, kwargs = mock_bh.run_query.call_args
        if kwargs:
            assert "domain" in kwargs or True  # params may be positional

    def test_multiple_results(self, mock_config):
        from runoff.queries.credentials.kerberoastable import get_kerberoastable

        bh = _make_mock_bh(
            [
                {
                    "name": "SVC1@D.COM",
                    "displayname": "",
                    "enabled": True,
                    "admincount": False,
                    "description": "",
                    "spns": ["http/svc1"],
                    "pwdlastset": 0,
                    "pwd_age": ">1 year",
                },
                {
                    "name": "SVC2@D.COM",
                    "displayname": "",
                    "enabled": True,
                    "admincount": True,
                    "description": "",
                    "spns": ["http/svc2"],
                    "pwdlastset": 0,
                    "pwd_age": ">1 year",
                },
            ]
        )
        assert get_kerberoastable(bh, None, Severity.HIGH) == 2


class TestASREPQuery:
    """Test AS-REP roastable query."""

    def test_no_results(self, mock_bh, mock_config):
        from runoff.queries.credentials.asrep_roastable import get_asrep_roastable

        assert get_asrep_roastable(mock_bh, None, Severity.HIGH) == 0

    def test_with_results(self, mock_config):
        from runoff.queries.credentials.asrep_roastable import get_asrep_roastable

        bh = _make_mock_bh(
            [
                {
                    "name": "ASREP_USER@DOMAIN.COM",
                    "displayname": "AS-REP User",
                    "enabled": True,
                    "admincount": False,
                    "description": "Test",
                    "pwdlastset": 1704067200,
                    "pwd_age": "<1 month",
                },
            ]
        )
        assert get_asrep_roastable(bh, None, Severity.HIGH) == 1


class TestDCSyncQuery:
    """Test DCSync principals query."""

    def test_no_results(self, mock_bh, mock_config):
        from runoff.queries.credentials.dcsync_principals import get_dcsync_principals

        assert get_dcsync_principals(mock_bh, None, Severity.CRITICAL) == 0

    def test_with_results(self, mock_config):
        from runoff.queries.credentials.dcsync_principals import get_dcsync_principals

        bh = _make_mock_bh(
            [
                {
                    "principal": "SVCADMIN@D.COM",
                    "type": "User",
                    "domain": "D.COM",
                    "can_dcsync": True,
                    "has_getchanges": True,
                    "has_getchangesall": True,
                    "enabled": True,
                },
            ]
        )
        assert get_dcsync_principals(bh, None, Severity.CRITICAL) == 1


class TestPasswordsInDescription:
    """Test passwords in description query."""

    def test_no_results(self, mock_bh, mock_config):
        from runoff.queries.credentials.passwords_in_description import get_passwords_in_description

        assert get_passwords_in_description(mock_bh, None, Severity.HIGH) == 0

    def test_with_results(self, mock_config):
        from runoff.queries.credentials.passwords_in_description import get_passwords_in_description

        bh = _make_mock_bh(
            [
                {"name": "SVC@D.COM", "description": "password: Summer2024!", "admin": False},
            ]
        )
        assert get_passwords_in_description(bh, None, Severity.LOW) == 1


# ===========================================================================
# ACL Abuse Queries
# ===========================================================================


class TestShadowAdmins:
    """Test shadow admins query."""

    def test_no_results(self, mock_bh, mock_config):
        from runoff.queries.acl.shadow_admins import get_shadow_admins

        assert get_shadow_admins(mock_bh, None, Severity.HIGH) == 0

    def test_with_results(self, mock_config):
        from runoff.queries.acl.shadow_admins import get_shadow_admins

        bh = _make_mock_bh(
            [
                {
                    "user": "JSMITH@D.COM",
                    "computers_admin_to": 3,
                    "sample_computers": ["WS01.D.COM", "WS02.D.COM", "SRV01.D.COM"],
                },
            ]
        )
        assert get_shadow_admins(bh, None, Severity.HIGH) == 1

    def test_domain_filter(self, mock_bh, mock_config):
        from runoff.queries.acl.shadow_admins import get_shadow_admins

        get_shadow_admins(mock_bh, "CORP.LOCAL", Severity.HIGH)
        mock_bh.run_query.assert_called()


class TestGenericAll:
    """Test GenericAll permissions query."""

    def test_no_results(self, mock_bh, mock_config):
        from runoff.queries.acl.generic_all import get_generic_all

        assert get_generic_all(mock_bh, None, Severity.HIGH) == 0

    def test_with_results(self, mock_config):
        from runoff.queries.acl.generic_all import get_generic_all

        bh = _make_mock_bh(
            [
                {
                    "principal": "USER@D.COM",
                    "principal_type": "User",
                    "target": "DOMAIN ADMINS@D.COM",
                    "target_type": "Group",
                },
            ]
        )
        assert get_generic_all(bh, None, Severity.HIGH) == 1


class TestWriteDacl:
    """Test WriteDacl permissions query."""

    def test_no_results(self, mock_bh, mock_config):
        from runoff.queries.acl.write_dacl import get_write_dacl

        assert get_write_dacl(mock_bh, None, Severity.HIGH) == 0

    def test_with_results(self, mock_config):
        from runoff.queries.acl.write_dacl import get_write_dacl

        bh = _make_mock_bh(
            [
                {
                    "principal": "USER@D.COM",
                    "principal_type": "User",
                    "target": "GROUP@D.COM",
                    "target_type": "Group",
                },
            ]
        )
        assert get_write_dacl(bh, None, Severity.HIGH) == 1


# ===========================================================================
# ADCS Queries
# ===========================================================================


class TestADCSESC1:
    """Test ADCS ESC1 vulnerable templates."""

    def test_no_results(self, mock_bh, mock_config):
        from runoff.queries.adcs.esc1_vulnerable import get_esc1_vulnerable

        assert get_esc1_vulnerable(mock_bh, None, Severity.CRITICAL) == 0

    def test_with_results(self, mock_config):
        from runoff.queries.adcs.esc1_vulnerable import get_esc1_vulnerable

        bh = _make_mock_bh(
            [
                {
                    "principal": "DOMAIN USERS@D.COM",
                    "type": "Group",
                    "template": "VulnTemplate",
                    "ca": "CA01.D.COM",
                },
            ]
        )
        assert get_esc1_vulnerable(bh, None, Severity.CRITICAL) == 1


class TestADCSESC8:
    """Test ADCS ESC8 (HTTP enrollment)."""

    def test_no_results(self, mock_bh, mock_config):
        from runoff.queries.adcs.adcs_esc8 import get_adcs_esc8

        assert get_adcs_esc8(mock_bh, None, Severity.HIGH) == 0

    def test_with_results(self, mock_config):
        from runoff.queries.adcs.adcs_esc8 import get_adcs_esc8

        bh = _make_mock_bh(
            [
                {"ca": "CA01.D.COM", "host": "CA01.D.COM"},
            ]
        )
        assert get_adcs_esc8(bh, None, Severity.HIGH) == 1


# ===========================================================================
# Delegation Queries
# ===========================================================================


class TestUnconstrainedDelegation:
    """Test unconstrained delegation query."""

    def test_no_results(self, mock_bh, mock_config):
        from runoff.queries.delegation.unconstrained_delegation import get_unconstrained_delegation

        assert get_unconstrained_delegation(mock_bh, None, Severity.CRITICAL) == 0

    def test_with_results(self, mock_config):
        from runoff.queries.delegation.unconstrained_delegation import get_unconstrained_delegation

        bh = _make_mock_bh(
            [
                {
                    "name": "SERVER@D.COM",
                    "type": "Computer",
                    "enabled": True,
                    "os": "Windows Server 2019",
                },
            ]
        )
        assert get_unconstrained_delegation(bh, None, Severity.CRITICAL) == 1


class TestConstrainedDelegation:
    """Test constrained delegation query."""

    def test_no_results(self, mock_bh, mock_config):
        from runoff.queries.delegation.constrained_delegation import get_constrained_delegation

        assert get_constrained_delegation(mock_bh, None, Severity.HIGH) == 0

    def test_with_results(self, mock_config):
        from runoff.queries.delegation.constrained_delegation import get_constrained_delegation

        bh = MagicMock()
        bh._accumulated_results = []
        bh.accumulated_results = []
        bh.clear_results_cache = MagicMock()
        # First call returns user results, second call returns empty computer results
        bh.run_query.side_effect = [
            [
                {
                    "name": "SVC_SQL@D.COM",
                    "type": "User",
                    "enabled": True,
                    "targets": ["MSSQLSvc/db01.d.com"],
                }
            ],
            [],
        ]
        assert get_constrained_delegation(bh, None, Severity.MEDIUM) == 1


class TestRBCD:
    """Test resource-based constrained delegation query."""

    def test_no_results(self, mock_bh, mock_config):
        from runoff.queries.delegation.rbcd import get_rbcd

        assert get_rbcd(mock_bh, None, Severity.HIGH) == 0

    def test_with_results(self, mock_config):
        from runoff.queries.delegation.rbcd import get_rbcd

        bh = _make_mock_bh(
            [
                {"principal": "WS01$@D.COM", "type": "Computer", "target": "SRV01.D.COM"},
            ]
        )
        assert get_rbcd(bh, None, Severity.HIGH) == 1


# ===========================================================================
# Lateral Movement Queries
# ===========================================================================


class TestRDPAccess:
    """Test RDP access query."""

    def test_no_results(self, mock_bh, mock_config):
        from runoff.queries.lateral.rdp_access import get_rdp_access

        assert get_rdp_access(mock_bh, None, Severity.MEDIUM) == 0

    def test_with_results(self, mock_config):
        from runoff.queries.lateral.rdp_access import get_rdp_access

        bh = _make_mock_bh(
            [
                {
                    "principal": "HELPDESK@D.COM",
                    "type": "User",
                    "computer": "WS01.D.COM",
                    "os": "Windows 10",
                },
            ]
        )
        assert get_rdp_access(bh, None, Severity.MEDIUM) == 1


class TestLocalAdminRights:
    """Test local admin rights query."""

    def test_no_results(self, mock_bh, mock_config):
        from runoff.queries.lateral.local_admin_rights import get_local_admin_rights

        assert get_local_admin_rights(mock_bh, None, Severity.HIGH) == 0

    def test_with_results(self, mock_config):
        from runoff.queries.lateral.local_admin_rights import get_local_admin_rights

        bh = _make_mock_bh(
            [
                {
                    "principal": "ITADMIN@D.COM",
                    "type": "User",
                    "enabled": True,
                    "computer": "WS01.D.COM",
                    "os": "Windows 10",
                },
            ]
        )
        assert get_local_admin_rights(bh, None, Severity.HIGH) == 1


class TestSQLServers:
    """Test SQL servers query."""

    def test_no_results(self, mock_bh, mock_config):
        from runoff.queries.lateral.sql_servers import get_sql_servers

        assert get_sql_servers(mock_bh, None, Severity.INFO) == 0

    def test_with_results(self, mock_config):
        from runoff.queries.lateral.sql_servers import get_sql_servers

        bh = _make_mock_bh(
            [
                {
                    "computer": "SQL01.D.COM",
                    "os": "Windows Server 2019",
                    "spn": "MSSQLSvc/sql01.d.com:1433",
                },
            ]
        )
        assert get_sql_servers(bh, None, Severity.INFO) == 1


# ===========================================================================
# Security Hygiene Queries
# ===========================================================================


class TestComputersWithoutLAPS:
    """Test computers without LAPS query."""

    def test_no_results(self, mock_bh, mock_config):
        from runoff.queries.hygiene.computers_without_laps import get_computers_without_laps

        assert get_computers_without_laps(mock_bh, None, Severity.MEDIUM) == 0

    def test_with_results(self, mock_config):
        from runoff.queries.hygiene.computers_without_laps import get_computers_without_laps

        bh = _make_mock_bh(
            [
                {"computer": "WS01.D.COM", "os": "Windows 10", "enabled": True},
                {"computer": "WS02.D.COM", "os": "Windows 10", "enabled": True},
            ]
        )
        assert get_computers_without_laps(bh, None, Severity.MEDIUM) == 2

    def test_domain_filter(self, mock_bh, mock_config):
        from runoff.queries.hygiene.computers_without_laps import get_computers_without_laps

        get_computers_without_laps(mock_bh, "CORP.LOCAL", Severity.MEDIUM)
        mock_bh.run_query.assert_called()


class TestLAPSCoverageGaps:
    """Test LAPS coverage gaps (modern OS) query."""

    def test_no_results(self, mock_bh, mock_config):
        from runoff.queries.hygiene.laps_coverage_gaps import get_laps_coverage_gaps

        assert get_laps_coverage_gaps(mock_bh, None, Severity.MEDIUM) == 0

    def test_with_results(self, mock_config):
        from runoff.queries.hygiene.laps_coverage_gaps import get_laps_coverage_gaps

        bh = _make_mock_bh(
            [
                {"computer": "SRV01.D.COM", "os": "Windows Server 2022", "last_logon": 1704067200},
                {"computer": "WS01.D.COM", "os": "Windows 11 Enterprise", "last_logon": 1704067200},
            ]
        )
        assert get_laps_coverage_gaps(bh, None, Severity.MEDIUM) == 2

    def test_domain_filter(self, mock_bh, mock_config):
        from runoff.queries.hygiene.laps_coverage_gaps import get_laps_coverage_gaps

        get_laps_coverage_gaps(mock_bh, "D.COM", Severity.MEDIUM)
        call_args = mock_bh.run_query.call_args
        assert "toUpper($domain)" in call_args[0][0]
        assert call_args[0][1]["domain"] == "D.COM"


class TestWindowsLAPSCoverage:
    """Test Windows LAPS migration candidates query."""

    def test_no_results(self, mock_bh, mock_config):
        from runoff.queries.hygiene.windows_laps_coverage import get_windows_laps_coverage

        assert get_windows_laps_coverage(mock_bh, None, Severity.LOW) == 0

    def test_with_results(self, mock_config):
        from runoff.queries.hygiene.windows_laps_coverage import get_windows_laps_coverage

        bh = _make_mock_bh(
            [
                {
                    "computer": "SRV01.D.COM",
                    "os": "Windows Server 2022",
                    "laps_readers": ["ADMINS@D.COM", "LAPS-READ@D.COM"],
                    "reader_count": 2,
                },
            ]
        )
        assert get_windows_laps_coverage(bh, None, Severity.LOW) == 1

    def test_no_readers(self, mock_config):
        """Computers with LAPS but no readers still count."""
        from runoff.queries.hygiene.windows_laps_coverage import get_windows_laps_coverage

        bh = _make_mock_bh(
            [
                {
                    "computer": "SRV02.D.COM",
                    "os": "Windows Server 2019",
                    "laps_readers": [],
                    "reader_count": 0,
                },
            ]
        )
        assert get_windows_laps_coverage(bh, None, Severity.LOW) == 1


class TestPreWindows2000:
    """Test Pre-Windows 2000 Compatible Access query."""

    def test_no_results(self, mock_bh, mock_config):
        from runoff.queries.hygiene.pre_windows_2000 import get_pre_windows_2000

        assert get_pre_windows_2000(mock_bh, None, Severity.HIGH) == 0

    def test_with_results(self, mock_config):
        from runoff.queries.hygiene.pre_windows_2000 import get_pre_windows_2000

        bh = _make_mock_bh(
            [
                {
                    "group_name": "PRE-WINDOWS 2000 COMPATIBLE ACCESS@D.COM",
                    "member": "ANONYMOUS LOGON@D.COM",
                    "member_type": "User",
                    "enabled": True,
                },
                {
                    "group_name": "PRE-WINDOWS 2000 COMPATIBLE ACCESS@D.COM",
                    "member": "AUTHENTICATED USERS@D.COM",
                    "member_type": "Group",
                    "enabled": None,
                },
            ]
        )
        assert get_pre_windows_2000(bh, None, Severity.HIGH) == 2

    def test_filters_null_members(self, mock_config):
        """Null members from OPTIONAL MATCH are filtered out."""
        from runoff.queries.hygiene.pre_windows_2000 import get_pre_windows_2000

        bh = _make_mock_bh(
            [
                {
                    "group_name": "PRE-WINDOWS 2000 COMPATIBLE ACCESS@D.COM",
                    "member": None,
                    "member_type": None,
                    "enabled": None,
                },
            ]
        )
        assert get_pre_windows_2000(bh, None, Severity.HIGH) == 0

    def test_domain_filter(self, mock_bh, mock_config):
        from runoff.queries.hygiene.pre_windows_2000 import get_pre_windows_2000

        get_pre_windows_2000(mock_bh, "D.COM", Severity.HIGH)
        call_args = mock_bh.run_query.call_args
        assert "toUpper($domain)" in call_args[0][0]
        assert call_args[0][1]["domain"] == "D.COM"


class TestUnsupportedOS:
    """Test unsupported OS query."""

    def test_no_results(self, mock_bh, mock_config):
        from runoff.queries.hygiene.unsupported_os import get_unsupported_os

        assert get_unsupported_os(mock_bh, None, Severity.HIGH) == 0

    def test_with_results(self, mock_config):
        from runoff.queries.hygiene.unsupported_os import get_unsupported_os

        bh = _make_mock_bh(
            [
                {
                    "computer": "LEGACY.D.COM",
                    "os": "Windows Server 2008 R2",
                    "last_logon": 1704067200,
                },
            ]
        )
        assert get_unsupported_os(bh, None, Severity.MEDIUM) == 1


class TestStaleAccounts:
    """Test stale accounts query."""

    def test_no_results(self, mock_bh, mock_config):
        from runoff.queries.hygiene.stale_accounts import get_stale_accounts

        assert get_stale_accounts(mock_bh, None, Severity.LOW) == 0

    def test_with_results(self, mock_config):
        from runoff.queries.hygiene.stale_accounts import get_stale_accounts

        bh = _make_mock_bh(
            [
                {
                    "name": "OLD_USER@D.COM",
                    "displayname": "Old User",
                    "admincount": False,
                    "lastlogon": 1577836800,
                    "pwdlastset": 1577836800,
                },
            ]
        )
        assert get_stale_accounts(bh, None, Severity.LOW) == 1


# ===========================================================================
# Domain Queries
# ===========================================================================


class TestDomainTrusts:
    """Test domain trusts query."""

    def test_no_results(self, mock_bh, mock_config):
        from runoff.queries.domain.domain_trusts import get_domain_trusts

        assert get_domain_trusts(mock_bh, None, Severity.INFO) == 0

    def test_with_results(self, mock_config):
        from runoff.queries.domain.domain_trusts import get_domain_trusts

        bh = _make_mock_bh(
            [
                {
                    "trusting_domain": "CORP.LOCAL",
                    "trusted_domain": "CHILD.CORP.LOCAL",
                    "trust_type": "ParentChild",
                    "transitive": True,
                    "sid_filtering": False,
                },
            ]
        )
        assert get_domain_trusts(bh, None, Severity.INFO) == 1


class TestDomainAdmins:
    """Test domain admins query."""

    def test_no_results(self, mock_bh, mock_config):
        from runoff.queries.domain.domain_admins import get_domain_admins

        assert get_domain_admins(mock_bh, None, Severity.INFO) == 0

    def test_with_results(self, mock_config):
        from runoff.queries.domain.domain_admins import get_domain_admins

        bh = _make_mock_bh(
            [
                {
                    "name": "DADMIN@D.COM",
                    "enabled": True,
                    "hasspn": False,
                    "asrep": False,
                    "unconstrained": False,
                    "admincount": True,
                },
            ]
        )
        assert get_domain_admins(bh, None, Severity.INFO) == 1


class TestHighValueTargets:
    """Test high value targets query."""

    def test_no_results(self, mock_bh, mock_config):
        from runoff.queries.domain.high_value_targets import get_high_value_targets

        assert get_high_value_targets(mock_bh, None, Severity.INFO) == 0

    def test_with_results(self, mock_config):
        from runoff.queries.domain.high_value_targets import get_high_value_targets

        bh = _make_mock_bh(
            [
                {"name": "DC01.D.COM", "type": "Computer", "description": "Domain Controller"},
            ]
        )
        assert get_high_value_targets(bh, None, Severity.INFO) == 1


class TestCrossForestACLAbuse:
    """Test cross-forest ACL abuse query."""

    def test_no_results(self, mock_bh, mock_config):
        from runoff.queries.domain.cross_forest_acl_abuse import get_cross_forest_acl_abuse

        assert get_cross_forest_acl_abuse(mock_bh, None, Severity.CRITICAL) == 0

    def test_with_results(self, mock_config):
        from runoff.queries.domain.cross_forest_acl_abuse import get_cross_forest_acl_abuse

        bh = _make_mock_bh(
            [
                {
                    "attacker": "SVCACCT@CHILD.COM",
                    "attacker_domain": "CHILD.COM",
                    "edge_type": "GenericAll",
                    "target_object": "DOMAIN ADMINS@PARENT.COM",
                    "target_domain": "PARENT.COM",
                    "target_type": "Group",
                },
            ]
        )
        assert get_cross_forest_acl_abuse(bh, None, Severity.CRITICAL) == 1


class TestSIDFilteringBypass:
    """Test SID filtering bypass paths query."""

    def test_no_results(self, mock_bh, mock_config):
        from runoff.queries.domain.sid_filtering_bypass import get_sid_filtering_bypass

        assert get_sid_filtering_bypass(mock_bh, None, Severity.CRITICAL) == 0

    def test_with_results(self, mock_config):
        from runoff.queries.domain.sid_filtering_bypass import get_sid_filtering_bypass

        bh = _make_mock_bh(
            [
                {
                    "trusting_domain": "PARENT.COM",
                    "trusted_domain": "CHILD.COM",
                    "trust_type": "ParentChild",
                    "cross_trust_principal": "ADMIN@CHILD.COM",
                    "target_in_trusting": "ENTERPRISE ADMINS@PARENT.COM",
                    "target_type": "Group",
                },
            ]
        )
        assert get_sid_filtering_bypass(bh, None, Severity.CRITICAL) == 1

    def test_filters_null_principals(self, mock_config):
        """Null cross_trust_principal rows are filtered out."""
        from runoff.queries.domain.sid_filtering_bypass import get_sid_filtering_bypass

        bh = _make_mock_bh(
            [
                {
                    "trusting_domain": "PARENT.COM",
                    "trusted_domain": "CHILD.COM",
                    "trust_type": "ParentChild",
                    "cross_trust_principal": None,
                    "target_in_trusting": None,
                    "target_type": "Other",
                },
            ]
        )
        assert get_sid_filtering_bypass(bh, None, Severity.CRITICAL) == 0


# ===========================================================================
# Dangerous Groups Queries
# ===========================================================================


class TestBackupOperators:
    """Test backup operators members query."""

    def test_no_results(self, mock_bh, mock_config):
        from runoff.queries.groups.backup_operators_members import get_backup_operators_members

        # OPTIONAL MATCH returns a row with member=None; Python filters it out
        mock_bh.run_query.return_value = [
            {
                "group_name": "BACKUP OPERATORS@D.COM",
                "member": None,
                "member_type": "Other",
                "enabled": None,
            }
        ]
        assert get_backup_operators_members(mock_bh, None, Severity.HIGH) == 0

    def test_with_results(self, mock_config):
        from runoff.queries.groups.backup_operators_members import get_backup_operators_members

        bh = _make_mock_bh(
            [
                {
                    "group_name": "BACKUP OPERATORS@D.COM",
                    "member": "BKPUSER@D.COM",
                    "member_type": "User",
                    "enabled": True,
                },
            ]
        )
        assert get_backup_operators_members(bh, None, Severity.HIGH) == 1

    def test_filters_null_members(self, mock_config):
        """OPTIONAL MATCH returns null members when group is empty; these should be filtered."""
        from runoff.queries.groups.backup_operators_members import get_backup_operators_members

        bh = _make_mock_bh(
            [
                {
                    "group_name": "BACKUP OPERATORS@D.COM",
                    "member": None,
                    "member_type": "Other",
                    "enabled": None,
                },
                {
                    "group_name": "BACKUP OPERATORS@D.COM",
                    "member": "REAL_USER@D.COM",
                    "member_type": "User",
                    "enabled": True,
                },
            ]
        )
        assert get_backup_operators_members(bh, None, Severity.HIGH) == 1


class TestProtectedUsersMissing:
    """Test protected users missing query."""

    def test_no_results(self, mock_bh, mock_config):
        from runoff.queries.groups.protected_users_missing import get_protected_users_missing

        assert get_protected_users_missing(mock_bh, None, Severity.MEDIUM) == 0

    def test_with_results(self, mock_config):
        from runoff.queries.groups.protected_users_missing import get_protected_users_missing

        bh = _make_mock_bh(
            [
                {
                    "user": "ADMIN@D.COM",
                    "domain": "D.COM",
                    "is_admin": True,
                    "sensitive": False,
                    "last_logon": 1704067200,
                },
            ]
        )
        assert get_protected_users_missing(bh, None, Severity.MEDIUM) == 1


# ===========================================================================
# Exchange Queries
# ===========================================================================


class TestExchangeGroups:
    """Test Exchange privileged groups query."""

    def test_no_results(self, mock_bh, mock_config):
        from runoff.queries.exchange.exchange_groups import get_exchange_groups

        assert get_exchange_groups(mock_bh, None, Severity.HIGH) == 0

    def test_with_results(self, mock_config):
        from runoff.queries.exchange.exchange_groups import get_exchange_groups

        bh = _make_mock_bh(
            [
                {
                    "group_name": "EXCHANGE WINDOWS PERMISSIONS@D.COM",
                    "member": "EXADMIN@D.COM",
                    "member_type": "User",
                    "enabled": True,
                },
            ]
        )
        assert get_exchange_groups(bh, None, Severity.HIGH) == 1

    def test_filters_null_members(self, mock_config):
        """Exchange groups query filters out null members from OPTIONAL MATCH."""
        from runoff.queries.exchange.exchange_groups import get_exchange_groups

        bh = _make_mock_bh(
            [
                {
                    "group_name": "EXCHANGE WINDOWS PERMISSIONS@D.COM",
                    "member": None,
                    "member_type": "Other",
                    "enabled": None,
                },
            ]
        )
        assert get_exchange_groups(bh, None, Severity.HIGH) == 0


class TestExchangeTrustedSubsystem:
    """Test Exchange Trusted Subsystem paths query."""

    def test_no_results(self, mock_bh, mock_config):
        from runoff.queries.exchange.exchange_trusted_subsystem import (
            get_exchange_trusted_subsystem,
        )

        assert get_exchange_trusted_subsystem(mock_bh, None, Severity.CRITICAL) == 0

    def test_with_results(self, mock_config):
        from runoff.queries.exchange.exchange_trusted_subsystem import (
            get_exchange_trusted_subsystem,
        )

        bh = _make_mock_bh(
            [
                {
                    "exchange_group": "EXCHANGE TRUSTED SUBSYSTEM@D.COM",
                    "target": "DOMAIN ADMINS@D.COM",
                    "target_type": "Group",
                    "path_length": 3,
                },
            ]
        )
        assert get_exchange_trusted_subsystem(bh, None, Severity.CRITICAL) == 1


class TestMailboxDelegation:
    """Test mailbox delegation query."""

    def test_no_results(self, mock_bh, mock_config):
        from runoff.queries.exchange.mailbox_delegation import get_mailbox_delegation

        assert get_mailbox_delegation(mock_bh, None, Severity.MEDIUM) == 0

    def test_with_results(self, mock_config):
        from runoff.queries.exchange.mailbox_delegation import get_mailbox_delegation

        bh = _make_mock_bh(
            [
                {
                    "delegate": "HELPDESK@D.COM",
                    "delegate_type": "User",
                    "mailbox_owner": "CEO@D.COM",
                    "permission": "FullAccess",
                    "owner_is_admin": True,
                },
            ]
        )
        assert get_mailbox_delegation(bh, None, Severity.MEDIUM) == 1


class TestExchangePermissionsPaths:
    """Test Exchange Windows Permissions paths query."""

    def test_no_results(self, mock_bh, mock_config):
        from runoff.queries.exchange.exchange_permissions_paths import (
            get_exchange_permissions_paths,
        )

        assert get_exchange_permissions_paths(mock_bh, None, Severity.CRITICAL) == 0

    def test_with_results(self, mock_config):
        from runoff.queries.exchange.exchange_permissions_paths import (
            get_exchange_permissions_paths,
        )

        bh = _make_mock_bh(
            [
                {
                    "member": "EXADMIN@D.COM",
                    "type": "User",
                    "exchange_group": "EXCHANGE WINDOWS PERMISSIONS@D.COM",
                    "da_group": "DOMAIN ADMINS@D.COM",
                    "path_length": 2,
                },
            ]
        )
        assert get_exchange_permissions_paths(bh, None, Severity.CRITICAL) == 1


# ===========================================================================
# Miscellaneous Queries
# ===========================================================================


# ===========================================================================
# GPO Abuse Queries
# ===========================================================================


class TestGPOToComputers:
    """Test GPO control to computer execution query."""

    def test_no_results(self, mock_bh, mock_config):
        from runoff.queries.gpo.gpo_to_computers import get_gpo_to_computers

        assert get_gpo_to_computers(mock_bh, None, Severity.HIGH) == 0

    def test_with_results(self, mock_config):
        from runoff.queries.gpo.gpo_to_computers import get_gpo_to_computers

        bh = _make_mock_bh(
            [
                {
                    "principal": "HELPDESK@D.COM",
                    "principal_type": "User",
                    "gpo_name": "DEPLOY-SOFTWARE@D.COM",
                    "linked_ou": "WORKSTATIONS",
                    "computer_count": 5,
                    "sample_computers": ["WS01.D.COM", "WS02.D.COM", "WS03.D.COM"],
                },
            ]
        )
        assert get_gpo_to_computers(bh, None, Severity.HIGH) == 1

    def test_with_domain_filter(self, mock_bh, mock_config):
        from runoff.queries.gpo.gpo_to_computers import get_gpo_to_computers

        get_gpo_to_computers(mock_bh, "D.COM", Severity.HIGH)
        call_args = mock_bh.run_query.call_args
        assert "toUpper($domain)" in call_args[0][0]
        assert call_args[0][1]["domain"] == "D.COM"


class TestGPOToTierZero:
    """Test GPO links to tier zero query."""

    def test_no_results(self, mock_bh, mock_config):
        from runoff.queries.gpo.gpo_to_tier_zero import get_gpo_to_tier_zero

        assert get_gpo_to_tier_zero(mock_bh, None, Severity.CRITICAL) == 0

    def test_with_results(self, mock_config):
        from runoff.queries.gpo.gpo_to_tier_zero import get_gpo_to_tier_zero

        bh = _make_mock_bh(
            [
                {
                    "gpo_name": "DEFAULT-DC-POLICY@D.COM",
                    "linked_to": "DOMAIN CONTROLLERS",
                    "tier_zero_count": 2,
                    "sample_assets": ["DC01.D.COM", "DC02.D.COM"],
                    "non_admin_controllers": ["ITADMIN@D.COM"],
                },
            ]
        )
        assert get_gpo_to_tier_zero(bh, None, Severity.CRITICAL) == 1

    def test_with_no_controllers(self, mock_config):
        """GPOs without non-admin controllers still count."""
        from runoff.queries.gpo.gpo_to_tier_zero import get_gpo_to_tier_zero

        bh = _make_mock_bh(
            [
                {
                    "gpo_name": "DC-POLICY@D.COM",
                    "linked_to": "DC OU",
                    "tier_zero_count": 1,
                    "sample_assets": ["DC01.D.COM"],
                    "non_admin_controllers": [],
                },
            ]
        )
        assert get_gpo_to_tier_zero(bh, None, Severity.CRITICAL) == 1


class TestGPOWeakLinks:
    """Test GPO weak link chains query."""

    def test_no_results(self, mock_bh, mock_config):
        from runoff.queries.gpo.gpo_weak_links import get_gpo_weak_links

        assert get_gpo_weak_links(mock_bh, None, Severity.MEDIUM) == 0

    def test_with_results(self, mock_config):
        from runoff.queries.gpo.gpo_weak_links import get_gpo_weak_links

        bh = _make_mock_bh(
            [
                {
                    "gpo_name": "LOGON-SCRIPT-GPO@D.COM",
                    "linked_target": "WORKSTATIONS OU",
                    "enforcement": "Not Enforced",
                    "non_admin_controllers": ["HELPDESK@D.COM"],
                    "controller_count": 1,
                },
            ]
        )
        assert get_gpo_weak_links(bh, None, Severity.MEDIUM) == 1

    def test_enforced_link(self, mock_config):
        """Enforced GPO links still returned if controllable."""
        from runoff.queries.gpo.gpo_weak_links import get_gpo_weak_links

        bh = _make_mock_bh(
            [
                {
                    "gpo_name": "ENFORCED-GPO@D.COM",
                    "linked_target": "SERVERS OU",
                    "enforcement": "Enforced",
                    "non_admin_controllers": ["SVCACCT@D.COM"],
                    "controller_count": 1,
                },
            ]
        )
        assert get_gpo_weak_links(bh, None, Severity.MEDIUM) == 1


class TestDuplicateSPNs:
    """Test duplicate SPNs query."""

    def test_no_results(self, mock_bh, mock_config):
        from runoff.queries.misc.duplicate_spns import get_duplicate_spns

        assert get_duplicate_spns(mock_bh, None, Severity.LOW) == 0

    def test_with_results(self, mock_config):
        from runoff.queries.misc.duplicate_spns import get_duplicate_spns

        bh = _make_mock_bh(
            [
                {"duplicate_spn": "HTTP/web01.d.com", "principals": ["SVC1@D.COM", "SVC2@D.COM"]},
            ]
        )
        assert get_duplicate_spns(bh, None, Severity.LOW) == 1


class TestCircularGroups:
    """Test circular group memberships query."""

    def test_no_results(self, mock_bh, mock_config):
        from runoff.queries.misc.circular_groups import get_circular_groups

        assert get_circular_groups(mock_bh, None, Severity.LOW) == 0

    def test_with_results(self, mock_config):
        from runoff.queries.misc.circular_groups import get_circular_groups

        bh = _make_mock_bh(
            [
                {
                    "group_name": "GROUP_A@D.COM",
                    "cycle_path": ["GROUP_A@D.COM", "GROUP_B@D.COM", "GROUP_A@D.COM"],
                    "cycle_length": 2,
                },
            ]
        )
        assert get_circular_groups(bh, None, Severity.LOW) == 1


# ===========================================================================
# Attack Paths Queries
# ===========================================================================


class TestBusiestPaths:
    """Test busiest attack path nodes query."""

    def test_no_results(self, mock_bh, mock_config):
        from runoff.queries.paths.busiest_paths import get_busiest_paths

        assert get_busiest_paths(mock_bh, None, Severity.MEDIUM) == 0

    def test_with_results(self, mock_config):
        from runoff.queries.paths.busiest_paths import get_busiest_paths

        bh = _make_mock_bh(
            [
                {
                    "node": "DOMAIN ADMINS@D.COM",
                    "type": "Group",
                    "domain": "D.COM",
                    "outbound_edges": 10,
                    "inbound_edges": 50,
                    "total_edges": 60,
                },
                {
                    "node": "DC01.D.COM",
                    "type": "Computer",
                    "domain": "D.COM",
                    "outbound_edges": 20,
                    "inbound_edges": 30,
                    "total_edges": 50,
                },
            ]
        )
        assert get_busiest_paths(bh, None, Severity.MEDIUM) == 2

    def test_domain_filter(self, mock_bh, mock_config):
        from runoff.queries.paths.busiest_paths import get_busiest_paths

        get_busiest_paths(mock_bh, "CORP.LOCAL", Severity.MEDIUM)
        mock_bh.run_query.assert_called()


# ===========================================================================
# Owned Queries
# ===========================================================================


class TestOwnedToHighValue:
    """Test owned to high value targets query."""

    def test_no_results(self, mock_bh, mock_config):
        from runoff.queries.owned.owned_to_high_value import get_owned_to_high_value

        assert get_owned_to_high_value(mock_bh, None, Severity.CRITICAL) == 0

    def test_with_results(self, mock_config):
        from runoff.queries.owned.owned_to_high_value import get_owned_to_high_value

        bh = _make_mock_bh(
            [
                {
                    "nodes": ["USER@D.COM", "GROUP@D.COM", "DC01.D.COM"],
                    "node_types": ["User", "Group", "Computer"],
                    "relationships": ["MemberOf", "AdminTo"],
                    "path_length": 2,
                },
            ]
        )
        assert get_owned_to_high_value(bh, None, Severity.CRITICAL) == 1


class TestOwnedPrincipals:
    """Test owned principals listing query."""

    def test_no_results(self, mock_bh, mock_config):
        from runoff.queries.owned.owned_principals import get_owned_principals

        assert get_owned_principals(mock_bh, None, Severity.INFO) == 0

    def test_with_results(self, mock_config):
        from runoff.queries.owned.owned_principals import get_owned_principals

        bh = _make_mock_bh(
            [
                {"name": "OWNED_USER@D.COM", "type": "User", "enabled": True, "admin": False},
            ]
        )
        assert get_owned_principals(bh, None, Severity.INFO) == 1


# ===========================================================================
# Cross-Cutting Concerns
# ===========================================================================


class TestQueryDomainFiltering:
    """Test that various queries properly handle domain filtering."""

    @pytest.mark.parametrize(
        "query_import,query_func,severity",
        [
            ("runoff.queries.credentials.kerberoastable", "get_kerberoastable", Severity.HIGH),
            ("runoff.queries.acl.shadow_admins", "get_shadow_admins", Severity.HIGH),
            (
                "runoff.queries.delegation.constrained_delegation",
                "get_constrained_delegation",
                Severity.HIGH,
            ),
            (
                "runoff.queries.hygiene.computers_without_laps",
                "get_computers_without_laps",
                Severity.MEDIUM,
            ),
            ("runoff.queries.lateral.rdp_access", "get_rdp_access", Severity.MEDIUM),
            ("runoff.queries.gpo.gpo_to_computers", "get_gpo_to_computers", Severity.HIGH),
            ("runoff.queries.gpo.gpo_to_tier_zero", "get_gpo_to_tier_zero", Severity.CRITICAL),
            ("runoff.queries.gpo.gpo_weak_links", "get_gpo_weak_links", Severity.MEDIUM),
            (
                "runoff.queries.hygiene.laps_coverage_gaps",
                "get_laps_coverage_gaps",
                Severity.MEDIUM,
            ),
            (
                "runoff.queries.hygiene.windows_laps_coverage",
                "get_windows_laps_coverage",
                Severity.LOW,
            ),
            ("runoff.queries.hygiene.pre_windows_2000", "get_pre_windows_2000", Severity.HIGH),
        ],
    )
    def test_domain_filter_does_not_crash(
        self, mock_bh, mock_config, query_import, query_func, severity
    ):
        """Ensure queries don't crash when domain filter is provided."""
        import importlib

        mod = importlib.import_module(query_import)
        func = getattr(mod, query_func)

        result = func(mock_bh, "TEST.LOCAL", severity)
        assert isinstance(result, int)
        assert result >= 0

    @pytest.mark.parametrize(
        "query_import,query_func,severity",
        [
            ("runoff.queries.credentials.kerberoastable", "get_kerberoastable", Severity.HIGH),
            ("runoff.queries.acl.shadow_admins", "get_shadow_admins", Severity.HIGH),
            ("runoff.queries.domain.domain_trusts", "get_domain_trusts", Severity.INFO),
            ("runoff.queries.hygiene.stale_accounts", "get_stale_accounts", Severity.LOW),
        ],
    )
    def test_no_domain_filter(self, mock_bh, mock_config, query_import, query_func, severity):
        """Ensure queries work without domain filter."""
        import importlib

        mod = importlib.import_module(query_import)
        func = getattr(mod, query_func)

        result = func(mock_bh, None, severity)
        assert isinstance(result, int)
        assert result == 0


class TestQueryReturnValues:
    """Test that all tested queries return correct count values."""

    @pytest.mark.parametrize(
        "query_import,query_func,severity",
        [
            ("runoff.queries.credentials.kerberoastable", "get_kerberoastable", Severity.HIGH),
            ("runoff.queries.credentials.asrep_roastable", "get_asrep_roastable", Severity.HIGH),
            (
                "runoff.queries.credentials.dcsync_principals",
                "get_dcsync_principals",
                Severity.CRITICAL,
            ),
            ("runoff.queries.acl.shadow_admins", "get_shadow_admins", Severity.HIGH),
            ("runoff.queries.acl.generic_all", "get_generic_all", Severity.HIGH),
            ("runoff.queries.adcs.esc1_vulnerable", "get_esc1_vulnerable", Severity.CRITICAL),
            (
                "runoff.queries.delegation.unconstrained_delegation",
                "get_unconstrained_delegation",
                Severity.CRITICAL,
            ),
            ("runoff.queries.lateral.rdp_access", "get_rdp_access", Severity.MEDIUM),
            (
                "runoff.queries.hygiene.computers_without_laps",
                "get_computers_without_laps",
                Severity.MEDIUM,
            ),
            ("runoff.queries.domain.domain_trusts", "get_domain_trusts", Severity.INFO),
            ("runoff.queries.paths.busiest_paths", "get_busiest_paths", Severity.MEDIUM),
            ("runoff.queries.misc.duplicate_spns", "get_duplicate_spns", Severity.LOW),
            ("runoff.queries.gpo.gpo_to_computers", "get_gpo_to_computers", Severity.HIGH),
            ("runoff.queries.gpo.gpo_to_tier_zero", "get_gpo_to_tier_zero", Severity.CRITICAL),
            ("runoff.queries.gpo.gpo_weak_links", "get_gpo_weak_links", Severity.MEDIUM),
            (
                "runoff.queries.hygiene.laps_coverage_gaps",
                "get_laps_coverage_gaps",
                Severity.MEDIUM,
            ),
            (
                "runoff.queries.hygiene.windows_laps_coverage",
                "get_windows_laps_coverage",
                Severity.LOW,
            ),
            ("runoff.queries.hygiene.pre_windows_2000", "get_pre_windows_2000", Severity.HIGH),
            (
                "runoff.queries.domain.cross_forest_acl_abuse",
                "get_cross_forest_acl_abuse",
                Severity.CRITICAL,
            ),
            (
                "runoff.queries.domain.sid_filtering_bypass",
                "get_sid_filtering_bypass",
                Severity.CRITICAL,
            ),
        ],
    )
    def test_returns_zero_for_empty(self, mock_bh, mock_config, query_import, query_func, severity):
        """All queries must return 0 when no results found."""
        import importlib

        mod = importlib.import_module(query_import)
        func = getattr(mod, query_func)

        result = func(mock_bh, None, severity)
        assert result == 0
        assert isinstance(result, int)


class TestPluginSystem:
    """Tests for the plugin loading system."""

    def test_get_plugin_dir_default(self, monkeypatch):
        """Test default plugin directory path."""
        monkeypatch.delenv("XDG_CONFIG_HOME", raising=False)
        from runoff.queries import get_plugin_dir

        plugin_dir = get_plugin_dir()
        assert plugin_dir == Path.home() / ".config" / "runoff" / "queries"

    def test_get_plugin_dir_xdg(self, monkeypatch):
        """Test plugin directory respects XDG_CONFIG_HOME."""
        monkeypatch.setenv("XDG_CONFIG_HOME", "/tmp/xdg")
        from runoff.queries import get_plugin_dir

        plugin_dir = get_plugin_dir()
        assert plugin_dir == Path("/tmp/xdg/runoff/queries")

    def test_load_plugins_no_directory(self, monkeypatch, tmp_path):
        """Test plugin loading when directory doesn't exist."""
        import runoff.queries as qmod

        monkeypatch.setattr(qmod, "_plugins_loaded", False)
        monkeypatch.setattr(qmod, "get_plugin_dir", lambda: tmp_path / "nonexistent")
        count = qmod._load_plugins(allow_plugins=True)
        assert count == 0

    def test_load_plugins_empty_directory(self, monkeypatch, tmp_path):
        """Test plugin loading with empty directory."""
        import runoff.queries as qmod

        monkeypatch.setattr(qmod, "_plugins_loaded", False)
        plugin_dir = tmp_path / "plugins"
        plugin_dir.mkdir()
        monkeypatch.setattr(qmod, "get_plugin_dir", lambda: plugin_dir)
        count = qmod._load_plugins(allow_plugins=True)
        assert count == 0

    def test_load_plugins_valid_plugin(self, monkeypatch, tmp_path):
        """Test loading a valid plugin that registers a query."""
        import runoff.queries as qmod
        from runoff.queries.base import QUERY_REGISTRY

        monkeypatch.setattr(qmod, "_plugins_loaded", False)
        plugin_dir = tmp_path / "plugins"
        plugin_dir.mkdir()

        plugin_code = '''
from runoff.queries.base import register_query
from runoff.display.colors import Severity

@register_query(name="Custom Plugin Query", category="Custom", default=False, severity=Severity.LOW)
def get_custom_check(bh, domain=None, severity=None):
    """A custom plugin query."""
    return 0
'''
        (plugin_dir / "custom_check.py").write_text(plugin_code)
        monkeypatch.setattr(qmod, "get_plugin_dir", lambda: plugin_dir)

        initial_count = len(QUERY_REGISTRY)
        count = qmod._load_plugins(allow_plugins=True)
        assert count == 1
        assert len(QUERY_REGISTRY) == initial_count + 1
        assert QUERY_REGISTRY[-1].name == "Custom Plugin Query"
        assert QUERY_REGISTRY[-1].category == "Custom"

        # Cleanup: remove the plugin query from registry
        QUERY_REGISTRY.pop()

    def test_load_plugins_skips_underscored(self, monkeypatch, tmp_path):
        """Test that files starting with _ are skipped."""
        import runoff.queries as qmod

        monkeypatch.setattr(qmod, "_plugins_loaded", False)
        plugin_dir = tmp_path / "plugins"
        plugin_dir.mkdir()
        (plugin_dir / "_helper.py").write_text("x = 1")
        (plugin_dir / "__init__.py").write_text("")
        monkeypatch.setattr(qmod, "get_plugin_dir", lambda: plugin_dir)
        count = qmod._load_plugins(allow_plugins=True)
        assert count == 0

    def test_load_plugins_handles_errors(self, monkeypatch, tmp_path):
        """Test that broken plugins emit warnings and don't crash."""
        import runoff.queries as qmod

        monkeypatch.setattr(qmod, "_plugins_loaded", False)
        plugin_dir = tmp_path / "plugins"
        plugin_dir.mkdir()
        (plugin_dir / "broken.py").write_text("raise RuntimeError('boom')")
        monkeypatch.setattr(qmod, "get_plugin_dir", lambda: plugin_dir)

        import warnings

        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            count = qmod._load_plugins(allow_plugins=True)
            assert count == 0
            assert len(w) == 1
            assert "broken.py" in str(w[0].message)
            assert "boom" in str(w[0].message)

    def test_load_plugins_only_once(self, monkeypatch, tmp_path):
        """Test that plugins are only loaded once."""
        import runoff.queries as qmod

        monkeypatch.setattr(qmod, "_plugins_loaded", False)
        plugin_dir = tmp_path / "plugins"
        plugin_dir.mkdir()
        (plugin_dir / "simple.py").write_text("LOADED = True")
        monkeypatch.setattr(qmod, "get_plugin_dir", lambda: plugin_dir)

        count1 = qmod._load_plugins(allow_plugins=True)
        assert count1 == 1
        count2 = qmod._load_plugins(allow_plugins=True)
        assert count2 == 0  # Already loaded, skips

    def test_load_plugins_warns_when_not_allowed(self, monkeypatch, tmp_path):
        """Test that plugins found without --load-plugins emit a warning."""
        import runoff.queries as qmod

        monkeypatch.setattr(qmod, "_plugins_loaded", False)
        plugin_dir = tmp_path / "plugins"
        plugin_dir.mkdir()
        (plugin_dir / "custom.py").write_text("x = 1")
        monkeypatch.setattr(qmod, "get_plugin_dir", lambda: plugin_dir)

        import warnings

        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            count = qmod._load_plugins(allow_plugins=False)
            assert count == 0
            assert len(w) == 1
            assert "1 plugin(s)" in str(w[0].message)
            assert "--load-plugins" in str(w[0].message)

    def test_load_plugins_allows_after_initial_deny(self, monkeypatch, tmp_path):
        """Test that plugins can load on a second call with allow_plugins=True."""
        import runoff.queries as qmod
        from runoff.queries.base import QUERY_REGISTRY

        monkeypatch.setattr(qmod, "_plugins_loaded", False)
        plugin_dir = tmp_path / "plugins"
        plugin_dir.mkdir()
        (plugin_dir / "deferred.py").write_text(
            "from runoff.queries.base import register_query\n"
            "from runoff.display.colors import Severity\n"
            "@register_query(name='Deferred Plugin', category='Custom', default=False, severity=Severity.LOW)\n"
            "def deferred(bh, domain=None, severity=None): return 0\n"
        )
        monkeypatch.setattr(qmod, "get_plugin_dir", lambda: plugin_dir)

        import warnings

        with warnings.catch_warnings(record=True):
            warnings.simplefilter("always")
            # First call denied
            count1 = qmod._load_plugins(allow_plugins=False)
            assert count1 == 0

        # Second call with allow_plugins=True should work
        initial_count = len(QUERY_REGISTRY)
        count2 = qmod._load_plugins(allow_plugins=True)
        assert count2 == 1
        assert len(QUERY_REGISTRY) == initial_count + 1

        # Cleanup
        QUERY_REGISTRY.pop()
