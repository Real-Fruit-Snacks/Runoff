"""Tests for BloodHoundCE class"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest


class TestBloodHoundCE:
    """Test BloodHoundCE class methods."""

    def test_attack_edges_constant(self):
        """Test ATTACK_EDGES constant contains expected edges."""
        from runoff.core.bloodhound import ATTACK_EDGES

        # Core edges
        assert "AdminTo" in ATTACK_EDGES
        assert "MemberOf" in ATTACK_EDGES
        assert "HasSession" in ATTACK_EDGES

        # ACL edges
        assert "GenericAll" in ATTACK_EDGES
        assert "GenericWrite" in ATTACK_EDGES
        assert "WriteDacl" in ATTACK_EDGES
        assert "WriteOwner" in ATTACK_EDGES

        # ADCS edges
        assert "Enroll" in ATTACK_EDGES
        assert "ManageCA" in ATTACK_EDGES

        # Delegation edges
        assert "AllowedToDelegate" in ATTACK_EDGES
        assert "AllowedToAct" in ATTACK_EDGES

    def test_connection_uri_parsing(self):
        """Test connection URI is stored correctly."""
        from runoff.core.bloodhound import BloodHoundCE

        bh = BloodHoundCE("bolt://localhost:7687", "neo4j", "password")
        assert bh.uri == "bolt://localhost:7687"
        assert bh.username == "neo4j"
        assert bh.password == "password"

    def test_debug_mode_setting(self):
        """Test debug mode is set correctly."""
        from runoff.core.bloodhound import BloodHoundCE

        bh = BloodHoundCE("bolt://localhost:7687", "neo4j", "password", debug=True)
        assert bh.debug is True

        bh2 = BloodHoundCE("bolt://localhost:7687", "neo4j", "password")
        assert bh2.debug is False

    def test_accumulated_results_property(self):
        """Test accumulated results tracking."""
        from runoff.core.bloodhound import BloodHoundCE

        bh = BloodHoundCE("bolt://localhost:7687", "neo4j", "password")
        assert bh.accumulated_results == []

        bh._accumulated_results = [{"test": "data"}]
        assert bh.accumulated_results == [{"test": "data"}]

    def test_clear_results_cache(self):
        """Test clearing results cache."""
        from runoff.core.bloodhound import BloodHoundCE

        bh = BloodHoundCE("bolt://localhost:7687", "neo4j", "password")
        bh._accumulated_results = [{"test": "data"}]
        bh.clear_results_cache()
        assert bh._accumulated_results == []


class TestCypherHelpers:
    """Test Cypher helper functions."""

    def test_node_type_function(self):
        """Test node_type() generates correct CASE expression."""
        from runoff.core.cypher import node_type

        result = node_type("n")
        assert "CASE" in result
        assert ":User" in result
        assert ":Computer" in result
        assert ":Group" in result


class TestDriverPool:
    """Tests for Neo4j driver connection pooling."""

    def test_pool_reuses_driver(self):
        """Test that the pool returns the same driver for same connection params."""
        from runoff.core.bloodhound import _DriverPool

        pool = _DriverPool()

        mock_driver = MagicMock()
        mock_driver.verify_connectivity = MagicMock()

        with patch(
            "runoff.core.bloodhound.GraphDatabase.driver", return_value=mock_driver
        ) as mock_gd:
            driver1 = pool.get_or_create("bolt://localhost:7687", "neo4j", "pass")
            driver2 = pool.get_or_create("bolt://localhost:7687", "neo4j", "pass")

            assert driver1 is driver2
            # GraphDatabase.driver should only be called once
            assert mock_gd.call_count == 1

        pool.close_all()

    def test_pool_different_params_different_drivers(self):
        """Test that different connection params get different drivers."""
        from runoff.core.bloodhound import _DriverPool

        pool = _DriverPool()

        mock_driver1 = MagicMock()
        mock_driver1.verify_connectivity = MagicMock()
        mock_driver2 = MagicMock()
        mock_driver2.verify_connectivity = MagicMock()

        with patch(
            "runoff.core.bloodhound.GraphDatabase.driver", side_effect=[mock_driver1, mock_driver2]
        ):
            driver1 = pool.get_or_create("bolt://host1:7687", "neo4j", "pass")
            driver2 = pool.get_or_create("bolt://host2:7687", "neo4j", "pass")

            assert driver1 is not driver2

        pool.close_all()

    def test_pool_recreates_stale_driver(self):
        """Test that pool recreates driver when connectivity check fails after staleness."""
        from runoff.core.bloodhound import _DriverPool

        pool = _DriverPool()

        stale_driver = MagicMock()
        stale_driver.verify_connectivity = MagicMock()
        fresh_driver = MagicMock()
        fresh_driver.verify_connectivity = MagicMock()

        # Create initial driver at time 0
        with patch("runoff.core.bloodhound.time.monotonic", return_value=0.0):
            with patch("runoff.core.bloodhound.GraphDatabase.driver", return_value=stale_driver):
                driver1 = pool.get_or_create("bolt://localhost:7687", "neo4j", "pass")
                assert driver1 is stale_driver

        # Simulate time passing beyond _STALE_SECONDS, connectivity check fails
        stale_driver.verify_connectivity.side_effect = Exception("stale")
        with patch("runoff.core.bloodhound.time.monotonic", return_value=400.0):
            with patch("runoff.core.bloodhound.GraphDatabase.driver", return_value=fresh_driver):
                driver2 = pool.get_or_create("bolt://localhost:7687", "neo4j", "pass")
                assert driver2 is fresh_driver

        pool.close_all()

    def test_pool_close_all(self):
        """Test that close_all closes all cached drivers."""
        from runoff.core.bloodhound import _DriverPool

        pool = _DriverPool()

        mock_driver = MagicMock()
        mock_driver.verify_connectivity = MagicMock()

        with patch("runoff.core.bloodhound.GraphDatabase.driver", return_value=mock_driver):
            pool.get_or_create("bolt://localhost:7687", "neo4j", "pass")

        pool.close_all()
        mock_driver.close.assert_called_once()
        assert len(pool._drivers) == 0

    def test_bloodhound_uses_pool(self):
        """Test that BloodHoundCE.connect() uses the driver pool."""
        from runoff.core.bloodhound import BloodHoundCE, _driver_pool

        mock_driver = MagicMock()
        mock_driver.verify_connectivity = MagicMock()

        with patch.object(_driver_pool, "get_or_create", return_value=mock_driver) as mock_pool:
            bh = BloodHoundCE("bolt://localhost:7687", "neo4j", "test")
            result = bh.connect()

            assert result is True
            assert bh.driver is mock_driver
            assert bh._owns_driver is False
            mock_pool.assert_called_once_with("bolt://localhost:7687", "neo4j", "test")

    def test_bloodhound_close_does_not_close_pooled_driver(self):
        """Test that close() doesn't close a pooled driver."""
        from runoff.core.bloodhound import BloodHoundCE

        bh = BloodHoundCE("bolt://localhost:7687", "neo4j", "test")
        mock_driver = MagicMock()
        bh.driver = mock_driver
        bh._owns_driver = False

        bh.close()

        mock_driver.close.assert_not_called()
        assert bh.driver is None

    def test_close_pool_delegates(self):
        """Test that close_pool() calls _driver_pool.close_all()."""
        from runoff.core.bloodhound import _driver_pool, close_pool

        with patch.object(_driver_pool, "close_all") as mock_close:
            close_pool()
            mock_close.assert_called_once()

    def test_run_query_raises_when_not_connected(self):
        """Test that run_query raises RuntimeError when not connected."""
        from runoff.core.bloodhound import BloodHoundCE

        bh = BloodHoundCE("bolt://localhost:7687", "neo4j", "pass")
        with pytest.raises(RuntimeError, match="Not connected"):
            bh.run_query("MATCH (n) RETURN n")

    def test_pool_returns_fresh_within_stale_window(self):
        """Test that pool returns cached driver without verify within stale window."""
        from runoff.core.bloodhound import _DriverPool

        pool = _DriverPool()
        mock_driver = MagicMock()
        mock_driver.verify_connectivity = MagicMock()

        # Create at time 0, reuse at time 10 (well within 300s window)
        with patch("runoff.core.bloodhound.time.monotonic", side_effect=[0.0, 10.0, 10.0]):
            with patch(
                "runoff.core.bloodhound.GraphDatabase.driver", return_value=mock_driver
            ) as mock_gd:
                pool.get_or_create("bolt://localhost:7687", "neo4j", "pass")
                driver2 = pool.get_or_create("bolt://localhost:7687", "neo4j", "pass")

                assert driver2 is mock_driver
                assert mock_gd.call_count == 1
                # verify_connectivity only called once (on creation)
                assert mock_driver.verify_connectivity.call_count == 1

        pool.close_all()

    def test_pool_different_password_different_driver(self):
        """Test that changing password gets a new driver."""
        from runoff.core.bloodhound import _DriverPool

        pool = _DriverPool()
        mock_driver1 = MagicMock()
        mock_driver1.verify_connectivity = MagicMock()
        mock_driver2 = MagicMock()
        mock_driver2.verify_connectivity = MagicMock()

        with patch(
            "runoff.core.bloodhound.GraphDatabase.driver", side_effect=[mock_driver1, mock_driver2]
        ):
            d1 = pool.get_or_create("bolt://localhost:7687", "neo4j", "pass1")
            d2 = pool.get_or_create("bolt://localhost:7687", "neo4j", "pass2")
            assert d1 is not d2

        pool.close_all()
