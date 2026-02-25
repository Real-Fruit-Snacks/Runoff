"""Tests for runoff/core/scoring.py"""

from unittest.mock import MagicMock

import pytest

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def make_bh(*return_values):
    """Return a mock BloodHoundCE that yields successive values from run_query."""
    bh = MagicMock()
    bh.run_query.side_effect = list(return_values)
    return bh


# ---------------------------------------------------------------------------
# calculate_risk_score
# ---------------------------------------------------------------------------


class TestCalculateRiskScore:
    """Tests for calculate_risk_score()."""

    def test_risk_score_zero_metrics(self):
        """Empty dict returns 0."""
        from runoff.core.scoring import calculate_risk_score

        assert calculate_risk_score({}) == 0

    def test_risk_score_critical(self):
        """All metrics at maximum values gives score == 100."""
        from runoff.core.scoring import calculate_risk_score

        metrics = {
            "pct_users_with_path_to_da": 51,  # > 50 → 25 pts
            "pct_computers_without_laps": 81,  # > 80 → 15 pts
            "kerberoastable_admins": 11,  # > 10 → 20 pts
            "asrep_roastable": 21,  # > 20 → 10 pts
            "unconstrained_delegation_non_dc": 6,  # > 5  → 15 pts
            "domain_admin_count": 51,  # > 50 → 15 pts
        }
        # 25 + 15 + 20 + 10 + 15 + 15 = 100
        assert calculate_risk_score(metrics) == 100

    def test_risk_score_high(self):
        """Moderate values produce a score in the 50-74 range."""
        from runoff.core.scoring import calculate_risk_score

        metrics = {
            "pct_users_with_path_to_da": 21,  # > 20 → 20 pts
            "pct_computers_without_laps": 51,  # > 50 → 10 pts
            "kerberoastable_admins": 1,  # > 0  → 10 pts
            "asrep_roastable": 6,  # > 5  → 7  pts
            "unconstrained_delegation_non_dc": 0,  # 0    → 0  pts
            "domain_admin_count": 0,  # 0    → 0  pts
        }
        # 20 + 10 + 10 + 7 = 47 — nudge one metric to push into HIGH range
        metrics["domain_admin_count"] = 21  # > 20 → 10 pts  → total = 57
        score = calculate_risk_score(metrics)
        assert 50 <= score <= 74

    def test_risk_score_medium(self):
        """Low values produce a score in the 25-49 range."""
        from runoff.core.scoring import calculate_risk_score

        metrics = {
            "pct_users_with_path_to_da": 6,  # > 5  → 10 pts
            "pct_computers_without_laps": 21,  # > 20 → 5  pts
            "kerberoastable_admins": 1,  # > 0  → 10 pts
            "asrep_roastable": 0,
            "unconstrained_delegation_non_dc": 0,
            "domain_admin_count": 0,
        }
        # 10 + 5 + 10 = 25
        score = calculate_risk_score(metrics)
        assert 25 <= score <= 49

    def test_risk_score_path_to_da_thresholds(self):
        """Each pct_users_with_path_to_da threshold awards the correct points."""
        from runoff.core.scoring import calculate_risk_score

        cases = [
            (0, 0),
            (1, 5),  # > 0
            (6, 10),  # > 5
            (11, 15),  # > 10
            (21, 20),  # > 20
            (51, 25),  # > 50
        ]
        for pct, expected_pts in cases:
            score = calculate_risk_score({"pct_users_with_path_to_da": pct})
            assert score == expected_pts, f"pct={pct}: expected {expected_pts} pts, got {score}"

    def test_risk_score_kerberoastable_thresholds(self):
        """Each kerberoastable_admins threshold awards the correct points."""
        from runoff.core.scoring import calculate_risk_score

        cases = [
            (0, 0),
            (1, 10),  # > 0
            (6, 15),  # > 5
            (11, 20),  # > 10
        ]
        for count, expected_pts in cases:
            score = calculate_risk_score({"kerberoastable_admins": count})
            assert score == expected_pts, f"count={count}: expected {expected_pts} pts, got {score}"

    def test_risk_score_unconstrained_thresholds(self):
        """Each unconstrained_delegation_non_dc threshold awards the correct points."""
        from runoff.core.scoring import calculate_risk_score

        cases = [
            (0, 0),
            (1, 5),  # > 0
            (3, 10),  # > 2
            (6, 15),  # > 5
        ]
        for count, expected_pts in cases:
            score = calculate_risk_score({"unconstrained_delegation_non_dc": count})
            assert score == expected_pts, f"count={count}: expected {expected_pts} pts, got {score}"

    def test_risk_score_capped_at_100(self):
        """Extreme values in all categories still return at most 100."""
        from runoff.core.scoring import calculate_risk_score

        metrics = {
            "pct_users_with_path_to_da": 100,
            "pct_computers_without_laps": 100,
            "kerberoastable_admins": 9999,
            "asrep_roastable": 9999,
            "unconstrained_delegation_non_dc": 9999,
            "domain_admin_count": 9999,
        }
        assert calculate_risk_score(metrics) == 100


# ---------------------------------------------------------------------------
# get_risk_rating
# ---------------------------------------------------------------------------


class TestGetRiskRating:
    """Tests for get_risk_rating()."""

    def test_rating_critical(self):
        """Score >= 75 returns CRITICAL."""
        from runoff.core.scoring import get_risk_rating

        assert get_risk_rating(75) == "CRITICAL"
        assert get_risk_rating(100) == "CRITICAL"
        assert get_risk_rating(99) == "CRITICAL"

    def test_rating_high(self):
        """Score 50-74 returns HIGH."""
        from runoff.core.scoring import get_risk_rating

        assert get_risk_rating(50) == "HIGH"
        assert get_risk_rating(74) == "HIGH"
        assert get_risk_rating(60) == "HIGH"

    def test_rating_medium(self):
        """Score 25-49 returns MEDIUM."""
        from runoff.core.scoring import get_risk_rating

        assert get_risk_rating(25) == "MEDIUM"
        assert get_risk_rating(49) == "MEDIUM"
        assert get_risk_rating(35) == "MEDIUM"

    def test_rating_low(self):
        """Score 1-24 returns LOW."""
        from runoff.core.scoring import get_risk_rating

        assert get_risk_rating(1) == "LOW"
        assert get_risk_rating(24) == "LOW"
        assert get_risk_rating(10) == "LOW"

    def test_rating_minimal(self):
        """Score 0 returns MINIMAL."""
        from runoff.core.scoring import get_risk_rating

        assert get_risk_rating(0) == "MINIMAL"


# ---------------------------------------------------------------------------
# calculate_exposure_metrics
# ---------------------------------------------------------------------------


class TestCalculateExposureMetrics:
    """Tests for calculate_exposure_metrics()."""

    def _make_empty_bh(self):
        """Return a mock bh where every run_query call returns []."""
        bh = MagicMock()
        bh.run_query.return_value = []
        return bh

    def test_metrics_empty_results(self):
        """When bh.run_query returns [] for all queries, result has expected keys."""
        from runoff.core.scoring import calculate_exposure_metrics

        bh = self._make_empty_bh()
        metrics = calculate_exposure_metrics(bh)

        # With all empty returns the keys populated from non-empty results are absent;
        # the function only sets keys when results exist.  The important thing is that
        # it doesn't raise and the returned value is a dict.
        assert isinstance(metrics, dict)
        # No percentages should be computed since there are no base counts.
        assert "pct_users_with_path_to_da" not in metrics
        assert "pct_computers_without_laps" not in metrics

    def test_metrics_with_domain_filter(self):
        """Passing a domain param causes run_query to be called with domain params."""
        from runoff.core.scoring import calculate_exposure_metrics

        bh = self._make_empty_bh()
        calculate_exposure_metrics(bh, domain="CORP.LOCAL")

        # Every call should include domain/domain_suffix params
        for c in bh.run_query.call_args_list:
            args, kwargs = c
            params = args[1] if len(args) > 1 else {}
            assert "domain" in params
            assert params["domain"] == "CORP.LOCAL"
            assert params["domain_suffix"] == ".CORP.LOCAL"

    def test_metrics_percentage_calculation(self):
        """pct_users_with_path_to_da and pct_computers_without_laps are computed correctly."""
        from runoff.core.scoring import calculate_exposure_metrics

        # run_query is called 8 times total (see scoring.py):
        #   1. enabled_users / total_users
        #   2. users_with_path_to_da
        #   3. total_computers / computers_without_laps
        #   4. tier_zero_count
        #   5. kerberoastable_admins
        #   6. asrep_roastable
        #   7. unconstrained_delegation_non_dc
        #   8. domain_admin_count
        bh = MagicMock()
        bh.run_query.side_effect = [
            [{"enabled_users": 100, "total_users": 120}],  # 1
            [{"users_with_path": 10}],  # 2
            [{"total_computers": 50, "no_laps": 40}],  # 3
            [{"tier_zero_count": 5}],  # 4
            [{"kerberoastable_admins": 3}],  # 5
            [{"asrep_users": 2}],  # 6
            [{"unconstrained_non_dc": 1}],  # 7
            [{"domain_admin_count": 7}],  # 8
        ]

        metrics = calculate_exposure_metrics(bh)

        assert metrics["enabled_users"] == 100
        assert metrics["total_users"] == 120
        assert metrics["users_with_path_to_da"] == 10
        assert metrics["total_computers"] == 50
        assert metrics["computers_without_laps"] == 40

        # 10 / 100 * 100 = 10.0
        assert metrics["pct_users_with_path_to_da"] == pytest.approx(10.0)
        # 40 / 50 * 100 = 80.0
        assert metrics["pct_computers_without_laps"] == pytest.approx(80.0)

    def test_metrics_zero_division(self):
        """Zero enabled_users and zero total_computers don't cause ZeroDivisionError."""
        from runoff.core.scoring import calculate_exposure_metrics

        bh = MagicMock()
        bh.run_query.side_effect = [
            [{"enabled_users": 0, "total_users": 0}],  # 1
            [{"users_with_path": 0}],  # 2
            [{"total_computers": 0, "no_laps": 0}],  # 3
            [{"tier_zero_count": 0}],  # 4
            [{"kerberoastable_admins": 0}],  # 5
            [{"asrep_users": 0}],  # 6
            [{"unconstrained_non_dc": 0}],  # 7
            [{"domain_admin_count": 0}],  # 8
        ]

        metrics = calculate_exposure_metrics(bh)

        # Percentages must not be computed (would divide by zero)
        assert "pct_users_with_path_to_da" not in metrics
        assert "pct_computers_without_laps" not in metrics
