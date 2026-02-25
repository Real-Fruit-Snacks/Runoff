"""Tests for configuration singleton and config file loading."""

import threading
from concurrent.futures import ThreadPoolExecutor


class TestConfigDefaults:
    """Test Config class default values."""

    def test_default_quiet_mode(self):
        """Test quiet_mode defaults to False."""
        from runoff.core.config import Config

        cfg = Config()
        assert cfg.quiet_mode is False

    def test_default_debug_mode(self):
        """Test debug_mode defaults to False."""
        from runoff.core.config import Config

        cfg = Config()
        assert cfg.debug_mode is False

    def test_default_no_color(self):
        """Test no_color defaults to False."""
        from runoff.core.config import Config

        cfg = Config()
        assert cfg.no_color is False

    def test_default_output_format(self):
        """Test output_format defaults to 'table'."""
        from runoff.core.config import Config

        cfg = Config()
        assert cfg.output_format == "table"

    def test_default_severity_filter(self):
        """Test severity_filter defaults to empty set."""
        from runoff.core.config import Config

        cfg = Config()
        assert cfg.severity_filter == set()

    def test_default_show_progress(self):
        """Test show_progress defaults to False."""
        from runoff.core.config import Config

        cfg = Config()
        assert cfg.show_progress is False

    def test_default_owned_cache(self):
        """Test owned_cache defaults to empty dict."""
        from runoff.core.config import Config

        cfg = Config()
        assert cfg.owned_cache == {}


class TestConfigSetters:
    """Test Config class property setters."""

    def test_set_quiet_mode(self):
        """Test setting quiet_mode."""
        from runoff.core.config import Config

        cfg = Config()
        cfg.quiet_mode = True
        assert cfg.quiet_mode is True

    def test_set_debug_mode(self):
        """Test setting debug_mode."""
        from runoff.core.config import Config

        cfg = Config()
        cfg.debug_mode = True
        assert cfg.debug_mode is True

    def test_set_no_color(self):
        """Test setting no_color."""
        from runoff.core.config import Config

        cfg = Config()
        cfg.no_color = True
        assert cfg.no_color is True

    def test_set_output_format(self):
        """Test setting output_format."""
        from runoff.core.config import Config

        cfg = Config()
        for fmt in ["table", "json", "csv", "html"]:
            cfg.output_format = fmt
            assert cfg.output_format == fmt

    def test_set_severity_filter(self):
        """Test setting severity_filter."""
        from runoff.core.config import Config

        cfg = Config()
        cfg.severity_filter = {"CRITICAL", "HIGH"}
        assert cfg.severity_filter == {"CRITICAL", "HIGH"}

    def test_set_show_progress(self):
        """Test setting show_progress."""
        from runoff.core.config import Config

        cfg = Config()
        cfg.show_progress = True
        assert cfg.show_progress is True

    def test_set_owned_cache(self):
        """Test setting owned_cache."""
        from runoff.core.config import Config

        cfg = Config()
        cache = {"USER@DOMAIN.COM": True, "ADMIN@DOMAIN.COM": True}
        cfg.owned_cache = cache
        assert cfg.owned_cache == cache


class TestConfigReset:
    """Test Config reset functionality."""

    def test_reset_restores_defaults(self):
        """Test reset() restores all default values."""
        from runoff.core.config import Config

        cfg = Config()

        # Modify all settings
        cfg.quiet_mode = True
        cfg.debug_mode = True
        cfg.no_color = True
        cfg.output_format = "json"
        cfg.severity_filter = {"CRITICAL"}
        cfg.show_progress = True
        cfg.owned_cache = {"USER@DOMAIN.COM": True}

        # Reset
        cfg.reset()

        # Verify defaults restored
        assert cfg.quiet_mode is False
        assert cfg.debug_mode is False
        assert cfg.no_color is False
        assert cfg.output_format == "table"
        assert cfg.severity_filter == set()
        assert cfg.show_progress is False
        assert cfg.owned_cache == {}


class TestConfigSingleton:
    """Test Config singleton behavior."""

    def test_singleton_instance_exists(self):
        """Test global config instance is accessible."""
        from runoff.core.config import config

        assert config is not None

    def test_singleton_modifications_persist(self):
        """Test modifications to singleton persist."""
        from runoff.core.config import config

        original = config.quiet_mode
        config.quiet_mode = not original
        assert config.quiet_mode == (not original)

        # Reset for other tests
        config.quiet_mode = original


class TestConfigThreadSafety:
    """Test Config thread safety."""

    def test_concurrent_reads(self):
        """Test concurrent reads don't cause issues."""
        from runoff.core.config import Config

        cfg = Config()
        cfg.quiet_mode = True
        results = []

        def read_config():
            for _ in range(100):
                results.append(cfg.quiet_mode)

        threads = [threading.Thread(target=read_config) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert all(r is True for r in results)

    def test_concurrent_writes(self):
        """Test concurrent writes don't corrupt state."""
        from runoff.core.config import Config

        cfg = Config()
        counter = {"value": 0}

        def increment_cache():
            for i in range(100):
                current = cfg.owned_cache.copy()
                current[f"USER{threading.current_thread().name}_{i}"] = True
                cfg.owned_cache = current
                counter["value"] += 1

        with ThreadPoolExecutor(max_workers=5) as executor:
            futures = [executor.submit(increment_cache) for _ in range(5)]
            for f in futures:
                f.result()

        # Should have processed all increments without error
        assert counter["value"] == 500

    def test_concurrent_read_write(self):
        """Test concurrent reads and writes work correctly."""
        from runoff.core.config import Config

        cfg = Config()
        errors = []

        def reader():
            try:
                for _ in range(100):
                    _ = cfg.debug_mode
                    _ = cfg.output_format
            except Exception as e:
                errors.append(e)

        def writer():
            try:
                for i in range(100):
                    cfg.debug_mode = i % 2 == 0
                    cfg.output_format = "json" if i % 2 == 0 else "table"
            except Exception as e:
                errors.append(e)

        threads = []
        for _ in range(5):
            threads.append(threading.Thread(target=reader))
            threads.append(threading.Thread(target=writer))

        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(errors) == 0, f"Thread errors occurred: {errors}"


# ===========================================================================
# Config File Loading — runoff.cli.defaults
# ===========================================================================


class TestLoadConfigDefaults:
    """Tests for load_config_defaults()."""

    def test_returns_empty_when_no_file(self, tmp_path, monkeypatch):
        """Returns empty dict when config file doesn't exist."""
        from runoff.cli.defaults import load_config_defaults

        monkeypatch.setattr("runoff.cli.defaults.get_config_dir", lambda: tmp_path)
        assert load_config_defaults() == {}

    def test_loads_simple_yaml(self, tmp_path, monkeypatch):
        """Loads key: value pairs from YAML config file."""
        from runoff.cli.defaults import load_config_defaults

        monkeypatch.setattr("runoff.cli.defaults.get_config_dir", lambda: tmp_path)
        config_file = tmp_path / "config.yaml"
        config_file.write_text(
            "bolt_uri: bolt://10.0.0.5:7687\n"
            "username: neo4j\n"
            "password: s3cret\n"
            "domain: CORP.LOCAL\n"
        )

        result = load_config_defaults()
        assert result["bolt"] == "bolt://10.0.0.5:7687"
        assert result["username"] == "neo4j"
        assert result["password"] == "s3cret"
        assert result["domain"] == "CORP.LOCAL"

    def test_key_aliases(self, tmp_path, monkeypatch):
        """Various key aliases map to correct CLI option names."""
        from runoff.cli.defaults import load_config_defaults

        monkeypatch.setattr("runoff.cli.defaults.get_config_dir", lambda: tmp_path)
        config_file = tmp_path / "config.yaml"
        config_file.write_text(
            "uri: bolt://host:7687\n" "user: admin\n" "pass: mypassword\n" "format: json\n"
        )

        result = load_config_defaults()
        assert result["bolt"] == "bolt://host:7687"
        assert result["username"] == "admin"
        assert result["password"] == "mypassword"
        assert result["output_format"] == "json"

    def test_boolean_values(self, tmp_path, monkeypatch):
        """Boolean values are parsed correctly."""
        from runoff.cli.defaults import load_config_defaults

        monkeypatch.setattr("runoff.cli.defaults.get_config_dir", lambda: tmp_path)
        config_file = tmp_path / "config.yaml"
        config_file.write_text("quiet: true\n" "debug: false\n" "no_color: yes\n" "abuse: no\n")

        result = load_config_defaults()
        assert result["quiet"] is True
        assert result["debug"] is False
        assert result["no_color"] is True
        assert result["abuse"] is False

    def test_quoted_values(self, tmp_path, monkeypatch):
        """Quoted values have quotes stripped."""
        from runoff.cli.defaults import load_config_defaults

        monkeypatch.setattr("runoff.cli.defaults.get_config_dir", lambda: tmp_path)
        config_file = tmp_path / "config.yaml"
        config_file.write_text("password: 'my secret password'\n" 'domain: "CORP.LOCAL"\n')

        result = load_config_defaults()
        assert result["password"] == "my secret password"
        assert result["domain"] == "CORP.LOCAL"

    def test_invalid_output_format_ignored(self, tmp_path, monkeypatch):
        """Invalid output format values are ignored."""
        from runoff.cli.defaults import load_config_defaults

        monkeypatch.setattr("runoff.cli.defaults.get_config_dir", lambda: tmp_path)
        config_file = tmp_path / "config.yaml"
        config_file.write_text("output_format: invalid_format\n")

        result = load_config_defaults()
        assert "output_format" not in result

    def test_unknown_keys_ignored(self, tmp_path, monkeypatch):
        """Unknown config keys are silently ignored."""
        from runoff.cli.defaults import load_config_defaults

        monkeypatch.setattr("runoff.cli.defaults.get_config_dir", lambda: tmp_path)
        config_file = tmp_path / "config.yaml"
        config_file.write_text("bolt_uri: bolt://host:7687\n" "unknown_key: some_value\n")

        result = load_config_defaults()
        assert "bolt" in result
        assert "unknown_key" not in result

    def test_comments_and_empty_lines(self, tmp_path, monkeypatch):
        """Comments and empty lines are ignored."""
        from runoff.cli.defaults import load_config_defaults

        monkeypatch.setattr("runoff.cli.defaults.get_config_dir", lambda: tmp_path)
        config_file = tmp_path / "config.yaml"
        config_file.write_text(
            "# This is a comment\n" "\n" "username: neo4j\n" "\n" "password: test\n"
        )

        result = load_config_defaults()
        assert result["username"] == "neo4j"
        assert result["password"] == "test"

    def test_empty_values_skipped(self, tmp_path, monkeypatch):
        """Empty values are not included."""
        from runoff.cli.defaults import load_config_defaults

        monkeypatch.setattr("runoff.cli.defaults.get_config_dir", lambda: tmp_path)
        config_file = tmp_path / "config.yaml"
        config_file.write_text("username: neo4j\n" "password:\n")

        result = load_config_defaults()
        assert result["username"] == "neo4j"
        assert "password" not in result

    def test_malformed_file_returns_empty(self, tmp_path, monkeypatch):
        """Malformed file returns empty dict without crashing."""
        from runoff.cli.defaults import load_config_defaults

        monkeypatch.setattr("runoff.cli.defaults.get_config_dir", lambda: tmp_path)
        config_file = tmp_path / "config.yaml"
        config_file.write_bytes(b"\x00\x01\x02\x03")

        result = load_config_defaults()
        assert result == {}


class TestConfigFilePath:
    """Tests for get_config_file_path()."""

    def test_returns_path_object(self):
        from pathlib import Path

        from runoff.cli.defaults import get_config_file_path

        result = get_config_file_path()
        assert isinstance(result, Path)
        assert result.name == "config.yaml"

    def test_path_under_config_dir(self, monkeypatch, tmp_path):
        from runoff.cli.defaults import get_config_file_path

        monkeypatch.setattr("runoff.cli.defaults.get_config_dir", lambda: tmp_path)
        result = get_config_file_path()
        assert result.parent == tmp_path


class TestNormalise:
    """Tests for _normalise() key mapping."""

    def test_maps_bolt_uri(self):
        from runoff.cli.defaults import _normalise

        assert _normalise({"bolt_uri": "bolt://x"})["bolt"] == "bolt://x"

    def test_maps_user(self):
        from runoff.cli.defaults import _normalise

        assert _normalise({"user": "admin"})["username"] == "admin"

    def test_maps_no_color_hyphen(self):
        from runoff.cli.defaults import _normalise

        assert _normalise({"no-color": True})["no_color"] is True

    def test_case_insensitive(self):
        from runoff.cli.defaults import _normalise

        assert _normalise({"BOLT_URI": "bolt://x"})["bolt"] == "bolt://x"


class TestOutputFileConfig:
    """Test output_file property added for item 11."""

    def test_default_output_file(self):
        from runoff.core.config import Config

        cfg = Config()
        assert cfg.output_file is None

    def test_set_output_file(self):
        from runoff.core.config import Config

        cfg = Config()
        cfg.output_file = "/tmp/output.json"
        assert cfg.output_file == "/tmp/output.json"

    def test_reset_clears_output_file(self):
        from runoff.core.config import Config

        cfg = Config()
        cfg.output_file = "/tmp/output.json"
        cfg.reset()
        assert cfg.output_file is None
