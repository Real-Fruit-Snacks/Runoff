"""Load default settings from config file (~/.config/runoff/config.yaml)."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from runoff.api.config import get_config_dir


def get_config_file_path() -> Path:
    """Return the path to the user config file."""
    return get_config_dir() / "config.yaml"


def load_config_defaults() -> dict[str, Any]:
    """Load defaults from the YAML config file.

    Returns a dict with keys matching CLI option names:
      bolt, username, password, domain, output_format, severity, quiet, no_color, debug, abuse

    Missing keys are omitted (not set to None).
    """
    path = get_config_file_path()
    if not path.exists():
        return {}

    try:
        import yaml
    except ImportError:
        # PyYAML not installed — fall back silently
        return _load_simple_yaml(path)

    try:
        with open(path, encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
    except Exception:
        return {}

    if not isinstance(data, dict):
        return {}

    return _normalise(data)


def _load_simple_yaml(path: Path) -> dict[str, Any]:
    """Minimal YAML parser for simple key: value files (no PyYAML needed)."""
    result: dict[str, Any] = {}
    try:
        with open(path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if ":" not in line:
                    continue
                key, _, value = line.partition(":")
                key = key.strip()
                value = value.strip()
                # Strip quotes
                if len(value) >= 2 and value[0] == value[-1] and value[0] in ("'", '"'):
                    value = value[1:-1]
                # Boolean handling
                if value.lower() in ("true", "yes"):
                    result[key] = True
                elif value.lower() in ("false", "no"):
                    result[key] = False
                elif value == "":
                    continue
                else:
                    result[key] = value
    except Exception:
        return {}
    return _normalise(result)


# Map config file keys to CLI option names
_KEY_MAP = {
    "bolt_uri": "bolt",
    "bolt": "bolt",
    "uri": "bolt",
    "username": "username",
    "user": "username",
    "password": "password",
    "pass": "password",
    "domain": "domain",
    "output": "output_format",
    "output_format": "output_format",
    "format": "output_format",
    "severity": "severity",
    "quiet": "quiet",
    "no_color": "no_color",
    "no-color": "no_color",
    "debug": "debug",
    "abuse": "abuse",
}

# Valid values for constrained fields
_VALID_FORMATS = {"table", "json", "csv", "html", "markdown"}


def _normalise(data: dict) -> dict[str, Any]:
    """Map config file keys to CLI option names and validate values."""
    result: dict[str, Any] = {}
    for key, value in data.items():
        cli_key = _KEY_MAP.get(key.lower())
        if cli_key is None:
            continue
        # Skip None/empty values
        if value is None or value == "":
            continue
        # Validate output_format
        if cli_key == "output_format" and str(value).lower() not in _VALID_FORMATS:
            continue
        result[cli_key] = value
    return result
