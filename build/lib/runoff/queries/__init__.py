"""Query registry with auto-discovery from category modules.

This module imports all query category modules, which triggers the
@register_query decorator to populate QUERY_REGISTRY.
"""

from __future__ import annotations

import importlib.util
import os
import sys
from pathlib import Path

from runoff.queries.base import QUERY_REGISTRY, QueryMetadata, register_query

# Import all category modules to trigger decorator registration
# These imports look unused but are required to execute @register_query decorators
from . import acl  # noqa: F401
from . import adcs  # noqa: F401
from . import azure  # noqa: F401
from . import credentials  # noqa: F401
from . import delegation  # noqa: F401
from . import domain  # noqa: F401
from . import exchange  # noqa: F401
from . import gpo  # noqa: F401
from . import groups  # noqa: F401
from . import hygiene  # noqa: F401
from . import lateral  # noqa: F401
from . import misc  # noqa: F401
from . import owned  # noqa: F401
from . import paths  # noqa: F401


def get_plugin_dir() -> Path:
    """Get the plugin queries directory path."""
    xdg_config = os.environ.get("XDG_CONFIG_HOME")
    if xdg_config:
        return Path(xdg_config) / "runoff" / "queries"
    return Path.home() / ".config" / "runoff" / "queries"


_plugins_loaded = False


def _load_plugins(*, allow_plugins: bool = False) -> int:
    """Load custom query plugins from ~/.config/runoff/queries/.

    Args:
        allow_plugins: If True, load plugins. If False, warn if plugins exist.

    Returns:
        Number of plugins loaded successfully
    """
    global _plugins_loaded
    if _plugins_loaded:
        return 0

    plugin_dir = get_plugin_dir()
    if not plugin_dir.is_dir():
        _plugins_loaded = True
        return 0

    py_files = sorted(f for f in plugin_dir.glob("*.py") if not f.name.startswith("_"))
    if not py_files:
        _plugins_loaded = True
        return 0

    if not allow_plugins:
        # Don't set _plugins_loaded — allow a later call with allow_plugins=True
        import warnings

        warnings.warn(
            f"Found {len(py_files)} plugin(s) in {plugin_dir} — "
            f"use --load-plugins to enable custom queries",
            stacklevel=2,
        )
        return 0

    _plugins_loaded = True
    loaded = 0
    for py_file in py_files:
        module_name = f"runoff_plugin_{py_file.stem}"
        try:
            spec = importlib.util.spec_from_file_location(module_name, py_file)
            if spec is None or spec.loader is None:
                continue
            module = importlib.util.module_from_spec(spec)
            sys.modules[module_name] = module
            try:
                spec.loader.exec_module(module)
            except Exception:
                sys.modules.pop(module_name, None)
                raise
            loaded += 1
        except Exception as e:
            import warnings

            warnings.warn(
                f"Failed to load plugin {py_file.name}: {e}",
                stacklevel=2,
            )
    return loaded


def get_query_registry(*, allow_plugins: bool = False):
    """Return the full query registry."""
    _load_plugins(allow_plugins=allow_plugins)
    return QUERY_REGISTRY


def get_queries_by_category(*, allow_plugins: bool = False) -> dict:
    """Return queries grouped by category.

    Returns:
        Dictionary mapping category names to lists of QueryMetadata
    """
    _load_plugins(allow_plugins=allow_plugins)
    by_category: dict[str, list[QueryMetadata]] = {}
    for query in QUERY_REGISTRY:
        if query.category not in by_category:
            by_category[query.category] = []
        by_category[query.category].append(query)
    return by_category


def get_query_by_name(name: str, *, allow_plugins: bool = False) -> QueryMetadata | None:
    """Get a specific query by its display name.

    Args:
        name: The display name of the query
        allow_plugins: If True, load plugins before searching.

    Returns:
        QueryMetadata object or None if not found
    """
    _load_plugins(allow_plugins=allow_plugins)
    for query in QUERY_REGISTRY:
        if query.name == name:
            return query
    return None


__all__ = [
    "QUERY_REGISTRY",
    "QueryMetadata",
    "register_query",
    "get_query_registry",
    "get_queries_by_category",
    "get_query_by_name",
    "get_plugin_dir",
]
