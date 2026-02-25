"""
Runoff - BloodHound CE Quick Win Extractor

A CLI tool for identifying Active Directory attack paths, misconfigurations,
and privilege escalation opportunities from BloodHound Community Edition data.
"""

__version__ = "3.1.0"
__author__ = "Real-Fruit-Snacks"

from runoff.core.config import config
from runoff.display.colors import Severity, colors


# Lazy imports to avoid requiring neo4j at import time
def __getattr__(name):
    if name == "BloodHoundCE":
        from runoff.core.bloodhound import BloodHoundCE

        return BloodHoundCE
    if name == "get_query_registry":
        from runoff.queries import get_query_registry

        return get_query_registry
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


__all__ = [
    "BloodHoundCE",
    "config",
    "colors",
    "Severity",
    "get_query_registry",
]
