"""Query registration base classes and decorator"""

from dataclasses import dataclass
from typing import TYPE_CHECKING, Callable, List, Optional, Tuple

if TYPE_CHECKING:
    from runoff.display.colors import Severity

# Global query registry - populated by @register_query decorator
QUERY_REGISTRY: List["QueryMetadata"] = []


@dataclass
class QueryMetadata:
    """Metadata for a registered query function"""

    name: str
    func: Callable
    category: str
    default: bool
    severity: "Severity"
    tags: Tuple[str, ...] = ()
    depends_on: Tuple[str, ...] = ()


def register_query(
    name: str,
    category: str,
    default: bool = True,
    severity: Optional["Severity"] = None,
    tags: Tuple[str, ...] = (),
    depends_on: Tuple[str, ...] = (),
):
    """Decorator to register a query function in the global registry.

    Args:
        name: Display name for the query
        category: Category for grouping (e.g., "Privilege Escalation")
        default: Whether query runs by default with -a flag
        severity: Severity level (CRITICAL, HIGH, MEDIUM, LOW, INFO)
        tags: Optional tags for filtering (e.g., ("quick-win", "stealthy"))
        depends_on: Names of queries that should run before this one

    Usage:
        @register_query("Kerberoastable Users", "Privilege Escalation", True,
                         Severity.HIGH, tags=("quick-win", "requires-creds"))
        def get_kerberoastable(bh, domain=None, severity=None):
            ...
    """

    def decorator(func: Callable) -> Callable:
        from runoff.display.colors import Severity as SeverityEnum

        sev = severity if severity is not None else SeverityEnum.MEDIUM
        QUERY_REGISTRY.append(QueryMetadata(name, func, category, default, sev, tags, depends_on))
        return func

    return decorator


def sort_by_dependencies(queries: List["QueryMetadata"]) -> List["QueryMetadata"]:
    """Sort queries respecting depends_on ordering (topological sort).

    Queries with no dependencies come first. If A depends on B,
    B will appear before A. Circular dependencies are ignored.
    """
    name_to_query = {q.name: q for q in queries}
    name_set = set(name_to_query.keys())
    visited: set = set()
    result: List[QueryMetadata] = []

    def visit(q: "QueryMetadata") -> None:
        if q.name in visited:
            return
        visited.add(q.name)
        for dep_name in q.depends_on:
            if dep_name in name_set and dep_name not in visited:
                visit(name_to_query[dep_name])
        result.append(q)

    for q in queries:
        visit(q)

    return result
