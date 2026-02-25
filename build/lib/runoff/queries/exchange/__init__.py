"""Query functions for exchange"""

from .exchange_domain_rights import get_exchange_domain_rights
from .exchange_groups import get_exchange_groups
from .exchange_permissions_paths import get_exchange_permissions_paths
from .exchange_trusted_subsystem import get_exchange_trusted_subsystem
from .mailbox_delegation import get_mailbox_delegation

__all__ = [
    "get_exchange_domain_rights",
    "get_exchange_groups",
    "get_exchange_permissions_paths",
    "get_exchange_trusted_subsystem",
    "get_mailbox_delegation",
]
