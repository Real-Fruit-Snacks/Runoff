"""Entry point for python -m runoff"""

from __future__ import annotations

import sys


def main():
    from runoff.cli import cli

    return cli(standalone_mode=False)


if __name__ == "__main__":
    sys.exit(main() or 0)
