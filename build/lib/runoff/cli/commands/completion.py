"""Shell completion script generation.

Requires Click >= 8.0
"""

from __future__ import annotations

import click


@click.command()
@click.argument("shell", type=click.Choice(["bash", "zsh", "fish"]))
def completion(shell):
    """Generate shell completion script.

    Outputs a completion script for the specified shell.
    Add the output to your shell configuration to enable tab completion.

    \b
    Examples:
        runoff completion bash >> ~/.bashrc
        runoff completion zsh >> ~/.zshrc
        runoff completion fish > ~/.config/fish/completions/runoff.fish
    """
    scripts = {
        "bash": _bash_completion(),
        "zsh": _zsh_completion(),
        "fish": _fish_completion(),
    }
    click.echo(scripts[shell])


def _bash_completion() -> str:
    return """\
# Runoff Bash completion
# Add to ~/.bashrc or ~/.bash_completion
eval "$(_RUNOFF_COMPLETE=bash_source runoff)\""""


def _zsh_completion() -> str:
    return """\
# Runoff Zsh completion
# Add to ~/.zshrc
eval "$(_RUNOFF_COMPLETE=zsh_source runoff)\""""


def _fish_completion() -> str:
    return """\
# Runoff Fish completion
# Save to ~/.config/fish/completions/runoff.fish
_RUNOFF_COMPLETE=fish_source runoff | source"""
