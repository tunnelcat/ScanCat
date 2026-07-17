"""Shared notification convention for scancat.

A leading token tags each line's severity; the TUI colours the token (see
ui.py) and console output colours the whole line the same way. This module is
the single source of the token -> colour map so both stay in sync.
  [+] finding/success  [*] info  [!] warning  [-] error
"""
from termcolor import colored

NOTIFY_COLORS = {"[+]": "green", "[*]": "cyan", "[!]": "yellow", "[-]": "red"}


def cnote(line):
    """Return `line` coloured for the console by its leading notification
    token, or unchanged if it carries none."""
    color = NOTIFY_COLORS.get(line[:3])
    return colored(line, color) if color else line


def nprint(line):
    """print() a notification line coloured by its leading token."""
    print(cnote(line))
